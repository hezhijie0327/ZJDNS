package dnscrypt

import (
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

// Wire protocol constants.
const (
	clientMagicSize   = 8
	KeySize           = 32
	SharedKeySize     = 32
	nonceSize         = 24
	ResolverMagicSize = 8
	MinDNSPacketSize  = 12 + 5
	minUDPQuerySize   = 256
	padAlignment      = 64 // encrypt to multiple of 64 bytes for traffic analysis resistance
	// mlkemCiphertextSize defined in cert.go (1088 bytes, NIST FIPS 203)
)

// DNSCrypt query header sizes.
// Classic:  clientMagic(8) + clientPk(32) + nonceHalf(12) = 52
// PQ:       + mlkemCiphertext(1088) = 1140
const (
	QueryHeaderLen   = clientMagicSize + KeySize + nonceSize/2                       // 52
	QueryHeaderLenPQ = clientMagicSize + KeySize + mlkemCiphertextSize + nonceSize/2 // 1140
)

// ResolverMagic is prepended to every encrypted response.
var ResolverMagic = []byte{0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38}

// encryptedQuery holds the parsed header of an encrypted client query.
type encryptedQuery struct {
	ClientMagic [clientMagicSize]byte
	ClientPk    [KeySize]byte
	Nonce       [nonceSize]byte
}

// pqtQuery extends encryptedQuery with the ML-KEM ciphertext for PQ sessions.
type pqQuery struct {
	encryptedQuery
	MlkemCiphertext [mlkemCiphertextSize]byte
}

// parseQuery extracts the DNSCrypt header from a raw query packet.
// For PQ constructions, it also extracts the ML-KEM ciphertext.
func parseQuery(b []byte, cert *Certificate) (*encryptedQuery, *pqQuery, []byte, error) {
	headerLen := QueryHeaderLen
	if cert.ESVersion.IsPQ() {
		headerLen = QueryHeaderLenPQ
	}
	if len(b) < headerLen+secretbox.Overhead+MinDNSPacketSize {
		return nil, nil, nil, errTooShort
	}

	q := &encryptedQuery{}
	copy(q.ClientMagic[:], b[:clientMagicSize])
	copy(q.ClientPk[:], b[clientMagicSize:clientMagicSize+KeySize])

	var pq *pqQuery
	if cert.ESVersion.IsPQ() {
		pq = &pqQuery{encryptedQuery: *q}
		copy(pq.MlkemCiphertext[:], b[clientMagicSize+KeySize:clientMagicSize+KeySize+mlkemCiphertextSize])
		copy(pq.Nonce[:nonceSize/2], b[clientMagicSize+KeySize+mlkemCiphertextSize:headerLen])
	} else {
		copy(q.Nonce[:nonceSize/2], b[clientMagicSize+KeySize:headerLen])
	}

	if q.ClientMagic != cert.ClientMagic {
		return nil, nil, nil, errClientMagic
	}

	encrypted := b[headerLen:]
	return q, pq, encrypted, nil
}

// decrypt decrypts an encrypted DNS query using the classic X25519-only key exchange.
func (q *encryptedQuery) decrypt(encrypted []byte, cert *Certificate) ([]byte, error) {
	sharedKey, err := ComputeSharedKey(cert.ESVersion, &cert.ResolverSk, &q.ClientPk)
	if err != nil {
		return nil, fmt.Errorf("dnscrypt: shared key: %w", err)
	}

	var nonce [nonceSize]byte
	copy(nonce[:], q.Nonce[:])

	return decryptPayload(encrypted, &nonce, &sharedKey, cert.ESVersion)
}

// decryptPQ decrypts an encrypted DNS query using the hybrid post-quantum
// key exchange (X25519 + ML-KEM-768 → HKDF-SHA256).
func (pq *pqQuery) decryptPQ(encrypted []byte, cert *Certificate, mlkemDK *mlkem.DecapsulationKey768) ([]byte, error) {
	mlkemSS, err := mlkemDK.Decapsulate(pq.MlkemCiphertext[:])
	if err != nil {
		return nil, fmt.Errorf("dnscrypt: mlkem decapsulate: %w", err)
	}

	sharedKey, err := ComputeSharedKeyPQ(&cert.ResolverSk, &pq.ClientPk, mlkemSS)
	if err != nil {
		return nil, fmt.Errorf("dnscrypt: pq shared key: %w", err)
	}

	var nonce [nonceSize]byte
	copy(nonce[:], pq.Nonce[:])

	return decryptPayload(encrypted, &nonce, &sharedKey, cert.ESVersion.AEAD())
}

// decryptPayload decrypts a payload using the given AEAD construction.
func decryptPayload(encrypted []byte, nonce *[nonceSize]byte, sharedKey *[SharedKeySize]byte, aead CryptoConstruction) ([]byte, error) {
	var decrypted []byte
	var err error
	switch aead {
	case XSalsa20Poly1305:
		var ok bool
		decrypted, ok = secretbox.Open(nil, encrypted, nonce, sharedKey)
		if !ok {
			return nil, errors.New("dnscrypt: decryption failed")
		}
	case XChacha20Poly1305:
		decrypted, err = XChachaOpen(nil, nonce[:], encrypted, sharedKey[:])
		if err != nil {
			return nil, fmt.Errorf("dnscrypt: xchacha open: %w", err)
		}
	default:
		return nil, fmt.Errorf("dnscrypt: unknown crypto construction %d", aead)
	}
	return Unpad(decrypted)
}

// encryptResponse encrypts a DNS response using the query's parameters.
func encryptResponse(esVersion CryptoConstruction, packet []byte, sharedKey *[SharedKeySize]byte, queryNonce *[nonceSize]byte) ([]byte, error) {
	aead := esVersion
	if esVersion.IsPQ() {
		aead = esVersion.AEAD()
	}

	var nonce [nonceSize]byte
	copy(nonce[:nonceSize/2], queryNonce[:nonceSize/2])

	// Resolver nonce: 4 random bytes + 8 bytes timestamp.
	if _, err := rand.Read(nonce[nonceSize/2 : nonceSize/2+4]); err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint64(nonce[nonceSize/2+4:], uint64(time.Now().UnixNano()))

	padded := PadPacket(packet)

	response := make([]byte, 0, ResolverMagicSize+nonceSize+len(padded)+secretbox.Overhead)
	response = append(response, ResolverMagic...)
	response = append(response, nonce[:]...)
	switch aead {
	case XSalsa20Poly1305:
		response = secretbox.Seal(response, padded, &nonce, sharedKey)
	case XChacha20Poly1305:
		response = XChachaSeal(response, nonce[:], padded, sharedKey[:])
	default:
		return nil, fmt.Errorf("dnscrypt: unknown crypto construction %d", aead)
	}
	return response, nil
}

// ComputeSharedKey derives the shared key via X25519 ECDH followed by the
// construction-specific key derivation (HSalsa20 for XSalsa20Poly1305,
// HChaCha20 for XChacha20Poly1305). For PQ constructions, use computeSharedKeyPQ.
func ComputeSharedKey(esVersion CryptoConstruction, secretKey, publicKey *[KeySize]byte) ([SharedKeySize]byte, error) {
	var sharedKey [SharedKeySize]byte
	switch esVersion {
	case XSalsa20Poly1305:
		box.Precompute(&sharedKey, publicKey, secretKey)
		return sharedKey, nil
	case XChacha20Poly1305:
		return xchachaSharedKey(secretKey, publicKey)
	default:
		return sharedKey, fmt.Errorf("dnscrypt: unknown crypto construction %d", esVersion)
	}
}

// ComputeSharedKeyPQ combines X25519 ECDH and ML-KEM-768 shared secret via
// HKDF-SHA256 into a single 32-byte AEAD key.  The caller is responsible for
// the asymmetric ML-KEM-768 operation:
//
//	Client: mlkemSS, ciphertext = ek.Encapsulate()
//	Server: mlkemSS = mlkemDK.Decapsulate(ciphertext)
//
//	shared_key = HKDF-SHA256(x25519_ss || mlkem_ss, "dnscrypt-pq-v1", 32)
func ComputeSharedKeyPQ(x25519Sk, x25519Pk *[KeySize]byte, mlkemSS []byte) ([SharedKeySize]byte, error) {
	var zero [SharedKeySize]byte

	x25519SS, err := curve25519.X25519(x25519Sk[:], x25519Pk[:])
	if err != nil {
		return zero, fmt.Errorf("dnscrypt: x25519: %w", err)
	}

	combined := make([]byte, 0, KeySize+len(mlkemSS))
	combined = append(combined, x25519SS...)
	combined = append(combined, mlkemSS...)

	var sharedKey [SharedKeySize]byte
	kdf := hkdf.New(sha256.New, combined, nil, []byte("dnscrypt-pq-v1"))
	if _, err := io.ReadFull(kdf, sharedKey[:]); err != nil {
		return zero, fmt.Errorf("dnscrypt: hkdf: %w", err)
	}
	return sharedKey, nil
}

// GenerateX25519KeyPair creates an ephemeral X25519 key pair.
func GenerateX25519KeyPair() (publicKey, secretKey [KeySize]byte, err error) {
	if _, err := rand.Read(secretKey[:]); err != nil {
		return publicKey, secretKey, err
	}
	pk, err := curve25519.X25519(secretKey[:], curve25519.Basepoint)
	if err != nil {
		return publicKey, secretKey, err
	}
	copy(publicKey[:], pk)
	return publicKey, secretKey, nil
}

// padPacket pads a DNS packet to the minimum valid size for DNSCrypt.
// Padding format: 0x80 followed by NUL bytes, total length multiple of 64,
// minimum 256 bytes.
func PadPacket(packet []byte) []byte {
	minLen := len(packet) + 1
	if minLen < minUDPQuerySize {
		minLen = minUDPQuerySize
	}
	// Round up to next padAlignment-byte boundary.
	if minLen%padAlignment != 0 {
		minLen += padAlignment - minLen%padAlignment
	}
	padded := make([]byte, minLen)
	copy(padded, packet)
	padded[len(packet)] = 0x80
	return padded
}

// unpad removes ISO 7816-4 padding from a decrypted packet.
func Unpad(packet []byte) ([]byte, error) {
	for i := len(packet) - 1; i >= 0; i-- {
		if packet[i] == 0x80 {
			if i < MinDNSPacketSize {
				return nil, errTooShort
			}
			return packet[:i], nil
		}
		if packet[i] != 0x00 {
			return nil, errors.New("dnscrypt: invalid padding")
		}
	}
	return nil, errors.New("dnscrypt: missing padding marker")
}

// Err sentinels.
var (
	errTooShort    = errors.New("dnscrypt: message too short")
	errClientMagic = errors.New("dnscrypt: invalid client magic")
)
