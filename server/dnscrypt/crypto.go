package dnscrypt

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/cloudflare/circl/kem/xwing"
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
)

// DNSCrypt query header sizes.
// Classic: clientMagic(8) + clientPk(32) + nonceHalf(12) = 52
// X-Wing:  clientMagic(8) + xwing_ct(1120) + nonceHalf(12) = 1140
const (
	QueryHeaderLen      = clientMagicSize + KeySize + nonceSize/2             // 52
	QueryHeaderLenXWing = clientMagicSize + xwingCiphertextSize + nonceSize/2 // 1140
)

// ResolverMagic is prepended to every encrypted response.
var ResolverMagic = []byte{0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38}

// encryptedQuery holds the parsed header of a classic encrypted client query.
type encryptedQuery struct {
	ClientMagic [clientMagicSize]byte
	ClientPk    [KeySize]byte
	Nonce       [nonceSize]byte
}

// xwingQuery holds the parsed header of an X-Wing post-quantum client query.
type xwingQuery struct {
	ClientMagic [clientMagicSize]byte
	Ciphertext  [xwingCiphertextSize]byte // 1120 bytes
	Nonce       [nonceSize]byte
}

// parseQuery extracts the DNSCrypt header from a raw query packet.
// Returns an encryptedQuery for classic constructions, or an xwingQuery
// for XWingPQ. One of the two query pointers will always be nil.
func parseQuery(b []byte, cert *Certificate) (*encryptedQuery, *xwingQuery, []byte, error) {
	if cert.ESVersion == XWingPQ {
		headerLen := QueryHeaderLenXWing
		if len(b) < headerLen+secretbox.Overhead+MinDNSPacketSize {
			return nil, nil, nil, errTooShort
		}
		q := &xwingQuery{}
		copy(q.ClientMagic[:], b[:clientMagicSize])
		copy(q.Ciphertext[:], b[clientMagicSize:clientMagicSize+xwingCiphertextSize])
		copy(q.Nonce[:nonceSize/2], b[clientMagicSize+xwingCiphertextSize:headerLen])

		if q.ClientMagic != cert.ClientMagic {
			return nil, nil, nil, errClientMagic
		}
		return nil, q, b[headerLen:], nil
	}

	// Classic path.
	headerLen := QueryHeaderLen
	if len(b) < headerLen+secretbox.Overhead+MinDNSPacketSize {
		return nil, nil, nil, errTooShort
	}

	q := &encryptedQuery{}
	copy(q.ClientMagic[:], b[:clientMagicSize])
	copy(q.ClientPk[:], b[clientMagicSize:clientMagicSize+KeySize])
	copy(q.Nonce[:nonceSize/2], b[clientMagicSize+KeySize:headerLen])

	if q.ClientMagic != cert.ClientMagic {
		return nil, nil, nil, errClientMagic
	}

	return q, nil, b[headerLen:], nil
}

// decrypt decrypts a classic encrypted DNS query using X25519-only key exchange.
// Returns the decrypted DNS message and the shared key for response encryption.
func (q *encryptedQuery) decrypt(encrypted []byte, cert *Certificate) ([]byte, [SharedKeySize]byte, error) {
	sharedKey, err := ComputeSharedKey(cert.ESVersion, &cert.ResolverSk, &q.ClientPk)
	if err != nil {
		return nil, sharedKey, fmt.Errorf("dnscrypt: shared key: %w", err)
	}

	var nonce [nonceSize]byte
	copy(nonce[:], q.Nonce[:])

	dec, decErr := decryptPayload(encrypted, &nonce, &sharedKey, cert.ESVersion)
	return dec, sharedKey, decErr
}

// decrypt decrypts an X-Wing encrypted DNS query using the hybrid
// post-quantum key exchange (X-Wing KEM → HKDF-SHA256).
// Returns the decrypted DNS message and the shared key for response encryption.
func (q *xwingQuery) decrypt(encrypted []byte, cert *Certificate, xwingSK *xwing.PrivateKey) ([]byte, [SharedKeySize]byte, error) {
	ct := make([]byte, xwingCiphertextSize)
	copy(ct, q.Ciphertext[:])
	ss := make([]byte, xwingSharedKeySize)
	xwingSK.DecapsulateTo(ss, ct)

	certCtx := cert.CertContext()
	sharedKey := deriveSharedKeyXWing(cert.ESVersion, q.ClientMagic[:], ss, ct, certCtx)

	var nonce [nonceSize]byte
	copy(nonce[:], q.Nonce[:])

	dec, decErr := decryptPayload(encrypted, &nonce, &sharedKey, XChacha20Poly1305)
	return dec, sharedKey, decErr
}

// deriveSharedKeyXWing derives the per-query symmetric key from the X-Wing
// shared secret following the standard DNSCrypt PQ key schedule:
//
//	salt = esVersion(2) || clientMagic(8)
//	info = certContext || ciphertext(1120)
//	key  = HKDF-SHA256(salt, xwingSS, info)
func deriveSharedKeyXWing(esVersion CryptoConstruction, clientMagic, xwingSS, xwingCT, certCtx []byte) [SharedKeySize]byte {
	// salt = esVersion(2) || clientMagic(8)
	salt := make([]byte, 2+len(clientMagic))
	binary.BigEndian.PutUint16(salt[:2], uint16(esVersion))
	copy(salt[2:], clientMagic)

	// info = certContext || ciphertext(1120)
	info := make([]byte, len(certCtx)+len(xwingCT))
	copy(info, certCtx)
	copy(info[len(certCtx):], xwingCT)

	var key [SharedKeySize]byte
	kdf := hkdf.New(sha256.New, xwingSS, salt, info)
	if _, err := io.ReadFull(kdf, key[:]); err != nil {
		// HKDF-SHA256 never errors for 32-byte output; this is defensive.
		panic(fmt.Sprintf("dnscrypt: hkdf: %v", err))
	}
	return key
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
//
// For XWingPQ, a 2-byte control block length prefix is prepended to the
// plaintext before padding and encryption, matching the standard
// response format.
func encryptResponse(esVersion CryptoConstruction, packet []byte, sharedKey *[SharedKeySize]byte, queryNonce *[nonceSize]byte, controlBlock []byte) ([]byte, error) {
	aead := esVersion.AEAD()

	var nonce [nonceSize]byte
	copy(nonce[:nonceSize/2], queryNonce[:nonceSize/2])

	// Resolver nonce: 4 random bytes + 8 bytes timestamp.
	if _, err := rand.Read(nonce[nonceSize/2 : nonceSize/2+4]); err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint64(nonce[nonceSize/2+4:], uint64(time.Now().UnixNano()))

	// Build plaintext. For XWingPQ, prepend control block length + control block.
	var padded []byte
	if esVersion == XWingPQ {
		cbLen := len(controlBlock)
		plaintext := make([]byte, 2+cbLen+len(packet))
		binary.BigEndian.PutUint16(plaintext[:2], uint16(cbLen))
		if cbLen > 0 {
			copy(plaintext[2:], controlBlock)
		}
		copy(plaintext[2+cbLen:], packet)
		padded = PadPacketXWing(plaintext)
	} else {
		padded = PadPacket(packet)
	}

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
// HChaCha20 for XChacha20Poly1305). For XWingPQ, use deriveSharedKeyXWing.
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

// PadPacket pads a DNS packet to the minimum valid size for DNSCrypt.
// Padding format: 0x80 followed by NUL bytes, total length multiple of 64,
// minimum 256 bytes. Used for classic constructions.
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

// PadPacketXWing pads a DNS response for X-Wing PQ, following the
// standard: minimum 64 bytes, then round up to next 64-byte boundary.
func PadPacketXWing(packet []byte) []byte {
	minLen := len(packet) + 1 // +1 for 0x80 marker
	if minLen < padAlignment {
		minLen = padAlignment
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

// Unpad removes ISO 7816-4 padding from a decrypted packet.
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
