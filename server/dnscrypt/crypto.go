package dnscrypt

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/curve25519"
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
)

// ResolverMagic is prepended to every encrypted response.
var ResolverMagic = []byte{0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38}

// encryptedQuery holds the parsed header of an encrypted client query.
type encryptedQuery struct {
	ClientMagic [clientMagicSize]byte
	ClientPk    [KeySize]byte
	Nonce       [nonceSize]byte
}

// parseQuery extracts the DNSCrypt header from a raw query packet.
// Returns nil if the packet is not a valid encrypted query.
func parseQuery(b []byte, cert *Certificate) (*encryptedQuery, []byte, error) {
	headerLen := clientMagicSize + KeySize + nonceSize/2
	if len(b) < headerLen+secretbox.Overhead+MinDNSPacketSize {
		return nil, nil, errTooShort
	}

	q := &encryptedQuery{}
	copy(q.ClientMagic[:], b[:clientMagicSize])
	copy(q.ClientPk[:], b[clientMagicSize:clientMagicSize+KeySize])
	copy(q.Nonce[:nonceSize/2], b[clientMagicSize+KeySize:headerLen])

	if q.ClientMagic != cert.ClientMagic {
		return nil, nil, errClientMagic
	}

	encrypted := b[headerLen:]
	return q, encrypted, nil
}

// decryptQuery decrypts an encrypted DNS query.
func (q *encryptedQuery) decrypt(encrypted []byte, cert *Certificate) ([]byte, error) {
	sharedKey, err := ComputeSharedKey(cert.ESVersion, &cert.ResolverSk, &q.ClientPk)
	if err != nil {
		return nil, fmt.Errorf("dnscrypt: shared key: %w", err)
	}

	var nonce [nonceSize]byte
	copy(nonce[:], q.Nonce[:])

	var decrypted []byte
	switch cert.ESVersion {
	case XSalsa20Poly1305:
		var ok bool
		decrypted, ok = secretbox.Open(nil, encrypted, &nonce, &sharedKey)
		if !ok {
			return nil, errors.New("dnscrypt: decryption failed")
		}
	case XChacha20Poly1305:
		decrypted, err = XChachaOpen(nil, nonce[:], encrypted, sharedKey[:])
		if err != nil {
			return nil, fmt.Errorf("dnscrypt: xchacha open: %w", err)
		}
	default:
		return nil, fmt.Errorf("dnscrypt: unknown crypto construction %d", cert.ESVersion)
	}

	return Unpad(decrypted)
}

// encryptResponse encrypts a DNS response using the query's parameters.
func encryptResponse(esVersion CryptoConstruction, packet []byte, sharedKey *[SharedKeySize]byte, queryNonce *[nonceSize]byte) ([]byte, error) {
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
	switch esVersion {
	case XSalsa20Poly1305:
		response = secretbox.Seal(response, padded, &nonce, sharedKey)
	case XChacha20Poly1305:
		response = XChachaSeal(response, nonce[:], padded, sharedKey[:])
	default:
		return nil, fmt.Errorf("dnscrypt: unknown crypto construction %d", esVersion)
	}
	return response, nil
}

// ComputeSharedKey derives the shared key via X25519 ECDH followed by the
// construction-specific key derivation (HSalsa20 for XSalsa20Poly1305,
// HChaCha20 for XChacha20Poly1305).
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

// padPacket pads a DNS packet to the minimum valid size for DNSCrypt.
// Padding format: 0x80 followed by NUL bytes, total length multiple of 64,
// minimum 256 bytes.
func PadPacket(packet []byte) []byte {
	minLen := len(packet) + 1
	if minLen < minUDPQuerySize {
		minLen = minUDPQuerySize
	}
	// Round up to next 64-byte boundary.
	if minLen%64 != 0 {
		minLen += 64 - minLen%64
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
