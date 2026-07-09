// Package dnscrypt implements the DNSCrypt v2 protocol for encrypting DNS
// queries and responses.  It provides both client-side and server-side
// functionality using X25519 key exchange and XSalsa20-Poly1305 or
// XChacha20-Poly1305 authenticated encryption.
//
// See https://dnscrypt.info/protocol for the protocol specification.
package dnscrypt

import "fmt"

const (
	// minUDPQuestionSize is the minimum padded query size for UDP.  It must be
	// a multiple of 64 bytes.  Some servers (e.g. Quad9) reject smaller padded
	// queries.
	minUDPQuestionSize = 256

	// minDNSPacketSize is the minimum possible DNS packet size.
	minDNSPacketSize = 12 + 5

	// KeySize is the size of X25519 public and secret keys in bytes.
	KeySize = 32

	// SharedKeySize is the size of the shared key used to encrypt/decrypt
	// messages.
	SharedKeySize = 32

	// ClientMagicSize is the size of the client magic in bytes.  ClientMagic
	// is the first 8 bytes of a client query identifying which certificate
	// to use.  It may be a truncated public key.  Two valid certificates
	// cannot share the same client magic value.
	ClientMagicSize = 8

	// NonceSize is the size of the nonce in bytes.  For X25519-XSalsa20Poly1305
	// and X25519-XChacha20Poly1305, a 24-byte nonce must not be reused for a
	// given shared secret.
	NonceSize = 24

	// ResolverMagicSize is the size of the resolver magic in bytes.  It is the
	// first 8 bytes of every DNSCrypt response.
	ResolverMagicSize = 8

	// CertByteLength is the standard length of a serialized certificate.
	CertByteLength = 124

	// MinQueryLength is the minimum encrypted query length (header + tag +
	// minimum DNS packet).
	MinQueryLength = ClientMagicSize + KeySize + NonceSize/2 + TagSize + minDNSPacketSize

	// TagSize is the Poly1305 authentication tag size in bytes.
	TagSize = 16

	// EDNSSize is the overhead for DNSCrypt headers when calculating truncation.
	EDNSSize = 64

	// PQC public key, ciphertext, and certificate sizes for X-Wing PQ/T hybrid KEM.
	PQPublicKeySize  = 1216
	PQCiphertextSize = 1120
	PQCertByteLength = 1320
	PQProfileExtSize = 12

	// PQ query header sizes.
	PQResumeMagicLen = 8
	PQTicketLenSize  = 2

	// PQControlBlockMaxSize is the maximum size of a PQ response control block
	// (2 byte total len + 4 magic + 1 version + 4 lifetime + 2 ticket len + max
	// ticket).
	PQControlBlockMaxSize = 2 + 4 + 1 + 4 + 2 + 256
)

// CertMagic is the byte sequence that must appear at the beginning of every
// serialized certificate.
var CertMagic = [4]byte{0x44, 0x4e, 0x53, 0x43}

// ResolverMagic is the byte sequence that must appear at the beginning of every
// DNSCrypt response.
var ResolverMagic = []byte{0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38}

// PQResumeMagic is the byte sequence identifying a resumed PQ query (carries
// a resumption ticket instead of a full X-Wing ciphertext).
var PQResumeMagic = [8]byte{'P', 'Q', 'R', 'e', 's', 'u', 'm', 'e'}

// PQControlMagic is the byte sequence identifying a PQ response control block
// carrying a resumption ticket.
var PQControlMagic = [4]byte{'P', 'Q', 'D', 'R'}

// PQESVersion is the wire-format es-version for X-Wing PQ.
var PQESVersion = [2]byte{0x00, 0x03}

// Nonce is a convenient alias for nonce values.
type Nonce = [NonceSize]byte

// CryptoConstruction represents the encryption algorithm used for DNSCrypt.
type CryptoConstruction uint16

const (
	// XSalsa20Poly1305 uses X25519 key exchange with XSalsa20-Poly1305 AEAD.
	XSalsa20Poly1305 CryptoConstruction = 0x0001

	// XChacha20Poly1305 uses X25519 key exchange with XChacha20-Poly1305 AEAD.
	XChacha20Poly1305 CryptoConstruction = 0x0002

	// XWingPQ uses X-Wing PQ/T hybrid KEM (ML-KEM-768 + X25519) with
	// XChacha20-Poly1305 AEAD.
	XWingPQ CryptoConstruction = 0x0003
)

// ParseESVersion parses an ESVersion string into a CryptoConstruction value.
func ParseESVersion(s string) (CryptoConstruction, error) {
	switch s {
	case "xwingpq", "":
		return XWingPQ, nil
	case "xchacha20poly1305":
		return XChacha20Poly1305, nil
	case "xsalsa20poly1305":
		return XSalsa20Poly1305, nil
	default:
		return 0, fmt.Errorf("unsupported es_version: %q (supported: xwingpq, xchacha20poly1305, xsalsa20poly1305)", s)
	}
}

// IsPQ reports whether the CryptoConstruction uses post-quantum key exchange.
func (c CryptoConstruction) IsPQ() bool {
	return c == XWingPQ
}

// type check
var _ fmt.Stringer = CryptoConstruction(0)

// String implements the fmt.Stringer interface for CryptoConstruction.
func (c CryptoConstruction) String() (s string) {
	switch c {
	case XChacha20Poly1305:
		return "XChacha20Poly1305"
	case XSalsa20Poly1305:
		return "XSalsa20Poly1305"
	case XWingPQ:
		return "XWingPQ"
	default:
		return "Unknown"
	}
}
