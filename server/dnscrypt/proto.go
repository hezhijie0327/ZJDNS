// Package dnscrypt implements the DNSCrypt v2 protocol for encrypting DNS
// queries and responses.  It provides both client-side and server-side
// functionality using X25519 key exchange and XChacha20-Poly1305 or
// X-Wing PQ/T hybrid KEM authenticated encryption.
//
// See https://dnscrypt.info/protocol for the protocol specification.
package dnscrypt

import (
	"errors"
	"fmt"
)

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

	// NonceSize is the size of the nonce in bytes.  For X25519-XChacha20Poly1305,
	// a 24-byte nonce must not be reused for a given shared secret.
	NonceSize = 24

	// ResolverMagicSize is the size of the resolver magic in bytes.  It is the
	// first 8 bytes of every DNSCrypt response.
	ResolverMagicSize = 8

	// CertByteLength is the standard length of a serialized certificate.
	CertByteLength = 124

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
	default:
		return 0, fmt.Errorf("unsupported es_version: %q (supported: xwingpq, xchacha20poly1305)", s)
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
	case XWingPQ:
		return "XWingPQ"
	default:
		return "Unknown"
	}
}

// Sentinel errors for DNSCrypt protocol operations.
var (
	ErrTooShort             = errors.New("dnscrypt: message is too short")
	ErrQueryTooLarge        = errors.New("dnscrypt: query is too large")
	ErrESVersion            = errors.New("dnscrypt: unsupported es-version")
	ErrInvalidDate          = errors.New("dnscrypt: certificate has invalid date range")
	ErrInvalidQuery         = errors.New("dnscrypt: query is invalid and cannot be decrypted")
	ErrInvalidClientMagic   = errors.New("dnscrypt: query contains invalid client magic")
	ErrInvalidResolverMagic = errors.New("dnscrypt: response contains invalid resolver magic")
	ErrInvalidResponse      = errors.New("dnscrypt: response is invalid and cannot be decrypted")
	ErrInvalidPadding       = errors.New("dnscrypt: invalid padding")
	ErrCertTooShort         = errors.New("dnscrypt: certificate is too short")
	ErrCertMagic            = errors.New("dnscrypt: invalid certificate magic")
	ErrClientMagicQUIC      = errors.New("dnscrypt: client magic starts with seven zero bytes — collides with QUIC")
	ErrUnexpectedNonce      = errors.New("dnscrypt: unexpected nonce")
	ErrServerNotStarted     = errors.New("dnscrypt: server is not started")
	ErrServerAlreadyStarted = errors.New("dnscrypt: server is already started")
	ErrPQCertTooShort       = errors.New("dnscrypt: PQ certificate too short")
	ErrPQInvalidProfileExt  = errors.New("dnscrypt: invalid PQ profile extension")
	ErrPQInvalidTicket      = errors.New("dnscrypt: invalid PQ resumption ticket")
	ErrPQTicketExpired      = errors.New("dnscrypt: PQ resumption ticket expired")
)
