package dnscryptcrypto

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/cloudflare/circl/sign/ed25519"
)

// Certificate is a DNSCrypt server certificate containing the resolver's
// short-term public key and metadata needed for encrypted communication.
type Certificate struct {
	// Serial is a 4-byte serial number in big-endian format.  If multiple
	// certificates are valid, the client prefers the one with the higher
	// serial number.
	Serial uint32

	// ESVersion is the cryptographic construction to use with this certificate.
	ESVersion CryptoConstruction

	// Signature is a 64-byte Ed25519 signature over the signed portion of the
	// certificate (resolver-pk || client-magic || serial || ts-start || ts-end).
	Signature [64]byte

	// ResolverPk is the resolver's short-term X25519 public key (32 bytes).
	// For PQ certificates this is zero-filled — the key material is in PqPublicKey.
	ResolverPk [KeySize]byte

	// ResolverSk is the resolver's short-term X25519 secret key (32 bytes).
	// Only used server-side; never serialized or sent over the wire.
	// For PQ certificates this is zero-filled — the key material is in PqPrivateKey.
	ResolverSk [KeySize]byte

	// ClientMagic is the first 8 bytes of a client query built from this
	// certificate.  Two valid certificates cannot share the same client magic.
	ClientMagic [ClientMagicSize]byte

	// NotBefore is the Unix timestamp (big-endian uint32) from which the
	// certificate is valid.
	NotBefore uint32

	// NotAfter is the Unix timestamp (big-endian uint32) until which the
	// certificate is valid (inclusive).
	NotAfter uint32

	// PqPublicKey is the raw 1216-byte X-Wing public key.  Only set for PQ
	// certificates (ESVersion == XWingPQ).
	PqPublicKey []byte

	// PqPrivateKey is the raw 32-byte X-Wing private key seed.  Only set for
	// PQ certificates (ESVersion == XWingPQ).  Never serialized.
	PqPrivateKey []byte

	// PqCertContext is the HKDF info built from the signed certificate bytes
	// that binds the shared key to this exact certificate.  Only set for PQ
	// certificates.
	PqCertContext []byte
}

// CertPair holds the classical and PQ certificates for a single key window.
// Both certs share the same Serial, NotBefore, and NotAfter and are derived
// from the same X25519 short-term key seed.
type CertPair struct {
	Classical *Certificate // ESVersion = XChacha20Poly1305 (124 bytes)
	PQ        *Certificate // ESVersion = XWingPQ (1320 bytes)
}

// type checks

// Certificate wire format offsets.  The certificate has a fixed-size header
// followed by a signed portion whose layout differs between classical and PQ
// certificates.
//
//	Header (shared):  certMagic(4) + esVersion(2) + minor(2) + sig(64) = 72 bytes
//	Signed (classical): resolverPk(32) + clientMagic(8) + serial(4) +
//	                     tsStart(4) + tsEnd(4) = 52 bytes → 124 total
//	Signed (PQ):       pqPublicKey(1216) + clientMagic(8) + serial(4) +
//	                     tsStart(4) + tsEnd(4) + ext(12) = 1248 bytes → 1320 total
const (
	CertMagicOff     = 0
	CertMagicLen     = 4
	CertESVersionOff = 4
	CertMinorOff     = 6
	CertSigOff       = 8
	CertSigLen       = 64
	CertSignedOff    = 72

	// Classical certificate signed portion (52 bytes).
	CertClassicalPkOff     = CertSignedOff                           // 72
	CertClassicalPkLen     = KeySize                                 // 32
	CertClassicalMagicOff  = CertSignedOff + KeySize                 // 104
	CertClassicalSerialOff = CertClassicalMagicOff + ClientMagicSize // 112
	CertClassicalTSOff     = CertClassicalSerialOff + 4              // 116
	CertClassicalTEEnd     = CertByteLength                          // 124

	// PQ certificate signed portion (1248 bytes).
	CertPQPkOff     = CertSignedOff                    // 72
	CertPQPkLen     = PQPublicKeySize                  // 1216
	CertPQMagicOff  = CertSignedOff + PQPublicKeySize  // 1288
	CertPQSerialOff = CertPQMagicOff + ClientMagicSize // 1296
	CertPQTSOff     = CertPQSerialOff + 4              // 1300
	CertPQTEEnd     = CertPQTSOff + 4                  // 1304
	CertPQExtOff    = CertPQTEEnd + 4                  // 1308
	CertPQExtLen    = PQProfileExtSize                 // 12
)

// Ticket plaintext encoding sizes.  Matches the reference implementation
// (encrypted-dns-server) and draft-denis-dprive-dnscrypt-10 §10.7.1:
//
//	ticket-plain ::= resume-secret(32) <es-version>(2) <client-magic>(8)
//	                 <serial>(4) <ts-end>(4) <ticket-expiry>(4)
//	                 <profile-extension-hash>(32)   = 86 bytes
const (
	TicketPlaintextSecretOff = 0
	TicketPlaintextSecretLen = SharedKeySize // 32

	TicketPlaintextESOff = TicketPlaintextSecretOff + SharedKeySize // 32
	TicketPlaintextESLen = 2

	TicketPlaintextMagicOff = TicketPlaintextESOff + TicketPlaintextESLen // 34
	TicketPlaintextMagicLen = ClientMagicSize                             // 8

	TicketPlaintextSerialOff = TicketPlaintextMagicOff + ClientMagicSize // 42
	TicketPlaintextSerialLen = 4

	TicketPlaintextTSEndOff = TicketPlaintextSerialOff + TicketPlaintextSerialLen // 46
	TicketPlaintextTSEndLen = 4

	TicketPlaintextExpiryOff = TicketPlaintextTSEndOff + TicketPlaintextTSEndLen // 50
	TicketPlaintextExpiryLen = 4                                                 // uint32

	TicketPlaintextPEHashOff = TicketPlaintextExpiryOff + TicketPlaintextExpiryLen // 54
	TicketPlaintextPEHashLen = 32

	TicketPlaintextSize = TicketPlaintextPEHashOff + TicketPlaintextPEHashLen // 86

	// TicketKeyIDSize is the length of the ticket-key identifier prefix.
	TicketKeyIDSize = 4
)

// PQ padding floor constants — minimum padded sizes for initial and resumed
// PQ queries.  Both are multiples of 64.
const (
	PQMinPaddingInitial  = 64
	PQMinPaddingResumed  = 256
	PQMinControlBlockLen = 4 + 1 + 4 + 2 // magic + version + lifetime + ticketLen
)

var (
	_ encoding.BinaryMarshaler   = (*Certificate)(nil)
	_ encoding.BinaryUnmarshaler = (*Certificate)(nil)
	_ fmt.Stringer               = (*Certificate)(nil)
)

// MarshalBinary implements the encoding.BinaryMarshaler interface.  The
// certificate is serialized using the DNSCrypt v2 wire format:
//
//	<classical-cert> ::= <cert-magic> <es-version> <protocol-minor-version>
//	                     <signature> <resolver-pk> <client-magic>
//	                     <serial> <ts-start> <ts-end>
//
//	<pq-cert> ::= <cert-magic> <es-version> <protocol-minor-version>
//	              <signature> <pq-public-key> <client-magic>
//	              <serial> <ts-start> <ts-end> <extensions>
//
// Classical certs are CertByteLength (124) bytes; PQ certs are PQCertByteLength
// (1320) bytes.  err is always nil.
func (c *Certificate) MarshalBinary() (serialized []byte, err error) {
	if c.ESVersion.IsPQ() {
		return c.marshalPQ()
	}
	serialized = make([]byte, CertByteLength)
	copy(serialized[CertMagicOff:CertMagicOff+CertMagicLen], CertMagic[:])
	binary.BigEndian.PutUint16(serialized[CertESVersionOff:CertESVersionOff+2], uint16(c.ESVersion))
	copy(serialized[CertMinorOff:CertMinorOff+2], []byte{0, 0})
	copy(serialized[CertSigOff:CertSigOff+CertSigLen], c.Signature[:])
	c.writeSigned(serialized[CertSignedOff:])
	return serialized, nil
}

// marshalPQ serializes a post-quantum certificate (1320 bytes).
func (c *Certificate) marshalPQ() ([]byte, error) {
	serialized := make([]byte, PQCertByteLength)
	copy(serialized[CertMagicOff:CertMagicOff+CertMagicLen], CertMagic[:])
	binary.BigEndian.PutUint16(serialized[CertESVersionOff:CertESVersionOff+2], uint16(c.ESVersion))
	copy(serialized[CertMinorOff:CertMinorOff+2], []byte{0, 0})
	copy(serialized[CertSigOff:CertSigOff+CertSigLen], c.Signature[:])
	c.writeSigned(serialized[CertSignedOff:])
	return serialized, nil
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
func (c *Certificate) UnmarshalBinary(b []byte) (err error) {
	if len(b) < CertByteLength {
		if len(b) < PQCertByteLength {
			return ErrCertTooShort
		}
		return ErrPQCertTooShort
	}
	if !bytes.Equal(b[:4], CertMagic[:4]) {
		return ErrCertMagic
	}

	switch esVersion := binary.BigEndian.Uint16(b[4:6]); esVersion {
	case uint16(XChacha20Poly1305):
		c.ESVersion = XChacha20Poly1305
	case uint16(XWingPQ):
		c.ESVersion = XWingPQ
	default:
		return ErrESVersion
	}

	// PQ certificate: 1320-byte layout with X-Wing public key and profile extension.
	if c.ESVersion.IsPQ() {
		return c.unmarshalPQ(b)
	}

	copy(c.Signature[:], b[CertSigOff:CertSigOff+CertSigLen])
	copy(c.ResolverPk[:], b[CertClassicalPkOff:CertClassicalPkOff+CertClassicalPkLen])
	copy(c.ClientMagic[:], b[CertClassicalMagicOff:CertClassicalMagicOff+ClientMagicSize])
	if !isClientMagicValid(c.ClientMagic) {
		return ErrClientMagicQUIC
	}

	c.Serial = binary.BigEndian.Uint32(b[CertClassicalSerialOff : CertClassicalSerialOff+4])
	c.NotBefore = binary.BigEndian.Uint32(b[CertClassicalTSOff : CertClassicalTSOff+4])
	c.NotAfter = binary.BigEndian.Uint32(b[CertClassicalTSOff+4 : CertClassicalTEEnd])

	return nil
}

// unmarshalPQ parses a 1320-byte post-quantum certificate.
func (c *Certificate) unmarshalPQ(b []byte) error {
	if len(b) < PQCertByteLength {
		return ErrPQCertTooShort
	}

	// Validate profile extension.
	ext := b[CertPQExtOff : CertPQExtOff+CertPQExtLen]
	expectedExt := PQProfileExtension()
	if !bytes.Equal(ext, expectedExt) {
		return ErrPQInvalidProfileExt
	}
	// The es-version in the extension must match the cert header.
	if !bytes.Equal(b[CertESVersionOff:CertESVersionOff+2], ext[4:6]) {
		return ErrPQInvalidProfileExt
	}

	copy(c.Signature[:], b[CertSigOff:CertSigOff+CertSigLen])
	c.PqPublicKey = make([]byte, CertPQPkLen)
	copy(c.PqPublicKey, b[CertPQPkOff:CertPQPkOff+CertPQPkLen])
	copy(c.ClientMagic[:], b[CertPQMagicOff:CertPQMagicOff+ClientMagicSize])
	if !isClientMagicValid(c.ClientMagic) {
		return ErrClientMagicQUIC
	}

	c.Serial = binary.BigEndian.Uint32(b[CertPQSerialOff : CertPQSerialOff+4])
	c.NotBefore = binary.BigEndian.Uint32(b[CertPQTSOff : CertPQTSOff+4])
	c.NotAfter = binary.BigEndian.Uint32(b[CertPQTEEnd : CertPQTEEnd+4])

	// Pre-compute the cert context for HKDF binding.
	c.PqCertContext = PQCertContext(b)

	return nil
}

// Validate checks whether the certificate is valid (not expired, correct magic).
func (c *Certificate) Validate() (err error) {
	switch c.ESVersion {
	case XWingPQ:
		if len(c.PqPublicKey) != PQPublicKeySize {
			return ErrESVersion
		}
	default:
		return ErrESVersion
	}
	if !c.IsDateValid() {
		return ErrInvalidDate
	}
	return nil
}

// nowUnix32 returns the current Unix time as uint32.  The DNSCrypt protocol
// uses 32-bit timestamps throughout (certificates, tickets), and Unix epoch
// values fit in uint32 until year 2106.  All timestamp-to-uint32 conversions
// in this package route through this function so the bounds reasoning lives
// in one place.

// IsDateValid checks that the certificate is currently within its validity
// window.
func (c *Certificate) IsDateValid() (ok bool) {
	if c.NotBefore >= c.NotAfter {
		return false
	}
	now := NowUnix32()
	if now > c.NotAfter || now < c.NotBefore {
		return false
	}
	return true
}

// VerifySignature verifies the certificate's Ed25519 signature against the
// given public key.
func (c *Certificate) VerifySignature(publicKey ed25519.PublicKey) (ok bool) {
	b := make([]byte, c.signedSize())
	c.writeSigned(b)
	return ed25519.Verify(publicKey, b, c.Signature[:])
}

// Sign creates the certificate's Ed25519 signature using the given private key.
// It panics if ClientMagic breaks the spec §5.5 constraint (seven leading zeros).
func (c *Certificate) Sign(privateKey ed25519.PrivateKey) {
	if !isClientMagicValid(c.ClientMagic) {
		panic("dnscrypt: ClientMagic starts with seven zero bytes — collides with QUIC")
	}
	b := make([]byte, c.signedSize())
	c.writeSigned(b)
	signature := ed25519.Sign(privateKey, b)
	copy(c.Signature[:64], signature[:64])
}

// isClientMagicValid checks that the ClientMagic does not start with seven
// zero bytes, which would collide with QUIC per the specification.
func isClientMagicValid(magic [ClientMagicSize]byte) bool {
	zeroes := [7]byte{}
	return !bytes.Equal(magic[:7], zeroes[:])
}

// String implements the fmt.Stringer interface.
func (c *Certificate) String() (s string) {
	return fmt.Sprintf(
		"Certificate Serial=%d NotBefore=%s NotAfter=%s ESVersion=%s",
		c.Serial,
		time.Unix(int64(c.NotBefore), 0),
		time.Unix(int64(c.NotAfter), 0),
		c.ESVersion,
	)
}

// writeSigned writes the signed portion of the certificate to dst using the
// order specified by the protocol:
//
//	<classical>: <resolver-pk> <client-magic> <serial> <ts-start> <ts-end>
//	<pq>:        <pq-public-key> <client-magic> <serial> <ts-start>
//	             <ts-end> <extensions>
func (c *Certificate) writeSigned(dst []byte) { //nolint:gosec // G602: slice bounds guaranteed by signedSize()
	if c.ESVersion.IsPQ() {
		copy(dst[:CertPQPkLen], c.PqPublicKey)                                              //nolint:gosec // G602
		copy(dst[CertPQPkLen:CertPQPkLen+ClientMagicSize], c.ClientMagic[:ClientMagicSize]) //nolint:gosec // G602
		off := CertPQPkLen + ClientMagicSize
		binary.BigEndian.PutUint32(dst[off:off+4], c.Serial) //nolint:gosec // G602
		off += 4
		binary.BigEndian.PutUint32(dst[off:off+4], c.NotBefore) //nolint:gosec // G602
		off += 4
		binary.BigEndian.PutUint32(dst[off:off+4], c.NotAfter) //nolint:gosec // G602
		off += 4
		copy(dst[off:off+CertPQExtLen], PQProfileExtension())
		return
	}
	copy(dst[:CertClassicalPkLen], c.ResolverPk[:KeySize])                                            //nolint:gosec // G602
	copy(dst[CertClassicalPkLen:CertClassicalPkLen+ClientMagicSize], c.ClientMagic[:ClientMagicSize]) //nolint:gosec // G602
	off := CertClassicalPkLen + ClientMagicSize
	binary.BigEndian.PutUint32(dst[off:off+4], c.Serial) //nolint:gosec // G602
	off += 4
	binary.BigEndian.PutUint32(dst[off:off+4], c.NotBefore) //nolint:gosec // G602
	off += 4
	binary.BigEndian.PutUint32(dst[off:off+4], c.NotAfter) //nolint:gosec // G602
}

// signedSize returns the size of the signed portion for this certificate.
func (c *Certificate) signedSize() int {
	if c.ESVersion.IsPQ() {
		return PQPublicKeySize + ClientMagicSize + 4 + 4 + 4 + PQProfileExtSize
	}
	return KeySize + ClientMagicSize + 4 + 4 + 4
}
