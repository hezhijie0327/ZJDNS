package dnscrypt

import (
	"bytes"
	"crypto/ed25519"
	"encoding"
	"encoding/binary"
	"fmt"
	"time"
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
	Signature [ed25519.SignatureSize]byte

	// ResolverPk is the resolver's short-term X25519 public key (32 bytes).
	ResolverPk [KeySize]byte

	// ResolverSk is the resolver's short-term X25519 secret key (32 bytes).
	// Only used server-side; never serialized or sent over the wire.
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
}

// type checks
var (
	_ encoding.BinaryMarshaler   = (*Certificate)(nil)
	_ encoding.BinaryUnmarshaler = (*Certificate)(nil)
	_ fmt.Stringer               = (*Certificate)(nil)
)

// MarshalBinary implements the encoding.BinaryMarshaler interface.  The
// certificate is serialized using the DNSCrypt v2 wire format:
//
//	<cert> ::= <cert-magic> <es-version> <protocol-minor-version>
//	           <signature> <resolver-pk> <client-magic>
//	           <serial> <ts-start> <ts-end>
//
// The serialized form is exactly CertByteLength (124) bytes.  err is always nil.
func (c *Certificate) MarshalBinary() (serialized []byte, err error) {
	serialized = make([]byte, CertByteLength)
	copy(serialized[:4], CertMagic[:])
	binary.BigEndian.PutUint16(serialized[4:6], uint16(c.ESVersion))
	copy(serialized[6:8], []byte{0, 0})
	copy(serialized[8:72], c.Signature[:ed25519.SignatureSize])
	c.writeSigned(serialized[72:])
	return serialized, nil
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
func (c *Certificate) UnmarshalBinary(b []byte) (err error) {
	if len(b) < CertByteLength {
		return ErrCertTooShort
	}
	if !bytes.Equal(b[:4], CertMagic[:4]) {
		return ErrCertMagic
	}

	switch esVersion := binary.BigEndian.Uint16(b[4:6]); esVersion {
	case uint16(XSalsa20Poly1305):
		c.ESVersion = XSalsa20Poly1305
	case uint16(XChacha20Poly1305):
		c.ESVersion = XChacha20Poly1305
	default:
		return ErrESVersion
	}

	copy(c.Signature[:], b[8:72])
	copy(c.ResolverPk[:], b[72:104])
	copy(c.ClientMagic[:], b[104:112])

	c.Serial = binary.BigEndian.Uint32(b[112:116])
	c.NotBefore = binary.BigEndian.Uint32(b[116:120])
	c.NotAfter = binary.BigEndian.Uint32(b[120:CertByteLength])

	return nil
}

// Validate implements the validate.Interface for Certificate.
func (c *Certificate) Validate() (err error) {
	if c.ESVersion != XSalsa20Poly1305 && c.ESVersion != XChacha20Poly1305 {
		return ErrESVersion
	}
	if !c.IsDateValid() {
		return ErrInvalidDate
	}
	return nil
}

// IsDateValid checks that the certificate is currently within its validity
// window.
func (c *Certificate) IsDateValid() (ok bool) {
	if c.NotBefore >= c.NotAfter {
		return false
	}
	now := uint32(time.Now().Unix()) //nolint:gosec // G115: Unix timestamp fits in uint32 until 2106
	if now > c.NotAfter || now < c.NotBefore {
		return false
	}
	return true
}

// VerifySignature verifies the certificate's Ed25519 signature against the
// given public key.
func (c *Certificate) VerifySignature(publicKey ed25519.PublicKey) (ok bool) {
	b := make([]byte, 52)
	c.writeSigned(b)
	return ed25519.Verify(publicKey, b, c.Signature[:])
}

// Sign creates the certificate's Ed25519 signature using the given private key.
func (c *Certificate) Sign(privateKey ed25519.PrivateKey) {
	b := make([]byte, 52)
	c.writeSigned(b)
	signature := ed25519.Sign(privateKey, b)
	copy(c.Signature[:64], signature[:64])
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
//	<resolver-pk> <client-magic> <serial> <ts-start> <ts-end>
func (c *Certificate) writeSigned(dst []byte) {
	copy(dst[:32], c.ResolverPk[:KeySize])
	copy(dst[32:40], c.ClientMagic[:ClientMagicSize])
	binary.BigEndian.PutUint32(dst[40:44], c.Serial)
	binary.BigEndian.PutUint32(dst[44:48], c.NotBefore)
	binary.BigEndian.PutUint32(dst[48:52], c.NotAfter)
}
