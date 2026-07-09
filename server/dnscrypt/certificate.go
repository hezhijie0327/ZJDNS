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

// type checks
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
	copy(serialized[:4], CertMagic[:])
	binary.BigEndian.PutUint16(serialized[4:6], uint16(c.ESVersion))
	copy(serialized[6:8], []byte{0, 0})
	copy(serialized[8:72], c.Signature[:ed25519.SignatureSize])
	c.writeSigned(serialized[72:])
	return serialized, nil
}

// marshalPQ serializes a post-quantum certificate (1320 bytes).
func (c *Certificate) marshalPQ() ([]byte, error) {
	serialized := make([]byte, PQCertByteLength)
	copy(serialized[:4], CertMagic[:])
	binary.BigEndian.PutUint16(serialized[4:6], uint16(c.ESVersion))
	copy(serialized[6:8], []byte{0, 0})
	copy(serialized[8:72], c.Signature[:ed25519.SignatureSize])
	// writeSigned fills serialized[72:] with the full signed portion:
	// pq-public-key || client-magic || serial || ts-start || ts-end || extensions
	c.writeSigned(serialized[72:])
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
	case uint16(XSalsa20Poly1305):
		c.ESVersion = XSalsa20Poly1305
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

	copy(c.Signature[:], b[8:72])
	copy(c.ResolverPk[:], b[72:104])
	copy(c.ClientMagic[:], b[104:112])

	c.Serial = binary.BigEndian.Uint32(b[112:116])
	c.NotBefore = binary.BigEndian.Uint32(b[116:120])
	c.NotAfter = binary.BigEndian.Uint32(b[120:CertByteLength])

	return nil
}

// unmarshalPQ parses a 1320-byte post-quantum certificate.
func (c *Certificate) unmarshalPQ(b []byte) error {
	if len(b) < PQCertByteLength {
		return ErrPQCertTooShort
	}

	// Validate profile extension.
	ext := b[1308:1320]
	expectedExt := pqProfileExtension()
	if !bytes.Equal(ext, expectedExt) {
		return ErrPQInvalidProfileExt
	}
	// The es-version in the extension must match the cert header.
	if !bytes.Equal(b[4:6], ext[4:6]) {
		return ErrPQInvalidProfileExt
	}

	copy(c.Signature[:], b[8:72])
	c.PqPublicKey = make([]byte, PQPublicKeySize)
	copy(c.PqPublicKey, b[72:1288])
	copy(c.ClientMagic[:], b[1288:1296])

	c.Serial = binary.BigEndian.Uint32(b[1296:1300])
	c.NotBefore = binary.BigEndian.Uint32(b[1300:1304])
	c.NotAfter = binary.BigEndian.Uint32(b[1304:1308])

	// Pre-compute the cert context for HKDF binding.
	c.PqCertContext = pqCertContext(b)

	return nil
}

// Validate implements the validate.Interface for Certificate.
func (c *Certificate) Validate() (err error) {
	switch c.ESVersion {
	case XSalsa20Poly1305, XChacha20Poly1305:
		// OK
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
	b := make([]byte, c.signedSize())
	c.writeSigned(b)
	return ed25519.Verify(publicKey, b, c.Signature[:])
}

// Sign creates the certificate's Ed25519 signature using the given private key.
func (c *Certificate) Sign(privateKey ed25519.PrivateKey) {
	b := make([]byte, c.signedSize())
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
//	<classical>: <resolver-pk> <client-magic> <serial> <ts-start> <ts-end>
//	<pq>:        <pq-public-key> <client-magic> <serial> <ts-start>
//	             <ts-end> <extensions>
func (c *Certificate) writeSigned(dst []byte) { //nolint:gosec // G602: slice bounds guaranteed by signedSize()
	if c.ESVersion.IsPQ() {
		copy(dst[:PQPublicKeySize], c.PqPublicKey)                                                  //nolint:gosec // G602: bounds guaranteed by signedSize()
		copy(dst[PQPublicKeySize:PQPublicKeySize+ClientMagicSize], c.ClientMagic[:ClientMagicSize]) //nolint:gosec // G602: bounds guaranteed
		off := PQPublicKeySize + ClientMagicSize
		binary.BigEndian.PutUint32(dst[off:off+4], c.Serial) //nolint:gosec // G602
		off += 4
		binary.BigEndian.PutUint32(dst[off:off+4], c.NotBefore) //nolint:gosec // G602
		off += 4
		binary.BigEndian.PutUint32(dst[off:off+4], c.NotAfter) //nolint:gosec // G602
		off += 4
		copy(dst[off:off+PQProfileExtSize], pqProfileExtension())
		return
	}
	copy(dst[:32], c.ResolverPk[:KeySize])              //nolint:gosec // G602: bounds guaranteed
	copy(dst[32:40], c.ClientMagic[:ClientMagicSize])   //nolint:gosec // G602: bounds guaranteed
	binary.BigEndian.PutUint32(dst[40:44], c.Serial)    //nolint:gosec // G602: bounds guaranteed
	binary.BigEndian.PutUint32(dst[44:48], c.NotBefore) //nolint:gosec // G602: bounds guaranteed
	binary.BigEndian.PutUint32(dst[48:52], c.NotAfter)  //nolint:gosec // G602: bounds guaranteed
}

// signedSize returns the size of the signed portion for this certificate.
func (c *Certificate) signedSize() int {
	if c.ESVersion.IsPQ() {
		return PQPublicKeySize + ClientMagicSize + 4 + 4 + 4 + PQProfileExtSize
	}
	return KeySize + ClientMagicSize + 4 + 4 + 4
}
