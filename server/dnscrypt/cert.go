package dnscrypt

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/cloudflare/circl/kem/xwing"
	"golang.org/x/crypto/curve25519"
)

// DNSCrypt v2 certificate wire format constants.
const (
	certMagicBytes       = 4
	certMinSize          = 124  // classic cert size (X25519 only)
	xwingCertMinSize     = 1320 // X-Wing cert size (X25519 + ML-KEM-768)
	minorVersion         = 0
	xwingPublicKeySize   = xwing.PublicKeySize  // 1216
	xwingCiphertextSize  = xwing.CiphertextSize // 1120
	xwingSharedKeySize   = xwing.SharedKeySize  // 32
	xwingSeedSize        = 32                   // X-Wing seed per spec
	profileExtensionSize = 12
)

var certMagic = [certMagicBytes]byte{0x44, 0x4e, 0x53, 0x43} // "DNSC"

// CryptoConstruction is the encryption algorithm identifier.
type CryptoConstruction uint16

const (
	XSalsa20Poly1305  CryptoConstruction = 0x0001
	XChacha20Poly1305 CryptoConstruction = 0x0002
	XWingPQ           CryptoConstruction = 0x0003 // X-Wing hybrid KEM + XChaCha20-Poly1305
)

// IsPQ reports whether this construction uses post-quantum key exchange.
func (c CryptoConstruction) IsPQ() bool { return c == XWingPQ }

// AEAD returns the AEAD sub-construction. XWingPQ always uses XChacha20Poly1305.
func (c CryptoConstruction) AEAD() CryptoConstruction {
	if c == XWingPQ {
		return XChacha20Poly1305
	}
	return c
}

func (c CryptoConstruction) String() string {
	switch c {
	case XSalsa20Poly1305:
		return "XSalsa20Poly1305"
	case XChacha20Poly1305:
		return "XChacha20Poly1305"
	case XWingPQ:
		return "XWingPQ_XChacha20Poly1305"
	default:
		return fmt.Sprintf("Unknown(%d)", c)
	}
}

// Certificate is a DNSCrypt server certificate.
//
// For XWingPQ, ResolverPk stores the full X-Wing public key (1216 bytes):
//
//	ResolverPk[0:1184]  = ML-KEM-768 encapsulation key
//	ResolverPk[1184:1216] = X25519 public key
//
// For classic constructions, only ResolverPk[0:32] (X25519) is used.
type Certificate struct {
	Serial           uint32
	ESVersion        CryptoConstruction
	Signature        [ed25519.SignatureSize]byte
	ResolverPk       [xwingPublicKeySize]byte // 1216 bytes
	ResolverSk       [KeySize]byte            // X25519 secret key (classic only)
	XWingSeed        [xwingSeedSize]byte      // X-Wing seed (PQ only)
	ClientMagic      [clientMagicSize]byte
	NotBefore        uint32
	NotAfter         uint32
	ProfileExtension [profileExtensionSize]byte // PQ only
}

// XWingPublicKey returns the full X-Wing public key (1216 bytes).
func (c *Certificate) XWingPublicKey() []byte { return c.ResolverPk[:] }

// profileExtension returns the fixed 12-byte signed extensions field
// for X-Wing PQ certificates, as defined by the DNSCrypt PQ specification.
//
// Wire format (12 bytes):
//
//	"PQD" | ext_version(1) | es_version(2) | kdf_id(1) | aead_id(1) | pk_len(2) | ct_len(2)
//	hex:   505144           01              0003          01          01          04C0        0460
func profileExtension() [profileExtensionSize]byte {
	return [profileExtensionSize]byte{
		'P', 'Q', 'D', // magic
		0x01,       // ext_version
		0x00, 0x03, // es_version
		0x01,       // kdf_id (HKDF-SHA-256)
		0x01,       // aead_id (XChaCha20-Poly1305)
		0x04, 0xC0, // pk_len = 1216 (big-endian)
		0x04, 0x60, // ct_len = 1120 (big-endian)
	}
}

// CertContext builds the HKDF info that binds the shared key to the exact
// signed certificate. Mirrors the cert-context construction in the spec:
//
//	"DNSCrypt-PQ-v1" || es_version || minor || resolver_pk || client_magic || serial || ts_start || ts_end || extensions
func (c *Certificate) CertContext() []byte {
	raw, _ := c.Serialize()
	esVersion := raw[4:6]
	minor := raw[6:8]
	ext := raw[xwingCertMinSize-profileExtensionSize:]
	ctx := make([]byte, 0, 14+2+2+xwingPublicKeySize+8+4+4+4+profileExtensionSize)
	ctx = append(ctx, "DNSCrypt-PQ-v1"...)
	ctx = append(ctx, esVersion...)
	ctx = append(ctx, minor...)
	ctx = append(ctx, c.ResolverPk[:]...)
	ctx = append(ctx, c.ClientMagic[:]...)
	serial := make([]byte, 4)
	binary.BigEndian.PutUint32(serial, c.Serial)
	ctx = append(ctx, serial...)
	tsStart := make([]byte, 4)
	binary.BigEndian.PutUint32(tsStart, c.NotBefore)
	ctx = append(ctx, tsStart...)
	tsEnd := make([]byte, 4)
	binary.BigEndian.PutUint32(tsEnd, c.NotAfter)
	ctx = append(ctx, tsEnd...)
	ctx = append(ctx, ext...)
	return ctx
}

// GenerateCertificate creates a new signed certificate for the given provider.
// The Ed25519 private key signs the certificate; the X25519 key pair (and
// X-Wing key pair for PQ) are freshly generated for each certificate.
func GenerateCertificate(providerPrivateKey ed25519.PrivateKey, esVersion CryptoConstruction, certTTL time.Duration) (*Certificate, error) {
	if len(providerPrivateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("dnscrypt: invalid provider private key size")
	}

	if esVersion == 0 {
		esVersion = XSalsa20Poly1305
	}

	cert := &Certificate{
		ESVersion: esVersion,
		Serial:    uint32(time.Now().Unix()),
		NotBefore: uint32(time.Now().Unix()),
		NotAfter:  uint32(time.Now().Add(certTTL).Unix()),
	}

	if esVersion == XWingPQ {
		// Generate X-Wing key pair: 32-byte seed → DeriveKeyPair.
		if _, err := rand.Read(cert.XWingSeed[:]); err != nil {
			return nil, fmt.Errorf("dnscrypt: generate xwing seed: %w", err)
		}
		pk, _ := xwing.DeriveKeyPair(cert.XWingSeed[:])
		pkPacked, err := pk.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("dnscrypt: marshal xwing public key: %w", err)
		}
		copy(cert.ResolverPk[:], pkPacked)

		// Client magic = first 8 bytes of SHA-256(resolver_pk).
		h := sha256.Sum256(cert.ResolverPk[:])
		copy(cert.ClientMagic[:], h[:clientMagicSize])

		// Ensure client magic doesn't start with 7 zero bytes and doesn't
		// collide with "PQResume" (see encrypted-dns-server collision check).
		if isAllZero(cert.ClientMagic[:clientMagicSize-1]) || string(cert.ClientMagic[:]) == "PQResume" {
			cert.ClientMagic[0] ^= 0xFF
		}

		cert.ProfileExtension = profileExtension()
	} else {
		// Classic: generate X25519 key pair.
		if _, err := rand.Read(cert.ResolverSk[:]); err != nil {
			return nil, fmt.Errorf("dnscrypt: generate resolver secret key: %w", err)
		}
		pk, err := curve25519.X25519(cert.ResolverSk[:], curve25519.Basepoint)
		if err != nil {
			return nil, fmt.Errorf("dnscrypt: derive resolver public key: %w", err)
		}
		copy(cert.ResolverPk[:], pk)

		// Generate client magic (random 8 bytes).
		if _, err := rand.Read(cert.ClientMagic[:]); err != nil {
			return nil, fmt.Errorf("dnscrypt: generate client magic: %w", err)
		}
	}

	cert.Sign(providerPrivateKey)
	return cert, nil
}

// isAllZero reports whether all bytes in b are zero.
func isAllZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// Sign signs the certificate body with the given Ed25519 private key.
//
// For XWingPQ, the signature covers cert[72:] (everything after the signature
// field), matching the encrypted-dns-server / dnscrypt-proxy behavior.
// For classic, only the 52-byte signed portion is covered.
func (c *Certificate) Sign(privateKey ed25519.PrivateKey) {
	if c.ESVersion == XWingPQ {
		raw, _ := c.Serialize()
		// Sign everything after the 8-byte header (certMagic + es_version + minor).
		copy(c.Signature[:], ed25519.Sign(privateKey, raw[8:]))
		return
	}
	msg := make([]byte, 0, KeySize+clientMagicSize+12)
	msg = append(msg, c.ResolverPk[:KeySize]...)
	msg = append(msg, c.ClientMagic[:]...)
	serial := make([]byte, 4)
	binary.BigEndian.PutUint32(serial, c.Serial)
	msg = append(msg, serial...)
	tsStart := make([]byte, 4)
	binary.BigEndian.PutUint32(tsStart, c.NotBefore)
	msg = append(msg, tsStart...)
	tsEnd := make([]byte, 4)
	binary.BigEndian.PutUint32(tsEnd, c.NotAfter)
	msg = append(msg, tsEnd...)
	copy(c.Signature[:], ed25519.Sign(privateKey, msg))
}

// VerifySignature checks the certificate signature against the given public key.
func (c *Certificate) VerifySignature(publicKey ed25519.PublicKey) bool {
	if len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	if c.ESVersion == XWingPQ {
		raw, _ := c.Serialize()
		return ed25519.Verify(publicKey, raw[8:], c.Signature[:])
	}
	msg := make([]byte, 0, KeySize+clientMagicSize+12)
	msg = append(msg, c.ResolverPk[:KeySize]...)
	msg = append(msg, c.ClientMagic[:]...)
	serial := make([]byte, 4)
	binary.BigEndian.PutUint32(serial, c.Serial)
	msg = append(msg, serial...)
	tsStart := make([]byte, 4)
	binary.BigEndian.PutUint32(tsStart, c.NotBefore)
	msg = append(msg, tsStart...)
	tsEnd := make([]byte, 4)
	binary.BigEndian.PutUint32(tsEnd, c.NotAfter)
	msg = append(msg, tsEnd...)
	return ed25519.Verify(publicKey, msg, c.Signature[:])
}

// VerifyDate checks that the certificate is currently valid.
func (c *Certificate) VerifyDate() bool {
	if c.NotBefore >= c.NotAfter {
		return false
	}
	now := uint32(time.Now().Unix())
	return now >= c.NotBefore && now <= c.NotAfter
}

// Serialize encodes the certificate to wire format (124 bytes for classic,
// 1320 bytes for XWingPQ).
func (c *Certificate) Serialize() ([]byte, error) {
	var size int
	if c.ESVersion == XWingPQ {
		size = xwingCertMinSize
	} else {
		size = certMinSize
	}
	buf := make([]byte, size)
	copy(buf[0:4], certMagic[:])
	binary.BigEndian.PutUint16(buf[4:6], uint16(c.ESVersion))
	binary.BigEndian.PutUint16(buf[6:8], minorVersion)
	copy(buf[8:72], c.Signature[:])

	if c.ESVersion == XWingPQ {
		// X-Wing PK at [72:1288] = 1216 bytes
		copy(buf[72:72+xwingPublicKeySize], c.ResolverPk[:])
		copy(buf[1288:1296], c.ClientMagic[:])
		binary.BigEndian.PutUint32(buf[1296:1300], c.Serial)
		binary.BigEndian.PutUint32(buf[1300:1304], c.NotBefore)
		binary.BigEndian.PutUint32(buf[1304:1308], c.NotAfter)
		copy(buf[1308:1320], c.ProfileExtension[:])
	} else {
		copy(buf[72:104], c.ResolverPk[:KeySize])
		copy(buf[104:112], c.ClientMagic[:])
		binary.BigEndian.PutUint32(buf[112:116], c.Serial)
		binary.BigEndian.PutUint32(buf[116:120], c.NotBefore)
		binary.BigEndian.PutUint32(buf[120:124], c.NotAfter)
	}
	return buf, nil
}

// Deserialize parses a certificate from its wire format (124 or 1320 bytes).
func (c *Certificate) Deserialize(b []byte) error {
	if len(b) != certMinSize && len(b) != xwingCertMinSize {
		return errors.New("dnscrypt: invalid certificate format")
	}
	if string(b[:certMagicBytes]) != string(certMagic[:]) {
		return errors.New("dnscrypt: invalid certificate magic")
	}
	c.ESVersion = CryptoConstruction(binary.BigEndian.Uint16(b[4:6]))
	// minorVersion is at b[6:8], unused.
	copy(c.Signature[:], b[8:72])

	if c.ESVersion == XWingPQ {
		if len(b) < xwingCertMinSize {
			return errors.New("dnscrypt: X-Wing cert too short")
		}
		copy(c.ResolverPk[:], b[72:72+xwingPublicKeySize])
		copy(c.ClientMagic[:], b[1288:1296])
		c.Serial = binary.BigEndian.Uint32(b[1296:1300])
		c.NotBefore = binary.BigEndian.Uint32(b[1300:1304])
		c.NotAfter = binary.BigEndian.Uint32(b[1304:1308])
		copy(c.ProfileExtension[:], b[1308:1320])
	} else {
		copy(c.ResolverPk[:KeySize], b[72:104])
		copy(c.ClientMagic[:], b[104:112])
		c.Serial = binary.BigEndian.Uint32(b[112:116])
		c.NotBefore = binary.BigEndian.Uint32(b[116:120])
		c.NotAfter = binary.BigEndian.Uint32(b[120:124])
	}
	return nil
}

// TXTString returns the certificate as a hex-encoded TXT record value.
func (c *Certificate) TXTString() string {
	raw, _ := c.Serialize()
	return packTXT(raw)
}

// packTXT encodes binary data as a DNSCrypt TXT record (hex without colons).
func packTXT(data []byte) string {
	const hexDigits = "0123456789abcdef"
	buf := make([]byte, len(data)*2)
	for i, b := range data {
		buf[i*2] = hexDigits[b>>4]
		buf[i*2+1] = hexDigits[b&0x0f]
	}
	return string(buf)
}
