package dnscrypt

import (
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/curve25519"
)

// DNSCrypt v2 certificate wire format constants.
const (
	certMagicBytes = 4
	certMinSize    = 124  // standard cert size (X25519 only)
	pqCertMinSize  = 1308 // PQ cert size (X25519 + ML-KEM-768 PK)
	minorVersion   = 0
)

var certMagic = [certMagicBytes]byte{0x44, 0x4e, 0x53, 0x43} // "DNSC"

// CryptoConstruction is the encryption algorithm identifier.
type CryptoConstruction uint16

const (
	XSalsa20Poly1305  CryptoConstruction = 0x0001
	XChacha20Poly1305 CryptoConstruction = 0x0002
	// Hybrid post-quantum constructions: X25519 + ML-KEM-768 key exchange,
	// combined via HKDF-SHA256, then classical AEAD.
	X25519_MLKEM768_XSalsa20Poly1305  CryptoConstruction = 0x0101
	X25519_MLKEM768_XChacha20Poly1305 CryptoConstruction = 0x0102
)

// IsPQ reports whether this construction uses post-quantum hybrid key exchange.
func (c CryptoConstruction) IsPQ() bool { return c&0xff00 != 0 }

// AEAD returns the classical AEAD sub-construction for hybrid PQ constructions.
func (c CryptoConstruction) AEAD() CryptoConstruction { return c & 0xff }

func (c CryptoConstruction) String() string {
	switch c {
	case XSalsa20Poly1305:
		return "XSalsa20Poly1305"
	case XChacha20Poly1305:
		return "XChacha20Poly1305"
	case X25519_MLKEM768_XSalsa20Poly1305:
		return "X25519_MLKEM768_XSalsa20Poly1305"
	case X25519_MLKEM768_XChacha20Poly1305:
		return "X25519_MLKEM768_XChacha20Poly1305"
	default:
		return fmt.Sprintf("Unknown(%d)", c)
	}
}

// ML-KEM-768 key and ciphertext sizes (NIST FIPS 203).
const (
	mlkemPublicKeySize  = 1184
	mlkemCiphertextSize = 1088
)

// Certificate is a DNSCrypt server certificate.
type Certificate struct {
	Serial          uint32
	ESVersion       CryptoConstruction
	Signature       [ed25519.SignatureSize]byte
	ResolverPk      [KeySize]byte              // X25519 public key (serialized)
	ResolverSk      [KeySize]byte              // X25519 secret key (server-side only)
	ResolverMlkemPk [mlkemPublicKeySize]byte   // ML-KEM-768 encapsulation key (serialized for PQ)
	resolverMlkemDK *mlkem.DecapsulationKey768 // ML-KEM-768 decapsulation key (server-side only)
	ClientMagic     [clientMagicSize]byte
	NotBefore       uint32
	NotAfter        uint32
}

// MlkemDecapsulationKey returns the ML-KEM-768 decapsulation key for PQ
// constructions, or nil for classic certs.
func (c *Certificate) MlkemDecapsulationKey() *mlkem.DecapsulationKey768 {
	return c.resolverMlkemDK
}

// GenerateCertificate creates a new signed certificate for the given provider.
// The Ed25519 private key signs the certificate; the X25519 key pair is freshly
// generated for each certificate (forward secrecy / rotation).
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

	// Generate X25519 key pair.
	if _, err := rand.Read(cert.ResolverSk[:]); err != nil {
		return nil, fmt.Errorf("dnscrypt: generate resolver secret key: %w", err)
	}
	pk, err := curve25519.X25519(cert.ResolverSk[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("dnscrypt: derive resolver public key: %w", err)
	}
	copy(cert.ResolverPk[:], pk)

	// For PQ constructions, also generate an ML-KEM-768 key pair.
	if esVersion.IsPQ() {
		mlkemDK, err := mlkem.GenerateKey768()
		if err != nil {
			return nil, fmt.Errorf("dnscrypt: generate ML-KEM-768 key: %w", err)
		}
		ek := mlkemDK.EncapsulationKey()
		copy(cert.ResolverMlkemPk[:], ek.Bytes())
		cert.resolverMlkemDK = mlkemDK
	}

	// Generate client magic (random 8 bytes).
	if _, err := rand.Read(cert.ClientMagic[:]); err != nil {
		return nil, fmt.Errorf("dnscrypt: generate client magic: %w", err)
	}

	cert.Sign(providerPrivateKey)
	return cert, nil
}

// Sign signs the certificate body with the given Ed25519 private key.
func (c *Certificate) Sign(privateKey ed25519.PrivateKey) {
	msg := make([]byte, 0, KeySize+clientMagicSize+12)
	msg = append(msg, c.ResolverPk[:]...)
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
	msg := make([]byte, 0, KeySize+clientMagicSize+12)
	msg = append(msg, c.ResolverPk[:]...)
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
// 1308 bytes for PQ).
func (c *Certificate) Serialize() ([]byte, error) {
	size := certMinSize
	if c.ESVersion.IsPQ() {
		size = pqCertMinSize
	}
	buf := make([]byte, size)
	copy(buf[0:4], certMagic[:])
	binary.BigEndian.PutUint16(buf[4:6], uint16(c.ESVersion))
	binary.BigEndian.PutUint16(buf[6:8], minorVersion)
	copy(buf[8:72], c.Signature[:])
	copy(buf[72:104], c.ResolverPk[:])
	copy(buf[104:112], c.ClientMagic[:])
	binary.BigEndian.PutUint32(buf[112:116], c.Serial)
	binary.BigEndian.PutUint32(buf[116:120], c.NotBefore)
	binary.BigEndian.PutUint32(buf[120:124], c.NotAfter)
	if c.ESVersion.IsPQ() {
		copy(buf[124:], c.ResolverMlkemPk[:])
	}
	return buf, nil
}

// Deserialize parses a certificate from its wire format (124 or 1308 bytes).
func (c *Certificate) Deserialize(b []byte) error {
	if (len(b) != certMinSize && len(b) != pqCertMinSize) || string(b[:certMagicBytes]) != string(certMagic[:]) {
		return errors.New("dnscrypt: invalid certificate format")
	}
	c.ESVersion = CryptoConstruction(binary.BigEndian.Uint16(b[4:6]))
	// minorVersion is at b[6:8], unused.
	copy(c.Signature[:], b[8:72])
	copy(c.ResolverPk[:], b[72:104])
	copy(c.ClientMagic[:], b[104:112])
	c.Serial = binary.BigEndian.Uint32(b[112:116])
	c.NotBefore = binary.BigEndian.Uint32(b[116:120])
	c.NotAfter = binary.BigEndian.Uint32(b[120:124])
	// Read ML-KEM-768 PK from extended cert.
	if c.ESVersion.IsPQ() {
		if len(b) < pqCertMinSize {
			return errors.New("dnscrypt: PQ cert too short for ML-KEM-768 key")
		}
		copy(c.ResolverMlkemPk[:], b[124:])
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
