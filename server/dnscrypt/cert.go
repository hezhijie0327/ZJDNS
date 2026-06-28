package dnscrypt

import (
	"crypto/ed25519"
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
	certMinSize    = 124
	minorVersion   = 0
)

var certMagic = [certMagicBytes]byte{0x44, 0x4e, 0x53, 0x43} // "DNSC"

// CryptoConstruction is the encryption algorithm identifier.
type CryptoConstruction uint16

const (
	XSalsa20Poly1305  CryptoConstruction = 0x0001
	XChacha20Poly1305 CryptoConstruction = 0x0002
)

func (c CryptoConstruction) String() string {
	switch c {
	case XSalsa20Poly1305:
		return "XSalsa20Poly1305"
	case XChacha20Poly1305:
		return "XChacha20Poly1305"
	default:
		return fmt.Sprintf("Unknown(%d)", c)
	}
}

// Certificate is a DNSCrypt server certificate.
type Certificate struct {
	Serial      uint32
	ESVersion   CryptoConstruction
	Signature   [ed25519.SignatureSize]byte
	ResolverPk  [KeySize]byte
	ResolverSk  [KeySize]byte
	ClientMagic [clientMagicSize]byte
	NotBefore   uint32
	NotAfter    uint32
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

// Serialize encodes the certificate to its 124-byte wire format.
func (c *Certificate) Serialize() ([]byte, error) {
	buf := make([]byte, certMinSize)
	copy(buf[0:4], certMagic[:])
	binary.BigEndian.PutUint16(buf[4:6], uint16(c.ESVersion))
	binary.BigEndian.PutUint16(buf[6:8], minorVersion)
	copy(buf[8:72], c.Signature[:])
	copy(buf[72:104], c.ResolverPk[:])
	copy(buf[104:112], c.ClientMagic[:])
	binary.BigEndian.PutUint32(buf[112:116], c.Serial)
	binary.BigEndian.PutUint32(buf[116:120], c.NotBefore)
	binary.BigEndian.PutUint32(buf[120:124], c.NotAfter)
	return buf, nil
}

// Deserialize parses a certificate from its wire format.
func (c *Certificate) Deserialize(b []byte) error {
	if len(b) != certMinSize || string(b[:certMagicBytes]) != string(certMagic[:]) {
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
