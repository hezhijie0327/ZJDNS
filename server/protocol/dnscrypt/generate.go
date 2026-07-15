package dnscrypt

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"zjdns/config"
	zstamp "zjdns/internal/stamp"

	"github.com/cloudflare/circl/dh/x25519"
	"github.com/cloudflare/circl/sign/ed25519"
)

// ResolverConfig holds the DNSCrypt resolver configuration including keys and
// provider identity.  ResolverSk/ResolverPk are always X25519 keys; PQ keys
// are derived deterministically from them via DerivePQKeys.
type ResolverConfig struct {
	ProviderName string
	PublicKey    string // Ed25519 public key (hex)
	PrivateKey   string // Ed25519 private key (hex)
	ResolverSk   string // X25519 secret key (hex)
	ResolverPk   string // X25519 public key (hex)
}

// CertificateBlock holds the DNSCrypt certificate settings for generated config.
type CertificateBlock struct {
	DNSCrypt config.DNSCryptCertificate `json:"dnscrypt"`
}

// FullConfig is a complete ZJDNS configuration including both server-side
// DNSCrypt settings and client-side upstream entries.  It marshals to a
// single valid JSON config file.
type FullConfig struct {
	Server struct {
		Protocol    config.ProtocolSettings `json:"protocol"`
		Certificate CertificateBlock        `json:"certificate"`
	} `json:"server"`
	Upstream []config.UpstreamServer `json:"upstream"`
}

// GenerateResolverConfig generates a new resolver configuration.  If
// privateKey is nil, a new Ed25519 keypair is generated.  An X25519 short-term
// keypair is always generated; PQ keys are derived deterministically from it.
func GenerateResolverConfig(providerName string, privateKey ed25519.PrivateKey) (ResolverConfig, error) {
	cfg := ResolverConfig{}
	if !strings.HasPrefix(providerName, config.DNSCryptV2Prefix) {
		providerName = config.DNSCryptV2Prefix + providerName
	}
	cfg.ProviderName = providerName
	if privateKey == nil {
		var err error
		_, privateKey, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return cfg, fmt.Errorf("generating ed25519 key: %w", err)
		}
	}
	cfg.PrivateKey = hexEncodeKey(privateKey)
	cfg.PublicKey = hexEncodeKey(privateKey.Public().(ed25519.PublicKey))

	sk, pk := generateRandomKeyPair()
	cfg.ResolverSk = hexEncodeKey(sk[:])
	cfg.ResolverPk = hexEncodeKey(pk[:])
	return cfg, nil
}

// NewCert generates a signed classical X25519-XChacha20Poly1305 certificate.
// serial and timestamps are provided by the caller to guarantee alignment with
// the paired PQ cert.
func (rc *ResolverConfig) NewCert(serial, notBefore, notAfter uint32) (cert *Certificate, err error) {
	cert = &Certificate{
		Serial:    serial,
		NotAfter:  notAfter,
		NotBefore: notBefore,
		ESVersion: XChacha20Poly1305,
	}

	resolverPk, err := hexDecodeKey(rc.ResolverPk)
	if err != nil {
		return nil, fmt.Errorf("decoding resolver public key: %w", err)
	}
	resolverSk, err := hexDecodeKey(rc.ResolverSk)
	if err != nil {
		return nil, fmt.Errorf("decoding resolver secret key: %w", err)
	}
	if len(resolverPk) != KeySize || len(resolverSk) != KeySize {
		sk, pk := generateRandomKeyPair()
		resolverSk = sk[:]
		resolverPk = pk[:]
	}
	copy(cert.ResolverPk[:], resolverPk)
	copy(cert.ResolverSk[:], resolverSk)
	// ClientMagic for classical certs is the first 8 bytes of the
	// resolver public key (spec §5.5).
	copy(cert.ClientMagic[:], resolverPk[:ClientMagicSize])

	privateKey, err := hexDecodeKey(rc.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decoding private key: %w", err)
	}
	cert.Sign(privateKey)
	return cert, nil
}

// NewPQCert generates a signed PQ X-Wing certificate deterministically derived
// from the same X25519 seed as the classical cert.  Serial and timestamps are
// provided by the caller to guarantee alignment.
func (rc *ResolverConfig) NewPQCert(serial, notBefore, notAfter uint32) (cert *Certificate, err error) {
	resolverSk, err := hexDecodeKey(rc.ResolverSk)
	if err != nil {
		return nil, fmt.Errorf("decoding resolver secret key: %w", err)
	}

	pk, sk := DerivePQKeys(resolverSk)

	cert = &Certificate{
		Serial:       serial,
		NotAfter:     notAfter,
		NotBefore:    notBefore,
		ESVersion:    XWingPQ,
		PqPublicKey:  pk,
		PqPrivateKey: sk,
	}

	// ClientMagic for PQ certs: bytes 72–79 of the X-Wing public key
	// (matching the official encrypted-dns-server derivation).
	copy(cert.ClientMagic[:], pk[72:72+ClientMagicSize])

	binCert, _ := cert.MarshalBinary()
	cert.PqCertContext = pqCertContext(binCert)

	privateKey, err := hexDecodeKey(rc.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decoding private key: %w", err)
	}
	cert.Sign(privateKey)
	return cert, nil
}

// NewCertPair generates both classical and PQ certificates for a single key
// window.  Both certs share the same Serial, NotBefore, and NotAfter.
func (rc *ResolverConfig) NewCertPair() (*CertPair, error) {
	serial := nowUnix32()
	notBefore := serial
	notAfter := serial + uint32(config.DefaultDNSCryptCertificateTTL/time.Second)

	classical, err := rc.NewCert(serial, notBefore, notAfter)
	if err != nil {
		return nil, fmt.Errorf("classical cert: %w", err)
	}
	pq, err := rc.NewPQCert(serial, notBefore, notAfter)
	if err != nil {
		return nil, fmt.Errorf("PQ cert: %w", err)
	}
	return &CertPair{Classical: classical, PQ: pq}, nil
}

// CreateStamp generates a DNS stamp (sdns://) string for this resolver config.
func (rc *ResolverConfig) CreateStamp(addr string) (string, error) {
	serverPK, err := hexDecodeKey(rc.PublicKey)
	if err != nil {
		return "", fmt.Errorf("decoding public key: %w", err)
	}
	s := &zstamp.Stamp{
		Proto:        zstamp.ProtoDNSCrypt,
		Address:      addr,
		ProviderName: rc.ProviderName,
		PublicKey:    serverPK,
	}
	return s.String(), nil
}

// ParseStamp parses a DNSCrypt DNS stamp string (sdns://...) and returns the
// server address, provider name, and server public key.  It delegates to the
// general-purpose stamp parser and adds DNSCrypt-specific validation.
func ParseStamp(stampStr string) (addr, providerName string, publicKey []byte, err error) {
	s, err := zstamp.Parse(stampStr)
	if err != nil {
		return "", "", nil, err
	}
	if s.Proto != zstamp.ProtoDNSCrypt {
		return "", "", nil, fmt.Errorf("stamp is not DNSCrypt (proto=%d)", s.Proto)
	}
	return s.Address, s.ProviderName, s.PublicKey, nil
}

// hexEncodeKey encodes a byte slice as an uppercase hex string.
func hexEncodeKey(b []byte) (encoded string) {
	return strings.ToUpper(hex.EncodeToString(b))
}

// hexDecodeKey decodes a hex-encoded string (with optional colon separators)
// into a byte slice.
func hexDecodeKey(str string) (decoded []byte, err error) {
	return hex.DecodeString(strings.ReplaceAll(str, ":", ""))
}

// HexDecodeKey exported wrapper for hexDecodeKey.
func HexDecodeKey(str string) ([]byte, error) {
	return hexDecodeKey(str)
}

// generateRandomKeyPair generates a new X25519 keypair.
func generateRandomKeyPair() (secretKey, publicKey [KeySize]byte) {
	var sk, pk x25519.Key
	_, _ = rand.Read(sk[:])
	x25519.KeyGen(&pk, &sk)
	secretKey = [KeySize]byte(sk)
	publicKey = [KeySize]byte(pk)
	return secretKey, publicKey
}

// GenerateEd25519Keypair generates a new Ed25519 keypair for provider signing.
func GenerateEd25519Keypair() (publicKey, privateKey []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating ed25519 keypair: %w", err)
	}
	return pub, priv, nil
}

// GenerateDNSCryptConfig generates a complete ZJDNS JSON configuration for
// the given provider name and address.  The output includes the server-side
// DNSCrypt cert + protocol config and a client-side upstream entry with the
// sdns:// stamp.
func GenerateDNSCryptConfig(provider, addr string) (string, error) {
	if provider == "" {
		return "", errors.New("provider name is required (-provider <name>)")
	}
	if !strings.Contains(addr, ":") {
		return "", fmt.Errorf("address must be host:port format (got %q)", addr)
	}

	rc, err := GenerateResolverConfig(provider, nil)
	if err != nil {
		return "", fmt.Errorf("generating resolver config: %w", err)
	}

	stamp, err := rc.CreateStamp(addr)
	if err != nil {
		return "", fmt.Errorf("creating stamp: %w", err)
	}

	port := addr[strings.LastIndex(addr, ":")+1:]

	cfg := &FullConfig{}
	cfg.Server.Protocol.DNSCrypt = port
	cfg.Server.Certificate.DNSCrypt = config.DNSCryptCertificate{
		PublicKey:  rc.PublicKey,
		PrivateKey: rc.PrivateKey,
	}
	cfg.Upstream = []config.UpstreamServer{
		{Address: stamp},
	}

	output, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshaling config: %w", err)
	}
	return string(output), nil
}
