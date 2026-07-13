package dnscrypt

import (
	"crypto/rand"
	"crypto/sha256"
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
// provider identity.
type ResolverConfig struct {
	ProviderName string
	PublicKey    string // Ed25519 public key (hex)
	PrivateKey   string // Ed25519 private key (hex)
	ResolverSk   string // X25519 secret or X-Wing seed (hex; determined by ESVersion)
	ResolverPk   string // X25519 public or X-Wing public (hex; determined by ESVersion)
	ESVersion    CryptoConstruction
	CertTTL      time.Duration
}

// ConfigBlock holds the DNSCrypt server settings.
type ConfigBlock struct {
	Port         string `json:"port"`
	ProviderName string `json:"provider_name"`
	PublicKey    string `json:"public_key"`
	PrivateKey   string `json:"private_key"`
	ResolverSk   string `json:"resolver_sk,omitzero"`
	ResolverPk   string `json:"resolver_pk,omitzero"`
	ESVersion    string `json:"es_version"`
	CertTTL      string `json:"cert_ttl,omitzero"`
}

// FullConfig is a complete ZJDNS configuration including both server-side
// DNSCrypt settings and client-side upstream entries.  It marshals to a
// single valid JSON config file.
type FullConfig struct {
	Server struct {
		DNSCrypt ConfigBlock `json:"dnscrypt"`
	} `json:"server"`
	Upstream []config.UpstreamServer `json:"upstream"`
}

const (
	// DNSCryptV2Prefix is the provider name prefix for DNSCrypt v2.
	DNSCryptV2Prefix = "2.dnscrypt-cert."
)

// GenerateResolverConfig generates a new resolver configuration.  If
// privateKey is nil, a new Ed25519 keypair is generated.  For classical
// constructions an X25519 short-term keypair is generated; for PQ an X-Wing
// keypair is generated instead.
func GenerateResolverConfig(providerName string, privateKey ed25519.PrivateKey, esVersion CryptoConstruction, ttl time.Duration) (ResolverConfig, error) {
	cfg := ResolverConfig{
		ESVersion: esVersion,
		CertTTL:   ttl,
	}
	if !strings.HasPrefix(providerName, DNSCryptV2Prefix) {
		providerName = DNSCryptV2Prefix + providerName
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

	if esVersion.IsPQ() {
		pk, sk, err := pqGenKeyPair()
		if err != nil {
			return cfg, fmt.Errorf("generating X-Wing keypair: %w", err)
		}
		cfg.ResolverPk = hexEncodeKey(pk)
		cfg.ResolverSk = hexEncodeKey(sk)
	} else {
		sk, pk := generateRandomKeyPair()
		cfg.ResolverSk = hexEncodeKey(sk[:])
		cfg.ResolverPk = hexEncodeKey(pk[:])
	}
	return cfg, nil
}

// NewCert generates a signed Certificate from the resolver configuration.
func (rc *ResolverConfig) NewCert() (cert *Certificate, err error) {
	ttl := rc.CertTTL
	if ttl <= 0 {
		ttl = config.DefaultDNSCryptCertTTL
	}
	cert = &Certificate{
		Serial:    nowUnix32(),
		NotAfter:  nowUnix32() + uint32(ttl/time.Second),
		NotBefore: nowUnix32(),
		ESVersion: rc.ESVersion,
	}

	if rc.ESVersion.IsPQ() {
		if rc.ResolverPk != "" {
			cert.PqPublicKey, err = hexDecodeKey(rc.ResolverPk)
			if err != nil {
				return nil, fmt.Errorf("decoding PQ public key: %w", err)
			}
		}
		if rc.ResolverSk != "" {
			cert.PqPrivateKey, err = hexDecodeKey(rc.ResolverSk)
			if err != nil {
				return nil, fmt.Errorf("decoding PQ private key: %w", err)
			}
		}
		if len(cert.PqPublicKey) != PQPublicKeySize || len(cert.PqPrivateKey) != 32 {
			pk, sk, genErr := pqGenKeyPair()
			if genErr != nil {
				return nil, fmt.Errorf("generating X-Wing keypair: %w", genErr)
			}
			cert.PqPublicKey = pk
			cert.PqPrivateKey = sk
			rc.ResolverPk = hexEncodeKey(pk)
			rc.ResolverSk = hexEncodeKey(sk)
		}
		h := sha256.Sum256(cert.PqPublicKey)
		copy(cert.ClientMagic[:], h[:ClientMagicSize])
		binCert, _ := cert.MarshalBinary()
		cert.PqCertContext = pqCertContext(binCert)
	} else {
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
	}

	privateKey, err := hexDecodeKey(rc.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decoding private key: %w", err)
	}
	cert.Sign(privateKey)
	return cert, nil
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
// the given provider name and address.  The output includes two upstream
// entries: an sdns:// stamp (for dnscrypt-proxy / ZJDNS client) and a
// regular address+public_key entry (for explicit configuration).
func GenerateDNSCryptConfig(provider, addr, esVersion, certTTL string) (string, error) {
	if provider == "" {
		return "", errors.New("provider name is required (-provider <name>)")
	}
	if !strings.Contains(addr, ":") {
		return "", fmt.Errorf("address must be host:port format (got %q)", addr)
	}

	esVersionVal, err := ParseESVersion(esVersion)
	if err != nil {
		return "", err
	}

	rc, err := GenerateResolverConfig(provider, nil, esVersionVal, parseCertTTL(certTTL))
	if err != nil {
		return "", fmt.Errorf("generating resolver config: %w", err)
	}

	stamp, err := rc.CreateStamp(addr)
	if err != nil {
		return "", fmt.Errorf("creating stamp: %w", err)
	}

	port := addr[strings.LastIndex(addr, ":")+1:]

	cfg := &FullConfig{}
	cfg.Server.DNSCrypt = ConfigBlock{
		Port:         port,
		ProviderName: rc.ProviderName,
		PublicKey:    rc.PublicKey,
		PrivateKey:   rc.PrivateKey,
		ResolverSk:   rc.ResolverSk,
		ResolverPk:   rc.ResolverPk,
		ESVersion:    esVersion,
		CertTTL:      certTTL,
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
