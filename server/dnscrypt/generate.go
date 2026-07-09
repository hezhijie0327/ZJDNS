package dnscrypt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"zjdns/config"

	"golang.org/x/crypto/curve25519"
)

const (
	// DNSCryptV2Prefix is the provider name prefix for DNSCrypt v2.
	DNSCryptV2Prefix = "2.dnscrypt-cert."
)

// ResolverConfig holds the DNSCrypt resolver configuration including keys and
// provider identity.
type ResolverConfig struct {
	ProviderName string
	PublicKey    string // Ed25519 public key (hex)
	PrivateKey   string // Ed25519 private key (hex)
	ResolverSk   string // X25519 short-term secret key (hex)
	ResolverPk   string // X25519 short-term public key (hex)
	ESVersion    CryptoConstruction
	CertTTL      time.Duration
}

// StampProtoDNSCrypt is the DNS stamp protocol ID for DNSCrypt.
const StampProtoDNSCrypt = 0x01

// GenerateResolverConfig generates a new resolver configuration for the given
// provider name.  If privateKey is nil, a new Ed25519 keypair is generated.
// The X25519 short-term keypair is always generated fresh.
func GenerateResolverConfig(providerName string, privateKey ed25519.PrivateKey, ttl time.Duration) (ResolverConfig, error) {
	cfg := ResolverConfig{
		ESVersion: XSalsa20Poly1305,
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
	sk, pk := generateRandomKeyPair()
	cfg.ResolverSk = hexEncodeKey(sk[:])
	cfg.ResolverPk = hexEncodeKey(pk[:])
	return cfg, nil
}

// NewCert generates a signed Certificate from the resolver configuration to be
// used by the DNSCrypt server.
func (rc *ResolverConfig) NewCert() (cert *Certificate, err error) {
	ttl := rc.CertTTL
	if ttl <= 0 {
		ttl = config.DefaultDNSCryptCertTTL
	}
	cert = &Certificate{
		Serial:    uint32(time.Now().Unix()),          //nolint:gosec // G115: Unix timestamp fits in uint32 until 2106
		NotAfter:  uint32(time.Now().Add(ttl).Unix()), //nolint:gosec // G115: Unix timestamp fits in uint32 until 2106
		NotBefore: uint32(time.Now().Unix()),          //nolint:gosec // G115: Unix timestamp fits in uint32 until 2106
		ESVersion: rc.ESVersion,
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
	privateKey, err := hexDecodeKey(rc.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decoding private key: %w", err)
	}
	cert.Sign(privateKey)
	return cert, nil
}

// CreateStamp generates a DNS stamp (sdns://) string for this resolver config.
// addr should be the server's host:port (e.g. "1.2.3.4:8443").
func (rc *ResolverConfig) CreateStamp(addr string) (stamp string, err error) {
	serverPK, err := hexDecodeKey(rc.PublicKey)
	if err != nil {
		return "", fmt.Errorf("decoding public key: %w", err)
	}
	// DNS stamp binary format (DNSCrypt):
	//   1 byte: protocol (0x01 for DNSCrypt)
	//   8 bytes: properties
	//   varint: server address length + address
	//   32 bytes: server public key (fixed, not length-prefixed)
	//   varint: provider name length + provider name
	buf := make([]byte, 0, 128)
	buf = append(buf, StampProtoDNSCrypt, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // protocol + properties (9 bytes)
	// Server address as length-prefixed string.
	addrLen := uint8(len(addr)) //nolint:gosec // G115: Address length bounded to 255
	buf = append(buf, addrLen)
	buf = append(buf, []byte(addr)...)
	// Server public key (32 bytes, fixed — before provider name per dnsstamps spec).
	pkLen := uint8(len(serverPK)) //nolint:gosec // G115: Ed25519 key is 32 bytes
	buf = append(buf, pkLen)
	buf = append(buf, serverPK...)
	// Provider name as length-prefixed string.
	providerName := rc.ProviderName
	provLen := uint8(len(providerName)) //nolint:gosec // G115: Provider name length bounded to 255
	buf = append(buf, provLen)
	buf = append(buf, []byte(providerName)...)
	return "sdns://" + base64.RawURLEncoding.EncodeToString(buf), nil
}

// ParseStamp parses a DNSCrypt DNS stamp string (sdns://...) and returns the
// server address, provider name, and server public key.
func ParseStamp(stampStr string) (addr, providerName string, publicKey []byte, err error) {
	if !strings.HasPrefix(stampStr, "sdns://") {
		return "", "", nil, errors.New("invalid stamp: must start with sdns://")
	}
	b, err := base64.RawURLEncoding.DecodeString(stampStr[7:])
	if err != nil {
		return "", "", nil, fmt.Errorf("decoding stamp base64: %w", err)
	}
	if len(b) < 1 {
		return "", "", nil, errors.New("stamp too short")
	}
	if b[0] != StampProtoDNSCrypt {
		return "", "", nil, fmt.Errorf("stamp is not DNSCrypt (proto=%d)", b[0])
	}
	b = b[1:] // skip protocol byte
	if len(b) < 8 {
		return "", "", nil, errors.New("stamp: properties too short")
	}
	b = b[8:] // skip properties (8 bytes for DNSCrypt)
	// Read server address.
	if len(b) < 1 {
		return "", "", nil, errors.New("stamp: missing address")
	}
	addrLen := int(b[0])
	b = b[1:]
	if len(b) < addrLen {
		return "", "", nil, errors.New("stamp: truncated address")
	}
	addr = string(b[:addrLen])
	b = b[addrLen:]
	// Read server public key (length-prefixed).
	if len(b) < 1 {
		return "", "", nil, errors.New("stamp: missing public key length")
	}
	pkLen := int(b[0])
	b = b[1:]
	if pkLen < 1 || len(b) < pkLen {
		return "", "", nil, errors.New("stamp: truncated public key")
	}
	publicKey = make([]byte, pkLen)
	copy(publicKey, b[:pkLen])
	b = b[pkLen:]
	// Read provider name.
	if len(b) < 1 {
		return "", "", nil, errors.New("stamp: missing provider name")
	}
	provLen := int(b[0])
	b = b[1:]
	if len(b) < provLen {
		return "", "", nil, errors.New("stamp: truncated provider name")
	}
	providerName = string(b[:provLen])
	return addr, providerName, publicKey, nil
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

// generateRandomKeyPair generates a new X25519 keypair.
func generateRandomKeyPair() (secretKey, publicKey [KeySize]byte) {
	secretKey = [KeySize]byte{}
	publicKey = [KeySize]byte{}
	_, _ = rand.Read(secretKey[:])
	curve25519.ScalarBaseMult(&publicKey, &secretKey)
	return secretKey, publicKey
}

// GenerateClientMagic creates a client magic value from the resolver's public
// key by taking the first 8 bytes.
func GenerateClientMagic(resolverPk [KeySize]byte) (magic [ClientMagicSize]byte) {
	copy(magic[:], resolverPk[:ClientMagicSize])
	return magic
}

// StampToClientConfig parses a DNSCrypt stamp and returns the components
// needed for client configuration.
func StampToClientConfig(stamp string) (addr, providerName, publicKeyHex string, err error) {
	addr, providerName, pk, err := ParseStamp(stamp)
	if err != nil {
		return "", "", "", err
	}
	return addr, providerName, hexEncodeKey(pk), nil
}

// BuildStamp builds a DNSCrypt stamp from config components.  pkHex is the
// Ed25519 public key in hex format, addr is host:port.
func BuildStamp(pkHex, addr, providerName string) (string, error) {
	pk, err := hexDecodeKey(pkHex)
	if err != nil {
		return "", fmt.Errorf("decoding public key: %w", err)
	}
	if len(pk) != ed25519.PublicKeySize {
		return "", fmt.Errorf("public key must be %d bytes (got %d)", ed25519.PublicKeySize, len(pk))
	}
	buf := make([]byte, 0, 128)
	buf = append(buf, StampProtoDNSCrypt, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // protocol + properties (9 bytes)
	addrLen := uint8(len(addr))                                                           //nolint:gosec // G115: Address length bounded to 255
	buf = append(buf, addrLen)
	buf = append(buf, []byte(addr)...)
	//nolint:gosec // G115: Ed25519 key length is 32
	buf = append(buf, byte(len(pk)))    // key length (32 for Ed25519)
	buf = append(buf, pk...)            // server public key (32 bytes, before provider name)
	provLen := uint8(len(providerName)) //nolint:gosec // G115: Provider name length bounded to 255
	buf = append(buf, provLen)
	buf = append(buf, []byte(providerName)...)
	return "sdns://" + base64.RawURLEncoding.EncodeToString(buf), nil
}

// BuildStampFromCert builds a DNSCrypt stamp from the resolver config and address.
func BuildStampFromCert(rc ResolverConfig, addr string) (string, error) { //nolint:gocritic // ResolverConfig passed by value for caller convenience
	return BuildStamp(rc.PublicKey, addr, rc.ProviderName)
}

// AppendStampBinary appends the binary representation of a DNSCrypt stamp to
// the provided buffer.  This returns the new buffer and does not modify the
// original.
func AppendStampBinary(buf []byte, addr, providerName string, publicKey []byte) []byte {
	buf = append(buf, StampProtoDNSCrypt, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // protocol + properties (9 bytes)
	addrLen := uint8(len(addr))                                                           //nolint:gosec // G115: Address length bounded to 255
	buf = append(buf, addrLen)
	buf = append(buf, []byte(addr)...)
	//nolint:gosec // G115: Ed25519 key length is 32
	buf = append(buf, byte(len(publicKey))) // key length (32 for Ed25519)
	buf = append(buf, publicKey...)         // server public key (32 bytes, before provider name)
	provLen := uint8(len(providerName))     //nolint:gosec // G115: Provider name length bounded to 255
	buf = append(buf, provLen)
	buf = append(buf, []byte(providerName)...)
	return buf
}

// ReadStampLengths parses the variable-length fields from a binary stamp to
// determine the total stamp size in bytes.  Returns 0 if the stamp is invalid.
func ReadStampLengths(b []byte) (size int) {
	if len(b) < 4 || b[0] != StampProtoDNSCrypt {
		return 0
	}
	pos := 9 // skip protocol (1) + properties (8)
	if pos >= len(b) {
		return 0
	}
	addrLen := int(b[pos])
	pos += 1 + addrLen + ed25519.PublicKeySize // addr + pk (32 bytes)
	if pos >= len(b) {
		return 0
	}
	provLen := int(b[pos])
	pos += 1 + provLen
	return pos
}

// StampEncodeBase64 encodes binary stamp data as an sdns:// string.
func StampEncodeBase64(b []byte) string {
	return "sdns://" + base64.RawURLEncoding.EncodeToString(b)
}

// BuildStampBinary builds the binary representation of a DNSCrypt stamp.
func BuildStampBinary(addr, providerName string, publicKey []byte) []byte {
	return AppendStampBinary(nil, addr, providerName, publicKey)
}

// GenerateSDNSSalt generates a random 8-byte salt for use with SDNS stamps.
func GenerateSDNSSalt() (salt [8]byte) {
	_, _ = rand.Read(salt[:])
	return salt
}

// StampTypeToString returns a human-readable name for a DNS stamp protocol.
func StampTypeToString(proto uint8) string {
	switch proto {
	case StampProtoDNSCrypt:
		return "DNSCrypt"
	case 0x02:
		return "DoH"
	case 0x03:
		return "DoT"
	case 0x04:
		return "DoQ"
	default:
		return fmt.Sprintf("Unknown(%d)", proto)
	}
}

// EncodeStampFromConfig encodes a complete DNS stamp and returns its components.
func EncodeStampFromConfig(addr, providerName, pkHex string) (stamp string, err error) {
	pk, err := hexDecodeKey(pkHex)
	if err != nil {
		return "", fmt.Errorf("decoding public key: %w", err)
	}
	buf := BuildStampBinary(addr, providerName, pk)
	return StampEncodeBase64(buf), nil
}

// ResolverConfigFromStamp creates a bare ResolverConfig from stamp components.
func ResolverConfigFromStamp(addr, pkHex, providerName string) (ResolverConfig, error) {
	rc := ResolverConfig{
		ProviderName: providerName,
		ESVersion:    XSalsa20Poly1305,
	}
	if !strings.HasPrefix(providerName, DNSCryptV2Prefix) {
		rc.ProviderName = DNSCryptV2Prefix + providerName
	}
	rc.PublicKey = pkHex
	rc.ESVersion = XSalsa20Poly1305
	return rc, nil
}

// StampBinaryEncode encodes the stamp fields as raw binary.
func StampBinaryEncode(addr, providerName string, publicKey []byte) []byte {
	return AppendStampBinary(nil, addr, providerName, publicKey)
}

// HexDecodeKey exported wrapper.
func HexDecodeKey(str string) ([]byte, error) {
	return hexDecodeKey(str)
}

// HexEncodeKey exported wrapper.
func HexEncodeKey(b []byte) string {
	return hexEncodeKey(b)
}

// ClientMagicFromStamp extracts the client magic from a stamp.  For DNSCrypt,
// the client magic is derived from the resolver's public key.
func ClientMagicFromStamp(pk []byte) [ClientMagicSize]byte {
	var magic [ClientMagicSize]byte
	copy(magic[:], pk[:ClientMagicSize])
	return magic
}

// NSSalt generates a random nonce salt for NS queries.
func NSSalt() (salt [8]byte) {
	_, _ = rand.Read(salt[:])
	return salt
}

// SharedKeyFromStamp computes a shared key from the stamp components.
func SharedKeyFromStamp(pkHex, skHex string, esVersion CryptoConstruction) (sharedKey [SharedKeySize]byte, err error) {
	pkBytes, err := hexDecodeKey(pkHex)
	if err != nil {
		return sharedKey, fmt.Errorf("decoding public key: %w", err)
	}
	skBytes, err := hexDecodeKey(skHex)
	if err != nil {
		return sharedKey, fmt.Errorf("decoding secret key: %w", err)
	}
	var pkArr, skArr [KeySize]byte
	copy(pkArr[:], pkBytes)
	copy(skArr[:], skBytes)
	return computeSharedKey(esVersion, &skArr, &pkArr)
}

// GenerateKeyPair generates a new X25519 key pair and returns hex-encoded strings.
func GenerateKeyPair() (secretHex, publicHex string) {
	sk, pk := generateRandomKeyPair()
	return hexEncodeKey(sk[:]), hexEncodeKey(pk[:])
}

// StampFromConfig returns the SDNS stamp for a given DNSCrypt configuration.
func StampFromConfig(addr, pkHex, providerName string) string {
	stamp, _ := EncodeStampFromConfig(addr, providerName, pkHex)
	return stamp
}

// SerializeStampBinaryBytes serializes a stamp to sdns:// format.
func SerializeStampBinaryBytes(addr, providerName string, pk []byte) string {
	return StampEncodeBase64(StampBinaryEncode(addr, providerName, pk))
}

// ClientMagicFromKey creates a client magic value from a public key byte slice.
func ClientMagicFromKey(pk []byte) [ClientMagicSize]byte {
	var magic [ClientMagicSize]byte
	copy(magic[:], pk[:ClientMagicSize])
	return magic
}

// StampAddr extracts the server address from a DNSCrypt stamp.
func StampAddr(stamp string) (string, error) {
	addr, _, _, err := ParseStamp(stamp)
	return addr, err
}

// StampPK extracts the hex-encoded server public key from a stamp.
func StampPK(stamp string) (string, error) {
	_, _, pk, err := ParseStamp(stamp)
	if err != nil {
		return "", err
	}
	return hexEncodeKey(pk), nil
}

// StampProviderName extracts the provider name from a stamp.
func StampProviderName(stamp string) (string, error) {
	_, pn, _, err := ParseStamp(stamp)
	return pn, err
}

// CertFromConfig generates a certificate from the resolver configuration.
func CertFromConfig(providerName, privateKeyHex, resolverPkHex, resolverSkHex, esVersionStr string, certTTL time.Duration) (*Certificate, error) {
	esVersion, err := ParseESVersion(esVersionStr)
	if err != nil {
		return nil, err
	}
	privateKey, err := hexDecodeKey(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("decoding signing key: %w", err)
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("signing key must be %d bytes (got %d)", ed25519.PrivateKeySize, len(privateKey))
	}
	resolverPk, err := hexDecodeKey(resolverPkHex)
	if err != nil {
		return nil, fmt.Errorf("decoding resolver pk: %w", err)
	}
	resolverSk, err := hexDecodeKey(resolverSkHex)
	if err != nil {
		return nil, fmt.Errorf("decoding resolver sk: %w", err)
	}
	cert := &Certificate{
		Serial:    uint32(time.Now().Unix()),              //nolint:gosec // G115: Unix timestamp fits in uint32 until 2106
		NotBefore: uint32(time.Now().Unix()),              //nolint:gosec // G115: Unix timestamp fits in uint32 until 2106
		NotAfter:  uint32(time.Now().Add(certTTL).Unix()), //nolint:gosec // G115: Unix timestamp fits in uint32 until 2106
		ESVersion: esVersion,
	}
	copy(cert.ResolverPk[:], resolverPk)
	copy(cert.ResolverSk[:], resolverSk)
	cert.Sign(privateKey)
	return cert, nil
}

// CertSelfSigned generates a self-signed certificate for the given provider name.
func CertSelfSigned(providerName, esVersionStr string) (*Certificate, string, string, error) { //nolint:gocritic // multiple return values for ergonomic caller usage
	esVersion, err := ParseESVersion(esVersionStr)
	if err != nil {
		return nil, "", "", err
	}
	rc, err := GenerateResolverConfig(providerName, nil, 0)
	if err != nil {
		return nil, "", "", fmt.Errorf("generating config: %w", err)
	}
	rc.ESVersion = esVersion
	cert, err := rc.NewCert()
	if err != nil {
		return nil, "", "", fmt.Errorf("creating cert: %w", err)
	}
	return cert, rc.PublicKey, rc.PrivateKey, nil
}

// GenerateTestCert creates a test certificate for use in tests.
func GenerateTestCert(providerName string) (*Certificate, error) {
	rc, err := GenerateResolverConfig(providerName, nil, 0)
	if err != nil {
		return nil, err
	}
	return rc.NewCert()
}

// NewTestCert generates a test certificate from a ResolverConfig.
func NewTestCert(providerName string) (*Certificate, *ResolverConfig, error) {
	rc, err := GenerateResolverConfig(providerName, nil, 0)
	if err != nil {
		return nil, nil, err
	}
	cert, err := rc.NewCert()
	if err != nil {
		return nil, nil, err
	}
	return cert, &rc, nil
}

// ParseStampAddr extracts and returns just the server address from a stamp.
func ParseStampAddr(stamp string) (string, error) {
	addr, _, _, err := ParseStamp(stamp)
	return addr, err
}

// GenerateCert creates a certificate from configuration parameters.
func GenerateCert(providerName, publicKeyHex, privateKeyHex, resolverSkHex, resolverPkHex, esVersionStr string) (*Certificate, error) {
	esVersion, err := ParseESVersion(esVersionStr)
	if err != nil {
		return nil, err
	}
	pk, err := hexDecodeKey(publicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("decoding public key: %w", err)
	}
	sk, err := hexDecodeKey(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("decoding private key: %w", err)
	}
	resolverPk, err := hexDecodeKey(resolverPkHex)
	if err != nil {
		return nil, fmt.Errorf("decoding resolver pk: %w", err)
	}
	resolverSk, err := hexDecodeKey(resolverSkHex)
	if err != nil {
		return nil, fmt.Errorf("decoding resolver sk: %w", err)
	}
	cert := &Certificate{
		Serial:    uint32(time.Now().Unix()),                                    //nolint:gosec // G115: Unix timestamp fits in uint32 until 2106
		NotBefore: uint32(time.Now().Unix()),                                    //nolint:gosec // G115: Unix timestamp fits in uint32 until 2106
		NotAfter:  uint32(time.Now().Add(config.DefaultDNSCryptCertTTL).Unix()), //nolint:gosec // G115: Unix timestamp fits in uint32 until 2106
		ESVersion: esVersion,
	}
	copy(cert.ResolverPk[:], resolverPk)
	copy(cert.ResolverSk[:], resolverSk)
	// Try using privateKey as the signing key.
	signingKey := sk
	if len(signingKey) != ed25519.PrivateKeySize {
		// Fallback: derive from public.
		signingKey = make([]byte, ed25519.PrivateKeySize)
		copy(signingKey, pk)
	}
	cert.Sign(signingKey)
	// Verify the cert signature using the public key.
	if !cert.VerifySignature(pk) {
		return nil, errors.New("certificate self-verification failed")
	}
	if !cert.IsDateValid() {
		return nil, errors.New("certificate date range invalid")
	}
	return cert, nil
}

// SharedKeys computes the shared key from stamp and X25519 keypair.
func SharedKeys(stampPk, resolverSk, esVersionStr string) (sharedKey [SharedKeySize]byte, err error) {
	esVersion, err := ParseESVersion(esVersionStr)
	if err != nil {
		return sharedKey, err
	}
	pk, err := hexDecodeKey(stampPk)
	if err != nil {
		return sharedKey, fmt.Errorf("decoding stamp public key: %w", err)
	}
	sk, err := hexDecodeKey(resolverSk)
	if err != nil {
		return sharedKey, fmt.Errorf("decoding resolver secret: %w", err)
	}
	var pkArr, skArr [KeySize]byte
	copy(pkArr[:], pk)
	copy(skArr[:], sk)
	return computeSharedKey(esVersion, &skArr, &pkArr)
}

// GenerateEd25519Keypair generates a new Ed25519 keypair for provider signing.
func GenerateEd25519Keypair() (publicKey, privateKey []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating ed25519 keypair: %w", err)
	}
	return pub, priv, nil
}

// GenerateEd25519KeypairHex generates a new Ed25519 keypair as hex strings.
func GenerateEd25519KeypairHex() (publicHex, privateHex string, err error) {
	pub, priv, err := GenerateEd25519Keypair()
	if err != nil {
		return "", "", err
	}
	return hexEncodeKey(pub), hexEncodeKey(priv), nil
}

// StampFromKeys creates a stamp from individual key components.
func StampFromKeys(addr, providerName string, publicKey ed25519.PublicKey) string {
	return SerializeStampBinaryBytes(addr, providerName, publicKey)
}

// SerializeStamp creates a sdns:// stamp from hex-encoded components.
func SerializeStamp(addr, providerName, pkHex string) (string, error) {
	return BuildStamp(pkHex, addr, providerName)
}

// CertSerial generates a deterministic serial number based on current time.
func CertSerial() uint32 {
	return uint32(time.Now().Unix()) //nolint:gosec // G115: Unix timestamp fits in uint32 until 2106
}

// CertTTL returns the default certificate TTL duration.
func CertTTL() time.Duration {
	return config.DefaultDNSCryptCertTTL
}

// ServerConfig is a typed representation of the DNSCrypt server config block
// suitable for JSON marshaling.
type ServerConfig struct {
	Server struct {
		DNSCrypt ConfigBlock `json:"dnscrypt"`
	} `json:"server"`
}

// ConfigBlock holds the DNSCrypt server settings.
type ConfigBlock struct {
	Port         string `json:"port"`
	ProviderName string `json:"provider_name"`
	PublicKey    string `json:"public_key"`
	PrivateKey   string `json:"private_key"`
	ResolverSk   string `json:"resolver_sk"`
	ResolverPk   string `json:"resolver_pk"`
	ESVersion    string `json:"es_version"`
	CertTTL      string `json:"cert_ttl,omitempty"`
}

// ClientConfig is a typed representation of a DNSCrypt upstream entry.
type ClientConfig struct {
	Upstream []UpstreamEntry `json:"upstream"`
}

// UpstreamEntry is a single DNSCrypt upstream server entry.
type UpstreamEntry struct {
	Address  string `json:"address"`
	Protocol string `json:"protocol"`
}

// GenerateConfigs generates server and client config structs from the given
// parameters.  Keys are auto-generated if empty.  The returned structs can be
// marshaled to JSON directly.
func GenerateConfigs(provider, addr, esVersion, certTTL string) (*ServerConfig, *ClientConfig, error) {
	esVersionVal, err := ParseESVersion(esVersion)
	if err != nil {
		return nil, nil, err
	}

	rc, err := GenerateResolverConfig(provider, nil, parseCertTTL(certTTL))
	if err != nil {
		return nil, nil, fmt.Errorf("generating resolver config: %w", err)
	}
	rc.ESVersion = esVersionVal

	stamp, err := rc.CreateStamp(addr)
	if err != nil {
		return nil, nil, fmt.Errorf("creating stamp: %w", err)
	}

	port := addr[strings.LastIndex(addr, ":")+1:]

	serverCfg := &ServerConfig{}
	serverCfg.Server.DNSCrypt = ConfigBlock{
		Port:         port,
		ProviderName: rc.ProviderName,
		PublicKey:    rc.PublicKey,
		PrivateKey:   rc.PrivateKey,
		ResolverSk:   rc.ResolverSk,
		ResolverPk:   rc.ResolverPk,
		ESVersion:    esVersion,
		CertTTL:      certTTL,
	}

	clientCfg := &ClientConfig{
		Upstream: []UpstreamEntry{
			{Address: stamp, Protocol: "dnscrypt"},
		},
	}

	return serverCfg, clientCfg, nil
}

// GenerateDNSCryptConfig generates a formatted server + client JSON
// configuration pair for the given provider name and address.  It handles
// validation, key generation, stamp creation, and JSON marshaling — the
// caller only needs to print the result.
func GenerateDNSCryptConfig(provider, addr, esVersion, certTTL string) (string, error) {
	if provider == "" {
		return "", errors.New("provider name is required (-provider <name>)")
	}
	if !strings.Contains(addr, ":") {
		return "", fmt.Errorf("address must be host:port format (got %q)", addr)
	}

	serverCfg, clientCfg, err := GenerateConfigs(provider, addr, esVersion, certTTL)
	if err != nil {
		return "", err
	}

	serverJSON, _ := json.MarshalIndent(serverCfg, "", "  ")
	clientJSON, _ := json.MarshalIndent(clientCfg, "", "  ")
	return string(serverJSON) + "\n\n" + string(clientJSON), nil
}
