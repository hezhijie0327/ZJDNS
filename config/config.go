// Package config provides configuration types.
package config

// ServerConfig is the top-level configuration structure for the DNS server.
type ServerConfig struct {
	Server   ServerSettings   `json:"server"`
	Upstream []UpstreamServer `json:"upstream,omitzero"`
	Fallback []UpstreamServer `json:"fallback,omitzero"`
	Zone     ZoneConfig       `json:"zone,omitzero"`
	RuleSet  []RuleSet        `json:"ruleset,omitzero"`
}

// ServerSettings contains the server runtime settings and feature flags.
type ServerSettings struct {
	Pprof       string              `json:"pprof,omitzero"`
	LogLevel    string              `json:"log_level,omitzero"`
	Protocol    ProtocolSettings    `json:"protocol,omitzero"`
	Certificate CertificateSettings `json:"certificate,omitzero"`
	Features    FeatureFlags        `json:"features,omitzero"`
}

// ProtocolSettings holds the port and endpoint configuration for every DNS
// transport protocol that the server can listen on.  A protocol is enabled when
// its field is non-empty; an empty/omitted field means the listener is skipped.
type ProtocolSettings struct {
	UDP      string        `json:"udp,omitzero"`
	TCP      string        `json:"tcp,omitzero"`
	TLS      string        `json:"tls,omitzero"`
	QUIC     string        `json:"quic,omitzero"`
	HTTPS    HTTPSEndpoint `json:"https,omitzero"`
	HTTP3    HTTPSEndpoint `json:"http3,omitzero"`
	TLCP     string        `json:"tlcp,omitzero"`
	HTTPTLCP HTTPSEndpoint `json:"http_tlcp,omitzero"`
	DTLS     string        `json:"dod,omitzero"`
	DTLCP    string        `json:"dtlcp,omitzero"`
	DNSCrypt string        `json:"dnscrypt,omitzero"`
}

// HTTPSEndpoint holds the port and HTTP endpoint path for HTTP-based DNS
// transports (DoH, DoH3, TLCP DoH).
type HTTPSEndpoint struct {
	Port     string `json:"port,omitzero"`
	Endpoint string `json:"endpoint,omitzero"`
}

// CertificateSettings holds the unified TLS, TLCP, and DNSCrypt certificate and key
// material for server listeners.  Domain is the server identity (e.g. SNI
// hostname), used for self-signed cert generation and DNSCrypt provider name
// derivation.
type CertificateSettings struct {
	Domain   string              `json:"domain"`
	TLS      TLSCertificate      `json:"tls,omitzero"`
	TLCP     TLCPCertificate     `json:"tlcp,omitzero"`
	DNSCrypt DNSCryptCertificate `json:"dnscrypt,omitzero"`
}

// TLSCertificate holds the X.509 certificate configuration for TLS-based listeners
// (DoT, DoQ, DoH, DoH3).
type TLSCertificate struct {
	CertFile   string `json:"cert_file,omitzero"`
	KeyFile    string `json:"key_file,omitzero"`
	SelfSigned bool   `json:"self_signed,omitzero"`
}

// TLCPCertificate holds the SM2 certificate configuration for TLCP listeners
// (TLCP DoT and TLCP DoH).  TLCP requires two certificate pairs: one for
// signing and one for key exchange.
type TLCPCertificate struct {
	SignCertFile string `json:"sign_cert_file,omitzero"`
	SignKeyFile  string `json:"sign_key_file,omitzero"`
	EncCertFile  string `json:"enc_cert_file,omitzero"`
	EncKeyFile   string `json:"enc_key_file,omitzero"`
	SelfSigned   bool   `json:"self_signed,omitzero"`
}

// DNSCryptCertificate holds the DNSCrypt v2 identity keys.  The provider name is
// auto-derived from certificate.domain as "2.dnscrypt-cert.<domain>".
type DNSCryptCertificate struct {
	PrivateKey string `json:"private_key,omitzero"` // Ed25519 private key (hex, optional — auto-generated if empty)
	PublicKey  string `json:"public_key,omitzero"`  // Ed25519 public key (hex, optional — auto-generated if empty)
}

// FeatureFlags enables optional features: hijack protection, KTLS, DDR, ECS,
// database, cache, latency probes, and stats.
type FeatureFlags struct {
	KTLS             *KTLSSettings      `json:"ktls,omitzero"`
	HijackProtection bool               `json:"hijack_protection,omitzero"`
	DNSSECEnforce    bool               `json:"dnssec_enforce,omitzero"`
	DDR              DDRSettings        `json:"ddr,omitzero"`
	ECS              ECSConfig          `json:"ecs_subnet,omitzero"`
	Database         DatabaseSettings   `json:"database,omitzero"`
	Cache            CacheSettings      `json:"cache,omitzero"`
	LatencyProbe     []LatencyProbeStep `json:"latency_probe,omitzero"`
	DNS64            *DNS64Config       `json:"dns64,omitzero"`
}

// KTLSSettings configures kernel TLS offload for DoT/DoH server listeners.
type KTLSSettings struct {
	KernelTX bool `json:"kernel_tx,omitzero"`
	KernelRX bool `json:"kernel_rx,omitzero"`
}

// DNS64Config holds settings for DNS64 (RFC 6147) AAAA synthesis.
type DNS64Config struct {
	Prefix string `json:"prefix,omitzero"` // e.g. "64:ff9b::/96", defaults to RFC 6052 well-known
}

// DDRSettings configures Discovery of Designated Resolvers (DDR) advertisement.
// The server domain is in certificate.domain.
type DDRSettings struct {
	IPv4 string `json:"ipv4,omitzero"`
	IPv6 string `json:"ipv6,omitzero"`
}

// DatabaseSettings configures the shared SQLite database backing cache and zone.
type DatabaseSettings struct {
	DBPath      string `json:"db_path,omitzero"`       // database file path
	MMapSizeMB  int    `json:"mmap_size_mb,omitzero"`  // SQLite mmap_size PRAGMA
	CacheSizeMB int    `json:"cache_size_mb,omitzero"` // SQLite cache_size PRAGMA
}

// CacheSettings configures DNS response cache size and stale serving.
type CacheSettings struct {
	MaxEntries  int  `json:"max_entries,omitzero"`
	PreferStale bool `json:"prefer_stale,omitzero"`
}

// UpstreamServer defines a single upstream DNS server with address, protocol,
// and optional matching.
type UpstreamServer struct {
	Address       string   `json:"address"`
	Protocol      string   `json:"protocol,omitzero"`
	ServerName    string   `json:"server_name,omitzero"`
	SkipTLSVerify bool     `json:"skip_tls_verify,omitzero"`
	NoCache       bool     `json:"no_cache,omitzero"`
	Match         []string `json:"match,omitzero"`
	Proxy         string   `json:"proxy,omitzero"`
	PublicKey     string   `json:"public_key,omitzero"`
	PQDNSCrypt    *bool    `json:"pqdnscrypt,omitzero"` // prefer PQ DNSCrypt certs (default true)
}

// ZoneConfig wraps zone rules and global zone settings.
type ZoneConfig struct {
	Rules      []ZoneRule `json:"rules"`
	BypassTags []string   `json:"bypass_tags,omitzero"`
}

// ZoneRule defines a DNS zone rule for constructing synthetic responses.
// Matches on (QNAME, QTYPE, QCLASS) and returns ANSWER + AUTHORITY +
// ADDITIONAL + RCODE.  Client filtering uses CIDR match tags.
type ZoneRule struct {
	Name       string       `json:"name"`
	File       string       `json:"file,omitzero"`
	Match      []string     `json:"match,omitzero"`
	Rcode      int          `json:"rcode,omitzero"`
	Answer     []ZoneRecord `json:"answer,omitzero"`
	Authority  []ZoneRecord `json:"authority,omitzero"`
	Additional []ZoneRecord `json:"additional,omitzero"`

	// DynamicContent, when set, provides a function that returns TXT record
	// values at query time (e.g. for stats / db clear operations).
	DynamicContent func() []string `json:"-"`
}

// ZoneRecord defines a single DNS resource record for zone responses.
// Type and Class are numeric (IANA-registered values), enabling zero-allocation
// lookup and forward compatibility with new DNS types.
type ZoneRecord struct {
	Name    string `json:"name,omitzero"`
	Type    uint16 `json:"type"`
	Class   uint16 `json:"class,omitzero"`
	TTL     uint32 `json:"ttl,omitzero"`
	Content string `json:"content"`
}

// RuleSet defines a tag-bearing rule that can match by client IP (CIDR),
// query domain (suffix), or both. Files contain one entry per line (# comments).
type RuleSet struct {
	Tag  string   `json:"tag"`
	Type string   `json:"type"`
	Rule []string `json:"rule,omitzero"`
	File string   `json:"file,omitzero"`
}

// LatencyProbeStep defines a single latency probe step with protocol, port,
// and timeout.
type LatencyProbeStep struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port,omitzero"`
	Timeout  int    `json:"timeout,omitzero"`
}

// DNSCryptV2Prefix is the provider name prefix for DNSCrypt v2 certificates.
const DNSCryptV2Prefix = "2.dnscrypt-cert."

// IsEnabled reports whether DNSCrypt identity keys are configured.  Keys are
// auto-generated when empty, so this is always true when the dnscrypt cert
// block is present in config.
func (d *DNSCryptCertificate) IsEnabled() bool {
	return d.PublicKey != "" || d.PrivateKey != ""
}

// ProviderName returns the DNSCrypt v2 provider name derived from the DDR
// domain (e.g. "2.dnscrypt-cert.example.com").
func (d *DNSCryptCertificate) ProviderName(domain string) string {
	return DNSCryptV2Prefix + domain
}

// IsEnabled reports whether the TLCP certificate material is configured.
func (t *TLCPCertificate) IsEnabled() bool {
	return t.SelfSigned || (t.SignCertFile != "" && t.SignKeyFile != "" && t.EncCertFile != "" && t.EncKeyFile != "")
}

// IsEnabled reports whether the TLS certificate material is configured.
func (t *TLSCertificate) IsEnabled() bool {
	return t.SelfSigned || (t.CertFile != "" && t.KeyFile != "")
}

// IsRecursive reports whether the upstream server is the built-in recursive
// resolver.
func (s *UpstreamServer) IsRecursive() bool {
	if s == nil {
		return false
	}
	return s.Address == RecursiveIndicator
}
