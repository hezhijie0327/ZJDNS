// Package config provides configuration types.
package config

import "net"

// ServerConfig is the top-level configuration structure for the DNS server.
type ServerConfig struct {
	Server   ServerSettings   `json:"server"`
	Upstream []UpstreamServer `json:"upstream,omitzero"`
	Zone     []ZoneRule       `json:"zone,omitzero"`
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
	DTLS     string        `json:"dtls,omitzero"`
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
	// StateFile persists the DNSCrypt identity + cert windows across
	// restarts.  Empty (default) disables persistence — no file is created,
	// cert windows are re-minted on every restart.
	StateFile string `json:"state_file,omitzero"`
}

// FeatureFlags enables optional features: KTLS, DDR, ECS,
// cache, latency probes, and stats.
type FeatureFlags struct {
	KTLS          *KTLSSettings `json:"ktls,omitzero"`
	DNSSECEnforce bool          `json:"dnssec_enforce,omitzero"`
	// AddressFamily restricts recursive fan-out to one address family:
	// "dual" (default, empty) keeps both, "ipv4" drops IPv6 addresses,
	// "ipv6" drops IPv4 addresses.  Explicit operator choice — no runtime
	// reachability probing.
	AddressFamily string             `json:"address_family,omitzero"`
	DDR           DDRSettings        `json:"ddr,omitzero"`
	ECS           ECSConfig          `json:"ecs_subnet,omitzero"`
	Cache         CacheSettings      `json:"cache,omitzero"`
	LatencyProbe  []LatencyProbeStep `json:"latency_probe,omitzero"`
	DNS64         *DNS64Config       `json:"dns64,omitzero"`
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
// The server domain is in certificate.domain.  DDR also publishes RFC 9606
// RESINFO records for resolver.arpa (+ the DDR domain).
type DDRSettings struct {
	IPv4 string `json:"ipv4,omitzero"`
	IPv6 string `json:"ipv6,omitzero"`
	// InfoURL is the optional RFC 9606 infourl key: an https diagnostic page
	// URL advertised in the RESINFO record.
	InfoURL string `json:"infourl,omitzero"`
}

// CacheSettings configures DNS response cache size and stale serving.
// CacheSettings configures the cache subsystem's three stores (entries,
// latency, delegation), each with its own limit and persistence.
type CacheSettings struct {
	Entries    CacheStoreSettings `json:"entries,omitzero"`
	Latency    CacheStoreSettings `json:"latency,omitzero"`
	Delegation CacheStoreSettings `json:"delegation,omitzero"`
}

// CacheStoreSettings bounds and persists one cache-store: a two-tier limit
// (in-memory + disk spill) and state_file (empty = not persisted, no spill
// tier).  PreferStale is entries-only — it is ignored by latency/delegation.
type CacheStoreSettings struct {
	Limit       LimitSettings `json:"limit,omitzero"`
	PreferStale bool          `json:"prefer_stale,omitzero"`
	StateFile   string        `json:"state_file,omitzero"`
}

// LimitSettings defines the two-tier capacity in entries.  Mem bounds the
// in-memory LRU (<= 0 applies the store default); Disk bounds the spill
// file records (<= 0 = unbounded).  The disk tier is only active when
// StateFile is non-empty.
type LimitSettings struct {
	Mem  int `json:"mem,omitzero"`
	Disk int `json:"disk,omitzero"`
}

// UpstreamServer defines a single upstream DNS server with address, protocol,
// and optional matching.
type UpstreamServer struct {
	Address        string `json:"address,omitzero"`
	Protocol       string `json:"protocol,omitzero"`
	ServerName     string `json:"server_name,omitzero"`
	SkipTLSVerify  bool   `json:"skip_tls_verify,omitzero"`
	PrivacyProfile string `json:"privacy_profile,omitzero"` // "strict" (RFC 8310 §6) or "opportunistic" (§5)
	SkipCache      bool   `json:"skip_cache,omitzero"`
	// Fallback marks the server as a fallback upstream: it races every
	// primary at t=0 but its result is only adopted when no primary has
	// answered within DefaultFallbackTimeout.  Fallback results are never
	// cached and carry the ZJDNS-private fallback EDE (edns.EDEZJDNSFallback)
	// so downstream ZJDNS instances refuse to cache them too.  At least one
	// non-fallback upstream is required when any fallback is configured.
	Fallback      bool     `json:"fallback,omitzero"`
	Match         []string `json:"match,omitzero"`
	Proxy         string   `json:"proxy,omitzero"`
	PublicKey     string   `json:"public_key,omitzero"`
	PQDNSCrypt    *bool    `json:"pqdnscrypt,omitzero"`     // prefer PQ DNSCrypt certs (default true)
	EphemeralKeys *bool    `json:"ephemeral_keys,omitzero"` // per-query X25519 keys for forward secrecy (default true)
	Poisonguard   bool     `json:"poisonguard,omitzero"`
	Spoofguard    bool     `json:"spoofguard,omitzero"`
	Splitguard    bool     `json:"splitguard,omitzero"`
	HopGuard      bool     `json:"hopguard,omitzero"`
	// CapsGuard randomizes the case bit of every ASCII letter in the outbound
	// question (DNS 0x20, draft-vixie-dnsext-dns0x20-00 §5.1) and discards
	// responses that do not echo the randomized case, retrying once with the
	// original case.  Works over every protocol.
	CapsGuard bool `json:"capsguard,omitzero"`
	// MQType lists the QTYPE values (numeric, e.g. [1, 28] for A and AAAA)
	// to bundle into queries via the RFC 10029 MQTYPE-Query EDNS option — an
	// A (1) query also asks for AAAA (28).  The primary QTYPE is excluded
	// automatically; empty (default) disables the option.
	MQType []uint16 `json:"mqtype,omitzero"`
}

// ZoneRule defines a DNS zone rule for constructing synthetic responses.
// Matches on (QNAME, QTYPE, QCLASS) and returns ANSWER + AUTHORITY +
// ADDITIONAL + RCODE.  Client filtering uses CIDR match tags.
type ZoneRule struct {
	Name       string       `json:"name,omitzero"`
	File       string       `json:"file,omitzero"`
	Match      []string     `json:"match,omitzero"`
	Rcode      int          `json:"rcode,omitzero"`
	Answer     []ZoneRecord `json:"answer,omitzero"`
	Authority  []ZoneRecord `json:"authority,omitzero"`
	Additional []ZoneRecord `json:"additional,omitzero"`

	// DynamicContent, when set, provides a function that returns TXT record
	// values at query time (e.g. for ZJDNS.stats / ZJDNS.whoami / db clear).
	// The client's source IP is passed for per-client data (whoami).
	DynamicContent func(clientIP net.IP) []string `json:"-"`
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

// CacheStateFile returns the entries store persistence path ("" = pure
// memory).
func (f *FeatureFlags) CacheStateFile() string { return f.Cache.Entries.StateFile }

// LatencyStateFile returns the latency store persistence path ("" = pure
// memory).
func (f *FeatureFlags) LatencyStateFile() string { return f.Cache.Latency.StateFile }

// DelegationStateFile returns the delegation store persistence path
// ("" = pure memory).
func (f *FeatureFlags) DelegationStateFile() string { return f.Cache.Delegation.StateFile }

// ProviderName returns the DNSCrypt v2 provider name derived from the DDR
// domain (e.g. "2.dnscrypt-cert.example.com").
func (d *DNSCryptCertificate) ProviderName(domain string) string {
	if domain == "" {
		return DNSCryptV2Prefix
	}
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
// resolver (Protocol = "recursive").
func (s *UpstreamServer) IsRecursive() bool {
	if s == nil {
		return false
	}
	return s.Protocol == ProtoRecursive
}
