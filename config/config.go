// Package config provides configuration types, loading, generation, and validation.
package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"zjdns/internal/log"
	zstamp "zjdns/internal/stamp"

	"codeberg.org/miekg/dns"
)

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
	DTLS     string        `json:"dtls,omitzero"`
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
	ESVersion  string `json:"es_version,omitzero"`  // "xwingpq" (default) or "xchacha20poly1305"
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
	Protocol      string   `json:"protocol"`
	ServerName    string   `json:"server_name,omitzero"`
	SkipTLSVerify bool     `json:"skip_tls_verify,omitzero"`
	NoCache       bool     `json:"no_cache,omitzero"`
	Match         []string `json:"match,omitzero"`
	Proxy         string   `json:"proxy,omitzero"`
	PublicKey     string   `json:"public_key,omitzero"`
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

	NormalizedName   string          `json:"-"`
	CachedAnswer     []dns.RR        `json:"-"`
	CachedAuthority  []dns.RR        `json:"-"`
	CachedAdditional []dns.RR        `json:"-"`
	DynamicContent   func() []string `json:"-"`
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

// LoadConfig reads, parses, validates, and enriches the configuration from a
// JSON file.
func LoadConfig(configFile string) (*ServerConfig, error) {
	if configFile == "" {
		return NewDefaultServerConfig(), nil
	}

	data, err := os.ReadFile(configFile) //nolint:gosec // G304: config file path from user
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	// Warn if config file has group/other read permissions — it may contain
	// SOCKS5 proxy credentials and other sensitive values.
	if info, err := os.Stat(configFile); err == nil {
		if info.Mode().Perm()&GroupOtherPermMask != 0 {
			log.Warnf("CONFIG: config file has insecure permissions (%04o). Consider 'chmod 600 %s'",
				info.Mode().Perm(), configFile)
		}
	}

	cfg := &ServerConfig{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := validateConfig(cfg); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	if err := normalizeStamps(cfg); err != nil {
		return nil, fmt.Errorf("normalize stamps: %w", err)
	}

	if shouldEnableDDR(cfg) {
		addDDRRecords(cfg)
	}

	addChaosRecord(cfg)

	log.Infof("CONFIG: Configuration loaded successfully")
	return cfg, nil
}

// NewDefaultServerConfig returns a ServerConfig with sensible defaults.
func NewDefaultServerConfig() *ServerConfig {
	cfg := &ServerConfig{}
	cfg.Server.LogLevel = log.DefaultLevel

	cfg.Server.Protocol.UDP = DefaultUDPPort
	cfg.Server.Protocol.TCP = DefaultTCPPort
	cfg.Server.Protocol.TLS = DefaultTLSPort
	cfg.Server.Protocol.QUIC = DefaultQUICPort
	cfg.Server.Protocol.HTTPS = HTTPSEndpoint{Port: DefaultHTTPSPort, Endpoint: DefaultQueryPath}
	cfg.Server.Protocol.HTTP3 = HTTPSEndpoint{Port: DefaultHTTP3Port, Endpoint: DefaultQueryPath}

	cfg.Server.Certificate.Domain = "dns.example.com"
	cfg.Server.Features.DDR = DDRSettings{IPv4: "127.0.0.1", IPv6: "::1"}
	cfg.Server.Features.ECS = ECSConfig{IPv4: "auto", IPv6: "auto", PreferIPv4: true}
	cfg.Server.Features.DNSSECEnforce = true
	cfg.Server.Features.HijackProtection = true

	return cfg
}

// normalizeStamps resolves sdns:// addresses in upstream and fallback server
// configs, populating protocol, address, server_name, and public_key from the
// stamp.  Servers without an sdns:// address are left unchanged.
func normalizeStamps(cfg *ServerConfig) error {
	for i := range cfg.Upstream {
		if err := resolveStamp(&cfg.Upstream[i], i, "upstream"); err != nil {
			return err
		}
	}
	for i := range cfg.Fallback {
		if err := resolveStamp(&cfg.Fallback[i], i, "fallback"); err != nil {
			return err
		}
	}
	return nil
}

// resolveStamp parses an sdns:// stamp and populates missing fields on the
// UpstreamServer.  Non-stamp addresses are left unchanged.
func resolveStamp(server *UpstreamServer, index int, category string) error {
	if !strings.HasPrefix(server.Address, "sdns://") {
		return nil
	}

	s, err := zstamp.Parse(server.Address)
	if err != nil {
		return fmt.Errorf("%s server %d stamp parse failed: %w", category, index, err)
	}

	// Protocol: if not explicitly set, infer from stamp.
	stampProto := zstamp.ProtoToConfig(s.Proto)
	if server.Protocol == "" {
		server.Protocol = stampProto
	} else if !protocolMatchesStamp(server.Protocol, s.Proto) {
		return fmt.Errorf(
			"%s server %d: explicit protocol %q does not match stamp protocol %s",
			category, index, server.Protocol, stampProto,
		)
	}

	// Address: for DoH, reconstruct the full URL from stamp fields.
	switch s.Proto {
	case zstamp.ProtoDOH:
		server.Address = buildDOHURL(s)
	default:
		server.Address = s.Address
	}

	// ServerName: use stamp's ProviderName only if not explicitly set.
	if server.ServerName == "" && s.ProviderName != "" {
		server.ServerName = s.ProviderName
	}

	// PublicKey: for DNSCrypt, populate from stamp if not explicitly set.
	if s.Proto == zstamp.ProtoDNSCrypt {
		if server.PublicKey == "" && len(s.PublicKey) > 0 {
			server.PublicKey = hexEncodePublicKey(s.PublicKey)
		}
	}

	return nil
}

// protocolMatchesStamp checks whether the user-specified protocol string is
// compatible with the stamp's protocol ID.
func protocolMatchesStamp(userProto string, stampProto zstamp.StampProtoType) bool {
	switch stampProto {
	case zstamp.ProtoPlain:
		return userProto == ProtoUDP || userProto == ProtoTCP
	case zstamp.ProtoDNSCrypt:
		return userProto == ProtoDNSCrypt || userProto == ProtoDNSCryptTCP
	case zstamp.ProtoDOH:
		return userProto == ProtoDOH || userProto == ProtoHTTP
	case zstamp.ProtoDOT:
		return userProto == ProtoDOT || userProto == ProtoTLS
	case zstamp.ProtoDOQ:
		return userProto == ProtoDOQ || userProto == ProtoQUIC
	case zstamp.ProtoODoHTarget, zstamp.ProtoDNSCryptRelay, zstamp.ProtoODoHRelay:
		// These stamp types have no direct config protocol — always accept.
		return true
	default:
		return false
	}
}

// buildDOHURL constructs the full DoH URL from a stamp's fields.
// Stamp address is host:port; host_name is SNI; path is the HTTP endpoint.
func buildDOHURL(s *zstamp.Stamp) string {
	host, port, err := net.SplitHostPort(s.Address)
	if err != nil {
		// Fallback: use address as-is (shouldn't happen for valid stamps).
		return "https://" + s.Address + "/dns-query"
	}
	if s.ProviderName != "" {
		host = s.ProviderName
	}
	path := s.Path
	if path == "" {
		path = "/dns-query"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return "https://" + net.JoinHostPort(host, port) + path
}

// hexEncodePublicKey encodes a DNSCrypt Ed25519 public key as an uppercase hex
// string, matching the format used in server/dnscrypt for consistency.
func hexEncodePublicKey(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b) * 2)
	for _, v := range b {
		fmt.Fprintf(&sb, "%02X", v)
	}
	return sb.String()
}

func shouldEnableDDR(cfg *ServerConfig) bool {
	ddr := cfg.Server.Features.DDR
	return cfg.Server.Certificate.Domain != "" &&
		(ddr.IPv4 != "" || ddr.IPv6 != "")
}

func addDDRRecords(cfg *ServerConfig) {
	ddr := cfg.Server.Features.DDR
	domain := strings.TrimSuffix(cfg.Server.Certificate.Domain, ".")

	if strings.ContainsAny(domain, " \"") || strings.ContainsAny(ddr.IPv4, " \"") || strings.ContainsAny(ddr.IPv6, " \"") {
		log.Warnf("CONFIG: DDR domain/IP contains unsafe characters, DDR records will not be added")
		return
	}
	if domain == "" {
		log.Warnf("CONFIG: DDR domain is empty, DDR records will not be added")
		return
	}
	endpoint := cfg.Server.Protocol.HTTPS.Endpoint
	if endpoint == "" {
		endpoint = DefaultQueryPath
	}
	if !strings.HasPrefix(endpoint, "/") {
		endpoint = "/" + endpoint
	}
	dohPath := "dohpath=\"" + endpoint + "{?dns}\""

	// Zone equivalents.
	zoneDirectRecords := make([]ZoneRecord, 0, 2)
	if ddr.IPv4 != "" {
		zoneDirectRecords = append(zoneDirectRecords, ZoneRecord{Type: dns.TypeA, Content: ddr.IPv4})
	}
	if ddr.IPv6 != "" {
		zoneDirectRecords = append(zoneDirectRecords, ZoneRecord{Type: dns.TypeAAAA, Content: ddr.IPv6})
	}
	if len(zoneDirectRecords) > 0 {
		cfg.Zone.Rules = append(cfg.Zone.Rules, ZoneRule{Name: domain, Answer: zoneDirectRecords})
	}

	ddrNames := []string{"_dns.resolver.arpa", "_dns." + domain}
	if cfg.Server.Protocol.UDP != "" && cfg.Server.Protocol.UDP != DefaultUDPPort {
		ddrNames = append(ddrNames, "_"+cfg.Server.Protocol.UDP+"._dns."+domain)
	}

	// Build zone SVCB records.
	dohPort := cfg.Server.Protocol.HTTPS.Port
	if dohPort == "" {
		dohPort = cfg.Server.Protocol.HTTP3.Port
	}
	dotPort := cfg.Server.Protocol.TLS
	if dotPort == "" {
		dotPort = cfg.Server.Protocol.QUIC
	}
	zoneServiceRecords := make([]ZoneRecord, 2)
	zoneServiceRecords[0] = ZoneRecord{Type: dns.TypeSVCB, Content: "1 . alpn=h3,h2 port=" + dohPort + " " + dohPath}
	zoneServiceRecords[1] = ZoneRecord{Type: dns.TypeSVCB, Content: "2 . alpn=doq,dot port=" + dotPort}
	var zoneAdditional []ZoneRecord
	if ddr.IPv4 != "" {
		for i := range zoneServiceRecords {
			zoneServiceRecords[i].Content += " ipv4hint=" + ddr.IPv4
		}
		zoneAdditional = append(zoneAdditional, ZoneRecord{Name: domain, Type: dns.TypeA, Content: ddr.IPv4})
	}
	if ddr.IPv6 != "" {
		for i := range zoneServiceRecords {
			zoneServiceRecords[i].Content += " ipv6hint=" + ddr.IPv6
		}
		zoneAdditional = append(zoneAdditional, ZoneRecord{Name: domain, Type: dns.TypeAAAA, Content: ddr.IPv6})
	}

	for _, name := range ddrNames {
		cfg.Zone.Rules = append(cfg.Zone.Rules, ZoneRule{Name: name, Answer: zoneServiceRecords, Additional: zoneAdditional})
	}

	log.Infof("CONFIG: DDR enabled for domain %s (IPv4: %s, IPv6: %s)",
		domain, ddr.IPv4, ddr.IPv6)
}

func addChaosRecord(cfg *ServerConfig) {
	version := DefaultVersion
	if version == "" || version == "dev" {
		version = DefaultProjectName
	}
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = DefaultProjectName
	}
	chaosRecords := map[string]string{
		"id.server":      hostname,
		"hostname.bind":  hostname,
		"version.server": version,
		"version.bind":   version,
	}
	for name, value := range chaosRecords {
		cfg.Zone.Rules = append(cfg.Zone.Rules, ZoneRule{
			Name: name,
			Answer: []ZoneRecord{{
				Type:    dns.TypeTXT,
				Class:   dns.ClassCHAOS,
				TTL:     DefaultTTL,
				Content: strconv.Quote(value),
			}},
		})
	}
	for _, name := range []string{
		DefaultProjectName + ".stats",
		DefaultProjectName + ".db.clear",
		DefaultProjectName + ".db.clear.cache",
		DefaultProjectName + ".db.clear.stats",
		DefaultProjectName + ".db.clear.latency",
		DefaultProjectName + ".db.clear.zone",
		DefaultProjectName + ".db.clear.ruleset",
	} {
		cfg.Zone.Rules = append(cfg.Zone.Rules, ZoneRule{
			Name:   name,
			Answer: []ZoneRecord{{Type: dns.TypeTXT, Class: dns.ClassCHAOS, TTL: 0, Content: ""}},
		})
	}
}
