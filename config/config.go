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

	"codeberg.org/miekg/dns"
)

// ServerConfig is the top-level configuration structure for the DNS server.
type ServerConfig struct {
	Server   ServerSettings   `json:"server"`
	Upstream []UpstreamServer `json:"upstream"`
	Fallback []UpstreamServer `json:"fallback,omitempty"`
	Rewrite  []RewriteRule    `json:"rewrite"`
	CIDR     []CIDRConfig     `json:"cidr"`
}

// ServerSettings contains the server runtime settings and feature flags.
type ServerSettings struct {
	Port     string           `json:"port"`
	Pprof    string           `json:"pprof"`
	LogLevel string           `json:"log_level"`
	TLS      TLSSettings      `json:"tls"`
	DNSCrypt DNSCryptSettings `json:"dnscrypt,omitempty"`
	Features FeatureFlags     `json:"features"`
}

// DNSCryptSettings configures the DNSCrypt v2 encrypted DNS listener.
type DNSCryptSettings struct {
	Port         string `json:"port"`               // default "8443"
	ProviderName string `json:"provider_name"`      // e.g. "2.dnscrypt-cert.example.com"
	PrivateKey   string `json:"private_key"`        // Ed25519 private key (hex, optional)
	PublicKey    string `json:"public_key"`         // Ed25519 public key (hex, optional)
	ResolverSk   string `json:"resolver_sk"`        // X25519 short-term secret (hex, optional)
	ResolverPk   string `json:"resolver_pk"`        // X25519 short-term public (hex, optional)
	ESVersion    string `json:"es_version"`         // "xsalsa20poly1305" or "xchacha20poly1305"
	CertTTL      string `json:"cert_ttl,omitempty"` // e.g. "720h", "30d"; empty defaults to 365 days
}

// IsEnabled reports whether DNSCrypt is configured.  An empty DNSCryptSettings
// block means DNSCrypt is disabled.
func (d *DNSCryptSettings) IsEnabled() bool {
	return d.ProviderName != "" || d.PublicKey != "" || d.PrivateKey != ""
}

// TLSSettings configures TLS listener ports, certificates, and HTTPS settings.
type TLSSettings struct {
	Port       string        `json:"port"`
	CertFile   string        `json:"cert_file"`
	KeyFile    string        `json:"key_file"`
	SelfSigned bool          `json:"self_signed"`
	HTTPS      HTTPSSettings `json:"https"`
	KTLS       *KTLSSettings `json:"ktls,omitempty"`
}

// HTTPSSettings configures the HTTPS (DoH/DoH3) listener port and endpoint.
type HTTPSSettings struct {
	Port     string `json:"port"`
	Endpoint string `json:"endpoint"`
}

// KTLSSettings configures kernel TLS offload for DoT/DoH server listeners.
type KTLSSettings struct {
	KernelTX bool `json:"kernel_tx"` // kernel TLS TX offload (default false)
	KernelRX bool `json:"kernel_rx"` // kernel TLS RX offload (default false)
}

// FeatureFlags enables optional features: hijack protection, DDR, ECS, cache,
// latency probes, and stats.
type FeatureFlags struct {
	HijackProtection bool               `json:"hijack_protection"`
	DNSSECEnforce    bool               `json:"dnssec_enforce,omitempty"`
	DDR              DDRSettings        `json:"ddr,omitempty"`
	ECS              ECSConfig          `json:"ecs_subnet,omitempty"`
	Cache            CacheSettings      `json:"cache,omitempty"`
	LatencyProbe     []LatencyProbeStep `json:"latency_probe,omitempty"`
}

// DDRSettings configures Discovery of Designated Resolvers (DDR) advertisement.
type DDRSettings struct {
	Domain string `json:"domain"`
	IPv4   string `json:"ipv4"`
	IPv6   string `json:"ipv6"`
}

// CacheSettings configures DNS response cache size, persistence, and stale serving.
type CacheSettings struct {
	MaxEntries  int    `json:"max_entries,omitempty"`
	MMapSizeMB  int    `json:"mmap_size_mb,omitempty"`
	CacheSizeMB int    `json:"cache_size_mb,omitempty"`
	DBPath      string `json:"db_path,omitempty"`
	PreferStale bool   `json:"prefer_stale,omitempty"`
}

// UpstreamServer defines a single upstream DNS server with address, protocol,
// and optional matching.
type UpstreamServer struct {
	Address       string   `json:"address"`
	Protocol      string   `json:"protocol"`
	ServerName    string   `json:"server_name,omitempty"`
	SkipTLSVerify bool     `json:"skip_tls_verify,omitempty"`
	NoCache       bool     `json:"no_cache,omitempty"`
	Match         []string `json:"match,omitempty"`
	Proxy         string   `json:"proxy,omitempty"`      // socks5://[user:pass@]host:port
	PublicKey     string   `json:"public_key,omitempty"` // DNSCrypt resolver public key (hex); provider name uses server_name
}

// RewriteRule defines a DNS rewrite rule with synthetic response, client
// filtering, and record lists.
type RewriteRule struct {
	Name               string            `json:"name"`
	NormalizedName     string            `json:"normalized_name,omitempty"`
	ResponseCode       *int              `json:"response_code,omitempty"`
	Records            []DNSRecordConfig `json:"records,omitempty"`
	Additional         []DNSRecordConfig `json:"additional,omitempty"`
	ExcludeClients     []string          `json:"exclude_clients,omitempty"`
	IncludeClients     []string          `json:"include_clients,omitempty"`
	ExcludeClientCIDRs []*net.IPNet      `json:"-"`
	IncludeClientCIDRs []*net.IPNet      `json:"-"`
	CachedRecords      []dns.RR          `json:"-"`
	CachedAdditional   []dns.RR          `json:"-"`
	DynamicContent     func() []string   `json:"-"`
}

// DNSRecordConfig defines a single DNS resource record for rewrite responses.
type DNSRecordConfig struct {
	Name         string `json:"name,omitempty"`
	Type         string `json:"type"`
	Class        string `json:"class,omitempty"`
	TTL          uint32 `json:"ttl,omitempty"`
	Content      string `json:"content"`
	ResponseCode *int   `json:"response_code,omitempty"`

	// Pre-parsed during LoadRules to avoid string-to-uint16 lookups
	// and string normalizations on the query hot path.
	ParsedType  uint16
	ParsedClass uint16
}

// CIDRConfig defines a CIDR rule set loaded from a file or inline rules,
// associated with a tag.
type CIDRConfig struct {
	File  string   `json:"file,omitempty"`
	Rules []string `json:"rules,omitempty"`
	Tag   string   `json:"tag"`
}

// LatencyProbeStep defines a single latency probe step with protocol, port,
// and timeout.
type LatencyProbeStep struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port,omitempty"`
	Timeout  int    `json:"timeout,omitempty"`
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

	cfg.Server.Port = DefaultDNSPort

	cfg.Server.TLS.Port = DefaultDOTPort
	cfg.Server.TLS.HTTPS.Port = DefaultDOHPort
	cfg.Server.TLS.HTTPS.Endpoint = DefaultQueryPath

	cfg.Server.Features.DDR = DDRSettings{Domain: "dns.example.com", IPv4: "127.0.0.1", IPv6: "::1"}
	cfg.Server.Features.ECS = ECSConfig{IPv4: "auto", IPv6: "auto", PreferIPv4: true}
	cfg.Server.Features.DNSSECEnforce = true
	cfg.Server.Features.HijackProtection = true

	return cfg
}

func shouldEnableDDR(cfg *ServerConfig) bool {
	ddr := cfg.Server.Features.DDR
	return ddr.Domain != "" &&
		(ddr.IPv4 != "" || ddr.IPv6 != "")
}

func addDDRRecords(cfg *ServerConfig) {
	ddr := cfg.Server.Features.DDR

	if strings.ContainsAny(ddr.Domain, " \"") || strings.ContainsAny(ddr.IPv4, " \"") || strings.ContainsAny(ddr.IPv6, " \"") {
		log.Warnf("CONFIG: DDR domain/IP contains unsafe characters, DDR records will not be added")
		return
	}
	if ddr.Domain == "" {
		log.Warnf("CONFIG: DDR domain is empty, DDR records will not be added")
		return
	}
	domain := strings.TrimSuffix(ddr.Domain, ".")
	nxdomainCode := dns.RcodeNameError

	endpoint := cfg.Server.TLS.HTTPS.Endpoint
	if endpoint == "" {
		endpoint = DefaultQueryPath
	}
	if !strings.HasPrefix(endpoint, "/") {
		endpoint = "/" + endpoint
	}
	dohPath := "dohpath=\"" + endpoint + "{?dns}\""

	serviceRecords := []DNSRecordConfig{
		{Type: "SVCB", Content: "1 . alpn=h3,h2 port=" + cfg.Server.TLS.HTTPS.Port + " " + dohPath},
		{Type: "SVCB", Content: "2 . alpn=doq,dot port=" + cfg.Server.TLS.Port},
	}

	var additionalRecords []DNSRecordConfig
	var directRecords []DNSRecordConfig

	if ddr.IPv4 != "" {
		for i := range serviceRecords {
			serviceRecords[i].Content += " ipv4hint=" + ddr.IPv4
		}
		additionalRecords = append(additionalRecords, DNSRecordConfig{
			Name: domain, Type: "A", Content: ddr.IPv4,
		})
		directRecords = append(directRecords, DNSRecordConfig{
			Type: "A", Content: ddr.IPv4,
		})
	} else {
		directRecords = append(directRecords, DNSRecordConfig{
			Type: "A", ResponseCode: &nxdomainCode,
		})
	}

	if ddr.IPv6 != "" {
		for i := range serviceRecords {
			serviceRecords[i].Content += " ipv6hint=" + ddr.IPv6
		}
		additionalRecords = append(additionalRecords, DNSRecordConfig{
			Name: domain, Type: "AAAA", Content: ddr.IPv6,
		})
		directRecords = append(directRecords, DNSRecordConfig{
			Type: "AAAA", Content: ddr.IPv6,
		})
	} else {
		directRecords = append(directRecords, DNSRecordConfig{
			Type: "AAAA", ResponseCode: &nxdomainCode,
		})
	}

	cfg.Rewrite = append(cfg.Rewrite, RewriteRule{
		Name:    domain,
		Records: directRecords,
	})

	ddrNames := []string{"_dns.resolver.arpa", "_dns." + domain}
	if cfg.Server.Port != "" && cfg.Server.Port != DefaultDNSPort {
		ddrNames = append(ddrNames, "_"+cfg.Server.Port+"._dns."+domain)
	}

	for _, name := range ddrNames {
		cfg.Rewrite = append(cfg.Rewrite, RewriteRule{
			Name:       name,
			Records:    serviceRecords,
			Additional: additionalRecords,
		})
	}

	log.Infof("CONFIG: DDR enabled for domain %s (IPv4: %s, IPv6: %s)",
		domain, ddr.IPv4, ddr.IPv6)
}

func addChaosRecord(cfg *ServerConfig) {
	// version.server / version.bind expose the real server version by design —
	// config.Version is set by main.go from getVersion() before LoadConfig runs.
	// this helps operators identify which ZJDNS instance is serving a query.
	version := Version
	if version == "" || version == "dev" {
		version = ProjectName
	}

	// id.server / hostname.bind try the system hostname first; fall back to
	// ProjectName when the hostname cannot be determined.
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = ProjectName
	}

	chaosRecords := map[string]string{
		"id.server":      hostname,
		"hostname.bind":  hostname,
		"version.server": version,
		"version.bind":   version,
	}

	for name, value := range chaosRecords {
		cfg.Rewrite = append(cfg.Rewrite, RewriteRule{
			Name: name,
			Records: []DNSRecordConfig{{
				Type:    "TXT",
				Class:   "CH",
				TTL:     DefaultTTL,
				Content: strconv.Quote(value),
			}},
		})
	}

	// DynamicContent rules — populated at query time by server.New().
	// Destructive (db.clear*) rules are loopback-only.
	for _, name := range []string{
		ProjectName + ".stats",
		ProjectName + ".db.clear",
		ProjectName + ".db.clear.cache",
		ProjectName + ".db.clear.stats",
		ProjectName + ".db.clear.latency",
	} {
		var includeClients []string
		if strings.HasPrefix(name, ProjectName+".db.") {
			includeClients = []string{"127.0.0.1", "::1"}
		}
		cfg.Rewrite = append(cfg.Rewrite, RewriteRule{
			Name:           name,
			IncludeClients: includeClients,
			Records: []DNSRecordConfig{{
				Type:    "TXT",
				Class:   "CH",
				TTL:     0,
				Content: "",
			}},
		})
	}
}

// GenerateExampleConfig returns a complete example configuration as indented
// JSON.
func GenerateExampleConfig() string {
	cfg := NewDefaultServerConfig()

	cfg.Server.Pprof = DefaultPprofPort
	cfg.Server.LogLevel = log.DefaultLevel

	cfg.Server.TLS.CertFile = "/path/to/cert.pem"
	cfg.Server.TLS.KeyFile = "/path/to/key.pem"

	cfg.Server.TLS.KTLS = &KTLSSettings{KernelTX: true}

	cfg.Server.DNSCrypt = DNSCryptSettings{
		Port:         DefaultDNSCryptPort,
		ProviderName: "2.dnscrypt-cert.example.com",
		PublicKey:    "26B75000A825A6F6965C530024499E3FA119AF32CD7F9395C33A0AF8373DD142",
		PrivateKey:   "2BB45162041FBCAEE142CA5C100B050491A37DF6600DD13DBAA149FAB566387E26B75000A825A6F6965C530024499E3FA119AF32CD7F9395C33A0AF8373DD142",
		ResolverSk:   "93D6E7A4D65D62CD1F484D228EE4B6CEB0510A2D20C2FC0F5105CFEA9717C2CE",
		ResolverPk:   "4153FB871A95823475F06DA35BCA1F4FB62D60348DF061382A346730F45C334A",
		ESVersion:    "xsalsa20poly1305",
	}

	cfg.Server.Features.Cache.MaxEntries = DefaultMaxCacheEntries
	cfg.Server.Features.Cache.MMapSizeMB = DefaultCacheMMapSizeMB
	cfg.Server.Features.Cache.CacheSizeMB = DefaultCacheCacheSizeMB
	cfg.Server.Features.Cache.PreferStale = true
	cfg.Server.Features.Cache.DBPath = "cache.db"
	cfg.Server.Features.ECS = ECSConfig{IPv4: "auto", IPv6: "auto", PreferIPv4: true}
	cfg.Server.Features.LatencyProbe = []LatencyProbeStep{
		{Protocol: ProtoPing, Timeout: int(DefaultLatencyProbeTimeout.Milliseconds())},
		{Protocol: ProtoTCP, Port: DefaultProbePortHTTPS, Timeout: int(DefaultLatencyProbeTimeout.Milliseconds())},
		{Protocol: ProtoTCP, Port: DefaultProbePortHTTP, Timeout: int(DefaultLatencyProbeTimeout.Milliseconds())},
		{Protocol: ProtoUDP, Port: DefaultProbePortDNS, Timeout: int(DefaultLatencyProbeTimeout.Milliseconds())},
		{Protocol: ProtoHTTPPlain, Port: DefaultProbePortHTTP, Timeout: int(DefaultLatencyProbeTimeout.Milliseconds())},
		{Protocol: ProtoHTTP, Port: DefaultProbePortHTTPS, Timeout: int(DefaultLatencyProbeTimeout.Milliseconds())},
		{Protocol: ProtoHTTP3, Port: DefaultProbePortHTTPS, Timeout: int(DefaultLatencyProbeTimeout.Milliseconds())},
	}
	cfg.Upstream = []UpstreamServer{
		{Address: "223.5.5.5:53", Protocol: ProtoTCP, Proxy: "socks5://127.0.0.1:1080"},
		{Address: "223.6.6.6:53", Protocol: ProtoUDP},
		{Address: "223.5.5.5:853", Protocol: ProtoTLS, ServerName: "dns.alidns.com"},
		{Address: "223.6.6.6:853", Protocol: ProtoQUIC, ServerName: "dns.alidns.com", SkipTLSVerify: true},
		{Address: "https://223.5.5.5:443/dns-query", Protocol: ProtoHTTP, ServerName: "dns.alidns.com", Match: []string{"mixed"}},
		{Address: "https://223.6.6.6:443/dns-query", Protocol: ProtoHTTP3, ServerName: "dns.alidns.com", Match: []string{"!mixed"}},
	}

	cfg.Fallback = []UpstreamServer{
		{Address: RecursiveIndicator},
		{Address: "sdns://AQMAAAAAAAAADDkuOS45Ljk6ODQ0MyBnyEe4yHWM0SAkVUO-dWdG3zTfHYTAC4xHA2jfgh2GPhkyLmRuc2NyeXB0LWNlcnQucXVhZDkubmV0", Protocol: ProtoDNSCrypt},
		{Address: "149.112.112.9:53", Protocol: ProtoUDP, NoCache: true},
	}

	cfg.Rewrite = []RewriteRule{
		{ExcludeClients: []string{"10.0.0.100"}},
		{Name: "client-specific.example.com", IncludeClients: []string{"192.168.0.0/24"}, Records: []DNSRecordConfig{{Type: "A", Content: "127.0.0.1", TTL: DefaultTTL}}},
		{Name: "blocked.example.com", ExcludeClients: []string{"192.168.1.0/24"}, Records: []DNSRecordConfig{{Type: "A", Content: "127.0.0.1", TTL: DefaultTTL}}},
		{Name: "ipv6.blocked.example.com", Records: []DNSRecordConfig{{Type: "AAAA", Content: "::1", TTL: DefaultTTL}}},
	}

	cfg.CIDR = []CIDRConfig{
		{File: "whitelist.txt", Tag: "file"},
		{Rules: []string{"192.168.0.0/16", "10.0.0.0/8", "2001:db8::/32"}, Tag: "rules"},
		{File: "blacklist.txt", Rules: []string{"127.0.0.1/32"}, Tag: "mixed"},
	}

	data, _ := json.MarshalIndent(cfg, "", "  ")
	return string(data)
}
