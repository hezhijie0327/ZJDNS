// Package config provides configuration types, loading, generation, and validation.
package config

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"zjdns/edns"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"

	"github.com/miekg/dns"
)

// Default network ports and timeouts.
const (
	DefaultDNSPort   = "53"
	DefaultDOTPort   = "853"
	DefaultDOHPort   = "443"
	DefaultPprofPort = "6060"
	DefaultQueryPath = "/dns-query"

	DefaultCacheSize            = 4 * 1024 * 1024
	DefaultCachePersistInterval = 30 * time.Second
	DefaultTTL                  = 10

	DefaultLatencyProbeTimeout = 100 * time.Millisecond
	DefaultStatsPersistTTL     = 86400

	RecursiveIndicator = "builtin_recursive"

	MaxDomainLength = 253
	IdleTimeout     = 4 * time.Second
)

// ProjectName is the application name, set at build time.
var ProjectName = "ZJDNS"

// Version is the build version, set at build time via ldflags.
var Version = "dev"

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
	Port     string       `json:"port"`
	Pprof    string       `json:"pprof"`
	LogLevel string       `json:"log_level"`
	TLS      TLSSettings  `json:"tls"`
	Features FeatureFlags `json:"features"`

	MaxConcurrent int `json:"max_concurrent,omitempty"`
	RateLimit     int `json:"rate_limit,omitempty"`
	RateBurst     int `json:"rate_burst,omitempty"`
}

// TLSSettings configures TLS listener ports, certificates, and HTTPS settings.
type TLSSettings struct {
	Port       string        `json:"port"`
	CertFile   string        `json:"cert_file"`
	KeyFile    string        `json:"key_file"`
	SelfSigned bool          `json:"self_signed"`
	HTTPS      HTTPSSettings `json:"https"`
}

// HTTPSSettings configures the HTTPS (DoH/DoH3) listener port and endpoint.
type HTTPSSettings struct {
	Port     string `json:"port"`
	Endpoint string `json:"endpoint"`
}

// FeatureFlags enables optional features: hijack protection, DDR, ECS, cache,
// latency probes, and stats.
type FeatureFlags struct {
	HijackProtection bool                  `json:"hijack_protection"`
	DDR              DDRSettings           `json:"ddr,omitempty"`
	ECS              edns.DefaultECSConfig `json:"ecs_subnet,omitempty"`
	Cache            CacheSettings         `json:"cache,omitempty"`
	LatencyProbe     []LatencyProbeStep    `json:"latency_probe,omitempty"`
	Stats            *StatsSettings        `json:"stats,omitempty"`
}

// DDRSettings configures Discovery of Designated Resolvers (DDR) advertisement.
type DDRSettings struct {
	Domain string `json:"domain"`
	IPv4   string `json:"ipv4"`
	IPv6   string `json:"ipv6"`
}

// CacheSettings configures DNS response cache memory usage, persistence,
// and stale serving.
type CacheSettings struct {
	MemPercent  int                      `json:"mem_percent,omitempty"`
	Persist     CachePersistenceSettings `json:"persist,omitempty"`
	PreferStale bool                     `json:"prefer_stale,omitempty"`
}

// CachePersistenceSettings configures cache snapshot file persistence.
type CachePersistenceSettings struct {
	File     string `json:"file,omitempty"`
	Interval int    `json:"interval,omitempty"`
}

// StatsSettings configures periodic statistics collection and reset intervals.
type StatsSettings struct {
	Interval      int `json:"interval,omitempty"`
	ResetInterval int `json:"reset_interval,omitempty"`
}

// UpstreamServer defines a single upstream DNS server with address, protocol,
// and optional matching.
type UpstreamServer struct {
	Address       string   `json:"address"`
	Protocol      string   `json:"protocol"`
	ServerName    string   `json:"server_name,omitempty"`
	SkipTLSVerify bool     `json:"skip_tls_verify,omitempty"`
	Match         []string `json:"match,omitempty"`
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
}

// DNSRecordConfig defines a single DNS resource record for rewrite responses.
type DNSRecordConfig struct {
	Name         string `json:"name,omitempty"`
	Type         string `json:"type"`
	Class        string `json:"class,omitempty"`
	TTL          uint32 `json:"ttl,omitempty"`
	Content      string `json:"content"`
	ResponseCode *int   `json:"response_code,omitempty"`
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

// Loader loads, validates, and prepares the server configuration.
type Loader struct{}

// StatsInterval returns the stats collection interval in seconds, or 0 if
// not configured.
func (s *ServerSettings) StatsInterval() int {
	if s == nil || s.Features.Stats == nil || s.Features.Stats.Interval <= 0 {
		return 0
	}
	return s.Features.Stats.Interval
}

// StatsResetInterval returns the stats reset interval in seconds, or 0 if
// not configured.
func (s *ServerSettings) StatsResetInterval() int {
	if s == nil || s.Features.Stats == nil {
		return 0
	}
	return s.Features.Stats.ResetInterval
}

// StatsPersistTTL returns the stats persist TTL, defaulting to
// DefaultStatsPersistTTL.
func (s *ServerSettings) StatsPersistTTL() int {
	if s == nil || s.Features.Stats == nil || s.Features.Stats.ResetInterval <= 0 {
		return DefaultStatsPersistTTL
	}
	return s.Features.Stats.ResetInterval
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
func (cm *Loader) LoadConfig(configFile string) (*ServerConfig, error) {
	if configFile == "" {
		return cm.getDefaultConfig(), nil
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := &ServerConfig{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := cm.validateConfig(cfg); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	if cm.shouldEnableDDR(cfg) {
		cm.addDDRRecords(cfg)
	}

	cm.addChaosRecord(cfg)

	log.Infof("CONFIG: Configuration loaded successfully")
	return cfg, nil
}

func (cm *Loader) validateConfig(cfg *ServerConfig) error {
	validLevels := map[string]log.Level{
		"error": log.Error,
		"warn":  log.Warn,
		"info":  log.Info,
		"debug": log.Debug,
	}

	logLevelStr := strings.ToLower(cfg.Server.LogLevel)
	if logLevelStr == "" {
		logLevelStr = log.DefaultLevel
	}

	if level, ok := validLevels[logLevelStr]; ok {
		log.Default.SetLevel(level)
	} else {
		log.Default.SetLevel(log.Info)
		log.Warnf("CONFIG: Invalid log level '%s', using default: info", cfg.Server.LogLevel)
	}

	if !cfg.Server.Features.ECS.IsEmpty() {
		if err := cfg.Server.Features.ECS.Validate(); err != nil {
			return err
		}
	}

	cidrTags := make(map[string]bool)
	for i, cidrConfig := range cfg.CIDR {
		if cidrConfig.Tag == "" {
			return fmt.Errorf("CIDR config %d: tag cannot be empty", i)
		}
		if cidrTags[cidrConfig.Tag] {
			return fmt.Errorf("CIDR config %d: duplicate tag '%s'", i, cidrConfig.Tag)
		}
		cidrTags[cidrConfig.Tag] = true

		if cidrConfig.File == "" && len(cidrConfig.Rules) == 0 {
			return fmt.Errorf("CIDR config %d: either 'file' or 'rules' must be specified", i)
		}
		if cidrConfig.File != "" && !dnsutil.IsValidFilePath(cidrConfig.File) {
			return fmt.Errorf("CIDR config %d: file not found: %s", i, cidrConfig.File)
		}
	}

	for i, server := range cfg.Upstream {
		if !server.IsRecursive() {
			if _, _, err := net.SplitHostPort(server.Address); err != nil {
				if server.Protocol == "https" || server.Protocol == "http3" {
					if _, err := url.Parse(server.Address); err != nil {
						return fmt.Errorf("upstream server %d address invalid: %w", i, err)
					}
				} else {
					return fmt.Errorf("upstream server %d address invalid: %w", i, err)
				}
			}
		}

		validProtocols := map[string]bool{
			"udp": true, "tcp": true, "tls": true,
			"quic": true, "https": true, "http3": true,
		}
		if server.Protocol != "" && !validProtocols[strings.ToLower(server.Protocol)] {
			return fmt.Errorf("upstream server %d protocol invalid: %s", i, server.Protocol)
		}

		protocol := strings.ToLower(server.Protocol)
		if dnsutil.IsSecureProtocol(protocol) && server.ServerName == "" {
			return fmt.Errorf("upstream server %d using %s requires server_name", i, server.Protocol)
		}

		for _, matchTag := range server.Match {
			cleanTag := strings.TrimPrefix(matchTag, "!")
			if !cidrTags[cleanTag] {
				return fmt.Errorf("upstream server %d: match tag '%s' not found", i, cleanTag)
			}
		}
	}

	if pct := cfg.Server.Features.Cache.MemPercent; pct < 0 || pct > 100 {
		return fmt.Errorf("server.features.cache.mem_percent must be between 0 and 100")
	}
	if strings.Contains(cfg.Server.Features.Cache.Persist.File, "..") {
		return fmt.Errorf("server.features.cache.persist.file must not contain '..'")
	}
	if cfg.Server.Features.Cache.Persist.Interval < 0 {
		return fmt.Errorf("server.features.cache.persist.interval must be zero or positive")
	}
	if cfg.Server.Features.Stats != nil {
		if cfg.Server.Features.Stats.Interval < 0 {
			return fmt.Errorf("server.features.stats.interval must be zero or positive")
		}
		if cfg.Server.Features.Stats.ResetInterval < 0 {
			return fmt.Errorf("server.features.stats.reset_interval must be zero or positive")
		}
	}
	if cfg.Server.MaxConcurrent < 0 {
		return fmt.Errorf("server.max_concurrent must be zero or positive")
	}
	if cfg.Server.RateLimit < 0 {
		return fmt.Errorf("server.rate_limit must be zero or positive")
	}
	if cfg.Server.RateBurst < 0 {
		return fmt.Errorf("server.rate_burst must be zero or positive")
	}

	if err := validateLatencyProbeDefaults(cfg.Server.Features.LatencyProbe); err != nil {
		return err
	}

	if cfg.Server.TLS.SelfSigned && (cfg.Server.TLS.CertFile != "" || cfg.Server.TLS.KeyFile != "") {
		log.Warnf("CONFIG: TLS: Self-signed enabled, ignoring cert/key files")
	}

	if !cfg.Server.TLS.SelfSigned && (cfg.Server.TLS.CertFile != "" || cfg.Server.TLS.KeyFile != "") {
		if cfg.Server.TLS.CertFile == "" || cfg.Server.TLS.KeyFile == "" {
			return errors.New("config: cert and key files must be configured together")
		}
		if !dnsutil.IsValidFilePath(cfg.Server.TLS.CertFile) {
			return fmt.Errorf("config: cert file not found: %s", cfg.Server.TLS.CertFile)
		}
		if !dnsutil.IsValidFilePath(cfg.Server.TLS.KeyFile) {
			return fmt.Errorf("config: key file not found: %s", cfg.Server.TLS.KeyFile)
		}
		if _, err := tls.LoadX509KeyPair(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile); err != nil {
			return fmt.Errorf("config: load certificate: %w", err)
		}
	}

	return nil
}

func validateLatencyProbeStep(index int, step *LatencyProbeStep) error {
	protocol := strings.ToLower(strings.TrimSpace(step.Protocol))
	if protocol == "" {
		return fmt.Errorf("latency_probe step %d: protocol cannot be empty", index)
	}
	switch protocol {
	case "ping", "icmp":
	case "tcp":
		if step.Port <= 0 {
			step.Port = 80
		}
		if step.Port > 65535 {
			return fmt.Errorf("latency_probe step %d: tcp port must be between 1 and 65535", index)
		}
	case "udp":
		if step.Port <= 0 {
			step.Port = 53
		}
		if step.Port > 65535 {
			return fmt.Errorf("latency_probe step %d: udp port must be between 1 and 65535", index)
		}
	case "http":
		if step.Port <= 0 {
			step.Port = 80
		}
		if step.Port > 65535 {
			return fmt.Errorf("latency_probe step %d: http port must be between 1 and 65535", index)
		}
	case "https":
		if step.Port <= 0 {
			step.Port = 443
		}
		if step.Port > 65535 {
			return fmt.Errorf("latency_probe step %d: https port must be between 1 and 65535", index)
		}
	case "http3":
		if step.Port <= 0 {
			step.Port = 443
		}
		if step.Port > 65535 {
			return fmt.Errorf("latency_probe step %d: http3 port must be between 1 and 65535", index)
		}
	default:
		return fmt.Errorf("latency_probe step %d: unsupported protocol %s", index, step.Protocol)
	}
	return nil
}

func validateLatencyProbeDefaults(steps []LatencyProbeStep) error {
	for i, step := range steps {
		if err := validateLatencyProbeStep(i, &steps[i]); err != nil {
			return err
		}
		if step.Timeout <= 0 {
			steps[i].Timeout = int(DefaultLatencyProbeTimeout / time.Millisecond)
		}
	}
	return nil
}

func (cm *Loader) getDefaultConfig() *ServerConfig {
	cfg := &ServerConfig{}
	cfg.Server.LogLevel = log.DefaultLevel

	cfg.Server.Port = DefaultDNSPort

	cfg.Server.TLS.Port = DefaultDOTPort
	cfg.Server.TLS.HTTPS.Port = DefaultDOHPort
	cfg.Server.TLS.HTTPS.Endpoint = DefaultQueryPath

	cfg.Server.Features.Cache.Persist.Interval = int(DefaultCachePersistInterval / time.Second)
	cfg.Server.Features.DDR = DDRSettings{Domain: "dns.example.com", IPv4: "127.0.0.1", IPv6: "::1"}
	cfg.Server.Features.ECS = edns.DefaultECSConfig{IPv4: "auto", IPv6: "auto", PreferIPv4: true}
	cfg.Server.Features.HijackProtection = true

	return cfg
}

func (cm *Loader) shouldEnableDDR(cfg *ServerConfig) bool {
	ddr := cfg.Server.Features.DDR
	return ddr.Domain != "" &&
		(ddr.IPv4 != "" || ddr.IPv6 != "")
}

func (cm *Loader) addDDRRecords(cfg *ServerConfig) {
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

func (cm *Loader) addChaosRecord(cfg *ServerConfig) {
	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		hostname = ProjectName
	}

	version := ProjectName + " " + Version

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

	log.Infof("CONFIG: CHAOS TXT rewrite records enabled")
}

// GenerateExampleConfig returns a complete example configuration as indented
// JSON.
func GenerateExampleConfig() string {
	cm := &Loader{}
	cfg := cm.getDefaultConfig()

	cfg.Server.Pprof = DefaultPprofPort
	cfg.Server.LogLevel = log.DefaultLevel

	cfg.Server.TLS.CertFile = "/path/to/cert.pem"
	cfg.Server.TLS.KeyFile = "/path/to/key.pem"

	cfg.Server.Features.Cache.MemPercent = 5
	cfg.Server.Features.Cache.Persist = CachePersistenceSettings{
		File:     "cache.snapshot",
		Interval: int(DefaultCachePersistInterval / time.Second),
	}
	cfg.Server.Features.Cache.PreferStale = true
	cfg.Server.Features.ECS = edns.DefaultECSConfig{IPv4: "auto", IPv6: "auto", PreferIPv4: true}
	cfg.Server.Features.LatencyProbe = []LatencyProbeStep{
		{Protocol: "ping", Timeout: 100},
		{Protocol: "tcp", Port: 443, Timeout: 100},
		{Protocol: "tcp", Port: 80, Timeout: 100},
		{Protocol: "udp", Port: 53, Timeout: 100},
		{Protocol: "http", Port: 80, Timeout: 100},
		{Protocol: "https", Port: 443, Timeout: 100},
		{Protocol: "http3", Port: 443, Timeout: 100},
	}
	cfg.Server.Features.Stats = &StatsSettings{
		Interval:      3600,
		ResetInterval: 86400,
	}

	cfg.Upstream = []UpstreamServer{
		{Address: "223.5.5.5:53", Protocol: "tcp"},
		{Address: "223.6.6.6:53", Protocol: "udp"},
		{Address: "223.5.5.5:853", Protocol: "tls", ServerName: "dns.alidns.com"},
		{Address: "223.6.6.6:853", Protocol: "quic", ServerName: "dns.alidns.com", SkipTLSVerify: true},
		{Address: "https://223.5.5.5:443/dns-query", Protocol: "https", ServerName: "dns.alidns.com", Match: []string{"mixed"}},
		{Address: "https://223.6.6.6:443/dns-query", Protocol: "http3", ServerName: "dns.alidns.com", Match: []string{"!mixed"}},
		{Address: RecursiveIndicator},
	}

	cfg.Fallback = []UpstreamServer{
		{Address: "builtin_recursive"},
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
