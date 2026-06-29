// Package config provides configuration types, loading, generation, and validation.
package config

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	eTLS "gitlab.com/go-extension/tls"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"zjdns/edns"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
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
	DNSCrypt DNSCryptSettings `json:"dnscrypt"`
	Features FeatureFlags     `json:"features"`

	MaxConcurrent int `json:"max_concurrent,omitempty"`
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

// DNSCryptSettings configures the DNSCrypt v2 encrypted DNS listener.
type DNSCryptSettings struct {
	Port         string `json:"port,omitempty"`       // Listener port for UDP and TCP (default "8443")
	ProviderName string `json:"provider_name"`        // e.g. "2.dnscrypt-cert.example.org"
	PrivateKey   string `json:"private_key"`          // hex-encoded Ed25519 private key (128 hex chars)
	PublicKey    string `json:"public_key,omitempty"` // hex-encoded Ed25519 public key (informational, ignored by server)
	CertTTL      int    `json:"cert_ttl,omitempty"`   // Certificate lifetime in seconds (default 31536000 = 365d)
	ESVersion    string `json:"es_version,omitempty"` // Crypto construction: "xsalsa20" (default), "xchacha20", "xwing"
}

// FeatureFlags enables optional features: hijack protection, DDR, ECS, cache,
// latency probes, and stats.
type FeatureFlags struct {
	HijackProtection bool                  `json:"hijack_protection"`
	DNSSECEnforce    bool                  `json:"dnssec_enforce,omitempty"`
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
	Size        int64                    `json:"size,omitempty"`
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
	Address           string   `json:"address"`
	Protocol          string   `json:"protocol"`
	ServerName        string   `json:"server_name,omitempty"`
	SkipTLSVerify     bool     `json:"skip_tls_verify,omitempty"`
	Match             []string `json:"match,omitempty"`
	Proxy             string   `json:"proxy,omitempty"`               // socks5://[user:pass@]host:port
	DNSCryptPublicKey string   `json:"dnscrypt_public_key,omitempty"` // hex-encoded Ed25519 public key (DNSCrypt only)
	DNSCryptTCP       bool     `json:"dnscrypt_tcp,omitempty"`        // use TCP for DNSCrypt upstream (default: UDP)
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

// StatsPersistInterval returns the stats persist TTL, defaulting to
// DefaultStatsPersistInterval.
func (s *ServerSettings) StatsPersistInterval() int {
	if s == nil || s.Features.Stats == nil || s.Features.Stats.ResetInterval <= 0 {
		return DefaultStatsPersistInterval
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
func LoadConfig(configFile string) (*ServerConfig, error) {
	if configFile == "" {
		return NewDefaultServerConfig(), nil
	}

	data, err := os.ReadFile(configFile)
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

// validatePort checks that a port string is a valid numeric port in [1, 65535].
func validatePort(field, value string) error {
	if value == "" {
		return fmt.Errorf("%s must not be empty", field)
	}
	p, err := strconv.Atoi(value)
	if err != nil {
		return fmt.Errorf("%s must be a numeric port: %w", field, err)
	}
	if p < 1 || p > 65535 {
		return fmt.Errorf("%s must be between 1 and 65535", field)
	}
	return nil
}

func validateConfig(cfg *ServerConfig) error {
	validateLogLevel(cfg)

	if !cfg.Server.Features.ECS.IsEmpty() {
		if err := cfg.Server.Features.ECS.Validate(); err != nil {
			return err
		}
	}

	cidrTags, err := validateCIDRConfigs(cfg)
	if err != nil {
		return err
	}

	if err := validateUpstreamServers(cfg, cidrTags); err != nil {
		return err
	}

	if err := validateCacheAndStats(cfg); err != nil {
		return err
	}

	if err := validatePorts(cfg); err != nil {
		return err
	}

	if err := validateLatencyProbeDefaults(cfg.Server.Features.LatencyProbe); err != nil {
		return err
	}

	if err := validateTLSCertConfig(cfg); err != nil {
		return err
	}
	if err := validateDNSCryptConfig(cfg); err != nil {
		return err
	}
	return nil
}

func validateLogLevel(cfg *ServerConfig) {
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
}

func validateCIDRConfigs(cfg *ServerConfig) (map[string]bool, error) {
	cidrTags := make(map[string]bool)
	for i, cidrConfig := range cfg.CIDR {
		if cidrConfig.Tag == "" {
			return nil, fmt.Errorf("CIDR config %d: tag cannot be empty", i)
		}
		if cidrTags[cidrConfig.Tag] {
			return nil, fmt.Errorf("CIDR config %d: duplicate tag '%s'", i, cidrConfig.Tag)
		}
		cidrTags[cidrConfig.Tag] = true

		if cidrConfig.File == "" && len(cidrConfig.Rules) == 0 {
			return nil, fmt.Errorf("CIDR config %d: either 'file' or 'rules' must be specified", i)
		}
		if cidrConfig.File != "" && !dnsutil.IsValidFilePath(cidrConfig.File) {
			return nil, fmt.Errorf("CIDR config %d: file not found: %s", i, cidrConfig.File)
		}
	}
	return cidrTags, nil
}

func validateUpstreamServers(cfg *ServerConfig, cidrTags map[string]bool) error {
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
			"dnscrypt": true,
		}
		if server.Protocol != "" && !validProtocols[strings.ToLower(server.Protocol)] {
			return fmt.Errorf("upstream server %d protocol invalid: %s", i, server.Protocol)
		}

		protocol := strings.ToLower(server.Protocol)
		if dnsutil.IsSecureProtocol(protocol) && server.ServerName == "" {
			return fmt.Errorf("upstream server %d using %s requires server_name", i, server.Protocol)
		}

		if server.Proxy != "" {
			u, err := url.Parse(server.Proxy)
			if err != nil {
				return fmt.Errorf("upstream server %d proxy URL invalid: %w", i, err)
			}
			if u.Scheme != "socks5" {
				return fmt.Errorf("upstream server %d proxy scheme must be socks5 (got %q)", i, u.Scheme)
			}
			if u.Hostname() == "" {
				return fmt.Errorf("upstream server %d proxy host required", i)
			}
			if p := u.Port(); p != "" {
				if port, err := strconv.Atoi(p); err != nil || port < 1 || port > 65535 {
					return fmt.Errorf("upstream server %d proxy port invalid: %s", i, p)
				}
			}
		}

		for _, matchTag := range server.Match {
			cleanTag := strings.TrimPrefix(matchTag, "!")
			if !cidrTags[cleanTag] {
				return fmt.Errorf("upstream server %d: match tag '%s' not found", i, cleanTag)
			}
		}
	}
	return nil
}

func validateCacheAndStats(cfg *ServerConfig) error {
	if cfg.Server.Features.Cache.Size < 0 {
		return fmt.Errorf("server.features.cache.size must be zero or positive")
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
	return nil
}

func validatePorts(cfg *ServerConfig) error {
	if err := validatePort("server.port", cfg.Server.Port); err != nil {
		return err
	}
	if cfg.Server.Pprof != "" {
		if err := validatePort("server.pprof", cfg.Server.Pprof); err != nil {
			return err
		}
	}
	if cfg.Server.TLS.SelfSigned || (cfg.Server.TLS.CertFile != "" && cfg.Server.TLS.KeyFile != "") {
		if err := validatePort("server.tls.port", cfg.Server.TLS.Port); err != nil {
			return err
		}
		if cfg.Server.TLS.HTTPS.Port != "" {
			if err := validatePort("server.tls.https.port", cfg.Server.TLS.HTTPS.Port); err != nil {
				return err
			}
		}
	}
	// Detect port conflicts: DNS port must not overlap with TLS/HTTPS/DNSCrypt/pprof.
	seen := map[string]string{cfg.Server.Port: "server.port"}
	if cfg.Server.Pprof != "" {
		if first, ok := seen[cfg.Server.Pprof]; ok {
			return fmt.Errorf("port conflict: server.pprof=%s and %s=%s both use port %s",
				cfg.Server.Pprof, first, cfg.Server.Pprof, cfg.Server.Pprof)
		}
		seen[cfg.Server.Pprof] = "server.pprof"
	}
	if cfg.Server.TLS.Port != "" {
		if first, ok := seen[cfg.Server.TLS.Port]; ok {
			return fmt.Errorf("port conflict: server.tls.port=%s and %s=%s both use port %s",
				cfg.Server.TLS.Port, first, cfg.Server.TLS.Port, cfg.Server.TLS.Port)
		}
		seen[cfg.Server.TLS.Port] = "server.tls.port"
	}
	if cfg.Server.TLS.HTTPS.Port != "" {
		if first, ok := seen[cfg.Server.TLS.HTTPS.Port]; ok {
			return fmt.Errorf("port conflict: server.tls.https.port=%s and %s=%s both use port %s",
				cfg.Server.TLS.HTTPS.Port, first, cfg.Server.TLS.HTTPS.Port, cfg.Server.TLS.HTTPS.Port)
		}
		seen[cfg.Server.TLS.HTTPS.Port] = "server.tls.https.port"
	}
	if cfg.Server.DNSCrypt.Port != "" {
		if first, ok := seen[cfg.Server.DNSCrypt.Port]; ok {
			return fmt.Errorf("port conflict: server.dnscrypt.port=%s and %s=%s both use port %s",
				cfg.Server.DNSCrypt.Port, first, cfg.Server.DNSCrypt.Port, cfg.Server.DNSCrypt.Port)
		}
	}
	return nil
}

func validateTLSCertConfig(cfg *ServerConfig) error {
	if cfg.Server.TLS.SelfSigned && (cfg.Server.TLS.CertFile != "" || cfg.Server.TLS.KeyFile != "") {
		log.Warnf("CONFIG: TLS: Self-signed enabled, ignoring cert/key files")
		return nil
	}

	if cfg.Server.TLS.CertFile == "" && cfg.Server.TLS.KeyFile == "" {
		return nil
	}
	if cfg.Server.TLS.CertFile == "" || cfg.Server.TLS.KeyFile == "" {
		return errors.New("config: cert and key files must be configured together")
	}
	if !dnsutil.IsValidFilePath(cfg.Server.TLS.CertFile) {
		return fmt.Errorf("config: cert file not found: %s", cfg.Server.TLS.CertFile)
	}
	if !dnsutil.IsValidFilePath(cfg.Server.TLS.KeyFile) {
		return fmt.Errorf("config: key file not found: %s", cfg.Server.TLS.KeyFile)
	}
	if info, err := os.Stat(cfg.Server.TLS.KeyFile); err == nil {
		if info.Mode().Perm()&GroupOtherPermMask != 0 {
			log.Warnf("CONFIG: TLS key file has insecure permissions (%04o). Consider 'chmod 600 %s'",
				info.Mode().Perm(), cfg.Server.TLS.KeyFile)
		}
	}
	if _, err := eTLS.LoadX509KeyPair(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile); err != nil {
		return fmt.Errorf("config: load certificate: %w", err)
	}
	return nil
}

// NormalizeDNSCryptProviderName ensures the provider name includes the
// 2.dnscrypt-cert. prefix required by the DNSCrypt v2 protocol.
func NormalizeDNSCryptProviderName(name string) string {
	if !strings.HasPrefix(name, DNSCryptV2Prefix) {
		name = DNSCryptV2Prefix + name
	}
	return name
}

func validateDNSCryptConfig(cfg *ServerConfig) error {
	d := cfg.Server.DNSCrypt
	if d.Port == "" {
		return nil
	}
	if d.ProviderName == "" {
		return errors.New("config: dnscrypt.provider_name is required when port is set")
	}
	name := NormalizeDNSCryptProviderName(d.ProviderName)
	if len(name) > 253 {
		return fmt.Errorf("config: dnscrypt.provider_name too long (%d bytes, max 253)", len(name))
	}
	if d.PrivateKey == "" {
		return errors.New("config: dnscrypt.private_key is required (generate with -generate-dnscrypt-keys)")
	}
	keyStr := strings.ReplaceAll(d.PrivateKey, ":", "")
	keyBytes, err := hex.DecodeString(keyStr)
	if err != nil {
		return fmt.Errorf("config: dnscrypt.private_key is not valid hex: %w", err)
	}
	if len(keyBytes) != ed25519.PrivateKeySize {
		return fmt.Errorf("config: dnscrypt.private_key must be %d bytes (%d hex chars), got %d bytes",
			ed25519.PrivateKeySize, ed25519.PrivateKeySize*2, len(keyBytes))
	}
	if d.CertTTL < 0 || d.CertTTL > 315360000 {
		return fmt.Errorf("config: dnscrypt.cert_ttl must be between 0 and 315360000 (10 years), got %d", d.CertTTL)
	}
	if d.ESVersion != "" {
		switch strings.ToLower(d.ESVersion) {
		case "xsalsa20", "xchacha20", "xwing":
		default:
			return fmt.Errorf("config: dnscrypt.es_version must be one of: xsalsa20, xchacha20, xwing, got: %s", d.ESVersion)
		}
	}
	return nil
}

func validateProbePort(index int, protocol string, port *int, defaultPort int) error {
	if *port <= 0 {
		*port = defaultPort
	}
	if *port > 65535 {
		return fmt.Errorf("latency_probe step %d: %s port must be between 1 and 65535", index, protocol)
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
		return validateProbePort(index, "tcp", &step.Port, DefaultProbePortHTTP)
	case "udp":
		return validateProbePort(index, "udp", &step.Port, DefaultProbePortDNS)
	case "http":
		return validateProbePort(index, "http", &step.Port, DefaultProbePortHTTP)
	case "https":
		return validateProbePort(index, "https", &step.Port, DefaultProbePortHTTPS)
	case "http3":
		return validateProbePort(index, "http3", &step.Port, DefaultProbePortHTTPS)
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

// NewDefaultServerConfig returns a ServerConfig with sensible defaults.
func NewDefaultServerConfig() *ServerConfig {
	cfg := &ServerConfig{}
	cfg.Server.LogLevel = log.DefaultLevel

	cfg.Server.Port = DefaultDNSPort

	cfg.Server.TLS.Port = DefaultDOTPort
	cfg.Server.TLS.HTTPS.Port = DefaultDOHPort
	cfg.Server.TLS.HTTPS.Endpoint = DefaultQueryPath

	cfg.Server.Features.Cache.Persist.Interval = int(DefaultCachePersistInterval / time.Second)
	cfg.Server.Features.DDR = DDRSettings{Domain: "dns.example.com", IPv4: "127.0.0.1", IPv6: "::1"}
	cfg.Server.Features.ECS = edns.DefaultECSConfig{IPv4: "auto", IPv6: "auto", PreferIPv4: true}
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

	log.Infof("CONFIG: CHAOS TXT rewrite records enabled")
}

// JoinDNSPort appends the default DNS port (53) to an IP address string,
// producing an "ip:53" pair suitable for use as a nameserver address.
func JoinDNSPort(ip string) string {
	return net.JoinHostPort(ip, DefaultDNSPort)
}
