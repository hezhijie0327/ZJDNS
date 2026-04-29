// Package main implements ZJDNS - High Performance DNS Server
package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	DefaultDNSPort   = "53"   // Default port for DNS over UDP/TCP
	DefaultDOTPort   = "853"  // Default port for DNS over TLS
	DefaultDOHPort   = "443"  // Default port for DNS over HTTPS
	DefaultPprofPort = "6060" // Default port for pprof profiling

	DefaultQueryPath = "/dns-query" // Default path for DoH queries
)

// ConfigManager handles loading and validating server configuration from files or defaults.
type ConfigManager struct{}

// ServerConfig represents the complete configuration for the ZJDNS server, including server settings, Redis, upstream servers, rewrite rules, and CIDR client filters.
type ServerConfig struct {
	Server   ServerSettings   `json:"server"`
	Redis    RedisSettings    `json:"redis"`
	Upstream []UpstreamServer `json:"upstream"`
	Fallback []UpstreamServer `json:"fallback,omitempty"`
	Rewrite  []RewriteRule    `json:"rewrite"`
	CIDR     []CIDRConfig     `json:"cidr"`
}

// ServerSettings contains runtime settings for the DNS server.
type ServerSettings struct {
	Port            string             `json:"port"`
	Pprof           string             `json:"pprof"`
	LogLevel        string             `json:"log_level"`
	DefaultECS      DefaultECSConfig   `json:"default_ecs_subnet"`
	MemoryCacheSize int                `json:"memory_cache_size,omitempty"`
	Stats           *StatsSettings     `json:"stats,omitempty"`
	DDR             DDRSettings        `json:"ddr"`
	TLS             TLSSettings        `json:"tls"`
	Features        FeatureFlags       `json:"features"`
	LatencyProbe    []LatencyProbeStep `json:"latency_probe,omitempty"`
}

// DefaultECSConfig represents the default ECS configuration for the server, allowing for automatic or specified subnet values for IPv4 and IPv6.
type DefaultECSConfig struct {
	IPv4       string `json:"ipv4,omitempty"`
	IPv6       string `json:"ipv6,omitempty"`
	PreferIPv4 bool   `json:"prefer_ipv4,omitempty"`
}

// DDRSettings contains DNS data replacement records and addresses.
type DDRSettings struct {
	Domain string `json:"domain"`
	IPv4   string `json:"ipv4"`
	IPv6   string `json:"ipv6"`
}

// TLSSettings contains TLS and HTTPS configuration for secure DNS listeners.
type TLSSettings struct {
	Port       string        `json:"port"`
	CertFile   string        `json:"cert_file"`
	KeyFile    string        `json:"key_file"`
	SelfSigned bool          `json:"self_signed"`
	HTTPS      HTTPSSettings `json:"https"`
}

// HTTPSSettings contains HTTPS endpoint configuration for DoH.
type HTTPSSettings struct {
	Port     string `json:"port"`
	Endpoint string `json:"endpoint"`
}

// FeatureFlags enables optional server features.
type FeatureFlags struct {
	HijackProtection bool `json:"hijack_protection"`
}

// StatsSettings configures statistics collection and reset behavior.
type StatsSettings struct {
	Interval      int `json:"interval,omitempty"`
	ResetInterval int `json:"reset_interval,omitempty"`
}

// RedisSettings contains Redis connection settings for caching and stats.
type RedisSettings struct {
	Address   string `json:"address"`
	Password  string `json:"password"`
	Database  int    `json:"database"`
	KeyPrefix string `json:"key_prefix"`
}

// UpstreamServer defines an upstream DNS or recursive server endpoint.
type UpstreamServer struct {
	Address       string   `json:"address"`
	Protocol      string   `json:"protocol"`
	ServerName    string   `json:"server_name,omitempty"`
	SkipTLSVerify bool     `json:"skip_tls_verify,omitempty"`
	Match         []string `json:"match,omitempty"`
}

// LoadConfig loads configuration from a file or returns defaults
func (cm *ConfigManager) LoadConfig(configFile string) (*ServerConfig, error) {
	if configFile == "" {
		return cm.getDefaultConfig(), nil
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	config := &ServerConfig{}
	if err := json.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := cm.validateConfig(config); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	if cm.shouldEnableDDR(config) {
		cm.addDDRRecords(config)
	}

	cm.addChaosRecord(config)

	LogInfo("CONFIG: Configuration loaded successfully")
	return config, nil
}

// validateConfig validates the server configuration
func (cm *ConfigManager) validateConfig(config *ServerConfig) error {
	validLevels := map[string]LogLevel{
		"error": Error,
		"warn":  Warn,
		"info":  Info,
		"debug": Debug,
	}

	logLevelStr := strings.ToLower(config.Server.LogLevel)
	if logLevelStr == "" {
		logLevelStr = DefaultLogLevel
	}

	if level, ok := validLevels[logLevelStr]; ok {
		globalLog.SetLevel(level)
	} else {
		globalLog.SetLevel(Info)
		LogWarn("CONFIG: Invalid log level '%s', using default: info", config.Server.LogLevel)
	}

	if !config.Server.DefaultECS.IsEmpty() {
		if err := config.Server.DefaultECS.Validate(); err != nil {
			return err
		}
	}

	cidrTags := make(map[string]bool)
	for i, cidrConfig := range config.CIDR {
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
		if cidrConfig.File != "" && !IsValidFilePath(cidrConfig.File) {
			return fmt.Errorf("CIDR config %d: file not found: %s", i, cidrConfig.File)
		}
	}

	for i, server := range config.Upstream {
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
		if IsSecureProtocol(protocol) && server.ServerName == "" {
			return fmt.Errorf("upstream server %d using %s requires server_name", i, server.Protocol)
		}

		for _, matchTag := range server.Match {
			cleanTag := strings.TrimPrefix(matchTag, "!")
			if !cidrTags[cleanTag] {
				return fmt.Errorf("upstream server %d: match tag '%s' not found", i, cleanTag)
			}
		}
	}

	if config.Redis.Address != "" {
		if _, _, err := net.SplitHostPort(config.Redis.Address); err != nil {
			return fmt.Errorf("redis address invalid: %w", err)
		}
	}

	if config.Server.MemoryCacheSize < 0 {
		return fmt.Errorf("server memory cache size must be non-negative")
	}
	if config.Server.Stats != nil {
		if config.Server.Stats.Interval < 0 {
			return fmt.Errorf("server.stats.interval must be zero or positive")
		}
		if config.Server.Stats.ResetInterval < 0 {
			return fmt.Errorf("server.stats.reset_interval must be zero or positive")
		}
	}

	if len(config.Server.LatencyProbe) > 0 {
		for i, step := range config.Server.LatencyProbe {
			protocol := strings.ToLower(strings.TrimSpace(step.Protocol))
			if protocol == "" {
				return fmt.Errorf("latency_probe step %d: protocol cannot be empty", i)
			}
			switch protocol {
			case "ping", "icmp":
				config.Server.LatencyProbe[i].Protocol = "ping"
			case "tcp":
				if step.Port <= 0 {
					config.Server.LatencyProbe[i].Port = 80
				}
				if step.Port > 65535 {
					return fmt.Errorf("latency_probe step %d: tcp port must be between 1 and 65535", i)
				}
			case "udp":
				if step.Port <= 0 {
					config.Server.LatencyProbe[i].Port = 53
				}
				if step.Port > 65535 {
					return fmt.Errorf("latency_probe step %d: udp port must be between 1 and 65535", i)
				}
			case "http":
				if step.Port <= 0 {
					config.Server.LatencyProbe[i].Port = 80
				}
				if step.Port > 65535 {
					return fmt.Errorf("latency_probe step %d: http port must be between 1 and 65535", i)
				}
			case "https":
				if step.Port <= 0 {
					config.Server.LatencyProbe[i].Port = 443
				}
				if step.Port > 65535 {
					return fmt.Errorf("latency_probe step %d: https port must be between 1 and 65535", i)
				}
			case "http3":
				if step.Port <= 0 {
					config.Server.LatencyProbe[i].Port = 443
				}
				if step.Port > 65535 {
					return fmt.Errorf("latency_probe step %d: http3 port must be between 1 and 65535", i)
				}
			default:
				return fmt.Errorf("latency_probe step %d: unsupported protocol %s", i, step.Protocol)
			}
			if step.Timeout <= 0 {
				config.Server.LatencyProbe[i].Timeout = int(DefaultLatencyProbeTimeout / time.Millisecond)
			}
		}
	}

	if config.Server.TLS.SelfSigned && (config.Server.TLS.CertFile != "" || config.Server.TLS.KeyFile != "") {
		LogWarn("CONFIG: TLS: Self-signed enabled, ignoring cert/key files")
	}

	if !config.Server.TLS.SelfSigned && (config.Server.TLS.CertFile != "" || config.Server.TLS.KeyFile != "") {
		if config.Server.TLS.CertFile == "" || config.Server.TLS.KeyFile == "" {
			return errors.New("config: cert and key files must be configured together")
		}
		if !IsValidFilePath(config.Server.TLS.CertFile) {
			return fmt.Errorf("config: cert file not found: %s", config.Server.TLS.CertFile)
		}
		if !IsValidFilePath(config.Server.TLS.KeyFile) {
			return fmt.Errorf("config: key file not found: %s", config.Server.TLS.KeyFile)
		}
		if _, err := tls.LoadX509KeyPair(config.Server.TLS.CertFile, config.Server.TLS.KeyFile); err != nil {
			return fmt.Errorf("config: load certificate: %w", err)
		}
	}

	return nil
}

// getDefaultConfig returns the default configuration
func (cm *ConfigManager) getDefaultConfig() *ServerConfig {
	config := &ServerConfig{}
	config.Server.Port = DefaultDNSPort
	config.Server.LogLevel = DefaultLogLevel
	config.Server.DefaultECS = DefaultECSConfig{IPv4: "auto", IPv6: "auto", PreferIPv4: true}
	config.Server.MemoryCacheSize = DefaultMemoryCacheSize
	config.Server.DDR.Domain = "dns.example.com"
	config.Server.DDR.IPv4 = "127.0.0.1"
	config.Server.DDR.IPv6 = "::1"
	config.Server.TLS.Port = DefaultDOTPort
	config.Server.TLS.HTTPS.Port = DefaultDOHPort
	config.Server.TLS.HTTPS.Endpoint = DefaultQueryPath
	config.Server.Features.HijackProtection = true
	config.Redis.KeyPrefix = "zjdns:"
	return config
}

// GetStatsInterval returns the configured stats logging interval in seconds.
func (s *ServerSettings) GetStatsInterval() int {
	if s == nil || s.Stats == nil || s.Stats.Interval <= 0 {
		return 0
	}
	return s.Stats.Interval
}

// GetStatsResetInterval returns the configured stats reset interval in seconds.
func (s *ServerSettings) GetStatsResetInterval() int {
	if s == nil || s.Stats == nil {
		return 0
	}
	return s.Stats.ResetInterval
}

func (c *DefaultECSConfig) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		return nil
	}

	if data[0] != '{' {
		return fmt.Errorf("default_ecs_subnet must be an object")
	}

	var aux struct {
		IPv4       string `json:"ipv4"`
		IPv6       string `json:"ipv6"`
		PreferIPv4 bool   `json:"prefer_ipv4"`
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	c.IPv4 = strings.TrimSpace(aux.IPv4)
	c.IPv6 = strings.TrimSpace(aux.IPv6)
	c.PreferIPv4 = aux.PreferIPv4
	return nil
}

// MarshalJSON customizes JSON marshalling for DefaultECSConfig to omit empty fields.
func (c DefaultECSConfig) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		IPv4       string `json:"ipv4,omitempty"`
		IPv6       string `json:"ipv6,omitempty"`
		PreferIPv4 bool   `json:"prefer_ipv4,omitempty"`
	}{
		IPv4:       c.IPv4,
		IPv6:       c.IPv6,
		PreferIPv4: c.PreferIPv4,
	})
}

// IsEmpty checks if both IPv4 and IPv6 fields are empty, indicating no default ECS configuration.
func (c DefaultECSConfig) IsEmpty() bool {
	return c.IPv4 == "" && c.IPv6 == ""
}

// Validate checks that at least one of IPv4 or IPv6 is specified and that any specified values are valid (either "auto" or a valid CIDR).
func (c DefaultECSConfig) Validate() error {
	if c.IPv4 == "" && c.IPv6 == "" {
		return errors.New("default_ecs_subnet must specify ipv4 and/or ipv6")
	}
	if c.IPv4 != "" {
		if err := validateECSConfigValue(c.IPv4); err != nil {
			return fmt.Errorf("invalid default_ecs_subnet.ipv4: %w", err)
		}
	}
	if c.IPv6 != "" {
		if err := validateECSConfigValue(c.IPv6); err != nil {
			return fmt.Errorf("invalid default_ecs_subnet.ipv6: %w", err)
		}
	}
	return nil
}

// HasAuto checks if either IPv4 or IPv6 is set to "auto", indicating that the server should automatically detect the public IP for ECS.
func (c DefaultECSConfig) HasAuto() bool {
	if c.IPv4 != "" && isAutoECSValue(c.IPv4) {
		return true
	}
	if c.IPv6 != "" && isAutoECSValue(c.IPv6) {
		return true
	}
	return false
}

// GetValueForQType returns the appropriate default ECS value based on the query type (A or AAAA) and the configuration. It prioritizes matching the query type but falls back to the other if the preferred one is not set. If neither is set, it returns an empty string.
func (c DefaultECSConfig) GetValueForQType(qtype uint16) string {
	if qtype == dns.TypeA {
		if c.IPv4 != "" {
			return c.IPv4
		}
		return c.IPv6
	}
	if qtype == dns.TypeAAAA {
		if c.IPv6 != "" {
			return c.IPv6
		}
		return c.IPv4
	}
	if c.PreferIPv4 {
		if c.IPv4 != "" {
			return c.IPv4
		}
		return c.IPv6
	}
	if c.IPv6 != "" {
		return c.IPv6
	}
	return c.IPv4
}

// validateECSConfigValue checks if the provided ECS configuration value is valid, allowing for "auto" or a valid CIDR notation.
func validateECSConfigValue(value string) error {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "auto" {
		return nil
	}
	if _, _, err := net.ParseCIDR(value); err != nil {
		return err
	}
	return nil
}

// isAutoECSValue checks if the given value is "auto" (case-insensitive), indicating that the server should automatically detect the public IP for ECS.
func isAutoECSValue(value string) bool {
	return strings.EqualFold(strings.TrimSpace(value), "auto")
}

// shouldEnableDDR checks if DDR should be enabled
func (cm *ConfigManager) shouldEnableDDR(config *ServerConfig) bool {
	return config.Server.DDR.Domain != "" &&
		(config.Server.DDR.IPv4 != "" || config.Server.DDR.IPv6 != "")
}

// addDDRRecords adds DDR records to the configuration
func (cm *ConfigManager) addDDRRecords(config *ServerConfig) {
	domain := strings.TrimSuffix(config.Server.DDR.Domain, ".")
	nxdomainCode := dns.RcodeNameError

	endpoint := config.Server.TLS.HTTPS.Endpoint
	if endpoint == "" {
		endpoint = DefaultQueryPath
	}
	if !strings.HasPrefix(endpoint, "/") {
		endpoint = "/" + endpoint
	}
	dohPath := "dohpath=\"" + endpoint + "{?dns}\""

	serviceRecords := []DNSRecordConfig{
		{Type: "SVCB", Content: "1 . alpn=h3,h2 port=" + config.Server.TLS.HTTPS.Port + " " + dohPath},
		{Type: "SVCB", Content: "2 . alpn=doq,dot port=" + config.Server.TLS.Port},
	}

	var additionalRecords []DNSRecordConfig
	var directRecords []DNSRecordConfig

	if config.Server.DDR.IPv4 != "" {
		for i := range serviceRecords {
			serviceRecords[i].Content += " ipv4hint=" + config.Server.DDR.IPv4
		}
		additionalRecords = append(additionalRecords, DNSRecordConfig{
			Name: domain, Type: "A", Content: config.Server.DDR.IPv4,
		})
		directRecords = append(directRecords, DNSRecordConfig{
			Type: "A", Content: config.Server.DDR.IPv4,
		})
	} else {
		directRecords = append(directRecords, DNSRecordConfig{
			Type: "A", ResponseCode: &nxdomainCode,
		})
	}

	if config.Server.DDR.IPv6 != "" {
		for i := range serviceRecords {
			serviceRecords[i].Content += " ipv6hint=" + config.Server.DDR.IPv6
		}
		additionalRecords = append(additionalRecords, DNSRecordConfig{
			Name: domain, Type: "AAAA", Content: config.Server.DDR.IPv6,
		})
		directRecords = append(directRecords, DNSRecordConfig{
			Type: "AAAA", Content: config.Server.DDR.IPv6,
		})
	} else {
		directRecords = append(directRecords, DNSRecordConfig{
			Type: "AAAA", ResponseCode: &nxdomainCode,
		})
	}

	config.Rewrite = append(config.Rewrite, RewriteRule{
		Name:    domain,
		Records: directRecords,
	})

	ddrNames := []string{"_dns.resolver.arpa", "_dns." + domain}
	if config.Server.Port != "" && config.Server.Port != DefaultDNSPort {
		ddrNames = append(ddrNames, "_"+config.Server.Port+"._dns."+domain)
	}

	for _, name := range ddrNames {
		config.Rewrite = append(config.Rewrite, RewriteRule{
			Name:       name,
			Records:    serviceRecords,
			Additional: additionalRecords,
		})
	}

	LogInfo("CONFIG: DDR enabled for domain %s (IPv4: %s, IPv6: %s)",
		domain, config.Server.DDR.IPv4, config.Server.DDR.IPv6)
}

// addChaosRecord adds built-in CHAOS TXT records for resolver identity/version queries.
func (cm *ConfigManager) addChaosRecord(config *ServerConfig) {
	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		hostname = ProjectName
	}

	version := ProjectName + " " + getVersion()

	chaosRecords := map[string]string{
		"id.server":      hostname,
		"hostname.bind":  hostname,
		"version.server": version,
		"version.bind":   version,
	}

	for name, value := range chaosRecords {
		config.Rewrite = append(config.Rewrite, RewriteRule{
			Name: name,
			Records: []DNSRecordConfig{{
				Type:    "TXT",
				Class:   "CH",
				TTL:     DefaultTTL,
				Content: strconv.Quote(value),
			}},
		})
	}

	LogInfo("CONFIG: CHAOS TXT rewrite records enabled")
}

// IsValidFilePath checks if a file path is safe and exists.
func IsValidFilePath(path string) bool {
	dangerousPrefixes := []string{"/etc/", "/proc/", "/sys/"}
	if strings.Contains(path, "..") || slices.ContainsFunc(dangerousPrefixes, func(prefix string) bool {
		return strings.HasPrefix(path, prefix)
	}) {
		return false
	}

	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// GenerateExampleConfig generates an example configuration.
func GenerateExampleConfig() string {
	cm := &ConfigManager{}
	config := cm.getDefaultConfig()

	config.Redis.Address = "127.0.0.1:6379"

	config.Server.Pprof = DefaultPprofPort
	config.Server.LogLevel = DefaultLogLevel
	config.Server.DefaultECS = DefaultECSConfig{IPv4: "auto", IPv6: "auto", PreferIPv4: true}
	config.Server.Stats = &StatsSettings{}
	config.Server.TLS.CertFile = "/path/to/cert.pem"
	config.Server.TLS.KeyFile = "/path/to/key.pem"

	config.Server.LatencyProbe = []LatencyProbeStep{
		{Protocol: "ping", Timeout: 100},
		{Protocol: "tcp", Port: 443, Timeout: 100},
		{Protocol: "tcp", Port: 80, Timeout: 100},
		{Protocol: "udp", Port: 53, Timeout: 100},
		{Protocol: "http", Port: 80, Timeout: 100},
		{Protocol: "https", Port: 443, Timeout: 100},
		{Protocol: "http3", Port: 443, Timeout: 100},
	}

	config.CIDR = []CIDRConfig{
		{File: "whitelist.txt", Tag: "file"},
		{Rules: []string{"192.168.0.0/16", "10.0.0.0/8", "2001:db8::/32"}, Tag: "rules"},
		{File: "blacklist.txt", Rules: []string{"127.0.0.1/32"}, Tag: "mixed"},
	}

	config.Upstream = []UpstreamServer{
		{Address: "223.5.5.5:53", Protocol: "tcp"},
		{Address: "223.6.6.6:53", Protocol: "udp"},
		{Address: "223.5.5.5:853", Protocol: "tls", ServerName: "dns.alidns.com"},
		{Address: "223.6.6.6:853", Protocol: "quic", ServerName: "dns.alidns.com", SkipTLSVerify: true},
		{Address: "https://223.5.5.5:443/dns-query", Protocol: "https", ServerName: "dns.alidns.com", Match: []string{"mixed"}},
		{Address: "https://223.6.6.6:443/dns-query", Protocol: "http3", ServerName: "dns.alidns.com", Match: []string{"!mixed"}},
		{Address: RecursiveIndicator},
	}

	config.Fallback = []UpstreamServer{
		{Address: "builtin_recursive"},
	}

	config.Rewrite = []RewriteRule{
		{ExcludeClients: []string{"10.0.0.100"}},
		{Name: "client-specific.example.com", IncludeClients: []string{"192.168.0.0/24"}, Records: []DNSRecordConfig{{Type: "A", Content: "127.0.0.1", TTL: DefaultTTL}}},
		{Name: "blocked.example.com", ExcludeClients: []string{"192.168.1.0/24"}, Records: []DNSRecordConfig{{Type: "A", Content: "127.0.0.1", TTL: DefaultTTL}}},
		{Name: "ipv6.blocked.example.com", Records: []DNSRecordConfig{{Type: "AAAA", Content: "::1", TTL: DefaultTTL}}},
	}

	data, _ := json.MarshalIndent(config, "", "  ")
	return string(data)
}
