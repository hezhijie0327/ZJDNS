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

// =============================================================================
// ConfigManager Implementation
// =============================================================================

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

	if config.Server.DefaultECS != "" {
		ecs := strings.ToLower(config.Server.DefaultECS)
		validPresets := []string{"auto", "auto_v4", "auto_v6"}
		isValidPreset := slices.Contains(validPresets, ecs)
		if !isValidPreset {
			if _, _, err := net.ParseCIDR(config.Server.DefaultECS); err != nil {
				return fmt.Errorf("invalid ECS subnet: %w", err)
			}
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
	config.Server.DefaultECS = "auto"
	config.Server.MemoryCacheSize = DefaultMemoryCacheSize
	config.Server.DDR.Domain = "dns.example.com"
	config.Server.DDR.IPv4 = "127.0.0.1"
	config.Server.DDR.IPv6 = "::1"
	config.Server.TLS.Port = DefaultDOTPort
	config.Server.TLS.HTTPS.Port = DefaultDOHPort
	config.Server.TLS.HTTPS.Endpoint = DefaultQueryPath
	config.Server.Features.ForceDNSSEC = true
	config.Server.Features.HijackProtection = true
	config.Redis.KeyPrefix = "zjdns:"
	return config
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
				TTL:     DefaultCacheTTL,
				Content: strconv.Quote(value),
			}},
		})
	}

	LogInfo("CONFIG: CHAOS TXT rewrite records enabled")
}
