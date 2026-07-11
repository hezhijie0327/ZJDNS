package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"

	eTLS "gitlab.com/go-extension/tls"
)

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

	rulesetTags, err := validateRuleSets(cfg)
	if err != nil {
		return err
	}

	if err := validateUpstreamServers(cfg, rulesetTags); err != nil {
		return err
	}

	if err := validateDatabase(cfg); err != nil {
		return err
	}
	if err := validateCache(cfg); err != nil {
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
	return nil
}

func validateLogLevel(cfg *ServerConfig) {
	levelStr := strings.TrimSpace(cfg.Server.LogLevel)
	if levelStr == "" {
		levelStr = log.DefaultLevel
	}

	// ParseLevelFilter supports both plain levels ("debug") and
	// component-filtered levels ("debug:upstream,recursion").
	lvl, components := log.ParseLevelFilter(levelStr, log.Info)
	log.Default.SetLevel(lvl)
	if len(components) > 0 {
		log.Default.SetComponentFilter(components)
		log.Infof("CONFIG: Log level set to %s, components filtered to: %v", lvl.String(), components)
	} else {
		log.Infof("CONFIG: Log level set to %s", lvl.String())
	}

	// Warn if the original string didn't parse as a known level.
	baseLevel := strings.SplitN(strings.ToLower(levelStr), ":", 2)[0]
	switch baseLevel {
	case "error", "warn", "info", "debug":
	default:
		log.Warnf("CONFIG: Invalid log level '%s', using default: info", cfg.Server.LogLevel)
	}
}

func validateRuleSets(cfg *ServerConfig) (map[string]bool, error) {
	rulesetTags := make(map[string]bool)
	for i, rs := range cfg.RuleSet {
		if rs.Tag == "" {
			return nil, fmt.Errorf("ruleset %d: tag cannot be empty", i)
		}
		if rulesetTags[rs.Tag] {
			return nil, fmt.Errorf("ruleset %d: duplicate tag '%s'", i, rs.Tag)
		}
		rulesetTags[rs.Tag] = true
		if rs.Type != "ip" && rs.Type != "domain" {
			return nil, fmt.Errorf("ruleset %d: type must be 'ip' or 'domain', got '%s'", i, rs.Type)
		}
		if rs.File == "" && len(rs.Rule) == 0 {
			return nil, fmt.Errorf("ruleset %d: must specify 'rule' or 'file'", i)
		}
		if rs.File != "" && !zdnsutil.IsValidFilePath(rs.File) {
			return nil, fmt.Errorf("ruleset %d: file not found: %s", i, rs.File)
		}
	}
	return rulesetTags, nil
}

func validateUpstreamServers(cfg *ServerConfig, rulesetTags map[string]bool) error {
	validProtocols := map[string]bool{
		ProtoUDP: true, ProtoTCP: true, ProtoTLS: true, ProtoDOT: true,
		ProtoQUIC: true, ProtoDOQ: true,
		ProtoHTTP: true, ProtoDOH: true,
		ProtoHTTP3: true, ProtoDOH3: true,
		ProtoTLSTCP: true, ProtoDNSCrypt: true, ProtoDNSCryptTCP: true,
	}

	for i, server := range cfg.Upstream {
		protocol := strings.ToLower(server.Protocol)
		if server.Protocol != "" && !validProtocols[protocol] {
			return fmt.Errorf("upstream server %d protocol invalid: %s", i, server.Protocol)
		}

		if !server.IsRecursive() {
			isStamp := strings.HasPrefix(server.Address, "sdns://")
			if isStamp {
				// Stamp addresses are parsed during normalization — the raw
				// sdns:// string is not a valid host:port or URL.
			} else if _, _, err := net.SplitHostPort(server.Address); err != nil {
				if protocol == ProtoHTTP || protocol == ProtoHTTP3 ||
					protocol == ProtoDOH || protocol == ProtoDOH3 {
					if _, err := url.Parse(server.Address); err != nil {
						return fmt.Errorf("upstream server %d address invalid: %w", i, err)
					}
				} else {
					return fmt.Errorf("upstream server %d address invalid: %w", i, err)
				}
			}
		}
		if zdnsutil.IsSecureProtocol(protocol) && server.ServerName == "" && !strings.HasPrefix(server.Address, "sdns://") {
			return fmt.Errorf("upstream server %d using %s requires server_name", i, server.Protocol)
		}
		if (protocol == ProtoDNSCrypt || protocol == ProtoDNSCryptTCP) && !strings.HasPrefix(server.Address, "sdns://") {
			if server.ServerName == "" {
				return fmt.Errorf("upstream server %d using dnscrypt requires server_name (provider name)", i)
			}
			if server.PublicKey == "" {
				return fmt.Errorf("upstream server %d using dnscrypt requires public_key", i)
			}
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
			if !rulesetTags[cleanTag] {
				return fmt.Errorf("upstream server %d: match tag '%s' not found", i, cleanTag)
			}
		}
	}
	return nil
}

func validateDatabase(cfg *ServerConfig) error {
	if strings.Contains(cfg.Server.Features.Database.DBPath, "..") {
		return errors.New("server.features.database.db_path must not contain '..'")
	}
	return nil
}

func validateCache(cfg *ServerConfig) error {
	if cfg.Server.Features.Cache.MaxEntries < 0 {
		return errors.New("server.features.cache.max_entries must be zero or positive")
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
	// Detect port conflicts: DNS port must not overlap with TLS/HTTPS/pprof/DNSCrypt.
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
	if cfg.Server.DNSCrypt.IsEnabled() {
		port := cfg.Server.DNSCrypt.Port
		if port == "" {
			port = DefaultDNSCryptPort
		}
		if first, ok := seen[port]; ok {
			return fmt.Errorf("port conflict: server.dnscrypt.port=%s and %s=%s both use port %s",
				port, first, port, port)
		}
		seen[port] = "server.dnscrypt.port"
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
	if !zdnsutil.IsValidFilePath(cfg.Server.TLS.CertFile) {
		return fmt.Errorf("config: cert file not found: %s", cfg.Server.TLS.CertFile)
	}
	if !zdnsutil.IsValidFilePath(cfg.Server.TLS.KeyFile) {
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
	case ProtoPing, ProtoICMP:
	case ProtoTCP:
		return validateProbePort(index, ProtoTCP, &step.Port, DefaultProbePortHTTP)
	case ProtoUDP:
		return validateProbePort(index, ProtoUDP, &step.Port, DefaultProbePortDNS)
	case ProtoHTTPPlain:
		return validateProbePort(index, ProtoHTTPPlain, &step.Port, DefaultProbePortHTTP)
	case ProtoHTTP:
		return validateProbePort(index, ProtoHTTP, &step.Port, DefaultProbePortHTTPS)
	case ProtoHTTP3:
		return validateProbePort(index, ProtoHTTP3, &step.Port, DefaultProbePortHTTPS)
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
