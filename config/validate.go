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
	"zjdns/internal/log"

	zdnsutil "zjdns/internal/dnsutil"

	"gitee.com/Trisia/gotlcp/tlcp"
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

	if err := validateDDR(cfg); err != nil {
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

	if err := validateTLSCertificateConfig(cfg); err != nil {
		return err
	}

	if err := validateTLCPCertificateConfig(cfg); err != nil {
		return err
	}

	if err := validateCertDomain(cfg); err != nil {
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
		// Plain DNS
		ProtoUDP: true,
		ProtoTCP: true,

		// TLS-based
		ProtoTLS:   true,
		ProtoQUIC:  true,
		ProtoHTTPS: true,
		ProtoHTTP3: true,
		ProtoDTLS:  true,

		// DNSCrypt
		ProtoDNSCrypt:    true,
		ProtoDNSCryptTCP: true,

		// TLCP-based (GB/T 38636-2020)
		ProtoTLCP:     true,
		ProtoHTTPTLCP: true,

		// DTLS-based (GM/T 0128-2023)
		ProtoDTLCP: true,
	}

	for i := range cfg.Upstream {
		server := &cfg.Upstream[i]
		protocol := strings.ToLower(server.Protocol)
		if server.Protocol != "" && !validProtocols[protocol] {
			return fmt.Errorf("upstream server %d protocol invalid: %s", i, server.Protocol)
		}

		if !server.IsRecursive() {
			// Stamp addresses are parsed during normalization — the raw
			// sdns:// string is not a valid host:port or URL.
			if !strings.HasPrefix(server.Address, "sdns://") {
				if _, _, err := net.SplitHostPort(server.Address); err != nil {
					if protocol == ProtoHTTPS || protocol == ProtoHTTP3 ||
						protocol == ProtoHTTPTLCP {
						if _, err := url.Parse(server.Address); err != nil {
							return fmt.Errorf("upstream server %d address invalid: %w", i, err)
						}
					} else {
						return fmt.Errorf("upstream server %d address invalid: %w", i, err)
					}
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

// validateDDR checks that DDR (Discovery of Designated Resolvers) IPv4/IPv6
// addresses are valid IPs when non-empty. Invalid values would silently create
// malformed zone entries during DDR record generation.
func validateDDR(cfg *ServerConfig) error {
	if v4 := cfg.Server.Features.DDR.IPv4; v4 != "" {
		if ip := net.ParseIP(v4); ip == nil || ip.To4() == nil {
			return fmt.Errorf("server.features.ddr.ipv4: %q is not a valid IPv4 address", v4)
		}
	}
	if v6 := cfg.Server.Features.DDR.IPv6; v6 != "" {
		if ip := net.ParseIP(v6); ip == nil || ip.To16() == nil {
			return fmt.Errorf("server.features.ddr.ipv6: %q is not a valid IPv6 address", v6)
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
	proto := &cfg.Server.Protocol

	// Validate all non-empty ports.
	for _, p := range []struct{ field, value string }{
		{"server.protocol.udp", proto.UDP},
		{"server.protocol.tcp", proto.TCP},
		{"server.protocol.tls", proto.TLS},
		{"server.protocol.quic", proto.QUIC},
		{"server.protocol.https.port", proto.HTTPS.Port},
		{"server.protocol.http3.port", proto.HTTP3.Port},
		{"server.protocol.tlcp", proto.TLCP},
		{"server.protocol.http_tlcp.port", proto.HTTPTLCP.Port},
		{"server.protocol.dtls", proto.DTLS},
		{"server.protocol.dtlcp", proto.DTLCP},
		{"server.protocol.dnscrypt", proto.DNSCrypt},
	} {
		if p.value != "" {
			if err := validatePort(p.field, p.value); err != nil {
				return err
			}
		}
	}
	if cfg.Server.Pprof != "" {
		if err := validatePort("server.pprof", cfg.Server.Pprof); err != nil {
			return err
		}
	}

	// Detect port conflicts.  TCP and UDP ports are tracked separately —
	// e.g. UDP:53 and TCP:53 can coexist, but TLS:853 and TCP:853 cannot.
	type portEntry struct {
		field     string
		value     string
		transport string // "tcp" or "udp"
	}
	entries := []portEntry{
		{"server.protocol.udp", proto.UDP, "udp"},
		{"server.protocol.tcp", proto.TCP, "tcp"},
		{"server.protocol.tls", proto.TLS, "tcp"},
		{"server.protocol.quic", proto.QUIC, "udp"},
		{"server.protocol.https.port", proto.HTTPS.Port, "tcp"},
		{"server.protocol.http3.port", proto.HTTP3.Port, "udp"},
		{"server.protocol.tlcp", proto.TLCP, "tcp"},
		{"server.protocol.http_tlcp.port", proto.HTTPTLCP.Port, "tcp"},
		{"server.protocol.dtls", proto.DTLS, "udp"},
		{"server.protocol.dtlcp", proto.DTLCP, "udp"},
		{"server.protocol.dnscrypt", proto.DNSCrypt, "udp"},
		{"server.pprof", cfg.Server.Pprof, "tcp"},
	}

	tcpSeen := map[string]string{}
	udpSeen := map[string]string{}
	for _, e := range entries {
		if e.value == "" {
			continue
		}
		var seen map[string]string
		if e.transport == "udp" {
			seen = udpSeen
		} else {
			seen = tcpSeen
		}
		if first, ok := seen[e.value]; ok {
			return fmt.Errorf("port conflict: %s=%s and %s=%s both use %s port %s",
				e.field, e.value, first, e.value, e.transport, e.value)
		}
		seen[e.value] = e.field
	}
	return nil
}

func validateTLSCertificateConfig(cfg *ServerConfig) error {
	tlsCert := &cfg.Server.Certificate.TLS
	if !tlsCert.IsEnabled() {
		return nil
	}

	// Only require cert validation if at least one TLS-based protocol is enabled.
	proto := &cfg.Server.Protocol
	tlsEnabled := proto.TLS != "" || proto.QUIC != "" || proto.HTTPS.Port != "" || proto.HTTP3.Port != ""
	if !tlsEnabled {
		return nil
	}

	if tlsCert.SelfSigned {
		if tlsCert.CertFile != "" || tlsCert.KeyFile != "" {
			log.Warnf("CONFIG: TLS: Self-signed enabled, ignoring cert/key files")
		}
		return nil
	}

	if tlsCert.CertFile == "" || tlsCert.KeyFile == "" {
		return errors.New("config: certificate.tls.cert_file and certificate.tls.key_file must be configured together, or enable self_signed")
	}
	if !zdnsutil.IsValidFilePath(tlsCert.CertFile) {
		return fmt.Errorf("config: TLS cert file not found: %s", tlsCert.CertFile)
	}
	if !zdnsutil.IsValidFilePath(tlsCert.KeyFile) {
		return fmt.Errorf("config: TLS key file not found: %s", tlsCert.KeyFile)
	}
	if info, err := os.Stat(tlsCert.KeyFile); err == nil {
		if info.Mode().Perm()&GroupOtherPermMask != 0 {
			log.Warnf("CONFIG: TLS key file has insecure permissions (%04o). Consider 'chmod 600 %s'",
				info.Mode().Perm(), tlsCert.KeyFile)
		}
	}
	if _, err := eTLS.LoadX509KeyPair(tlsCert.CertFile, tlsCert.KeyFile); err != nil {
		return fmt.Errorf("config: load TLS certificate: %w", err)
	}
	return nil
}

// validateProbePort validates and default-fills the port field.
// NOTE: modifies *port as a side effect — this is intentional to keep
// default-setting close to validation logic.
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
	case ProtoHTTP:
		return validateProbePort(index, ProtoHTTP, &step.Port, DefaultProbePortHTTP)
	case ProtoHTTPS:
		return validateProbePort(index, ProtoHTTPS, &step.Port, DefaultProbePortHTTPS)
	case ProtoHTTP3:
		return validateProbePort(index, ProtoHTTP3, &step.Port, DefaultProbePortHTTPS)
	default:
		return fmt.Errorf("latency_probe step %d: unsupported protocol %s", index, step.Protocol)
	}
	return nil
}

func validateTLCPCertificateConfig(cfg *ServerConfig) error {
	tlcpCert := &cfg.Server.Certificate.TLCP
	if !tlcpCert.IsEnabled() {
		return nil
	}

	// Only require cert validation if at least one TLCP protocol is enabled.
	proto := &cfg.Server.Protocol
	tlcpEnabled := proto.TLCP != "" || proto.HTTPTLCP.Port != ""
	if !tlcpEnabled {
		return nil
	}

	if tlcpCert.SelfSigned {
		return nil
	}
	if !zdnsutil.IsValidFilePath(tlcpCert.SignCertFile) {
		return fmt.Errorf("config: TLCP sign cert file not found: %s", tlcpCert.SignCertFile)
	}
	if !zdnsutil.IsValidFilePath(tlcpCert.SignKeyFile) {
		return fmt.Errorf("config: TLCP sign key file not found: %s", tlcpCert.SignKeyFile)
	}
	if !zdnsutil.IsValidFilePath(tlcpCert.EncCertFile) {
		return fmt.Errorf("config: TLCP enc cert file not found: %s", tlcpCert.EncCertFile)
	}
	if !zdnsutil.IsValidFilePath(tlcpCert.EncKeyFile) {
		return fmt.Errorf("config: TLCP enc key file not found: %s", tlcpCert.EncKeyFile)
	}
	if info, err := os.Stat(tlcpCert.SignKeyFile); err == nil {
		if info.Mode().Perm()&GroupOtherPermMask != 0 {
			log.Warnf("CONFIG: TLCP sign key file has insecure permissions (%04o). Consider 'chmod 600 %s'",
				info.Mode().Perm(), tlcpCert.SignKeyFile)
		}
	}
	if info, err := os.Stat(tlcpCert.EncKeyFile); err == nil {
		if info.Mode().Perm()&GroupOtherPermMask != 0 {
			log.Warnf("CONFIG: TLCP enc key file has insecure permissions (%04o). Consider 'chmod 600 %s'",
				info.Mode().Perm(), tlcpCert.EncKeyFile)
		}
	}
	// Verify certificates are loadable.
	if _, err := tlcp.LoadX509KeyPair(tlcpCert.SignCertFile, tlcpCert.SignKeyFile); err != nil {
		return fmt.Errorf("config: load TLCP sign certificate: %w", err)
	}
	if _, err := tlcp.LoadX509KeyPair(tlcpCert.EncCertFile, tlcpCert.EncKeyFile); err != nil {
		return fmt.Errorf("config: load TLCP enc certificate: %w", err)
	}
	return nil
}

func validateCertDomain(cfg *ServerConfig) error {
	proto := &cfg.Server.Protocol
	cert := &cfg.Server.Certificate

	needsDomain := proto.TLS != "" || proto.QUIC != "" || proto.HTTPS.Port != "" || proto.HTTP3.Port != "" ||
		proto.TLCP != "" || proto.HTTPTLCP.Port != "" || proto.DTLS != "" || proto.DTLCP != "" || proto.DNSCrypt != ""
	if !needsDomain {
		return nil
	}

	if cert.Domain == "" {
		return errors.New("config: certificate.domain is required when secure protocols (tls/quic/https/http3/tlcp/http_tlcp/dtls/dtlcp/dnscrypt) are enabled")
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
