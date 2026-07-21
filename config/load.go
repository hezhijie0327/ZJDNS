package config

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"zjdns/internal/log"
	zstamp "zjdns/internal/stamp"

	"codeberg.org/miekg/dns"
)

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
	cfg.Server.Protocol.DTLS = DefaultDTLSPort
	cfg.Server.Protocol.DNSCrypt = DefaultDNSCryptPort
	cfg.Server.Protocol.TLCP = DefaultTLCPPort
	cfg.Server.Protocol.HTTPTLCP = HTTPSEndpoint{Port: DefaultHTTPTLCPPort, Endpoint: DefaultQueryPath}
	cfg.Server.Protocol.DTLCP = DefaultDTLCPPort

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
		server.Address = s.BuildDoHURL()
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
func protocolMatchesStamp(userProto string, stampProto zstamp.ProtoType) bool {
	switch stampProto {
	case zstamp.ProtoPlain:
		return userProto == ProtoUDP || userProto == ProtoTCP
	case zstamp.ProtoDNSCrypt:
		return userProto == ProtoDNSCrypt || userProto == ProtoDNSCryptTCP
	case zstamp.ProtoDOH:
		return userProto == ProtoHTTP
	case zstamp.ProtoDOT:
		return userProto == ProtoTLS
	case zstamp.ProtoDOQ:
		return userProto == ProtoQUIC
	case zstamp.ProtoODoHTarget, zstamp.ProtoDNSCryptRelay, zstamp.ProtoODoHRelay:
		// These stamp types have no direct config protocol — always accept.
		return true
	default:
		return false
	}
}

// hexEncodePublicKey encodes a DNSCrypt Ed25519 public key as an uppercase hex
// string, matching the format used in server/dnscrypt for consistency.
func hexEncodePublicKey(b []byte) string {
	return hex.EncodeToString(b)
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
