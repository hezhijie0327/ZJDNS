package config

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"zjdns/internal/log"
	zstamp "zjdns/internal/stamp"
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

	log.Debugf("CONFIG: upstream=%d recursive=%t dnssec_enforce=%t log_level=%s",
		len(cfg.Upstream), len(cfg.Upstream) == 0,
		cfg.Server.Features.DNSSECEnforce, cfg.Server.LogLevel)
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

	return cfg
}

// normalizeStamps resolves sdns:// addresses in upstream server configs,
// populating protocol, address, server_name, and public_key from the stamp.
// Servers without an sdns:// address are left unchanged.
func normalizeStamps(cfg *ServerConfig) error {
	for i := range cfg.Upstream {
		if err := resolveStamp(&cfg.Upstream[i], i, "upstream"); err != nil {
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
			server.PublicKey = hex.EncodeToString(s.PublicKey)
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
		// Map to ProtoHTTP (not ProtoHTTPS): the stamp's endpoint is a URL,
		// and BuildDoHURL() prepends "https://" at query time.
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
