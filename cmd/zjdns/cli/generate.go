package cli

import (
	"encoding/json"
	"fmt"
	"zjdns/config"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"

	// NOTE(DC-05): CLI imports server/protocol/dnscrypt directly for config
	// generation.  Key generation was extracted to internal/dnscryptcrypto,
	// but GenerateDNSCryptConfig still lives in server/protocol/dnscrypt
	// because it wires cert signing into the protocol package's config.
	serverdnscrypt "zjdns/server/protocol/dnscrypt"
)

// generateExampleConfig returns a complete example configuration as indented JSON.
func generateExampleConfig() (string, error) {
	cfg := config.NewDefaultServerConfig()

	// ── server ──────────────────────────────────────────────────────────────

	cfg.Server.Pprof = config.DefaultPprofPort
	cfg.Server.LogLevel = log.DefaultLevel

	// The example advertises every protocol using RFC standard ports with
	// shared-port multiplexing: TCP 443 (DoH+HTTPoverTLCP+DNSCrypt),
	// TCP 853 (DoT+DoT/TLCP), UDP 443 (DoH3), UDP 853 (DoQ+DTLS+DTLCP).
	cfg.Server.Protocol.TLS = config.DefaultTLSPort
	cfg.Server.Protocol.QUIC = config.DefaultQUICPort
	cfg.Server.Protocol.HTTPS = config.HTTPSEndpoint{Port: config.DefaultHTTPSPort, Endpoint: config.DefaultQueryPath}
	cfg.Server.Protocol.HTTP3 = config.HTTPSEndpoint{Port: config.DefaultHTTP3Port, Endpoint: config.DefaultQueryPath}
	cfg.Server.Protocol.DTLS = config.DefaultDTLSPort
	cfg.Server.Protocol.DNSCrypt = config.DefaultDNSCryptPort
	cfg.Server.Protocol.TLCP = config.DefaultTLCPPort
	cfg.Server.Protocol.HTTPTLCP = config.HTTPSEndpoint{Port: config.DefaultHTTPTLCPPort, Endpoint: config.DefaultQueryPath}
	cfg.Server.Protocol.DTLCP = config.DefaultDTLCPPort

	cfg.Server.Certificate.Domain = "dns.example.com"
	cfg.Server.Certificate.TLS = config.TLSCertificate{
		SelfSigned: true,
	}
	// Example identity key pair.  The private key is PUBLIC — anyone copying
	// this config verbatim publishes a known DNSCrypt signing key and all
	// clients of that server are impersonable.  Generate a fresh pair with
	// `zjdns --generate dnscrypt` before deployment (M-low).
	cfg.Server.Certificate.DNSCrypt = config.DNSCryptCertificate{
		PublicKey:  "1A10FA5B04BC9188691C303960080BC93CCE83E7BC922AA5E59C49C34D675074",
		PrivateKey: "34E2546B6F4C1FCE695E0C62DD3D74D39CEA52C70A283E7615EF4B67F82178D51A10FA5B04BC9188691C303960080BC93CCE83E7BC922AA5E59C49C34D675074",
		StateFile:  "./zjdns.dnscrypt",
	}

	cfg.Server.Features.KTLS = &config.KTLSSettings{KernelTX: true}
	cfg.Server.Features.Cache = config.CacheSettings{
		Entries: config.CacheStoreSettings{
			Limit: config.LimitSettings{
				Mem:  config.DefaultMaxCacheEntries,
				Disk: config.DefaultSpillCacheEntries,
			},
			PreferStale: true,
			StateFile:   "./zjdns.cache",
		},
		Latency: config.CacheStoreSettings{
			Limit: config.LimitSettings{
				Mem:  config.DefaultMaxLatencyEntries,
				Disk: config.DefaultSpillLatencyEntries,
			},
			StateFile: "./zjdns.latency",
		},
		Delegation: config.CacheStoreSettings{
			Limit: config.LimitSettings{
				Mem:  config.DefaultMaxDelegationEntries,
				Disk: config.DefaultSpillDelegationEntries,
			},
			StateFile: "./zjdns.delegation",
		},
	}
	cfg.Server.Features.DDR = config.DDRSettings{IPv4: "127.0.0.1", IPv6: "::1"}
	cfg.Server.Features.AddressFamily = "dual"
	cfg.Server.Features.DNSSECEnforce = true
	cfg.Server.Features.ECS = config.ECSConfig{IPv4: "auto", IPv6: "auto", PreferIPv4: true}
	cfg.Server.Features.LatencyProbe = []config.LatencyProbeStep{
		{Protocol: config.ProtoPing, Timeout: int(config.DefaultLatencyProbeTimeout.Milliseconds())},
		{Protocol: config.ProtoTCP, Port: config.DefaultProbePortHTTPS, Timeout: int(config.DefaultLatencyProbeTimeout.Milliseconds())},
		{Protocol: config.ProtoTCP, Port: config.DefaultProbePortHTTP, Timeout: int(config.DefaultLatencyProbeTimeout.Milliseconds())},
		{Protocol: config.ProtoUDP, Port: config.DefaultProbePortDNS, Timeout: int(config.DefaultLatencyProbeTimeout.Milliseconds())},
		{Protocol: config.ProtoHTTP, Port: config.DefaultProbePortHTTP, Timeout: int(config.DefaultLatencyProbeTimeout.Milliseconds())},
		{Protocol: config.ProtoHTTPS, Port: config.DefaultProbePortHTTPS, Timeout: int(config.DefaultLatencyProbeTimeout.Milliseconds())},
		{Protocol: config.ProtoHTTP3, Port: config.DefaultProbePortHTTPS, Timeout: int(config.DefaultLatencyProbeTimeout.Milliseconds())},
	}

	// ── upstream ────────────────────────────────────────────────────────────

	cfg.Upstream = []config.UpstreamServer{
		{Address: "223.5.5.5:53", Protocol: config.ProtoTCP, Proxy: "socks5://127.0.0.1:1080"},
		{Address: "223.6.6.6:53", Protocol: config.ProtoUDP},
		{Address: "223.5.5.5:853", Protocol: config.ProtoTLS, ServerName: "dns.alidns.com"},
		{Address: "223.6.6.6:853", Protocol: config.ProtoQUIC, ServerName: "dns.alidns.com", SkipTLSVerify: true},
		{Address: "https://223.5.5.5:443/dns-query", Protocol: config.ProtoHTTPS, ServerName: "dns.alidns.com", Match: []string{"corp-net"}},
		{Address: "https://223.6.6.6:443/dns-query", Protocol: config.ProtoHTTP3, ServerName: "dns.alidns.com", Match: []string{"!corp-net"}},
		// DNS stamps — protocol auto-detected by normalizeStamps
		{Address: "sdns://AQMAAAAAAAAADDkuOS45Ljk6ODQ0MyBnyEe4yHWM0SAkVUO-dWdG3zTfHYTAC4xHA2jfgh2GPhkyLmRuc2NyeXB0LWNlcnQucXVhZDkubmV0"},
		{Address: "sdns://AgMAAAAAAAAABzkuOS45LjkgKhX11qy258CQGt5Ou8dDsszUiQMrRuFkLwaTaDABJYoSZG5zOS5xdWFkOS5uZXQ6NDQzCi9kbnMtcXVlcnk"},
		// Fallback upstream: results adopted only after DefaultFallbackTimeout
		// (or when every primary has exited without a result) — EDE 65280
		// marks fallback-served answers, which are never cached.
		{Address: "https://1.1.1.1/dns-query", Protocol: config.ProtoHTTPS, ServerName: "one.one.one.one", Fallback: true},
	}

	// ── zone / ruleset ──────────────────────────────────────────────────────

	cfg.Zone = []config.ZoneRule{
		{Match: []string{"gateway"}}, // bypass: gateway-tagged clients skip zone entirely
		{Name: "blocked.com", Rcode: dns.RcodeNameError},
		{Name: "static.example.com", Answer: []config.ZoneRecord{
			{Type: dns.TypeA, TTL: 300, Content: "10.0.0.1"},
			{Type: dns.TypeAAAA, TTL: 3600, Content: "::1"},
		}},
		{
			Name: "*.cdn.example.com", Match: []string{"corp-net", "!guest"},
			Answer: []config.ZoneRecord{{Type: dns.TypeA, TTL: 300, Content: "10.0.0.1"}},
		},
		{
			Name:       "example.com",
			Answer:     []config.ZoneRecord{{Type: dns.TypeA, TTL: 300, Content: "10.0.0.1"}},
			Authority:  []config.ZoneRecord{{Type: dns.TypeSOA, TTL: 3600, Content: "ns1.example.com. admin.example.com. 1 3600 900 86400 3600"}},
			Additional: []config.ZoneRecord{{Type: dns.TypeA, Name: "ns1.example.com", TTL: 3600, Content: "10.0.0.2"}},
		},
	}

	cfg.RuleSet = []config.RuleSet{
		{Type: "ip", Rule: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}, Tag: "corp-net"},
		{Type: "ip", Rule: []string{"0.0.0.0/0"}, Tag: "guest"},
		{Type: "ip", Rule: []string{"10.0.0.1/32"}, Tag: "gateway"},
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal example config: %w", err)
	}
	return string(data), nil
}

// generateDNSCryptConfig wraps the server/dnscrypt config generator for CLI use.
func generateDNSCryptConfig(provider, addr string) (string, error) {
	return serverdnscrypt.GenerateDNSCryptConfig(provider, addr)
}
