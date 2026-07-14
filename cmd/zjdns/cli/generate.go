package cli

import (
	"encoding/json"
	"zjdns/config"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
	serverdnscrypt "zjdns/server/dnscrypt"
)

// generateExampleConfig returns a complete example configuration as indented JSON.
func generateExampleConfig() string {
	cfg := config.NewDefaultServerConfig()

	cfg.Server.Pprof = config.DefaultPprofPort
	cfg.Server.LogLevel = log.DefaultLevel

	cfg.Server.TLS.CertFile = "/path/to/cert.pem"
	cfg.Server.TLS.KeyFile = "/path/to/key.pem"

	cfg.Server.TLS.KTLS = &config.KTLSSettings{KernelTX: true}

	cfg.Server.DNSCrypt = config.DNSCryptSettings{
		Port:         config.DefaultDNSCryptPort,
		ProviderName: "2.dnscrypt-cert.example.com",
		PublicKey:    "1A10FA5B04BC9188691C303960080BC93CCE83E7BC922AA5E59C49C34D675074",
		PrivateKey:   "34E2546B6F4C1FCE695E0C62DD3D74D39CEA52C70A283E7615EF4B67F82178D51A10FA5B04BC9188691C303960080BC93CCE83E7BC922AA5E59C49C34D675074",
		ESVersion:    "xwingpq",
	}

	cfg.Server.Features.Database.DBPath = "cache.db"
	cfg.Server.Features.Database.MMapSizeMB = config.DefaultCacheMMapSizeMB
	cfg.Server.Features.Database.CacheSizeMB = config.DefaultCacheCacheSizeMB

	cfg.Server.Features.Cache.MaxEntries = config.DefaultMaxCacheEntries
	cfg.Server.Features.Cache.PreferStale = true

	cfg.Server.Features.ECS = config.ECSConfig{IPv4: "auto", IPv6: "auto", PreferIPv4: true}
	cfg.Server.Features.LatencyProbe = []config.LatencyProbeStep{
		{Protocol: config.ProtoPing, Timeout: int(config.DefaultLatencyProbeTimeout.Milliseconds())},
		{Protocol: config.ProtoTCP, Port: config.DefaultProbePortHTTPS, Timeout: int(config.DefaultLatencyProbeTimeout.Milliseconds())},
		{Protocol: config.ProtoTCP, Port: config.DefaultProbePortHTTP, Timeout: int(config.DefaultLatencyProbeTimeout.Milliseconds())},
		{Protocol: config.ProtoUDP, Port: config.DefaultProbePortDNS, Timeout: int(config.DefaultLatencyProbeTimeout.Milliseconds())},
		{Protocol: config.ProtoHTTPPlain, Port: config.DefaultProbePortHTTP, Timeout: int(config.DefaultLatencyProbeTimeout.Milliseconds())},
		{Protocol: config.ProtoHTTP, Port: config.DefaultProbePortHTTPS, Timeout: int(config.DefaultLatencyProbeTimeout.Milliseconds())},
		{Protocol: config.ProtoHTTP3, Port: config.DefaultProbePortHTTPS, Timeout: int(config.DefaultLatencyProbeTimeout.Milliseconds())},
	}
	cfg.Upstream = []config.UpstreamServer{
		{Address: "223.5.5.5:53", Protocol: config.ProtoTCP, Proxy: "socks5://127.0.0.1:1080"},
		{Address: "223.6.6.6:53", Protocol: config.ProtoUDP},
		{Address: "223.5.5.5:853", Protocol: config.ProtoTLS, ServerName: "dns.alidns.com"},
		{Address: "223.6.6.6:853", Protocol: config.ProtoQUIC, ServerName: "dns.alidns.com", SkipTLSVerify: true},
		{Address: "https://223.5.5.5:443/dns-query", Protocol: config.ProtoHTTP, ServerName: "dns.alidns.com", Match: []string{"corp-net"}},
		{Address: "https://223.6.6.6:443/dns-query", Protocol: config.ProtoHTTP3, ServerName: "dns.alidns.com", Match: []string{"!corp-net"}},
		// DNS stamps — protocol auto-detected by normalizeStamps
		{Address: "sdns://AQMAAAAAAAAADDkuOS45Ljk6ODQ0MyBnyEe4yHWM0SAkVUO-dWdG3zTfHYTAC4xHA2jfgh2GPhkyLmRuc2NyeXB0LWNlcnQucXVhZDkubmV0"},
		{Address: "sdns://AgMAAAAAAAAABzkuOS45LjkgKhX11qy258CQGt5Ou8dDsszUiQMrRuFkLwaTaDABJYoSZG5zOS5xdWFkOS5uZXQ6NDQzCi9kbnMtcXVlcnk"},
	}

	cfg.Fallback = []config.UpstreamServer{
		{Address: config.RecursiveIndicator},
		{Address: "sdns://AQcAAAAAAAAAEjk0LjE0MC4xNC4xNDA6NTQ0MyC16ETWuDo-PhJo62gfvqcN48X6aNvWiBQdvy7AZrLa-iUyLmRuc2NyeXB0LnVuZmlsdGVyZWQubnMxLmFkZ3VhcmQuY29t"},
		{Address: "149.112.112.9:53", Protocol: config.ProtoUDP, NoCache: true},
	}

	cfg.Zone.BypassTags = []string{"gateway"}

	cfg.Zone.Rules = []config.ZoneRule{
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
		log.Warnf("CONFIG: example config marshal failed: %v", err)
		return ""
	}
	return string(data)
}

// generateDNSCryptConfig wraps the server/dnscrypt config generator for CLI use.
func generateDNSCryptConfig(provider, addr, esVersion string) (string, error) {
	return serverdnscrypt.GenerateDNSCryptConfig(provider, addr, esVersion)
}
