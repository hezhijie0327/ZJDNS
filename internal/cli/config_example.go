package cli

import (
	"encoding/json"

	"zjdns/config"
)

// GenerateExampleConfig returns a complete example configuration as indented
// JSON.
func GenerateExampleConfig() string {
	cfg := config.NewDefaultServerConfig()

	cfg.Server.Pprof = config.DefaultPprofPort
	cfg.Server.LogLevel = "info"

	cfg.Server.TLS.CertFile = "/path/to/cert.pem"
	cfg.Server.TLS.KeyFile = "/path/to/key.pem"

	cfg.Server.TLS.KTLS = &config.KTLSSettings{KernelTX: true}

	cfg.Server.Features.Cache.MaxEntries = config.DefaultMaxCacheEntries
	cfg.Server.Features.Cache.Persist = config.CachePersistenceSettings{
		File: "cache.db",
	}
	cfg.Server.Features.Cache.PreferStale = true
	cfg.Server.Features.ECS = config.ECSConfig{IPv4: "auto", IPv6: "auto", PreferIPv4: true}
	cfg.Server.Features.LatencyProbe = []config.LatencyProbeStep{
		{Protocol: "ping", Timeout: 100},
		{Protocol: "tcp", Port: config.DefaultProbePortHTTPS, Timeout: 100},
		{Protocol: "tcp", Port: config.DefaultProbePortHTTP, Timeout: 100},
		{Protocol: "udp", Port: config.DefaultProbePortDNS, Timeout: 100},
		{Protocol: "http", Port: config.DefaultProbePortHTTP, Timeout: 100},
		{Protocol: "https", Port: config.DefaultProbePortHTTPS, Timeout: 100},
		{Protocol: "http3", Port: config.DefaultProbePortHTTPS, Timeout: 100},
	}
	cfg.Server.Features.Stats = &config.StatsSettings{}

	cfg.Upstream = []config.UpstreamServer{
		{Address: "223.5.5.5:53", Protocol: "tcp", Proxy: "socks5://127.0.0.1:1080"},
		{Address: "223.6.6.6:53", Protocol: "udp"},
		{Address: "223.5.5.5:853", Protocol: "tls", ServerName: "dns.alidns.com"},
		{Address: "223.6.6.6:853", Protocol: "quic", ServerName: "dns.alidns.com", SkipTLSVerify: true},
		{Address: "https://223.5.5.5:443/dns-query", Protocol: "https", ServerName: "dns.alidns.com", Match: []string{"mixed"}},
		{Address: "https://223.6.6.6:443/dns-query", Protocol: "http3", ServerName: "dns.alidns.com", Match: []string{"!mixed"}},
	}

	cfg.Fallback = []config.UpstreamServer{
		{Address: config.RecursiveIndicator},
	}

	cfg.Rewrite = []config.RewriteRule{
		{ExcludeClients: []string{"10.0.0.100"}},
		{Name: "client-specific.example.com", IncludeClients: []string{"192.168.0.0/24"}, Records: []config.DNSRecordConfig{{Type: "A", Content: "127.0.0.1", TTL: config.DefaultTTL}}},
		{Name: "blocked.example.com", ExcludeClients: []string{"192.168.1.0/24"}, Records: []config.DNSRecordConfig{{Type: "A", Content: "127.0.0.1", TTL: config.DefaultTTL}}},
		{Name: "ipv6.blocked.example.com", Records: []config.DNSRecordConfig{{Type: "AAAA", Content: "::1", TTL: config.DefaultTTL}}},
	}

	cfg.CIDR = []config.CIDRConfig{
		{File: "whitelist.txt", Tag: "file"},
		{Rules: []string{"192.168.0.0/16", "10.0.0.0/8", "2001:db8::/32"}, Tag: "rules"},
		{File: "blacklist.txt", Rules: []string{"127.0.0.1/32"}, Tag: "mixed"},
	}

	data, _ := json.MarshalIndent(cfg, "", "  ")
	return string(data)
}
