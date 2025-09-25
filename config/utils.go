package config

import (
	"encoding/json"

	zjdns "zjdns/dns"
	"zjdns/types"
)

// getDefaultConfig 获取默认配置
func (cm *ConfigManager) getDefaultConfig() *types.ServerConfig {
	config := &types.ServerConfig{}

	config.Server.Port = zjdns.DefaultDNSPort
	config.Server.LogLevel = zjdns.DefaultLogLevel
	config.Server.DefaultECS = "auto"
	config.Server.TrustedCIDRFile = ""
	config.Server.DDR.Domain = ""
	config.Server.DDR.IPv4 = ""
	config.Server.DDR.IPv6 = ""

	config.Server.TLS.Port = zjdns.DefaultSecureDNSPort
	config.Server.TLS.HTTPS.Port = zjdns.DefaultHTTPSPort
	config.Server.TLS.HTTPS.Endpoint = zjdns.DefaultDNSQueryPath
	config.Server.TLS.CertFile = ""
	config.Server.TLS.KeyFile = ""

	config.Server.Features.ServeStale = false
	config.Server.Features.Prefetch = false
	config.Server.Features.DNSSEC = true
	config.Server.Features.HijackProtection = true
	config.Server.Features.Padding = true
	config.Server.Features.IPv6 = true

	// 速度测试配置
	config.Redis.Address = ""
	config.Redis.Password = ""
	config.Redis.Database = 0
	config.Redis.KeyPrefix = "zjdns:"

	config.Upstream = []types.UpstreamServer{}
	config.Rewrite = []types.RewriteRule{}

	// 添加这一行
	config.Speedtest = []types.SpeedTestMethod{}

	return config
}
func GenerateExampleConfig() string {
	config := globalConfigManager.getDefaultConfig()

	config.Server.TrustedCIDRFile = "trusted_cidr.txt"

	config.Server.DDR.Domain = "dns.example.com"
	config.Server.DDR.IPv4 = "127.0.0.1"
	config.Server.DDR.IPv6 = "::1"

	config.Redis.Address = "127.0.0.1:6379"

	config.Server.TLS.CertFile = "/path/to/cert.pem"
	config.Server.TLS.KeyFile = "/path/to/key.pem"
	config.Server.TLS.HTTPS.Port = zjdns.DefaultHTTPSPort
	config.Server.TLS.HTTPS.Endpoint = zjdns.DefaultDNSQueryPath

	config.Upstream = []types.UpstreamServer{
		{
			Address:  "223.5.5.5:53",
			Policy:   "all",
			Protocol: "tcp",
		},
		{
			Address:  "223.6.6.6:53",
			Policy:   "all",
			Protocol: "udp",
		},
		{
			Address:       "223.5.5.5:853",
			Policy:        "trusted_only",
			Protocol:      "tls",
			ServerName:    "dns.alidns.com",
			SkipTLSVerify: false,
		},
		{
			Address:       "223.6.6.6:853",
			Policy:        "all",
			Protocol:      "quic",
			ServerName:    "dns.alidns.com",
			SkipTLSVerify: true,
		},
		{
			Address:       "https://dns.alidns.com/dns-query",
			Policy:        "all",
			Protocol:      "https",
			ServerName:    "dns.alidns.com",
			SkipTLSVerify: false,
		},
		{
			Address:       "https://dns.alidns.com/dns-query",
			Policy:        "trusted_only",
			Protocol:      "http3",
			ServerName:    "dns.alidns.com",
			SkipTLSVerify: false,
		},
		{
			Address: zjdns.RecursiveServerIndicator,
			Policy:  "all",
		},
	}

	config.Rewrite = []types.RewriteRule{
		{
			Name: "blocked.example.com",
			Records: []types.DNSRecordConfig{
				{
					Type:    "A",
					Content: "127.0.0.1",
					TTL:     300,
				},
			},
		},
		{
			Name: "ipv6.blocked.example.com",
			Records: []types.DNSRecordConfig{
				{
					Type:    "AAAA",
					Content: "::1",
					TTL:     300,
				},
			},
		},
	}

	// 速度测试配置示例
	config.Speedtest = []types.SpeedTestMethod{
		{
			Type:    "icmp",
			Timeout: 1000,
		},
		{
			Type:    "tcp",
			Port:    "443",
			Timeout: 1000,
		},
		{
			Type:    "tcp",
			Port:    "80",
			Timeout: 1000,
		},
		{
			Type:    "udp",
			Port:    "53",
			Timeout: 1000,
		},
	}

	data, _ := json.MarshalIndent(config, "", "  ")
	return string(data)
}
