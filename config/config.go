package config

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	zjdns "zjdns/dns"
	"zjdns/types"
	"zjdns/utils"
)

func NewConfigManager() *ConfigManager {
	return &ConfigManager{}
}

// LoadConfig 从文件加载配置
func (cm *ConfigManager) LoadConfig(configFile string) (*ServerConfig, error) {
	// 读取配置文件
	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("📖 读取配置文件失败: %w", err)
	}

	// 解析JSON配置
	config := &ServerConfig{}
	if err := json.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("📖 解析配置文件失败: %w", err)
	}

	// 验证配置
	if err := cm.validateConfig(config); err != nil {
		return nil, fmt.Errorf("✅ 配置验证失败: %w", err)
	}

	// 如果启用了DDR功能，则自动添加DDR相关的重写规则
	if cm.shouldEnableDDR(config) {
		cm.addDDRRecords(config)
	}

	utils.WriteLog(zjdns.LogInfo, "✅ 配置加载成功: %s", configFile)
	return config, nil
}

// validateConfig 验证配置文件的有效性
func (cm *ConfigManager) validateConfig(config *ServerConfig) error {
	// 日志级别验证
	validLevels := map[string]utils.LogLevel{
		"none": utils.LogNone, "error": utils.LogError, "warn": utils.LogWarn,
		"info": utils.LogInfo, "debug": utils.LogDebug,
	}
	if level, ok := validLevels[strings.ToLower(config.Server.LogLevel)]; ok {
		utils.SetLogLevel(level)
	} else {
		return fmt.Errorf("❌ 无效的日志级别: %s", config.Server.LogLevel)
	}

	// ECS配置验证
	if config.Server.DefaultECS != "" {
		ecs := strings.ToLower(config.Server.DefaultECS)
		validPresets := []string{"auto", "auto_v4", "auto_v6"}
		isValidPreset := false
		for _, preset := range validPresets {
			if ecs == preset {
				isValidPreset = true
				break
			}
		}
		if !isValidPreset {
			if _, _, err := net.ParseCIDR(config.Server.DefaultECS); err != nil {
				return fmt.Errorf("🌍 ECS子网格式错误: %w", err)
			}
		}
	}

	// 上游服务器验证
	for i, server := range config.Upstream {
		if server.Address != zjdns.RecursiveServerIndicator {
			if _, _, err := net.SplitHostPort(server.Address); err != nil {
				if server.Protocol == "https" || server.Protocol == "http3" {
					if _, err := url.Parse(server.Address); err != nil {
						return fmt.Errorf("🔗 上游服务器 %d 地址格式错误: %w", i, err)
					}
				} else {
					return fmt.Errorf("🔗 上游服务器 %d 地址格式错误: %w", i, err)
				}
			}
		}

		validPolicies := map[string]bool{"all": true, "trusted_only": true, "untrusted_only": true}
		if !validPolicies[server.Policy] {
			return fmt.Errorf("🛡️ 上游服务器 %d 信任策略无效: %s", i, server.Policy)
		}

		validProtocols := map[string]bool{"udp": true, "tcp": true, "tls": true, "quic": true, "https": true, "http3": true}
		if server.Protocol != "" && !validProtocols[strings.ToLower(server.Protocol)] {
			return fmt.Errorf("🔌 上游服务器 %d 协议无效: %s", i, server.Protocol)
		}

		protocol := strings.ToLower(server.Protocol)
		if utils.IsSecureProtocol(protocol) && server.ServerName == "" {
			return fmt.Errorf("🔒 上游服务器 %d 使用 %s 协议需要配置 server_name", i, server.Protocol)
		}
	}

	// Redis配置验证
	if config.Redis.Address != "" {
		if _, _, err := net.SplitHostPort(config.Redis.Address); err != nil {
			return fmt.Errorf("💾 Redis地址格式错误: %w", err)
		}
	} else {
		if config.Server.Features.ServeStale {
			utils.WriteLog(utils.LogWarn, "⚠️ 无缓存模式下禁用过期缓存服务功能")
			config.Server.Features.ServeStale = false
		}
		if config.Server.Features.Prefetch {
			utils.WriteLog(utils.LogWarn, "⚠️ 无缓存模式下禁用预取功能")
			config.Server.Features.Prefetch = false
		}
	}

	// TLS证书验证
	if config.Server.TLS.CertFile != "" || config.Server.TLS.KeyFile != "" {
		if config.Server.TLS.CertFile == "" || config.Server.TLS.KeyFile == "" {
			return fmt.Errorf("🔐 证书和私钥文件必须同时配置")
		}

		if !utils.IsValidFilePath(config.Server.TLS.CertFile) {
			return fmt.Errorf("📄 证书文件不存在: %s", config.Server.TLS.CertFile)
		}
		if !utils.IsValidFilePath(config.Server.TLS.KeyFile) {
			return fmt.Errorf("🔑 私钥文件不存在: %s", config.Server.TLS.KeyFile)
		}

		if _, err := tls.LoadX509KeyPair(config.Server.TLS.CertFile, config.Server.TLS.KeyFile); err != nil {
			return fmt.Errorf("🔐 证书加载失败: %w", err)
		}

		utils.WriteLog(utils.LogInfo, "✅ TLS证书验证通过")
	}

	return nil
}

// getDefaultConfig 获取默认配置
func (cm *ConfigManager) getDefaultConfig() *types.ServerConfig {
	config := &types.ServerConfig{}

	config.Server.Port = zjdns.DefaultDNSPort
	config.Server.LogLevel = zjdns.DefaultLogLevel
	config.Server.DefaultECS = "auto"
	config.Server.TrustedCIDRFile = ""
	config.Server.DDR.Domain = "dns.example.com"
	config.Server.DDR.IPv4 = "127.0.0.1"
	config.Server.DDR.IPv6 = "::1"

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

var globalConfigManager = NewConfigManager()

func LoadConfig(filename string) (*types.ServerConfig, error) {
	return globalConfigManager.LoadConfig(filename)
}

func GenerateExampleConfig() string {
	config := globalConfigManager.getDefaultConfig()

	config.Server.LogLevel = zjdns.DefaultLogLevel
	config.Server.DefaultECS = "auto"
	config.Server.TrustedCIDRFile = "trusted_cidr.txt"

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

// shouldEnableDDR 检查是否应该启用DDR功能
func (cm *ConfigManager) shouldEnableDDR(config *types.ServerConfig) bool {
	return config.Server.DDR.Domain != "" &&
		(config.Server.DDR.IPv4 != "" || config.Server.DDR.IPv6 != "")
}

// addDDRRecords 添加DDR相关的A和AAAA记录重写规则
func (cm *ConfigManager) addDDRRecords(config *types.ServerConfig) {
	domain := strings.TrimSuffix(config.Server.DDR.Domain, ".")

	// 创建通用的SVCB记录配置文本
	svcbRecord1Text := "1 . alpn=doq,dot port=" + config.Server.TLS.Port
	svcbRecord2Text := "2 . alpn=h3,h2 port=" + config.Server.TLS.HTTPS.Port

	// 添加IPv4和IPv6提示
	if config.Server.DDR.IPv4 != "" {
		svcbRecord1Text += " ipv4hint=" + config.Server.DDR.IPv4
		svcbRecord2Text += " ipv4hint=" + config.Server.DDR.IPv4
	}

	if config.Server.DDR.IPv6 != "" {
		svcbRecord1Text += " ipv6hint=" + config.Server.DDR.IPv6
		svcbRecord2Text += " ipv6hint=" + config.Server.DDR.IPv6
	}

	// 添加IPv4记录
	if config.Server.DDR.IPv4 != "" {
		_ = types.DNSRecordConfig{
			Type:    "A",
			Content: config.Server.DDR.IPv4,
			TTL:     300,
		}
	}

	// 添加IPv6记录
	if config.Server.DDR.IPv6 != "" {
		_ = types.DNSRecordConfig{
			Type:    "AAAA",
			Content: config.Server.DDR.IPv6,
			TTL:     300,
		}
	}

	// 添加DDR SVCB记录规则
	if config.Server.DDR.IPv4 != "" || config.Server.DDR.IPv6 != "" {
		// 统一的DDR SVCB记录规则名称列表
		ddrRuleNames := []string{
			"_dns.resolver.arpa",
			"_dns." + domain,
		}

		// 如果服务器运行在非标准端口上，添加 _port._dns.domain 记录
		if config.Server.Port != "" && config.Server.Port != zjdns.DefaultDNSPort {
			ddrRuleNames = append(ddrRuleNames, "_"+config.Server.Port+"._dns."+domain)
		}

		// 为每个规则名称添加相同的SVCB记录
		for _, ruleName := range ddrRuleNames {
			ddrRule := types.RewriteRule{
				Name: ruleName,
				Records: []types.DNSRecordConfig{
					{
						Type:    "SVCB",
						Content: svcbRecord1Text,
						TTL:     300,
					},
					{
						Type:    "SVCB",
						Content: svcbRecord2Text,
						TTL:     300,
					},
				},
			}
			config.Rewrite = append(config.Rewrite, ddrRule)
			utils.WriteLog(utils.LogDebug, "📝 添加DDR SVCB重写规则: %s", ruleName)
		}

		// 添加用于直接查询的A/AAAA记录规则
		var directRecords []types.DNSRecordConfig
		if config.Server.DDR.IPv4 != "" {
			directRecords = append(directRecords, types.DNSRecordConfig{
				Type:    "A",
				Content: config.Server.DDR.IPv4,
				TTL:     300,
			})
		}
		if config.Server.DDR.IPv6 != "" {
			directRecords = append(directRecords, types.DNSRecordConfig{
				Type:    "AAAA",
				Content: config.Server.DDR.IPv6,
				TTL:     300,
			})
		}

		if len(directRecords) > 0 {
			directRule := types.RewriteRule{
				Name:    domain,
				Records: directRecords,
			}
			config.Rewrite = append(config.Rewrite, directRule)
			utils.WriteLog(utils.LogDebug, "📝 添加DDR直接查询重写规则: %s (%d条记录)", domain, len(directRecords))
		}
	}
}
