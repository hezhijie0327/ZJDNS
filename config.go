package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

// ==================== 配置管理器 ====================

type ConfigManager struct{}

func NewConfigManager() *ConfigManager {
	return &ConfigManager{}
}

func (cm *ConfigManager) LoadConfig(filename string) (*ServerConfig, error) {
	config := cm.getDefaultConfig()

	if filename == "" {
		writeLog(LogInfo, "📄 使用默认配置")
		return config, nil
	}

	if !isValidFilePath(filename) {
		return nil, fmt.Errorf("❌ 无效的配置文件路径: %s", filename)
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("📖 读取配置文件失败: %w", err)
	}

	if len(data) > MaxConfigFileSizeBytes {
		return nil, fmt.Errorf("📏 配置文件过大: %d bytes", len(data))
	}

	if err := json.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("📦 解析配置文件失败: %w", err)
	}

	writeLog(LogInfo, "✅ 配置文件加载成功: %s", filename)
	return config, cm.ValidateConfig(config)
}

func (cm *ConfigManager) ValidateConfig(config *ServerConfig) error {
	// 日志级别验证
	validLevels := map[string]LogLevel{
		"none": LogNone, "error": LogError, "warn": LogWarn,
		"info": LogInfo, "debug": LogDebug,
	}
	if level, ok := validLevels[strings.ToLower(config.Server.LogLevel)]; ok {
		SetLogLevel(level)
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
		if !server.IsRecursive() {
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
		if isSecureProtocol(protocol) && server.ServerName == "" {
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
			writeLog(LogWarn, "⚠️ 无缓存模式下禁用过期缓存服务功能")
			config.Server.Features.ServeStale = false
		}
		if config.Server.Features.Prefetch {
			writeLog(LogWarn, "⚠️ 无缓存模式下禁用预取功能")
			config.Server.Features.Prefetch = false
		}
	}

	// TLS证书验证
	if config.Server.TLS.CertFile != "" || config.Server.TLS.KeyFile != "" {
		if config.Server.TLS.CertFile == "" || config.Server.TLS.KeyFile == "" {
			return fmt.Errorf("🔐 证书和私钥文件必须同时配置")
		}

		if !isValidFilePath(config.Server.TLS.CertFile) {
			return fmt.Errorf("📄 证书文件不存在: %s", config.Server.TLS.CertFile)
		}
		if !isValidFilePath(config.Server.TLS.KeyFile) {
			return fmt.Errorf("🔑 私钥文件不存在: %s", config.Server.TLS.KeyFile)
		}

		if _, err := tls.LoadX509KeyPair(config.Server.TLS.CertFile, config.Server.TLS.KeyFile); err != nil {
			return fmt.Errorf("🔐 证书加载失败: %w", err)
		}

		writeLog(LogInfo, "✅ TLS证书验证通过")
	}

	return nil
}

func (cm *ConfigManager) getDefaultConfig() *ServerConfig {
	config := &ServerConfig{}

	config.Server.Port = DefaultDNSPort
	config.Server.IPv6 = true
	config.Server.LogLevel = "info"
	config.Server.DefaultECS = "auto"
	config.Server.TrustedCIDRFile = ""

	config.Server.TLS.Port = DefaultSecureDNSPort
	config.Server.TLS.HTTPS.Port = DefaultHTTPSPort
	config.Server.TLS.HTTPS.Endpoint = strings.TrimPrefix(DefaultDNSQueryPath, "/")
	config.Server.TLS.CertFile = ""
	config.Server.TLS.KeyFile = ""

	config.Server.Features.ServeStale = false
	config.Server.Features.Prefetch = false
	config.Server.Features.DNSSEC = true
	config.Server.Features.HijackProtection = false
	config.Server.Features.Padding = false

	config.Redis.Address = ""
	config.Redis.Password = ""
	config.Redis.Database = 0
	config.Redis.KeyPrefix = "zjdns:"

	config.Upstream = []UpstreamServer{}
	config.Rewrite = []RewriteRule{}

	return config
}

var globalConfigManager = NewConfigManager()

func LoadConfig(filename string) (*ServerConfig, error) {
	return globalConfigManager.LoadConfig(filename)
}

func GenerateExampleConfig() string {
	config := globalConfigManager.getDefaultConfig()

	config.Server.LogLevel = "info"
	config.Server.DefaultECS = "auto"
	config.Server.TrustedCIDRFile = "trusted_cidr.txt"

	config.Server.TLS.CertFile = "/path/to/cert.pem"
	config.Server.TLS.KeyFile = "/path/to/key.pem"
	config.Server.TLS.HTTPS.Port = DefaultHTTPSPort
	config.Server.TLS.HTTPS.Endpoint = strings.TrimPrefix(DefaultDNSQueryPath, "/")

	config.Redis.Address = "127.0.0.1:6379"
	config.Server.Features.ServeStale = true
	config.Server.Features.Prefetch = true
	config.Server.Features.HijackProtection = true
	config.Server.Features.Padding = false

	config.Upstream = []UpstreamServer{
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
			Address: RecursiveServerIndicator,
			Policy:  "all",
		},
	}

	config.Rewrite = []RewriteRule{
		{
			TypeString:  "exact",
			Pattern:     "blocked.example.com",
			Replacement: "127.0.0.1",
		},
		{
			TypeString:  "suffix",
			Pattern:     "ads.example.com",
			Replacement: "127.0.0.1",
		},
	}

	data, _ := json.MarshalIndent(config, "", "  ")
	return string(data)
}
