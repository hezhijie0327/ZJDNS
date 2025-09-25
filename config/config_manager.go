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

var globalConfigManager = NewConfigManager()

func LoadConfig(filename string) (*types.ServerConfig, error) {
	return globalConfigManager.LoadConfig(filename)
}
