package config

import (
	"strings"

	zjdns "zjdns/dns"
	"zjdns/types"
	"zjdns/utils"
)

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
