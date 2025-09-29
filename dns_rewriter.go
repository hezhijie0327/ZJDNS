package main

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

func NewDNSRewriter() *DNSRewriter {
	return &DNSRewriter{
		rules: make([]RewriteRule, 0, 32),
	}
}

func (r *DNSRewriter) LoadRules(rules []RewriteRule) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	validRules := make([]RewriteRule, 0, len(rules))
	for _, rule := range rules {
		if len(rule.Name) > MaxDomainNameLengthRFC {
			continue
		}

		validRules = append(validRules, rule)
	}

	r.rules = validRules
	writeLog(LogInfo, "🔄 DNS重写器加载完成: %d条规则", len(validRules))
	return nil
}

// RewriteWithDetails 根据查询详细信息进行重写，支持响应码和自定义记录
func (r *DNSRewriter) RewriteWithDetails(domain string, qtype uint16) DNSRewriteResult {
	result := DNSRewriteResult{
		Domain:        domain,
		ShouldRewrite: false,
		ResponseCode:  dns.RcodeSuccess, // 默认NOERROR
		Records:       nil,
		Additional:    nil,
	}

	if !r.HasRules() || len(domain) > MaxDomainNameLengthRFC {
		return result
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	for i := range r.rules {
		rule := &r.rules[i]

		// 精确匹配域名
		if domain == strings.ToLower(rule.Name) {
			// 处理响应码重写
			if rule.ResponseCode != nil {
				result.ResponseCode = *rule.ResponseCode
				result.ShouldRewrite = true
				// 如果设置了响应码，则不返回记录
				return result
			}

			// 处理自定义记录
			if len(rule.Records) > 0 || len(rule.Additional) > 0 {
				result.Records = make([]dns.RR, 0)
				result.Additional = make([]dns.RR, 0)

				// 处理Answer Section记录
				for _, record := range rule.Records {
					// 检查记录类型是否与查询类型匹配
					recordType := dns.StringToType[record.Type]

					// 特别处理带有response_code的记录，仅当类型匹配时才应用
					if record.ResponseCode != nil {
						if record.Type == "" || recordType == qtype {
							result.ResponseCode = *record.ResponseCode
							result.ShouldRewrite = true
							// 清空已收集的记录，因为我们要返回响应码
							result.Records = nil
							result.Additional = nil
							return result
						}
						// 如果类型不匹配，继续检查其他记录
						continue
					}

					// 如果记录类型不匹配查询类型，则跳过
					if record.Type != "" && recordType != qtype {
						continue
					}

					rr := r.buildDNSRecord(domain, record)
					if rr != nil {
						result.Records = append(result.Records, rr)
					}
				}

				// 处理Additional Section记录
				for _, record := range rule.Additional {
					rr := r.buildDNSRecord(domain, record)
					if rr != nil {
						result.Additional = append(result.Additional, rr)
					}
				}

				result.ShouldRewrite = true
				return result
			}
		}
	}

	return result
}

// buildDNSRecord 根据配置构建DNS记录
func (r *DNSRewriter) buildDNSRecord(domain string, record DNSRecordConfig) dns.RR {
	ttl := record.TTL
	if ttl == 0 {
		ttl = DefaultCacheTTLSeconds // 默认TTL
	}

	// 确定记录名称（优先使用record.Name，否则使用domain）
	name := dns.Fqdn(domain)
	if record.Name != "" {
		name = dns.Fqdn(record.Name)
	}

	// 尝试解析记录内容
	rrStr := fmt.Sprintf("%s %d IN %s %s", name, ttl, record.Type, record.Content)

	// 使用miekg/dns库的解析功能
	rr, err := dns.NewRR(rrStr)
	if err == nil {
		return rr
	}

	// 如果解析失败，使用RFC3597通用格式
	rrType, exists := dns.StringToType[record.Type]
	if !exists {
		rrType = 0
	}

	rfc3597 := &dns.RFC3597{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: rrType,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
	}
	rfc3597.Rdata = record.Content
	return rfc3597
}

func (r *DNSRewriter) HasRules() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.rules) > 0
}
