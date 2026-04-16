// Package main implements ZJDNS - High Performance DNS Server
package main

import (
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// =============================================================================
// RewriteManager Implementation
// =============================================================================

// NewRewriteManager creates a new DNS rewrite manager
func NewRewriteManager() *RewriteManager {
	rm := &RewriteManager{}
	initialRules := make([]RewriteRule, 0, 16)
	rm.rules.Store(&initialRules)
	rm.rulesLen.Store(0)
	return rm
}

// LoadRules loads rewrite rules into the manager
func (rm *RewriteManager) LoadRules(rules []RewriteRule) error {
	validRules := make([]RewriteRule, 0, len(rules))
	for _, rule := range rules {
		if len(rule.Name) <= MaxDomainLength {
			rule.NormalizedName = NormalizeDomain(rule.Name)
			validRules = append(validRules, rule)
		}
	}

	rm.rules.Store(&validRules)
	rm.rulesLen.Store(uint64(len(validRules)))
	LogInfo("REWRITE: DNS rewriter loaded: %d rules", len(validRules))
	return nil
}

// hasRules checks if any rewrite rules are loaded
func (rm *RewriteManager) hasRules() bool {
	return rm.rulesLen.Load() > 0
}

// RewriteWithDetails checks if a domain should be rewritten and returns the result
func (rm *RewriteManager) RewriteWithDetails(domain string, qtype uint16, qclass uint16) DNSRewriteResult {
	result := DNSRewriteResult{
		Domain:        domain,
		ResponseCode:  dns.RcodeSuccess,
		ShouldRewrite: false,
	}

	if qclass == 0 {
		qclass = dns.ClassINET
	}

	if !rm.hasRules() || len(domain) > MaxDomainLength {
		return result
	}

	rulesPtr := rm.rules.Load()
	if rulesPtr == nil {
		return result
	}
	rules := *rulesPtr
	domain = NormalizeDomain(domain)

	for i := range rules {
		rule := &rules[i]
		if domain != rule.NormalizedName {
			continue
		}

		// Check for response code override at rule level
		if rule.ResponseCode != nil {
			result.ResponseCode = *rule.ResponseCode
			result.ShouldRewrite = true
			return result
		}

		// Process records if configured
		if len(rule.Records) > 0 || len(rule.Additional) > 0 {
			result.Records = make([]dns.RR, 0, len(rule.Records))
			result.Additional = make([]dns.RR, 0, len(rule.Additional))

			// Build answer records
			for _, record := range rule.Records {
				recordType := dns.StringToType[record.Type]
				var recordClass uint16 = dns.ClassINET
				if record.Class != "" {
					if parsedClass, ok := dns.StringToClass[strings.ToUpper(strings.TrimSpace(record.Class))]; ok {
						recordClass = parsedClass
					} else {
						continue
					}
				}
				// Check for record-level response code
				if record.ResponseCode != nil {
					if (record.Type == "" || recordType == qtype) && recordClass == qclass {
						result.ResponseCode = *record.ResponseCode
						result.ShouldRewrite = true
						result.Records = nil
						result.Additional = nil
						return result
					}
					continue
				}
				if recordClass != qclass {
					continue
				}
				// Skip records that don't match query type
				if record.Type != "" && recordType != qtype {
					continue
				}
				if rr := rm.buildDNSRecord(domain, record); rr != nil {
					result.Records = append(result.Records, rr)
				}
			}

			// Build additional records
			for _, record := range rule.Additional {
				if rr := rm.buildDNSRecord(domain, record); rr != nil {
					result.Additional = append(result.Additional, rr)
				}
			}

			result.ShouldRewrite = true
			return result
		}
	}

	return result
}

// buildDNSRecord creates a DNS RR from a record configuration
func (rm *RewriteManager) buildDNSRecord(domain string, record DNSRecordConfig) dns.RR {
	ttl := record.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}

	class := strings.ToUpper(strings.TrimSpace(record.Class))
	if class == "" {
		class = "IN"
	}

	name := dns.Fqdn(domain)
	if record.Name != "" {
		name = dns.Fqdn(record.Name)
	}

	// Build RR string in standard format
	var sb strings.Builder
	sb.Grow(len(name) + len(class) + len(record.Type) + len(record.Content) + 20)
	sb.WriteString(name)
	sb.WriteByte(' ')
	sb.WriteString(strconv.FormatUint(uint64(ttl), 10))
	sb.WriteByte(' ')
	sb.WriteString(class)
	sb.WriteByte(' ')
	sb.WriteString(record.Type)
	sb.WriteByte(' ')
	sb.WriteString(record.Content)

	// Try to parse as standard record
	if rr, err := dns.NewRR(sb.String()); err == nil {
		return rr
	}

	// Fallback to RFC3597 for unknown record types
	rrType, exists := dns.StringToType[record.Type]
	if !exists {
		rrType = 0
	}

	classValue := uint16(dns.ClassINET)
	if parsedClass, ok := dns.StringToClass[class]; ok {
		classValue = parsedClass
	}

	return &dns.RFC3597{
		Hdr:   dns.RR_Header{Name: name, Rrtype: rrType, Class: classValue, Ttl: ttl},
		Rdata: record.Content,
	}
}
