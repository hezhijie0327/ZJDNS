// Package main implements ZJDNS - High Performance DNS Server
package main

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/miekg/dns"
)

// RewriteRule defines a domain rewrite rule and optional client filters.
type RewriteRule struct {
	Name               string            `json:"name"`
	NormalizedName     string            `json:"normalized_name,omitempty"`
	ResponseCode       *int              `json:"response_code,omitempty"`
	Records            []DNSRecordConfig `json:"records,omitempty"`
	Additional         []DNSRecordConfig `json:"additional,omitempty"`
	ExcludeClients     []string          `json:"exclude_clients,omitempty"`
	IncludeClients     []string          `json:"include_clients,omitempty"`
	ExcludeClientCIDRs []*net.IPNet      `json:"-"`
	IncludeClientCIDRs []*net.IPNet      `json:"-"`
}

// DNSRecordConfig defines a record entry for rewrite responses.
type DNSRecordConfig struct {
	Name         string `json:"name,omitempty"`
	Type         string `json:"type"`
	Class        string `json:"class,omitempty"`
	TTL          uint32 `json:"ttl,omitempty"`
	Content      string `json:"content"`
	ResponseCode *int   `json:"response_code,omitempty"`
}

// DNSRewriteResult carries the result of evaluating rewrite rules for a query.
type DNSRewriteResult struct {
	Domain        string
	ShouldRewrite bool
	ResponseCode  int
	Records       []dns.RR
	Additional    []dns.RR
}

// RewriteManager manages DNS rewrite rules and applies them to incoming queries.
type RewriteManager struct {
	rules              atomic.Pointer[[]RewriteRule]
	rulesLen           atomic.Uint64
	globalExcludeCIDRs atomic.Pointer[[]*net.IPNet]
}

// NewRewriteManager creates a new DNS rewrite manager
func NewRewriteManager() *RewriteManager {
	rm := &RewriteManager{}
	initialRules := make([]RewriteRule, 0, 16)
	initialExcludes := make([]*net.IPNet, 0)
	rm.rules.Store(&initialRules)
	rm.globalExcludeCIDRs.Store(&initialExcludes)
	rm.rulesLen.Store(0)
	return rm
}

// LoadRules loads rewrite rules into the manager
func (rm *RewriteManager) LoadRules(rules []RewriteRule) error {
	validRules := make([]RewriteRule, 0, len(rules))
	globalExcludes := make([]*net.IPNet, 0)
	for i, rule := range rules {
		if len(rule.Name) > MaxDomainLength {
			continue
		}

		if len(rule.ExcludeClients) > 0 {
			nets := make([]*net.IPNet, 0, len(rule.ExcludeClients))
			for _, entry := range rule.ExcludeClients {
				ipNet, err := parseRewriteCIDREntry(entry)
				if err != nil {
					return fmt.Errorf("rewrite rule '%s' invalid exclude_clients entry '%s': %w", rule.Name, entry, err)
				}
				nets = append(nets, ipNet)
			}
			rule.ExcludeClientCIDRs = nets
		}

		if len(rule.IncludeClients) > 0 {
			nets := make([]*net.IPNet, 0, len(rule.IncludeClients))
			for _, entry := range rule.IncludeClients {
				ipNet, err := parseRewriteCIDREntry(entry)
				if err != nil {
					return fmt.Errorf("rewrite rule '%s' invalid include_clients entry '%s': %w", rule.Name, entry, err)
				}
				nets = append(nets, ipNet)
			}
			rule.IncludeClientCIDRs = nets
		}

		if rule.Name == "" {
			if len(rule.Records) > 0 || len(rule.Additional) > 0 || rule.ResponseCode != nil || len(rule.IncludeClientCIDRs) > 0 {
				return fmt.Errorf("rewrite rule %d: unnamed rules may only contain exclude_clients", i)
			}
			if len(rule.ExcludeClientCIDRs) > 0 {
				globalExcludes = append(globalExcludes, rule.ExcludeClientCIDRs...)
			}
			continue
		}

		rule.NormalizedName = NormalizeDomain(rule.Name)
		validRules = append(validRules, rule)
	}

	rm.rules.Store(&validRules)
	rm.rulesLen.Store(uint64(len(validRules)))
	rm.globalExcludeCIDRs.Store(&globalExcludes)
	LogInfo("REWRITE: DNS rewriter loaded: %d rules", len(validRules))
	return nil
}

// parseRewriteCIDREntry parses a CIDR or IP address entry for rewrite client filters
func parseRewriteCIDREntry(entry string) (*net.IPNet, error) {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return nil, errors.New("empty CIDR or IP address")
	}

	if ip := net.ParseIP(entry); ip != nil {
		if ip.To4() != nil {
			return &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}, nil
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
	}

	_, ipNet, err := net.ParseCIDR(entry)
	if err != nil {
		return nil, err
	}
	return ipNet, nil
}

// hasRules checks if any rewrite rules are loaded
func (rm *RewriteManager) hasRules() bool {
	return rm.rulesLen.Load() > 0
}

// RewriteWithDetails checks if a domain should be rewritten and returns the result
func (rm *RewriteManager) RewriteWithDetails(domain string, qtype uint16, qclass uint16, clientIP net.IP) DNSRewriteResult {
	result := DNSRewriteResult{
		Domain:        domain,
		ResponseCode:  dns.RcodeSuccess,
		ShouldRewrite: false,
	}

	if qclass == 0 {
		qclass = dns.ClassINET
	}

	if len(domain) > MaxDomainLength {
		return result
	}

	excludePtr := rm.globalExcludeCIDRs.Load()
	if excludePtr != nil && clientIP != nil {
		for _, ipNet := range *excludePtr {
			if ipNet.Contains(clientIP) {
				return result
			}
		}
	}

	if !rm.hasRules() {
		return result
	}

	rulesPtr := rm.rules.Load()
	if rulesPtr == nil {
		return result
	}
	rules := *rulesPtr
	domain = NormalizeDomain(domain)

ruleLoop:
	for i := range rules {
		rule := &rules[i]
		if domain != rule.NormalizedName {
			continue
		}

		if len(rule.IncludeClientCIDRs) > 0 {
			if clientIP == nil {
				continue ruleLoop
			}
			included := false
			for _, ipNet := range rule.IncludeClientCIDRs {
				if ipNet.Contains(clientIP) {
					included = true
					break
				}
			}
			if !included {
				continue ruleLoop
			}
		}

		if len(rule.ExcludeClientCIDRs) > 0 && clientIP != nil {
			for _, ipNet := range rule.ExcludeClientCIDRs {
				if ipNet.Contains(clientIP) {
					continue ruleLoop
				}
			}
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
