// Package rewrite provides domain-based DNS rewrite rules.
package rewrite

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"

	"zjdns/config"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"

	"github.com/miekg/dns"
)

// Result carries the result of evaluating rewrite rules for a query.
type Result struct {
	Domain        string
	ShouldRewrite bool
	ResponseCode  int
	Records       []dns.RR
	Additional    []dns.RR
}

// Manager manages DNS rewrite rules and applies them to incoming queries.
type Manager struct {
	rules              atomic.Pointer[[]config.RewriteRule]
	rulesLen           atomic.Uint64
	globalExcludeCIDRs atomic.Pointer[[]*net.IPNet]
}

// New creates a new DNS rewrite Manager.
func New() *Manager {
	rm := &Manager{}
	initialRules := make([]config.RewriteRule, 0, 16)
	initialExcludes := make([]*net.IPNet, 0)
	rm.rules.Store(&initialRules)
	rm.globalExcludeCIDRs.Store(&initialExcludes)
	rm.rulesLen.Store(0)
	return rm
}

// LoadRules loads rewrite rules into the Manager.
func (rm *Manager) LoadRules(rules []config.RewriteRule) error {
	validRules := make([]config.RewriteRule, 0, len(rules))
	globalExcludes := make([]*net.IPNet, 0)
	for i, rule := range rules {
		if len(rule.Name) > config.MaxDomainLength {
			log.Warnf("REWRITE: rule name too long (%d chars, max %d), skipping", len(rule.Name), config.MaxDomainLength)
			continue
		}
		// Validate record content to prevent DNS record injection
		for j, rec := range rule.Records {
			if strings.Contains(rec.Content, "\n") || strings.HasPrefix(rec.Content, " ") || strings.HasSuffix(rec.Content, " ") {
				return fmt.Errorf("rewrite rule '%s': record %d content must not contain newlines or leading/trailing spaces", rule.Name, j)
			}
		}

		if len(rule.ExcludeClients) > 0 {
			nets := make([]*net.IPNet, 0, len(rule.ExcludeClients))
			for _, entry := range rule.ExcludeClients {
				ipNet, err := parseCIDREntry(entry)
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
				ipNet, err := parseCIDREntry(entry)
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

		rule.NormalizedName = dnsutil.NormalizeDomain(rule.Name)
		validRules = append(validRules, rule)
	}

	rm.rules.Store(&validRules)
	rm.rulesLen.Store(uint64(len(validRules)))
	rm.globalExcludeCIDRs.Store(&globalExcludes)
	log.Infof("REWRITE: DNS rewriter loaded: %d rules", len(validRules))
	return nil
}

// parseCIDREntry parses a CIDR or IP address entry for rewrite client filters.
func parseCIDREntry(entry string) (*net.IPNet, error) {
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

// HasRules reports whether any rewrite rules are loaded.
func (rm *Manager) HasRules() bool {
	return rm.rulesLen.Load() > 0
}

// Evaluate checks if a domain should be rewritten and returns the result.
func (rm *Manager) Evaluate(domain string, qtype uint16, qclass uint16, clientIP net.IP) Result {
	result := Result{
		Domain:        domain,
		ResponseCode:  dns.RcodeSuccess,
		ShouldRewrite: false,
	}
	if qclass == 0 {
		qclass = dns.ClassINET
	}
	if len(domain) > config.MaxDomainLength {
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
	if !rm.HasRules() {
		return result
	}

	rulesPtr := rm.rules.Load()
	if rulesPtr == nil {
		return result
	}
	rules := *rulesPtr
	domain = dnsutil.NormalizeDomain(domain)

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
		if rule.ResponseCode != nil {
			result.ResponseCode = *rule.ResponseCode
			result.ShouldRewrite = true
			return result
		}
		if len(rule.Records) > 0 || len(rule.Additional) > 0 {
			result.Records = make([]dns.RR, 0, len(rule.Records))
			result.Additional = make([]dns.RR, 0, len(rule.Additional))
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
				if record.Type != "" && recordType != qtype {
					continue
				}
				if rr := rm.buildRecord(domain, record); rr != nil {
					result.Records = append(result.Records, rr)
				}
			}
			for _, record := range rule.Additional {
				if rr := rm.buildRecord(domain, record); rr != nil {
					result.Additional = append(result.Additional, rr)
				}
			}
			result.ShouldRewrite = true
			return result
		}
	}
	return result
}

// buildRecord creates a DNS RR from a record configuration.
func (rm *Manager) buildRecord(domain string, record config.DNSRecordConfig) dns.RR {
	ttl := record.TTL
	if ttl == 0 {
		ttl = config.DefaultTTL
	}
	class := strings.ToUpper(strings.TrimSpace(record.Class))
	if class == "" {
		class = "IN"
	}
	name := dns.Fqdn(domain)
	if record.Name != "" {
		name = dns.Fqdn(record.Name)
	}
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
	if rr, err := dns.NewRR(sb.String()); err == nil {
		return rr
	}
	rrType := dns.StringToType[record.Type]
	classValue := uint16(dns.ClassINET)
	if parsedClass, ok := dns.StringToClass[class]; ok {
		classValue = parsedClass
	}
	return &dns.RFC3597{
		Hdr:   dns.RR_Header{Name: name, Rrtype: rrType, Class: classValue, Ttl: ttl},
		Rdata: record.Content,
	}
}
