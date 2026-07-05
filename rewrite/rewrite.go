// Package rewrite provides domain-level DNS response rewriting.
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

	"codeberg.org/miekg/dns"
	dnsutilv2 "codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// No local DNS class constant; use config.DefaultDNSClass.

// Result holds the outcome of a rewrite rule evaluation.
type Result struct {
	Domain        string
	ShouldRewrite bool
	ResponseCode  int
	Records       []dns.RR
	Additional    []dns.RR
	CreatedAt     int64 // Unix timestamp when the rules were loaded (for TTL decrement)
}

// Evaluator manages rewrite rules and evaluates them against queries.
type Evaluator struct {
	rules              atomic.Pointer[[]config.RewriteRule]
	rulesLen           atomic.Uint64
	globalExcludeCIDRs atomic.Pointer[[]*net.IPNet]
	loadedAt           atomic.Int64 // Unix timestamp of last LoadRules
}

// New creates an Evaluator with no rules loaded.
func New() *Evaluator {
	rm := &Evaluator{}
	initialRules := make([]config.RewriteRule, 0, config.DefaultRewriteRulesCapacity)
	initialExcludes := make([]*net.IPNet, 0)
	rm.rules.Store(&initialRules)
	rm.globalExcludeCIDRs.Store(&initialExcludes)
	rm.rulesLen.Store(0)
	return rm
}

// preParseRecordTypes pre-parses Type and Class strings to uint16 values
// to avoid allocation-heavy map lookups on the query hot path.
func preParseRecordTypes(records []config.DNSRecordConfig) {
	for j := range records {
		if t, _ := dnsutilv2.StringToType(records[j].Type); t != 0 {
			records[j].ParsedType = t
		}
		if records[j].Class != "" {
			if parsed, err := dnsutilv2.StringToClass(strings.ToUpper(strings.TrimSpace(records[j].Class))); err == nil {
				records[j].ParsedClass = parsed
			}
		}
		if records[j].ParsedClass == 0 {
			records[j].ParsedClass = dns.ClassINET
		}
	}
}

// LoadRules validates and loads rewrite rules into the Evaluator.
func (e *Evaluator) LoadRules(rules []config.RewriteRule) error {
	validRules := make([]config.RewriteRule, 0, len(rules))
	globalExcludes := make([]*net.IPNet, 0)
	for i, rule := range rules {
		if len(rule.Name) > config.MaxDomainLength {
			log.Warnf("REWRITE: rule name too long (%d chars, max %d), skipping", len(rule.Name), config.MaxDomainLength)
			continue
		}

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

		// Pre-parse Type/Class strings to uint16 to avoid allocation-heavy
		// map lookups and string normalizations on every query (hot path).
		preParseRecordTypes(rule.Records)
		preParseRecordTypes(rule.Additional)

		// Pre-build DNS records from config so they are not e-parsed
		// from zone file strings on every query.
		rule.CachedRecords = make([]dns.RR, 0, len(rule.Records))
		for _, rec := range rule.Records {
			if rec.ResponseCode != nil {
				continue // handled in Evaluate, not a real RR
			}
			if rr := e.buildRecord(rule.Name, rec); rr != nil {
				rule.CachedRecords = append(rule.CachedRecords, rr)
			}
		}
		rule.CachedAdditional = make([]dns.RR, 0, len(rule.Additional))
		for _, rec := range rule.Additional {
			if rec.ResponseCode != nil {
				continue
			}
			if rr := e.buildRecord(rule.Name, rec); rr != nil {
				rule.CachedAdditional = append(rule.CachedAdditional, rr)
			}
		}

		validRules = append(validRules, rule)
	}

	e.rules.Store(&validRules)
	e.rulesLen.Store(uint64(len(validRules)))
	e.globalExcludeCIDRs.Store(&globalExcludes)
	e.loadedAt.Store(log.NowUnix())
	log.Infof("REWRITE: DNS rewriter loaded: %d rules", len(validRules))
	return nil
}

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

// HasRules reports whether any rewrite rules are currently loaded.
func (e *Evaluator) HasRules() bool {
	return e.rulesLen.Load() > 0
}

// Evaluate checks a query against loaded rules and returns a rewrite Result.
func (e *Evaluator) Evaluate(domain string, qtype uint16, qclass uint16, clientIP net.IP) Result {
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

	excludePtr := e.globalExcludeCIDRs.Load()
	if excludePtr != nil && clientIP != nil {
		for _, ipNet := range *excludePtr {
			if ipNet.Contains(clientIP) {
				return result
			}
		}
	}
	if !e.HasRules() {
		return result
	}

	rulesPtr := e.rules.Load()
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
		if len(rule.CachedRecords) > 0 || len(rule.CachedAdditional) > 0 || len(rule.Records) > 0 {
			// Check for per-record response_code overrides first
			// (these are not pre-built into CachedRecords).
			for _, record := range rule.Records {
				if record.ResponseCode == nil {
					continue
				}
				if (record.Type == "" || record.ParsedType == qtype) && record.ParsedClass == qclass {
					result.ResponseCode = *record.ResponseCode
					result.ShouldRewrite = true
					result.Records = nil
					result.Additional = nil
					return result
				}
			}

			// Use pre-built RRs (built once at LoadRules time) —
			// filter by query type and class.
			for _, rr := range rule.CachedRecords {
				// hdr removed
				if rr.Header().Class == qclass && dns.RRToType(rr) == qtype {
					if r := rr.Clone(); r != nil {
						result.Records = append(result.Records, r)
					}
				}
			}
			for _, rr := range rule.CachedAdditional {
				// hdr removed
				if rr.Header().Class == qclass && dns.RRToType(rr) == qtype {
					if r := rr.Clone(); r != nil {
						result.Additional = append(result.Additional, r)
					}
				}
			}
			result.ShouldRewrite = true
			result.CreatedAt = e.loadedAt.Load()
			return result
		}
	}
	return result
}

func (e *Evaluator) buildRecord(domain string, record config.DNSRecordConfig) dns.RR {
	ttl := record.TTL
	if ttl == 0 {
		ttl = config.DefaultTTL
	}
	class := strings.ToUpper(strings.TrimSpace(record.Class))
	if class == "" {
		class = config.DefaultDNSClass
	}
	name := dnsutilv2.Fqdn(domain)
	if record.Name != "" {
		name = dnsutilv2.Fqdn(record.Name)
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
	if rr, err := dns.New(sb.String()); err == nil {
		return rr
	}
	rrType, _ := dnsutilv2.StringToType(record.Type)
	classValue := uint16(dns.ClassINET)
	if parsedClass, err := dnsutilv2.StringToClass(class); err == nil {
		classValue = parsedClass
	}
	return &dns.RFC3597{
		Hdr:     dns.Header{Name: name, Class: classValue, TTL: ttl},
		RFC3597: rdata.RFC3597{RRType: rrType, Data: record.Content},
	}
}
