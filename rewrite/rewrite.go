// Package rewrite provides domain-level DNS response rewriting with O(1)
// exact-domain matching via map lookup.
package rewrite

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// Result holds the outcome of a rewrite rule evaluation.
type Result struct {
	Domain        string
	ShouldRewrite bool
	ResponseCode  int
	Records       []dns.RR
	Additional    []dns.RR
	CreatedAt     int64 // Unix timestamp when the rules were loaded
}

// ruleEntry is a pre-built rewrite result for exact-domain matching.
type ruleEntry struct {
	responseCode   int
	records        []dns.RR
	additional     []dns.RR
	includeClients []*net.IPNet
	excludeClients []*net.IPNet
	dynamic        func() []string // DynamicContent callback; nil for static
	recordConfigs  []config.DNSRecordConfig
}

// Evaluator manages rewrite rules with O(1) map lookup for all rule types.
type Evaluator struct {
	domainMap          atomic.Pointer[map[string]*ruleEntry]
	ruleCount          atomic.Uint64
	globalExcludeCIDRs atomic.Pointer[[]*net.IPNet]
	loadedAt           atomic.Int64
}

// New creates an Evaluator with no rules loaded.
func New() *Evaluator {
	rm := &Evaluator{}
	initialMap := make(map[string]*ruleEntry)
	initialExcludes := make([]*net.IPNet, 0)
	rm.domainMap.Store(&initialMap)
	rm.globalExcludeCIDRs.Store(&initialExcludes)
	return rm
}

// preParseRecordTypes pre-parses Type/Class strings to uint16 for hot-path use.
func preParseRecordTypes(records []config.DNSRecordConfig) {
	for j := range records {
		if t, _ := dnsutil.StringToType(records[j].Type); t != 0 {
			records[j].ParsedType = t
		}
		if records[j].Class != "" {
			if parsed, err := dnsutil.StringToClass(strings.ToUpper(strings.TrimSpace(records[j].Class))); err == nil {
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
	globalExcludes := make([]*net.IPNet, 0)
	domainMap := make(map[string]*ruleEntry)

	for i := range rules {
		rule := &rules[i]
		if len(rule.Name) > config.MaxDomainLength {
			log.Warnf("REWRITE: rule name too long (%d chars, max %d), skipping", len(rule.Name), config.MaxDomainLength)
			continue
		}

		for j, rec := range rule.Records {
			if strings.Contains(rec.Content, "\n") || strings.HasPrefix(rec.Content, " ") || strings.HasSuffix(rec.Content, " ") {
				return fmt.Errorf("rewrite rule '%s': record %d content must not contain newlines or leading/trailing spaces", rule.Name, j)
			}
		}

		if err := parseClientCIDRs(rule); err != nil {
			return err
		}

		if rule.Name == "" {
			if len(rule.Records) > 0 || len(rule.Additional) > 0 || rule.ResponseCode != nil || len(rule.IncludeClientCIDRs) > 0 {
				return fmt.Errorf("rewrite rule %d: unnamed rules may only contain exclude_clients", i)
			}
			globalExcludes = append(globalExcludes, rule.ExcludeClientCIDRs...)
			continue
		}

		rule.NormalizedName = zdnsutil.NormalizeDomain(rule.Name)
		preParseRecordTypes(rule.Records)
		preParseRecordTypes(rule.Additional)

		// Pre-build RRs for static rules.
		if rule.DynamicContent == nil {
			rule.CachedRecords = buildRRs(rule.Name, rule.Records)
			rule.CachedAdditional = buildRRs(rule.Name, rule.Additional)
		}

		entry := &ruleEntry{
			responseCode:   dns.RcodeSuccess,
			records:        rule.CachedRecords,
			additional:     rule.CachedAdditional,
			includeClients: rule.IncludeClientCIDRs,
			excludeClients: rule.ExcludeClientCIDRs,
			dynamic:        rule.DynamicContent,
			recordConfigs:  rule.Records,
		}
		if rule.ResponseCode != nil {
			entry.responseCode = *rule.ResponseCode
		}
		domainMap[rule.NormalizedName] = entry
	}

	e.domainMap.Store(&domainMap)
	e.ruleCount.Store(uint64(len(domainMap)))
	e.globalExcludeCIDRs.Store(&globalExcludes)
	e.loadedAt.Store(log.NowUnix())
	log.Infof("REWRITE: DNS rewriter loaded: %d rules", len(domainMap))
	return nil
}

func parseClientCIDRs(rule *config.RewriteRule) error {
	if len(rule.ExcludeClients) > 0 {
		nets, err := parseCIDRList(rule.ExcludeClients)
		if err != nil {
			return fmt.Errorf("rewrite rule '%s' invalid exclude_clients: %w", rule.Name, err)
		}
		rule.ExcludeClientCIDRs = nets
	}
	if len(rule.IncludeClients) > 0 {
		nets, err := parseCIDRList(rule.IncludeClients)
		if err != nil {
			return fmt.Errorf("rewrite rule '%s' invalid include_clients: %w", rule.Name, err)
		}
		rule.IncludeClientCIDRs = nets
	}
	return nil
}

func parseCIDRList(entries []string) ([]*net.IPNet, error) {
	nets := make([]*net.IPNet, 0, len(entries))
	for _, entry := range entries {
		ipNet, err := parseCIDREntry(entry)
		if err != nil {
			return nil, err
		}
		nets = append(nets, ipNet)
	}
	return nets, nil
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
	return e.ruleCount.Load() > 0
}

// Evaluate checks a query against loaded rules.  O(1) map lookup for all
// rule types — static, client-filtered, and dynamic content.
func (e *Evaluator) Evaluate(domain string, qtype, qclass uint16, clientIP net.IP) Result {
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

	domain = zdnsutil.NormalizeDomain(domain)

	dm := e.domainMap.Load()
	if dm == nil {
		return result
	}
	entry, ok := (*dm)[domain]
	if !ok {
		return result
	}

	// Client filtering.
	if len(entry.includeClients) > 0 {
		if clientIP == nil || !containsAny(entry.includeClients, clientIP) {
			return result
		}
	}
	if len(entry.excludeClients) > 0 && clientIP != nil {
		if containsAny(entry.excludeClients, clientIP) {
			return result
		}
	}

	// Dynamic content — evaluate now.
	if entry.dynamic != nil {
		var contents []string
		for _, record := range entry.recordConfigs {
			if record.ParsedType == qtype && record.ParsedClass == qclass {
				if contents == nil {
					contents = entry.dynamic()
				}
				for _, content := range contents {
					rr := buildRecord(domain, &config.DNSRecordConfig{
						Type:    record.Type,
						Class:   record.Class,
						TTL:     record.TTL,
						Content: strconv.Quote(content),
					})
					if rr != nil {
						result.Records = append(result.Records, rr)
					}
				}
			}
		}
		if len(result.Records) > 0 {
			result.ShouldRewrite = true
			result.CreatedAt = e.loadedAt.Load()
		}
		return result
	}

	// Static content — pre-built.
	result.ResponseCode = entry.responseCode
	for _, rr := range entry.records {
		if rr.Header().Class == qclass && dns.RRToType(rr) == qtype {
			result.Records = append(result.Records, rr)
		}
	}
	for _, rr := range entry.additional {
		if rr.Header().Class == qclass && dns.RRToType(rr) == qtype {
			result.Additional = append(result.Additional, rr)
		}
	}
	if result.ResponseCode != dns.RcodeSuccess || len(result.Records) > 0 || len(result.Additional) > 0 {
		result.ShouldRewrite = true
		result.CreatedAt = e.loadedAt.Load()
	}
	return result
}

func containsAny(nets []*net.IPNet, ip net.IP) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func buildRRs(domain string, records []config.DNSRecordConfig) []dns.RR {
	if len(records) == 0 {
		return nil
	}
	rr := make([]dns.RR, 0, len(records))
	for _, rec := range records {
		if rec.ResponseCode != nil {
			continue
		}
		if r := buildRecord(domain, &rec); r != nil {
			rr = append(rr, r)
		}
	}
	return rr
}

func buildRecord(domain string, record *config.DNSRecordConfig) dns.RR {
	ttl := record.TTL
	if ttl == 0 {
		ttl = config.DefaultTTL
	}
	class := strings.ToUpper(strings.TrimSpace(record.Class))
	if class == "" {
		class = config.DefaultDNSClass
	}
	name := dnsutil.Fqdn(domain)
	if record.Name != "" {
		name = dnsutil.Fqdn(record.Name)
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
	rrType, _ := dnsutil.StringToType(record.Type)
	classValue := uint16(dns.ClassINET)
	if parsedClass, err := dnsutil.StringToClass(class); err == nil {
		classValue = parsedClass
	}
	return &dns.RFC3597{
		Hdr:     dns.Header{Name: name, Class: classValue, TTL: ttl},
		RFC3597: rdata.RFC3597{RRType: rrType, Data: record.Content},
	}
}
