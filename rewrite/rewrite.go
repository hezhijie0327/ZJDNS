// Package rewrite provides domain-level DNS response rewriting with O(1)
// exact-domain matching, wildcard suffix matching, and file-based rule import.
package rewrite

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
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

// wildcardPrefix marks a domain as a wildcard rule.
const wildcardPrefix = "*."

// Result holds the outcome of a rewrite rule evaluation.
type Result struct {
	Domain        string
	ShouldRewrite bool
	ResponseCode  int
	Records       []dns.RR
	Additional    []dns.RR
	CreatedAt     int64
}

// ruleEntry is a pre-built rewrite result for exact-domain or wildcard matching.
type ruleEntry struct {
	responseCode   int
	records        []dns.RR
	additional     []dns.RR
	includeClients []*net.IPNet
	excludeClients []*net.IPNet
	dynamic        func() []string
	recordConfigs  []config.DNSRecordConfig
}

// Evaluator manages rewrite rules with O(1) map lookup.
type Evaluator struct {
	domainMap          atomic.Pointer[map[string]*ruleEntry] // exact domain → rule
	wildcardMap        atomic.Pointer[map[string]*ruleEntry] // base domain → wildcard rule
	ruleCount          atomic.Uint64
	globalExcludeCIDRs atomic.Pointer[[]*net.IPNet]
	loadedAt           atomic.Int64
}

// New creates an Evaluator with no rules loaded.
func New() *Evaluator {
	rm := &Evaluator{}
	im := make(map[string]*ruleEntry)
	ie := make([]*net.IPNet, 0)
	wm := make(map[string]*ruleEntry)
	rm.domainMap.Store(&im)
	rm.wildcardMap.Store(&wm)
	rm.globalExcludeCIDRs.Store(&ie)
	return rm
}

// LoadRules validates and loads rewrite rules, expanding file-based rules
// and populating both exact and wildcard lookup maps.
func (e *Evaluator) LoadRules(rules []config.RewriteRule) error {
	globalExcludes := make([]*net.IPNet, 0)
	domainMap := make(map[string]*ruleEntry)
	wildcardMap := make(map[string]*ruleEntry)

	for i := range rules {
		rule := &rules[i]

		// File-based expansion — parse each line directly into domainMap/wildcardMap.
		if rule.File != "" {
			n, err := parseRuleFile(rule, domainMap, wildcardMap)
			if err != nil {
				return fmt.Errorf("rewrite file %q: %w", rule.File, err)
			}
			log.Infof("REWRITE: loaded %d domains from %s", n, rule.File)
			continue
		}

		if err := e.loadInlineRule(rule, i, &globalExcludes, domainMap, wildcardMap); err != nil {
			return err
		}
	}

	e.domainMap.Store(&domainMap)
	e.wildcardMap.Store(&wildcardMap)
	e.ruleCount.Store(uint64(len(domainMap) + len(wildcardMap)))
	e.globalExcludeCIDRs.Store(&globalExcludes)
	e.loadedAt.Store(log.NowUnix())
	log.Infof("REWRITE: DNS rewriter loaded: %d exact + %d wildcard", len(domainMap), len(wildcardMap))
	return nil
}

func (e *Evaluator) loadInlineRule(rule *config.RewriteRule, idx int, globalExcludes *[]*net.IPNet,
	domainMap, wildcardMap map[string]*ruleEntry,
) error {
	if len(rule.Name) > config.MaxDomainLength {
		log.Warnf("REWRITE: rule name too long, skipping")
		return nil
	}

	for j, rec := range rule.Records {
		if strings.Contains(rec.Content, "\n") || strings.HasPrefix(rec.Content, " ") || strings.HasSuffix(rec.Content, " ") {
			return fmt.Errorf("rule '%s': record %d invalid content", rule.Name, j)
		}
	}

	if err := parseClientCIDRs(rule); err != nil {
		return err
	}

	// Unnamed rules with only exclude_clients → global exclude.
	if rule.Name == "" {
		if allowed := len(rule.Records) > 0 || len(rule.Additional) > 0 || rule.ResponseCode != nil || len(rule.IncludeClientCIDRs) > 0; allowed {
			return fmt.Errorf("rewrite rule %d: unnamed rules may only contain exclude_clients", idx)
		}
		*globalExcludes = append(*globalExcludes, rule.ExcludeClientCIDRs...)
		return nil
	}

	// Wildcard: *.domain.com → key base domain in wildcardMap.
	if isWildcard := strings.HasPrefix(rule.Name, wildcardPrefix); isWildcard {
		base := rule.Name[len(wildcardPrefix):]
		rule.NormalizedName = zdnsutil.NormalizeDomain(base)
		e.buildEntry(rule, wildcardMap)
		return nil
	}

	// Exact domain match.
	rule.NormalizedName = zdnsutil.NormalizeDomain(rule.Name)
	e.buildEntry(rule, domainMap)
	return nil
}

func (e *Evaluator) buildEntry(rule *config.RewriteRule, m map[string]*ruleEntry) {
	preParseRecordTypes(rule.Records)
	preParseRecordTypes(rule.Additional)
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
	m[rule.NormalizedName] = entry
}

// ---------------------------------------------------------------------------
// File import — CSV format, all RewriteRule fields supported
// ---------------------------------------------------------------------------

// Columns: domain, type, content, ttl, rcode
// Empty cells inherit from the parent rule.
// Header row is optional and auto-detected (first cell == "domain").

// rcodeNames maps config-level rcode strings to dns.Rcode* values.
var rcodeNames = map[string]int{
	"NOERROR":  dns.RcodeSuccess,
	"FORMERR":  dns.RcodeFormatError,
	"SERVFAIL": dns.RcodeServerFailure,
	"NXDOMAIN": dns.RcodeNameError,
	"NOTIMP":   dns.RcodeNotImplemented,
	"REFUSED":  dns.RcodeRefused,
}

// csvRow is one parsed line from a rule CSV file.
// Column order: domain, type, content, ttl, rcode.
type csvRow struct {
	domain  string
	rtype   string // empty = inherit
	content string // empty = inherit
	ttl     string // empty = inherit
	rcode   string // empty = inherit
}

// parseRuleFile reads a CSV file and populates exact/wildcard maps.
// Columns: domain, rcode, type, content, ttl
// Empty cells inherit from the parent RewriteRule.
func parseRuleFile(parent *config.RewriteRule, domainMap, wildcardMap map[string]*ruleEntry) (int, error) {
	f, err := os.Open(parent.File) //nolint:gosec // G304: user-configured file path
	if err != nil {
		return 0, fmt.Errorf("open: %w", err)
	}
	defer func() { _ = f.Close() }()

	// Pre-build parent defaults.
	parentRcode := ""
	if parent.ResponseCode != nil {
		parentRcode = strconv.Itoa(*parent.ResponseCode)
	}
	parentTTL := ""
	for _, r := range parent.Records {
		if r.TTL > 0 {
			parentTTL = strconv.FormatUint(uint64(r.TTL), 10)
			break
		}
	}

	// Accumulate records per domain (handles multi-row domains).
	type accum struct {
		rcode   string
		records []config.DNSRecordConfig
	}
	entries := make(map[string]*accum)

	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		row := parseCSVLine(line)
		if row == nil {
			continue
		}
		// Auto-detect header row.
		if lineNo == 1 && row.domain == "domain" {
			continue
		}
		if row.domain == "" || !zdnsutil.IsValidDomainLabels(row.domain) {
			continue
		}

		key := zdnsutil.NormalizeDomain(row.domain)
		a, ok := entries[key]
		if !ok {
			a = &accum{rcode: row.rcode}
			entries[key] = a
		}
		if row.rtype != "" {
			a.records = append(a.records, config.DNSRecordConfig{
				Type:    row.rtype,
				Content: row.content,
				TTL:     parseTTL(row.ttl, parentTTL),
			})
		}
	}
	if err := sc.Err(); err != nil {
		return 0, fmt.Errorf("read: %w", err)
	}

	count := 0
	for key, a := range entries {
		// Determine rcode.  Custom records reset rcode to NOERROR unless
		// explicitly overridden in the rcode column.
		rc := dns.RcodeSuccess
		rcode := a.rcode
		if rcode == "" {
			if len(a.records) > 0 {
				rcode = "0" // custom RR → NOERROR
			} else {
				rcode = parentRcode
			}
		}
		if n, nameOk := rcodeNames[strings.ToUpper(rcode)]; nameOk {
			rc = n
		} else if n, numErr := strconv.Atoi(rcode); numErr == nil && rcode != "" {
			rc = n
		}

		// Determine records.
		var recs []dns.RR
		if len(a.records) > 0 {
			preParseRecordTypes(a.records)
			recs = buildRRs("", a.records)
		} else if len(parent.Records) > 0 {
			recs = parentEntryRecords(parent)
		}

		entry := &ruleEntry{
			responseCode: rc,
			records:      recs,
			additional:   parentEntryAdditional(parent),
		}

		// Wildcard or exact.
		if isWildcard := strings.HasPrefix(key, "*."); isWildcard {
			wildcardMap[key[len("*."):]] = entry
		} else {
			domainMap[key] = entry
		}
		count++
	}
	return count, nil
}

func parentEntryRecords(parent *config.RewriteRule) []dns.RR {
	preParseRecordTypes(parent.Records)
	return buildRRs("", parent.Records)
}

func parentEntryAdditional(parent *config.RewriteRule) []dns.RR {
	preParseRecordTypes(parent.Additional)
	return buildRRs("", parent.Additional)
}

// parseCSVLine splits a comma-separated line into up to 5 fields.
func parseCSVLine(line string) *csvRow {
	var fields [5]string
	f := fields[:0]
	start := 0
	for i := 0; i < len(line) && len(f) < 5; i++ {
		if line[i] == ',' {
			f = append(f, strings.TrimSpace(line[start:i]))
			start = i + 1
		}
	}
	f = append(f, strings.TrimSpace(line[start:]))
	for len(f) < 5 {
		f = append(f, "")
	}
	return &csvRow{domain: f[0], rtype: f[1], content: f[2], ttl: f[3], rcode: f[4]}
}

func parseTTL(val, parent string) uint32 {
	if val == "" {
		val = parent
	}
	if val == "" {
		return 0
	}
	n, _ := strconv.Atoi(val)
	if n > 0 {
		return uint32(n) //nolint:gosec // G115: TTL values fit uint32
	}
	return 0
}

// ---------------------------------------------------------------------------
// Evaluate
// ---------------------------------------------------------------------------

// Evaluate checks a query against loaded rules.
// O(1) exact match → O(labels) wildcard suffix walk.
func (e *Evaluator) Evaluate(domain string, qtype, qclass uint16, clientIP net.IP) Result {
	result := Result{ResponseCode: dns.RcodeSuccess}
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
	if e.ruleCount.Load() == 0 {
		return result
	}

	domain = zdnsutil.NormalizeDomain(domain)

	// 1. O(1) exact match.
	dm := e.domainMap.Load()
	if dm != nil {
		if entry, ok := (*dm)[domain]; ok {
			if e.matchEntry(entry, domain, qtype, qclass, clientIP, &result) {
				return result
			}
		}
	}

	// 2. Wildcard suffix walk — O(labels).
	wm := e.wildcardMap.Load()
	if wm != nil && len(*wm) > 0 {
		// Walk from leftmost label to parent domains.
		rest := domain
		for {
			idx := strings.IndexByte(rest, '.')
			if idx < 0 {
				break
			}
			rest = rest[idx+1:]
			if rest == "" {
				break
			}
			if entry, ok := (*wm)[rest]; ok {
				if e.matchEntry(entry, domain, qtype, qclass, clientIP, &result) {
					return result
				}
			}
		}
	}

	return result
}

func (e *Evaluator) matchEntry(entry *ruleEntry, domain string, qtype, qclass uint16, clientIP net.IP, result *Result) bool {
	// Client filtering.
	if len(entry.includeClients) > 0 {
		if clientIP == nil || !containsAny(entry.includeClients, clientIP) {
			return false
		}
	}
	if len(entry.excludeClients) > 0 && clientIP != nil {
		if containsAny(entry.excludeClients, clientIP) {
			return false
		}
	}

	// Dynamic content.
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
		return true
	}

	// Static content.
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
	return true
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// HasRules reports whether any rewrite rules are currently loaded.
func (e *Evaluator) HasRules() bool { return e.ruleCount.Load() > 0 }

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

func parseClientCIDRs(rule *config.RewriteRule) error {
	if len(rule.ExcludeClients) > 0 {
		nets, err := parseCIDRList(rule.ExcludeClients)
		if err != nil {
			return fmt.Errorf("rule '%s' invalid exclude_clients: %w", rule.Name, err)
		}
		rule.ExcludeClientCIDRs = nets
	}
	if len(rule.IncludeClients) > 0 {
		nets, err := parseCIDRList(rule.IncludeClients)
		if err != nil {
			return fmt.Errorf("rule '%s' invalid include_clients: %w", rule.Name, err)
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
		return nil, errors.New("empty CIDR")
	}
	if ip := net.ParseIP(entry); ip != nil {
		if ip.To4() != nil {
			return &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}, nil
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
	}
	_, ipNet, err := net.ParseCIDR(entry)
	return ipNet, err
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
