// Package zone provides DNS zone-file-style query matching and synthetic
// response construction.  Each zone rule is keyed by (QNAME, QTYPE, QCLASS)
// and can return ANSWER + AUTHORITY + ADDITIONAL + RCODE.
package zone

import (
	"bufio"
	"errors"
	"fmt"
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

// key is the composite lookup key: (qname, qtype, qclass).
type key struct {
	qname  string
	qtype  uint16
	qclass uint16
}

// matchTag is a parsed CIDR tag condition.
type matchTag struct {
	tag    string // bare tag name (without !)
	negate bool   // true if !tag
}

// entry is a pre-built zone response for one (qname, qtype, qclass) key.
type entry struct {
	rcode         int
	answer        []dns.RR
	authority     []dns.RR
	additional    []dns.RR
	dynamic       func() []string     // nil for static entries
	recordConfigs []config.ZoneRecord // original config (for dynamic type/class matching)
	matchTags     []matchTag          // parsed CIDR match conditions
}

// Result holds the outcome of a zone rule evaluation.
type Result struct {
	Domain     string
	Matched    bool
	Rcode      int
	Answer     []dns.RR
	Authority  []dns.RR
	Additional []dns.RR
	CreatedAt  int64 // LoadRules timestamp for TTL cycling
}

// Evaluator manages zone rules with O(1) composite-key lookup.
type Evaluator struct {
	exactMap    atomic.Pointer[map[key]*entry] // (qname, qtype, qclass) → entry
	wildcardMap atomic.Pointer[map[key]*entry] // (base, qtype, qclass) → entry
	ruleCount   atomic.Uint64
	loadedAt    atomic.Int64
	usedTags    atomic.Pointer[[]string] // unique tag names referenced by rules
}

// New creates an Evaluator with no rules loaded.
func New() *Evaluator {
	z := &Evaluator{}
	em := make(map[key]*entry)
	wm := make(map[key]*entry)
	ut := make([]string, 0)
	z.exactMap.Store(&em)
	z.wildcardMap.Store(&wm)
	z.usedTags.Store(&ut)
	return z
}

// UsedTags returns the set of unique CIDR tag names referenced by loaded rules.
// The handler uses this to resolve which tags to check for each client IP.
func (e *Evaluator) UsedTags() []string {
	p := e.usedTags.Load()
	if p == nil {
		return nil
	}
	return *p
}

// HasRules reports whether any zone rules are currently loaded.
func (e *Evaluator) HasRules() bool { return e.ruleCount.Load() > 0 }

// LoadRules validates and loads zone rules, populating exact and wildcard
// lookup maps keyed by (qname, qtype, qclass).
func (e *Evaluator) LoadRules(rules []config.ZoneRule) error {
	exactMap := make(map[key]*entry)
	wildcardMap := make(map[key]*entry)
	tagSet := make(map[string]struct{})

	for i := range rules {
		rule := &rules[i]
		if rule.File != "" {
			n, err := parseRuleFile(rule, exactMap, wildcardMap, tagSet)
			if err != nil {
				return fmt.Errorf("zone file %q: %w", rule.File, err)
			}
			log.Infof("ZONE: loaded %d entries from %s", n, rule.File)
			continue
		}
		if err := loadInlineRule(rule, exactMap, wildcardMap, tagSet); err != nil {
			return err
		}
	}

	usedTags := make([]string, 0, len(tagSet))
	for t := range tagSet {
		usedTags = append(usedTags, t)
	}

	e.exactMap.Store(&exactMap)
	e.wildcardMap.Store(&wildcardMap)
	e.ruleCount.Store(uint64(len(exactMap) + len(wildcardMap)))
	e.usedTags.Store(&usedTags)
	e.loadedAt.Store(log.NowUnix())
	log.Infof("ZONE: DNS zone loaded: %d exact + %d wildcard entries", len(exactMap), len(wildcardMap))
	return nil
}

func loadInlineRule(rule *config.ZoneRule, exactMap, wildcardMap map[key]*entry, tagSet map[string]struct{}) error {
	if rule.Name == "" {
		return errors.New("zone rule: name is required")
	}
	if len(rule.Name) > config.MaxDomainLength {
		log.Warnf("ZONE: rule name too long, skipping")
		return nil
	}

	tags, err := parseMatchTags(rule.Match)
	if err != nil {
		return fmt.Errorf("zone rule %q: %w", rule.Name, err)
	}
	for _, t := range tags {
		tagSet[t.tag] = struct{}{}
	}

	normalizedName := zdnsutil.NormalizeDomain(rule.Name)
	loadedAt := log.NowUnix()

	// Group answer records by (Type, Class).
	groups := groupRecordsByTypeClass(rule.Answer)
	if len(groups) > 0 {
		for _, g := range groups {
			e := buildEntry(rule, g.records, rule.Authority, rule.Additional, loadedAt, tags)
			k := key{qname: normalizedName, qtype: g.qtype, qclass: g.qclass}
			if isWildcard := strings.HasPrefix(rule.Name, wildcardPrefix); isWildcard {
				wildcardMap[key{qname: normalizedName[len(wildcardPrefix):], qtype: g.qtype, qclass: g.qclass}] = e
			} else {
				exactMap[k] = e
			}
		}
	} else if rule.Rcode != dns.RcodeSuccess || rule.DynamicContent != nil {
		// Sentinal entry for rcode-only or dynamic rules (match all qtype/qclass).
		e := buildEntry(rule, nil, rule.Authority, rule.Additional, loadedAt, tags)
		k := key{qname: normalizedName, qtype: 0, qclass: 0}
		if isWildcard := strings.HasPrefix(rule.Name, wildcardPrefix); isWildcard {
			wildcardMap[key{qname: normalizedName[len(wildcardPrefix):], qtype: 0, qclass: 0}] = e
		} else {
			exactMap[k] = e
		}
	}

	return nil
}

// recordGroup holds records that share the same (Type, Class).
type recordGroup struct {
	qtype   uint16
	qclass  uint16
	records []config.ZoneRecord
}

func groupRecordsByTypeClass(records []config.ZoneRecord) []recordGroup {
	if len(records) == 0 {
		return nil
	}
	groups := make([]recordGroup, 0, len(records))
	seen := make(map[key]int) // key{qname:"", qtype, qclass} → index in groups
	for _, rec := range records {
		qclass := rec.Class
		if qclass == 0 {
			qclass = dns.ClassINET
		}
		idxKey := key{qtype: rec.Type, qclass: qclass}
		if idx, ok := seen[idxKey]; ok {
			groups[idx].records = append(groups[idx].records, rec)
		} else {
			seen[idxKey] = len(groups)
			groups = append(groups, recordGroup{qtype: rec.Type, qclass: qclass, records: []config.ZoneRecord{rec}})
		}
	}
	return groups
}

func buildEntry(rule *config.ZoneRule, records, authority, additional []config.ZoneRecord, loadedAt int64, tags []matchTag) *entry {
	e := &entry{
		rcode:      rule.Rcode,
		matchTags:  tags,
		dynamic:    rule.DynamicContent,
		answer:     buildRRs(rule.Name, records),
		authority:  buildRRs(rule.Name, authority),
		additional: buildRRs(rule.Name, additional),
	}
	if e.dynamic != nil {
		e.recordConfigs = rule.Answer
	}
	return e
}

// ---------------------------------------------------------------------------
// Evaluate
// ---------------------------------------------------------------------------

// Evaluate checks a query against loaded zone rules.
// matchedTags is the set of CIDR tags the client IP matched (from cidr.Filter).
// nil or empty map means no CIDR matching is active.
func (e *Evaluator) Evaluate(qname string, qtype, qclass uint16, matchedTags map[string]bool) Result {
	result := Result{Rcode: dns.RcodeSuccess}
	if qclass == 0 {
		qclass = dns.ClassINET
	}
	if len(qname) > config.MaxDomainLength {
		return result
	}
	if e.ruleCount.Load() == 0 {
		return result
	}

	qname = zdnsutil.NormalizeDomain(qname)

	// 1. Exact composite key lookup.
	em := e.exactMap.Load()
	if em != nil {
		// Try specific key first.
		if entry, ok := (*em)[key{qname: qname, qtype: qtype, qclass: qclass}]; ok {
			if matchTagsOK(entry.matchTags, matchedTags) {
				return buildResult(qname, entry, qtype, qclass, e.loadedAt.Load())
			}
		}
		// Try sentinel key (qtype=0, qclass=0) for rcode-only / dynamic rules.
		if entry, ok := (*em)[key{qname: qname, qtype: 0, qclass: 0}]; ok {
			if matchTagsOK(entry.matchTags, matchedTags) {
				return buildResult(qname, entry, qtype, qclass, e.loadedAt.Load())
			}
		}
	}

	// 2. Wildcard suffix walk.
	wm := e.wildcardMap.Load()
	if wm != nil && len(*wm) > 0 {
		rest := qname
		for {
			idx := strings.IndexByte(rest, '.')
			if idx < 0 {
				break
			}
			rest = rest[idx+1:]
			if rest == "" {
				break
			}
			// Try specific key.
			if entry, ok := (*wm)[key{qname: rest, qtype: qtype, qclass: qclass}]; ok {
				if matchTagsOK(entry.matchTags, matchedTags) {
					return buildResult(qname, entry, qtype, qclass, e.loadedAt.Load())
				}
			}
			// Try sentinel key.
			if entry, ok := (*wm)[key{qname: rest, qtype: 0, qclass: 0}]; ok {
				if matchTagsOK(entry.matchTags, matchedTags) {
					return buildResult(qname, entry, qtype, qclass, e.loadedAt.Load())
				}
			}
		}
	}

	return result
}

func buildResult(domain string, e *entry, qtype, qclass uint16, loadedAt int64) Result {
	result := Result{
		Domain:     domain,
		Matched:    true,
		Rcode:      e.rcode,
		Answer:     e.answer,
		Authority:  e.authority,
		Additional: e.additional,
		CreatedAt:  loadedAt,
	}

	// Dynamic content: generate records at query time.
	if e.dynamic != nil {
		var contents []string
		for _, rec := range e.recordConfigs {
			recClass := rec.Class
			if recClass == 0 {
				recClass = dns.ClassINET
			}
			if rec.Type == qtype && recClass == qclass {
				if contents == nil {
					contents = e.dynamic()
				}
				for _, content := range contents {
					rr := buildRecord(domain, &config.ZoneRecord{
						Type:    rec.Type,
						Class:   rec.Class,
						TTL:     rec.TTL,
						Content: strconv.Quote(content),
					})
					if rr != nil {
						result.Answer = append(result.Answer, rr)
					}
				}
			}
		}
		if len(result.Answer) > 0 {
			result.Rcode = dns.RcodeSuccess
		}
	}

	return result
}

func matchTagsOK(entryTags []matchTag, matchedTags map[string]bool) bool {
	if len(entryTags) == 0 {
		return true
	}
	if matchedTags == nil {
		// No CIDR filter configured — rules with match tags don't match.
		return false
	}
	for _, mt := range entryTags {
		matched, exists := matchedTags[mt.tag]
		if !exists {
			// Unknown tag — skip rule (tag not configured in CIDR).
			return false
		}
		if mt.negate == matched {
			// negate=true AND matched=true → exclusion tag matched → skip
			// negate=false AND matched=false → inclusion tag not matched → skip
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Match tag parsing
// ---------------------------------------------------------------------------

func parseMatchTags(raw []string) ([]matchTag, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	tags := make([]matchTag, 0, len(raw))
	for _, s := range raw {
		s = strings.TrimSpace(s)
		if s == "" {
			return nil, errors.New("empty match tag")
		}
		negate := strings.HasPrefix(s, "!")
		tag := strings.TrimPrefix(s, "!")
		if tag == "" {
			return nil, fmt.Errorf("invalid match tag %q", s)
		}
		tags = append(tags, matchTag{tag: tag, negate: negate})
	}
	return tags, nil
}

// ---------------------------------------------------------------------------
// Zone file import — zone-file-like format with domain headers and record lines.
//
// Format:
//
//	# comment / blank → skip
//	.domain.name [rcode=N] [match=tag1,!tag2]   ← domain header (starts with .)
//	*.wild.name [rcode=N] [match=tag1,!tag2]    ← wildcard header (starts with *.)
//	  TYPE CONTENT [TTL] [key=value ...]         ← record line (indented, TYPE is numeric)
//
// Record line key=value options: class=N, name=STR, section=answer|authority|additional
// ---------------------------------------------------------------------------

func parseRuleFile(parent *config.ZoneRule, exactMap, wildcardMap map[key]*entry, tagSet map[string]struct{}) (int, error) {
	f, err := os.Open(parent.File) //nolint:gosec // G304: user-configured file path
	if err != nil {
		return 0, fmt.Errorf("open: %w", err)
	}
	defer func() { _ = f.Close() }()

	parentTags, err := parseMatchTags(parent.Match)
	if err != nil {
		return 0, err
	}
	for _, t := range parentTags {
		tagSet[t.tag] = struct{}{}
	}

	sc := bufio.NewScanner(f)
	count := 0

	var (
		curDomain    string
		curWildcard  bool
		curRcode     int
		curTags      []matchTag
		curRecords   []config.ZoneRecord
		curAuthority []config.ZoneRecord
		curAddl      []config.ZoneRecord
	)

	flushDomain := func() {
		if curDomain == "" {
			return
		}
		groups := groupRecordsByTypeClass(curRecords)
		if len(groups) > 0 {
			for _, g := range groups {
				e := &entry{
					rcode:      curRcode,
					matchTags:  curTags,
					answer:     buildRRs("", g.records),
					authority:  buildRRs("", curAuthority),
					additional: buildRRs("", curAddl),
				}
				k := key{qname: curDomain, qtype: g.qtype, qclass: g.qclass}
				if curWildcard {
					wildcardMap[k] = e
				} else {
					exactMap[k] = e
				}
				count++
			}
		} else if curRcode != dns.RcodeSuccess {
			e := &entry{
				rcode:      curRcode,
				matchTags:  curTags,
				authority:  buildRRs("", curAuthority),
				additional: buildRRs("", curAddl),
			}
			k := key{qname: curDomain, qtype: 0, qclass: 0}
			if curWildcard {
				wildcardMap[k] = e
			} else {
				exactMap[k] = e
			}
			count++
		}
	}

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}

		// Domain header: starts with . or *.
		if line[0] == '.' || (len(line) > 1 && line[0] == '*' && line[1] == '.') {
			flushDomain()

			isWildcard := line[0] == '*'
			var rawName string
			if isWildcard {
				rawName = line[2:] // strip "*."
			} else {
				rawName = line[1:] // strip leading "."
			}

			// Parse optional rcode= and match= from remaining fields.
			fields := strings.Fields(rawName)
			domain := fields[0]
			curDomain = zdnsutil.NormalizeDomain(domain)
			curWildcard = isWildcard
			curRcode = parent.Rcode
			curTags = append([]matchTag(nil), parentTags...)
			curRecords = nil
			curAuthority = nil
			curAddl = nil

			for _, f := range fields[1:] {
				if strings.HasPrefix(f, "rcode=") {
					if n, err := strconv.Atoi(f[6:]); err == nil {
						curRcode = n
					}
				} else if strings.HasPrefix(f, "match=") {
					tagStrs := strings.Split(f[6:], ",")
					curTags, _ = parseMatchTags(tagStrs)
					for _, t := range curTags {
						tagSet[t.tag] = struct{}{}
					}
				}
			}
			continue
		}

		// Record line: must start with a digit (TYPE).
		if line[0] < '0' || line[0] > '9' {
			continue
		}
		if curDomain == "" {
			continue
		}

		rec, section, err := parseRecordLine(line)
		if err != nil {
			log.Warnf("ZONE: skipping invalid record line: %s", line)
			continue
		}

		switch section {
		case "authority":
			curAuthority = append(curAuthority, rec)
		case "additional":
			curAddl = append(curAddl, rec)
		default:
			curRecords = append(curRecords, rec)
		}
	}
	flushDomain()

	if err := sc.Err(); err != nil {
		return 0, fmt.Errorf("read: %w", err)
	}
	return count, nil
}

// parseRecordLine parses a zone record line: TYPE CONTENT [TTL] [key=value ...]
func parseRecordLine(line string) (config.ZoneRecord, string, error) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return config.ZoneRecord{}, "", errors.New("record line too short")
	}

	typ, err := strconv.ParseUint(fields[0], 10, 16)
	if err != nil {
		return config.ZoneRecord{}, "", fmt.Errorf("invalid type: %s", fields[0])
	}

	rec := config.ZoneRecord{
		Type:    uint16(typ), //nolint:gosec // G115: DNS type fits uint16
		Content: fields[1],
	}
	section := "answer"

	for _, f := range fields[2:] {
		if !strings.Contains(f, "=") {
			// Bare number → TTL.
			if ttl, err := strconv.ParseUint(f, 10, 32); err == nil {
				rec.TTL = uint32(ttl) //nolint:gosec // G115: TTL fits uint32
			}
			continue
		}
		kv := strings.SplitN(f, "=", 2)
		k, v := kv[0], kv[1]
		switch k {
		case "class":
			if n, err := strconv.ParseUint(v, 10, 16); err == nil {
				rec.Class = uint16(n) //nolint:gosec // G115: DNS class fits uint16
			}
		case "name":
			rec.Name = v
		case "section":
			section = v
		}
	}

	return rec, section, nil
}

// ---------------------------------------------------------------------------
// RR builders
// ---------------------------------------------------------------------------

func buildRRs(domain string, records []config.ZoneRecord) []dns.RR {
	if len(records) == 0 {
		return nil
	}
	rr := make([]dns.RR, 0, len(records))
	for _, rec := range records {
		if r := buildRecord(domain, &rec); r != nil {
			rr = append(rr, r)
		}
	}
	return rr
}

func buildRecord(domain string, record *config.ZoneRecord) dns.RR {
	ttl := record.TTL
	if ttl == 0 {
		ttl = config.DefaultTTL
	}
	class := record.Class
	if class == 0 {
		class = dns.ClassINET
	}
	name := dnsutil.Fqdn(domain)
	if record.Name != "" {
		name = dnsutil.Fqdn(record.Name)
	}
	typeStr := dns.TypeToString[record.Type]
	if typeStr == "" {
		typeStr = "TYPE" + strconv.FormatUint(uint64(record.Type), 10)
	}
	classStr, ok := dns.ClassToString[class]
	if !ok {
		classStr = "CLASS" + strconv.FormatUint(uint64(class), 10)
	}
	var sb strings.Builder
	sb.Grow(len(name) + len(classStr) + len(typeStr) + len(record.Content) + 20)
	sb.WriteString(name)
	sb.WriteByte(' ')
	sb.WriteString(strconv.FormatUint(uint64(ttl), 10))
	sb.WriteByte(' ')
	sb.WriteString(classStr)
	sb.WriteByte(' ')
	sb.WriteString(typeStr)
	sb.WriteByte(' ')
	sb.WriteString(record.Content)
	if rr, err := dns.New(sb.String()); err == nil {
		return rr
	}
	// Fallback: RFC 3597 unknown type.
	return &dns.RFC3597{
		Hdr:     dns.Header{Name: name, Class: class, TTL: ttl},
		RFC3597: rdata.RFC3597{RRType: record.Type, Data: record.Content},
	}
}
