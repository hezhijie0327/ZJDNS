// Package zone provides DNS zone-file-style query matching backed by
// in-memory maps.  Rules are loaded at startup from config (LoadRules) into
// exact/wildcard lookup maps.
package zone

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"zjdns/config"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// matchTag is a parsed CIDR tag condition.
type matchTag struct {
	tag    string // bare tag name (without !)
	negate bool   // true if !tag
}

// Result holds the outcome of a zone rule evaluation.
type Result struct {
	Domain  string
	Matched bool
	// Wildcard is true when the match came from a "*." rule — the stored
	// Domain carries no prefix (LoadRules strips it), but the answer RR
	// owners keep the literal "*.<domain>" and must be rewritten to the
	// queried name before serving (RFC 1034 §4.3.3).
	Wildcard   bool
	Rcode      int
	Answer     []dns.RR
	Authority  []dns.RR
	Additional []dns.RR
	CreatedAt  int64 // LoadRules timestamp for TTL cycling

	score int // internal: winning rule's matchScore (cross-suffix comparison)
}

// dynamicEntry holds a dynamic content function and its record configs.
type dynamicEntry struct {
	fn      func(net.IP) []string
	configs []config.ZoneRecord
}

// exactKey is the composite lookup key for exact (non-wildcard) rules.
// Sentinel rules (rcode-only, no answer records) use qtype=0, qclass=0.
type exactKey struct {
	qname  string
	qtype  uint16
	qclass uint16
}

// zoneRule is one rule in memory.  Answer/Authority/Additional RRs are
// parsed once at load time (buildRRs); every match clones the winning
// rule's RRs (cloneRRs) — the zone middleware mutates the returned RRs in
// place (rewriteOwnerNames, TTL deduction), so shared RRs would corrupt
// each other across queries.  matchTags is pre-parsed at load time.
type zoneRule struct {
	qname      string
	qtype      uint16
	qclass     uint16
	rcode      int
	answer     []dns.RR
	authority  []dns.RR
	additional []dns.RR
	matchTags  []matchTag
	isWildcard bool
}

// zoneTable is one immutable snapshot of all loaded rules.  LoadRules builds
// a fresh table and publishes it via atomic.Pointer.Swap; Evaluate reads the
// current table lock-free (an in-flight query keeps the old table alive
// until it finishes — no reader/writer race possible).
type zoneTable struct {
	dynamics map[string]*dynamicEntry // qname → dynamic content
	bypass   [][]matchTag             // global bypass rules (only Match, no Name/File)
	// exactRules: (qname, qtype, qclass) → rules (sentinel rules use
	// qtype=0,qclass=0).  Buckets are sorted by match_tags at load so
	// equal-score ties resolve deterministically.
	exactRules map[exactKey][]*zoneRule
	// wildcardRules: wildcard suffix qname → rules (sorted by qtype DESC —
	// concrete qtype rows win ties against sentinel rows).
	wildcardRules map[string][]*zoneRule
}

// Evaluator manages zone rules as an immutable snapshot.  Evaluate reads the
// current table with a single atomic load — no lock on the query path.

type Evaluator struct {
	loadedAt  atomic.Int64
	ruleCount atomic.Int64
	table     atomic.Pointer[zoneTable]
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// wildcardPrefix marks a domain as a wildcard rule.
const wildcardPrefix = "*."

// New creates an in-memory Evaluator with an empty rule table.
func New() *Evaluator {
	e := &Evaluator{}
	e.table.Store(&zoneTable{
		dynamics:      make(map[string]*dynamicEntry),
		exactRules:    make(map[exactKey][]*zoneRule),
		wildcardRules: make(map[string][]*zoneRule),
	})
	return e
}

// HasRules reports whether any zone rules are currently loaded.
func (e *Evaluator) HasRules() bool { return e.ruleCount.Load() > 0 }

// ---------------------------------------------------------------------------
// LoadRules
// ---------------------------------------------------------------------------

// LoadRules validates and loads zone rules into memory, building a fresh
// snapshot table and publishing it atomically.  In-flight queries keep
// reading the previous table until they finish.  Rules always come from
// config at startup (or a config reload) — nothing is persisted.
func (e *Evaluator) LoadRules(rules []config.ZoneRule) error {
	table := &zoneTable{
		dynamics:      make(map[string]*dynamicEntry),
		exactRules:    make(map[exactKey][]*zoneRule),
		wildcardRules: make(map[string][]*zoneRule),
	}

	// Collect global bypass rules: only Match, no Name/File/Answer/DynamicContent.
	var content []config.ZoneRule
	for i := range rules {
		r := &rules[i]
		if r.Name == "" && r.File == "" && len(r.Answer) == 0 &&
			len(r.Authority) == 0 && len(r.Additional) == 0 &&
			r.DynamicContent == nil && len(r.Match) > 0 {
			tags, err := parseMatchTags(r.Match)
			if err != nil {
				return fmt.Errorf("zone bypass rule: %w", err)
			}
			table.bypass = append(table.bypass, tags)
			continue
		}
		content = append(content, *r)
	}
	if len(table.bypass) > 0 {
		log.Infof("ZONE: %d bypass rule(s) loaded", len(table.bypass))
	}

	total := int64(0)
	for i := range content {
		rule := &content[i]
		if rule.File != "" {
			n, err := e.loadFile(table, rule)
			if err != nil {
				return fmt.Errorf("zone file %q: %w", rule.File, err)
			}
			total += int64(n)
			log.Infof("ZONE: loaded %d entries from %s", n, rule.File)
			continue
		}
		n, err := e.loadInline(table, rule)
		if err != nil {
			return err
		}
		total += int64(n)
	}

	// Sort each bucket so equal-score ties resolve deterministically:
	// exact buckets by match_tags text, wildcard buckets by qtype DESC
	// (concrete qtype rows before sentinel rows).
	for _, rules := range table.exactRules {
		slices.SortStableFunc(rules, func(a, b *zoneRule) int {
			return strings.Compare(matchTagKey(a.matchTags), matchTagKey(b.matchTags))
		})
	}
	for _, rules := range table.wildcardRules {
		slices.SortStableFunc(rules, func(a, b *zoneRule) int {
			if a.qtype != b.qtype {
				if a.qtype > b.qtype {
					return -1
				}
				return 1
			}
			return strings.Compare(matchTagKey(a.matchTags), matchTagKey(b.matchTags))
		})
	}

	e.table.Store(table)
	e.ruleCount.Store(total)
	e.loadedAt.Store(log.NowUnix())
	log.Infof("ZONE: %d zone entries loaded", total)
	return nil
}

func (e *Evaluator) loadInline(table *zoneTable, rule *config.ZoneRule) (int, error) {
	if rule.Name == "" {
		return 0, errors.New("zone rule: name is required")
	}
	if len(rule.Name)+1 > config.MaxDomainLength {
		truncated := rule.Name
		if len(truncated) > 128 {
			truncated = truncated[:128] + "..."
		}
		log.Warnf("ZONE: rule name too long, skipping %q", truncated)
		return 0, nil
	}

	// Dynamic content: store function in Go map.
	normalizedName := dnsutil.Canonical(rule.Name)

	if rule.DynamicContent != nil {
		table.dynamics[normalizedName] = &dynamicEntry{fn: rule.DynamicContent, configs: rule.Answer}
	}
	tags, err := parseMatchTags(rule.Match)
	if err != nil {
		return 0, fmt.Errorf("zone rule %q: %w", rule.Name, err)
	}
	isWildcard := strings.HasPrefix(rule.Name, wildcardPrefix)
	if isWildcard {
		normalizedName = normalizedName[len(wildcardPrefix):]
	}

	groups := groupRecordsByTypeClass(rule.Answer)
	count := 0

	if len(groups) > 0 {
		for _, g := range groups {
			aw := buildRRs(rule.Name, g.records)
			auth := buildRRs(rule.Name, rule.Authority)
			addl := buildRRs(rule.Name, rule.Additional)
			addRule(table, &zoneRule{
				qname: normalizedName, qtype: g.qtype, qclass: g.qclass,
				rcode: rule.Rcode, answer: aw, authority: auth, additional: addl,
				matchTags: tags, isWildcard: isWildcard,
			})
			count++
		}
	} else if rule.Rcode != dns.RcodeSuccess || rule.DynamicContent != nil {
		// Sentinel entry for rcode-only or dynamic rules.
		auth := buildRRs(rule.Name, rule.Authority)
		addl := buildRRs(rule.Name, rule.Additional)
		addRule(table, &zoneRule{
			qname: normalizedName, qtype: 0, qclass: 0,
			rcode: rule.Rcode, authority: auth, additional: addl,
			matchTags: tags, isWildcard: isWildcard,
		})
		count++
	}

	return count, nil
}

// ruleTypeMatches reports whether a wildcard rule's (qtype, qclass) matches
// the query — the rule must match exactly, or be a sentinel rule (0, 0).
func ruleTypeMatches(r *zoneRule, qtype, qclass uint16) bool {
	return (r.qtype == qtype && r.qclass == qclass) || (r.qtype == 0 && r.qclass == 0)
}

// addRule registers a rule into the correct lookup map of a table being
// built.  The table is not published yet — no locking needed.
func addRule(table *zoneTable, r *zoneRule) {
	if r.isWildcard {
		table.wildcardRules[r.qname] = append(table.wildcardRules[r.qname], r)
		return
	}
	key := exactKey{qname: r.qname, qtype: r.qtype, qclass: r.qclass}
	table.exactRules[key] = append(table.exactRules[key], r)
}

// ---------------------------------------------------------------------------
// Evaluate
// ---------------------------------------------------------------------------

// Evaluate checks a query against loaded zone rules.
// matchedTags is the set of ruleset tags the client IP/domain matched.
// nil or empty map means no CIDR matching is active.
func (e *Evaluator) Evaluate(qname string, qtype, qclass uint16, matchedTags map[string]bool, clientIP net.IP) Result {
	if qclass == 0 {
		qclass = dns.ClassINET
	}
	if len(qname) > config.MaxDomainLength {
		return Result{Rcode: dns.RcodeSuccess}
	}

	table := e.table.Load()

	// 0. Check global bypass rules — if any matches, skip zone entirely.
	for i, tags := range table.bypass {
		score := matchScore(tags, matchedTags)
		log.Debugf("ZONE: bypass[%d] tags=%v client_tags=%v score=%d", i, tags, matchedTags, score)
		if score > 0 {
			log.Debugf("ZONE: bypass matched, skipping zone for %s", qname)
			return Result{Rcode: dns.RcodeSuccess}
		}
	}

	if e.ruleCount.Load() == 0 && len(table.bypass) == 0 {
		return Result{Rcode: dns.RcodeSuccess}
	}

	// Callers pass the canonical FQDN (handler canonicalizes qctx.Qname) —
	// Fqdn is a zero-alloc suffix check, and strings.ToLower uses the ASCII
	// fast path (no allocation when already lowercase).  dnsutil.Canonical
	// would re-lowercase via always-allocating strings.Map.
	qname = strings.ToLower(dnsutil.Fqdn(qname))

	// 1. Check dynamic content.
	if de, ok := table.dynamics[qname]; ok {
		return e.evalDynamic(qname, qtype, qclass, de, clientIP)
	}

	loadedAt := e.loadedAt.Load()

	// 2. Exact composite key lookup.
	if r := e.lookupExact(table, qname, qtype, qclass, matchedTags, loadedAt); r.Matched {
		return r
	}

	// 3. Sentinel key (rcode-only rules).
	if r := e.lookupExact(table, qname, 0, 0, matchedTags, loadedAt); r.Matched {
		return r
	}

	// 4. Wildcard suffix walk — deepest suffix first (the most specific
	// suffix wins equal scores).  Per-suffix buckets are pre-sorted by qtype
	// DESC so concrete qtype rows win ties against sentinel rows.
	return e.lookupWildcard(table, qname, qtype, qclass, matchedTags, loadedAt)
}

// bestMatch scores the candidate rules for a lookup key and returns the
// highest-scoring match.  Bucket order is deterministic (sorted at load), so
// equal-score ties resolve the same way on every query.  When wildcard is
// true, only rules whose (qtype, qclass) matches the query — or sentinel
// rules (0, 0) — are considered.
func (e *Evaluator) bestMatch(rules []*zoneRule, qname string, wildcard bool, qtype, qclass uint16, matchedTags map[string]bool, loadedAt int64) Result {
	var bestScore int
	var best Result
	for _, r := range rules {
		if wildcard && !ruleTypeMatches(r, qtype, qclass) {
			continue
		}
		score := matchScore(r.matchTags, matchedTags)
		if score < 0 {
			continue
		}
		if score <= bestScore && best.Matched {
			continue // not better than current best
		}
		bestScore = score
		best = Result{
			Domain:     r.qname,
			Matched:    true,
			Wildcard:   wildcard,
			Rcode:      r.rcode,
			Answer:     r.answer,
			Authority:  r.authority,
			Additional: r.additional,
			CreatedAt:  loadedAt,
			score:      score,
		}
	}
	if !best.Matched {
		return Result{Rcode: dns.RcodeSuccess}
	}
	// The winner's RRs are shared with the immutable rule table — clone
	// them once so the caller can mutate headers in place.
	best.Answer = cloneRRs(best.Answer)
	best.Authority = cloneRRs(best.Authority)
	best.Additional = cloneRRs(best.Additional)
	return best
}

func (e *Evaluator) lookupExact(table *zoneTable, qname string, qtype, qclass uint16, matchedTags map[string]bool, loadedAt int64) Result {
	return e.bestMatch(table.exactRules[exactKey{qname: qname, qtype: qtype, qclass: qclass}], qname, false, 0, 0, matchedTags, loadedAt)
}

// lookupWildcard walks the suffix candidates of qname from deepest to
// shallowest and returns the best wildcard match across all of them.
// Untagged rules score 0, so bestScore starts at -1 — the first (deepest)
// match is always accepted, equal scores keep the deeper suffix, and only a
// strictly higher score replaces it.
func (e *Evaluator) lookupWildcard(table *zoneTable, qname string, qtype, qclass uint16, matchedTags map[string]bool, loadedAt int64) Result {
	bestScore := -1
	var best Result
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
		if r := e.bestMatch(table.wildcardRules[rest], rest, true, qtype, qclass, matchedTags, loadedAt); r.Matched {
			if r.score > bestScore {
				bestScore = r.score
				best = r
			}
		}
	}
	return best
}

func (e *Evaluator) evalDynamic(qname string, qtype, qclass uint16, de *dynamicEntry, clientIP net.IP) Result {
	var contents []string
	if len(de.configs) == 0 {
		// No config records — invoke the dynamic function for every
		// query (e.g. ZJDNS.cache.clear rules that have no static
		// answer records, only a DynamicContent function).
		contents = de.fn(clientIP)
	} else {
		for _, rec := range de.configs {
			recClass := rec.Class
			if recClass == 0 {
				recClass = dns.ClassINET
			}
			if rec.Type == qtype && recClass == qclass {
				if contents == nil {
					contents = de.fn(clientIP)
				}
				break
			}
		}
	}

	result := Result{
		Domain:    qname,
		Matched:   len(contents) > 0,
		Rcode:     dns.RcodeSuccess,
		CreatedAt: e.loadedAt.Load(),
	}
	for _, content := range contents {
		rr := buildRecord(qname, &config.ZoneRecord{
			Type:    dns.TypeTXT,
			Class:   dns.ClassCHAOS,
			Content: strconv.Quote(content),
		})
		if rr != nil {
			result.Answer = append(result.Answer, rr)
		}
	}
	return result
}

// matchScore returns a match quality score: positive tag matches score 2,
// satisfied negations score 1, untagged rules score 0. Returns -1 if the
// rule is rejected (required positive tag missing, or negated tag present).
// When multiple rules match a query, the highest-scoring rule wins.
func matchScore(entryTags []matchTag, matchedTags map[string]bool) int {
	if len(entryTags) == 0 {
		return 0 // untagged — lowest priority
	}
	// When matchedTags is nil (no ruleset configured), nil-map reads
	// return the zero value without panic — no allocation needed.
	score := 0
	for _, mt := range entryTags {
		_, exists := matchedTags[mt.tag]
		if !exists {
			if mt.negate {
				score++ // satisfied negation
				continue
			}
			return -1 // required positive tag missing → rejected
		}
		// tag exists on client
		if mt.negate {
			return -1 // negated tag present → rejected
		}
		score += 2 // positive match
	}
	return score
}

// ---------------------------------------------------------------------------
// Match tag helpers
// ---------------------------------------------------------------------------

// matchTagKey renders parsed tags in the load config order ("tag1,!tag2,") —
// used as the deterministic sort key for equal-score tie-breaking.
func matchTagKey(tags []matchTag) string {
	var b strings.Builder
	for _, t := range tags {
		if t.negate {
			b.WriteByte('!')
		}
		b.WriteString(t.tag)
		b.WriteByte(',')
	}
	return b.String()
}

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
		tag := s
		if negate {
			tag = s[1:]
		}
		if tag == "" {
			return nil, fmt.Errorf("invalid match tag %q", s)
		}
		tags = append(tags, matchTag{tag: tag, negate: negate})
	}
	return tags, nil
}

// ---------------------------------------------------------------------------
