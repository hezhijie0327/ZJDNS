// Package zone provides DNS zone-file-style query matching. Rules are loaded
// from config at startup into in-memory maps — no BadgerDB persistence needed.
// All maps are write-once-read-many (WORM): populated by LoadRules at startup,
// then read concurrently by Evaluate without a lock.
package zone

import (
	"errors"
	"fmt"
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

type matchTag struct {
	tag    string
	negate bool
}

// Result holds the outcome of a zone rule evaluation.
type Result struct {
	Domain     string
	Matched    bool
	Rcode      int
	Answer     []dns.RR
	Authority  []dns.RR
	Additional []dns.RR
	CreatedAt  int64
}

// dynamicEntry holds the content generator for a dynamic zone rule together
// with its match tags, rcode, and authority/additional records — these were
// previously dropped, so a dynamic rule's match= / rcode= / authority=
// attributes never took effect.
type dynamicEntry struct {
	fn         func() []string
	configs    []config.ZoneRecord
	matchTags  []matchTag
	rcode      int
	authority  []dns.RR
	additional []dns.RR
}

// zoneRule is a single zone rule held in memory. matchTags is parsed at load
// time; answer/auth/additional are pre-packed wire blobs for zero-alloc unpack.
type zoneRule struct {
	matchTags  []matchTag
	rcode      int
	answer     []byte
	authority  []byte
	additional []byte
}

// zoneKey is a composite map key for exact/wildcard lookups — avoids the
// fmt.Sprintf allocation of the old "qname|qtype|qclass" string key.
type zoneKey struct {
	qname  string
	qtype  uint16
	qclass uint16
}

// Evaluator manages zone rules entirely in memory. All maps are WORM —
// populated by LoadRules at startup, read concurrently by Evaluate.
type Evaluator struct {
	loadedAt  atomic.Int64
	ruleCount atomic.Int64

	dynamics         map[string]*dynamicEntry // exact dynamic rules (normalized qname)
	wildcardDynamics map[string]*dynamicEntry // wildcard dynamic rules (stripped name)
	bypass           [][]matchTag             // global bypass rules
	exact            map[zoneKey][]zoneRule   // (qname, qtype, qclass) → rules
	wildcards        map[zoneKey][]zoneRule   // (suffix, qtype, qclass) → wildcard rules
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const (
	wildcardPrefix    = "*."
	maxWildcardLabels = 16
)

// New creates an Evaluator.
func New() *Evaluator {
	return &Evaluator{
		dynamics:         make(map[string]*dynamicEntry),
		wildcardDynamics: make(map[string]*dynamicEntry),
		exact:            make(map[zoneKey][]zoneRule),
		wildcards:        make(map[zoneKey][]zoneRule),
	}
}

// HasRules reports whether any zone rules are currently loaded.
func (e *Evaluator) HasRules() bool { return e.ruleCount.Load() > 0 }

// ---------------------------------------------------------------------------
// LoadRules
// ---------------------------------------------------------------------------

// LoadRules validates and loads zone rules into in-memory maps.
func (e *Evaluator) LoadRules(rules []config.ZoneRule) error {
	// Reset all maps.
	e.dynamics = make(map[string]*dynamicEntry)
	e.wildcardDynamics = make(map[string]*dynamicEntry)
	e.exact = make(map[zoneKey][]zoneRule)
	e.wildcards = make(map[zoneKey][]zoneRule)

	var bypass [][]matchTag
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
			bypass = append(bypass, tags)
			continue
		}
		content = append(content, *r)
	}
	e.bypass = bypass
	if len(bypass) > 0 {
		log.Infof("ZONE: %d bypass rule(s) loaded", len(bypass))
	}

	total := int64(0)
	for i := range content {
		rule := &content[i]
		if rule.File != "" {
			n, err := e.loadFile(rule)
			if err != nil {
				return fmt.Errorf("zone file %q: %w", rule.File, err)
			}
			total += int64(n)
			log.Infof("ZONE: loaded %d entries from %s", n, rule.File)
			continue
		}
		n, err := e.loadInline(rule)
		if err != nil {
			return err
		}
		total += int64(n)
	}

	e.ruleCount.Store(total)
	e.loadedAt.Store(log.NowUnix())
	log.Infof("ZONE: %d zone entries loaded", total)
	return nil
}

func (e *Evaluator) loadInline(rule *config.ZoneRule) (int, error) {
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

	normalizedName := dnsutil.Canonical(rule.Name)
	isWildcard := strings.HasPrefix(rule.Name, wildcardPrefix)
	if isWildcard {
		normalizedName = normalizedName[len(wildcardPrefix):]
	}

	tags, err := parseMatchTagsText(serializeMatchTags(rule.Match))
	if err != nil {
		return 0, fmt.Errorf("zone rule %q: invalid match tags: %w", rule.Name, err)
	}

	if rule.DynamicContent != nil {
		// Dynamic rules are keyed by the WILDCARD-STRIPPED name — otherwise
		// "*.example.com" would be stored as-is and never matched by any
		// real query name. Exact and wildcard rules live in SEPARATE maps:
		// the same name may legally carry both (e.g. "example.com" plus
		// "*.example.com"), and a wildcard never matches the bare domain
		// itself (RFC 1034 §4.3.2).
		entry := &dynamicEntry{
			fn:         rule.DynamicContent,
			configs:    rule.Answer,
			matchTags:  tags,
			rcode:      rule.Rcode,
			authority:  buildRRs(rule.Name, rule.Authority),
			additional: buildRRs(rule.Name, rule.Additional),
		}
		if isWildcard {
			e.wildcardDynamics[normalizedName] = entry
		} else {
			e.dynamics[normalizedName] = entry
		}
	}

	groups := groupRecordsByTypeClass(rule.Answer)
	count := 0

	if len(groups) > 0 {
		for _, g := range groups {
			entry := zoneRule{
				matchTags:  tags,
				rcode:      rule.Rcode,
				answer:     packRRs(rule.Name, g.records),
				authority:  packRRs(rule.Name, rule.Authority),
				additional: packRRs(rule.Name, rule.Additional),
			}
			key := exactKey(normalizedName, g.qtype, g.qclass)
			e.store(isWildcard, key, entry)
			count++
		}
	}
	// Dynamic rules generate TXT/CHAOS — store with their actual qtype/qclass.
	if rule.DynamicContent != nil {
		entry := zoneRule{
			matchTags:  tags,
			rcode:      rule.Rcode,
			authority:  packRRs(rule.Name, rule.Authority),
			additional: packRRs(rule.Name, rule.Additional),
		}
		e.store(isWildcard, exactKey(normalizedName, dns.TypeTXT, dns.ClassCHAOS), entry)
		count++
	} else if rule.Rcode != dns.RcodeSuccess && len(groups) == 0 {
		entry := zoneRule{
			matchTags:  tags,
			rcode:      rule.Rcode,
			authority:  packRRs(rule.Name, rule.Authority),
			additional: packRRs(rule.Name, rule.Additional),
		}
		e.store(isWildcard, exactKey(normalizedName, 0, 0), entry)
		count++
	}

	return count, nil
}

func (e *Evaluator) store(isWildcard bool, key zoneKey, entry zoneRule) { //nolint:gocritic // WORM map — value copy is correct
	if isWildcard {
		e.wildcards[key] = append(e.wildcards[key], entry)
	} else {
		e.exact[key] = append(e.exact[key], entry)
	}
}

func exactKey(qname string, qtype, qclass uint16) zoneKey {
	return zoneKey{qname: qname, qtype: qtype, qclass: qclass}
}

// ---------------------------------------------------------------------------
// Evaluate — O(1) map lookups
// ---------------------------------------------------------------------------

// Evaluate checks a query against loaded zone rules.
func (e *Evaluator) Evaluate(qname string, qtype, qclass uint16, matchedTags map[string]bool) Result {
	if qclass == 0 {
		qclass = dns.ClassINET
	}
	if len(qname) > config.MaxDomainLength {
		return Result{Rcode: dns.RcodeSuccess}
	}

	for i, tags := range e.bypass {
		score := matchScore(tags, matchedTags)
		log.Debugf("ZONE: bypass[%d] tags=%v client_tags=%v score=%d", i, tags, matchedTags, score)
		if score > 0 {
			return Result{Rcode: dns.RcodeSuccess}
		}
	}

	if e.ruleCount.Load() == 0 && len(e.bypass) == 0 {
		return Result{Rcode: dns.RcodeSuccess}
	}

	qname = dnsutil.Canonical(qname)
	loadedAt := e.loadedAt.Load()

	var bestScore int
	var best Result

	// Exact dynamic rule participates in best-scoring alongside the static
	// exact rules: a static rule with stronger match tags must win over a
	// generic dynamic answer (mirrors the wildcard path).
	if de, ok := e.dynamics[qname]; ok {
		if r, matched := e.evalDynamic(qname, qtype, qclass, de, matchedTags); matched {
			bestScore = matchScore(de.matchTags, matchedTags)
			best = r
		}
	}

	// Exact match — concrete qtype/qclass.
	e.pickBest(e.exact[exactKey(qname, qtype, qclass)], qname, matchedTags, loadedAt, &bestScore, &best)

	// Exact match — sentinel (qtype=0, qclass=0).
	e.pickBest(e.exact[exactKey(qname, 0, 0)], qname, matchedTags, loadedAt, &bestScore, &best)

	if best.Matched {
		return best
	}

	// Wildcard suffix matching.
	return e.wildcardMatch(qname, qtype, qclass, matchedTags, loadedAt)
}

// wildcardMatch iterates suffix candidates, picking the best-scored match.
func (e *Evaluator) wildcardMatch(qname string, qtype, qclass uint16, matchedTags map[string]bool, loadedAt int64) Result {
	suffixes := buildSuffixes(qname)
	var bestScore int
	var best Result
	for _, suffix := range suffixes {
		// Wildcard dynamic rules are keyed by the stripped name — a query
		// under that suffix hits them here (deepest suffix first). Exact
		// dynamic rules live in a separate map and are NOT consulted here:
		// an exact rule only answers its own name, never subdomains. A
		// dynamic match participates in best-scoring like static rules — a
		// static rule with stronger match tags must still win over a
		// generic dynamic answer.
		if de, ok := e.wildcardDynamics[suffix]; ok {
			if r, matched := e.evalDynamic(qname, qtype, qclass, de, matchedTags); matched {
				if score := matchScore(de.matchTags, matchedTags); score > bestScore || !best.Matched {
					bestScore = score
					best = r
				}
			}
		}
		e.pickBest(e.wildcards[exactKey(suffix, qtype, qclass)], suffix, matchedTags, loadedAt, &bestScore, &best)
		e.pickBest(e.wildcards[exactKey(suffix, 0, 0)], suffix, matchedTags, loadedAt, &bestScore, &best)
	}
	return best
}

// pickBest scores rules against matchedTags and updates best if a better match is found.
func (e *Evaluator) pickBest(rules []zoneRule, domain string, matchedTags map[string]bool, loadedAt int64, bestScore *int, best *Result) {
	for i := range rules {
		score := matchScore(rules[i].matchTags, matchedTags)
		if score < 0 || (score <= *bestScore && best.Matched) {
			continue
		}
		*bestScore = score
		*best = Result{
			Domain: domain, Matched: true,
			Rcode:      rules[i].rcode,
			Answer:     unpackRRs(rules[i].answer),
			Authority:  unpackRRs(rules[i].authority),
			Additional: unpackRRs(rules[i].additional),
			CreatedAt:  loadedAt,
		}
	}
}

// buildSuffixes returns TLD+1, TLD+2, … suffixes for wildcard matching.
func buildSuffixes(qname string) []string {
	var suffixes []string
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
		suffixes = append(suffixes, rest)
	}
	if len(suffixes) > maxWildcardLabels {
		suffixes = suffixes[:maxWildcardLabels]
	}
	return suffixes
}

// ---------------------------------------------------------------------------
// Dynamic content
// ---------------------------------------------------------------------------

// evalDynamic evaluates a dynamic rule. It reports (result, false) when the
// rule is filtered out (match tags not satisfied) or produces no content —
// the caller then falls through to ordinary exact/wildcard rules.
func (e *Evaluator) evalDynamic(qname string, qtype, qclass uint16, de *dynamicEntry, matchedTags map[string]bool) (Result, bool) {
	// Match-tag filter: a rule with tags the client does not carry must
	// not answer — fall through instead of serving content to the wrong
	// client.
	if score := matchScore(de.matchTags, matchedTags); score < 0 {
		return Result{}, false
	}

	// Dynamic rules generate TXT/CHAOS records. Only answer the qtypes
	// that can consume them — an A/INET query must not receive TXT/CHAOS.
	if qtype != dns.TypeTXT && qtype != dns.TypeANY {
		return Result{}, false
	}

	var contents []string
	if len(de.configs) == 0 {
		contents = de.fn()
	} else {
		for _, rec := range de.configs {
			recClass := rec.Class
			if recClass == 0 {
				recClass = dns.ClassINET
			}
			if rec.Type == qtype && recClass == qclass {
				if contents == nil {
					contents = de.fn()
				}
				break
			}
		}
	}
	if len(contents) == 0 {
		return Result{}, false
	}

	result := Result{
		Domain:     qname,
		Matched:    true,
		Rcode:      de.rcode,
		Authority:  de.authority,
		Additional: de.additional,
		CreatedAt:  e.loadedAt.Load(),
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
	return result, true
}

// ---------------------------------------------------------------------------
// Match score
// ---------------------------------------------------------------------------

func matchScore(entryTags []matchTag, matchedTags map[string]bool) int {
	if len(entryTags) == 0 {
		return 0
	}
	score := 0
	for _, mt := range entryTags {
		_, exists := matchedTags[mt.tag]
		if !exists {
			if mt.negate {
				score++
				continue
			}
			return -1
		}
		if mt.negate {
			return -1
		}
		score += 2
	}
	return score
}

// ---------------------------------------------------------------------------
// Match tag helpers
// ---------------------------------------------------------------------------

func serializeMatchTags(raw []string) string {
	if len(raw) == 0 {
		return ""
	}
	return strings.Join(raw, ",")
}

func parseMatchTagsText(text string) ([]matchTag, error) {
	if text == "" {
		return nil, nil
	}
	// A malformed tag must not silently degrade into match-all.
	return parseMatchTags(strings.Split(text, ","))
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
		// "!!foo" would mean negating the tag "!foo" — ambiguous; config
		// validation rejects it identically (config/validate.go).
		if strings.HasPrefix(tag, "!") {
			return nil, fmt.Errorf("invalid match tag %q: multiple '!' prefixes", s)
		}
		tags = append(tags, matchTag{tag: tag, negate: negate})
	}
	return tags, nil
}
