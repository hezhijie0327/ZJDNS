// Package ruleset provides tag-based matching for client IP (CIDR) and query
// domain (suffix).  Matching is in-memory: a binary radix trie for CIDRs and
// a suffix map for domains, both built from config at LoadRules time.  The
// config file is the authoritative source — nothing is persisted.
package ruleset

import (
	"net"
	"os"
	"strings"
	"sync/atomic"
	"zjdns/config"
	"zjdns/internal/log"
)

// ruleTable is one immutable snapshot of the loaded rules.  LoadRules builds
// a fresh table and publishes it via atomic.Pointer.Swap; Match reads the
// current table lock-free.
type ruleTable struct {
	tags        map[string]bool     // all known tags from config
	ipTrie      ipTrie              // binary radix trie for O(128) CIDR matching
	domainRules map[string][]string // TLD+1 domain key → tags; empty short-circuits Match
}

// Engine matches queries against rule sets to produce tags.
// IP rules are matched via an in-memory binary radix trie; domain rules via
// an in-memory suffix map.
type Engine struct {
	table atomic.Pointer[ruleTable]
}

// New creates an Engine with an empty rule table.
func New() *Engine {
	e := &Engine{}
	e.table.Store(&ruleTable{
		tags:        make(map[string]bool),
		domainRules: make(map[string][]string),
	})
	return e
}

// LoadRules builds the in-memory rule table from config.  Rules always come
// from config at startup (or a config reload) — nothing is persisted.
func (e *Engine) LoadRules(rulesets []config.RuleSet) error {
	table := &ruleTable{
		tags:        make(map[string]bool),
		domainRules: make(map[string][]string),
	}
	ruleCount := 0
	for _, rs := range rulesets {
		for _, v := range rs.Rule {
			if addRule(table, rs.Tag, rs.Type, v) {
				ruleCount++
			}
		}
		if rs.File != "" {
			lines, err := readDomainFile(rs.File)
			if err != nil {
				return err
			}
			for _, line := range lines {
				if addRule(table, rs.Tag, rs.Type, line) {
					ruleCount++
				}
			}
		}
		table.tags[rs.Tag] = true
	}

	e.table.Store(table)
	log.Infof("RULESET: %d rules loaded into %d tags", ruleCount, len(table.tags))
	return nil
}

// addRule registers a single rule (inline or file line) into the table being
// built.  Returns true when the rule was accepted.  Invalid CIDRs are
// skipped and logged, matching the former SQL-insert behaviour.
func addRule(table *ruleTable, tag, typ, value string) bool {
	switch typ {
	case "ip":
		// Single parse (D13): the former double ParseCIDR discarded the
		// second result's error without a comment and paid the parse twice.
		_, n, err := net.ParseCIDR(value)
		if err != nil {
			log.Warnf("RULESET: skipping invalid CIDR rule %s=%s: %v", tag, value, err)
			return false
		}
		table.ipTrie.insert(n, tag)
		return true
	case "domain":
		key := domainKey(value)
		table.domainRules[key] = append(table.domainRules[key], tag)
		return true
	default:
		return false
	}
}

// Match returns all tags that match the given query name and client IP.
func (e *Engine) Match(qname, ip string) map[string]bool {
	var tags map[string]bool

	// Domain: TLD+1 suffix lookup via the in-memory map.  Short-circuits when
	// no domain rules are configured.  The IP trie match below still runs.
	table := e.table.Load()
	key := tldPlusOne(qname)
	for _, tag := range table.domainRules[key] {
		if tag != "" {
			if tags == nil {
				tags = make(map[string]bool)
			}
			tags[tag] = true
		}
	}

	// IP: binary radix trie — O(128) regardless of rule count.
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return tags
	}

	for _, t := range table.ipTrie.match(parsedIP) {
		if tags == nil {
			tags = make(map[string]bool)
		}
		tags[t] = true
	}

	return tags
}

// HasIPTag reports whether a tag has CIDR rules for IP-based filtering.
func (e *Engine) HasIPTag(tag string) bool {
	return e.table.Load().ipTrie.hasTag(tag)
}

// MatchIP checks whether an IP matches a specific tag's CIDR rules.
// Tags prefixed with ! are negated.
func (e *Engine) MatchIP(ip, tag string) (matched, exists bool) {
	negate := false
	if tag != "" && tag[0] == '!' {
		negate = true
		tag = tag[1:]
	}
	table := e.table.Load()
	if !table.tags[tag] {
		return false, false
	}
	if !table.ipTrie.hasTag(tag) {
		return false, true
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false, true
	}

	matched = table.ipTrie.matchTag(parsedIP, tag)

	if negate {
		return !matched, true
	}
	return matched, true
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// readDomainFile reads a line-delimited domain file, skipping comments.
func readDomainFile(path string) ([]string, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path from trusted config file
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	var result []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		result = append(result, line)
	}
	return result, nil
}

// domainKey normalizes a domain pattern to its TLD+1 key.
func domainKey(p string) string {
	p = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(p)), ".")
	p = strings.TrimPrefix(p, "*.")
	return p
}

// tldPlusOne extracts the effective TLD+1 from a query name.
// "www.google.com." → "google.com"; "google.com." → "google.com".
// Multi-part TLDs are not handled (documented limitation).
func tldPlusOne(qname string) string {
	qname = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(qname)), ".")
	idx := strings.LastIndex(qname, ".")
	if idx < 0 {
		return qname
	}
	prev := strings.LastIndex(qname[:idx], ".")
	if prev < 0 {
		return qname
	}
	return qname[prev+1:]
}
