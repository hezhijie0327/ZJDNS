// Package ruleset provides tag-based matching for client IP (CIDR) and query
// domain (suffix). IP rules use a binary radix trie O(128); domain rules use a
// suffix map O(1). Both share a single tag registry. All data is in-memory,
// loaded from config at startup.
package ruleset

import (
	"net"
	"os"
	"strings"
	"zjdns/config"
	"zjdns/internal/log"
)

// Engine matches queries against rule sets to produce tags.
type Engine struct {
	tags        map[string]bool     // all registered tags
	domainRules map[string][]string // suffix → matching tags
	ipTrie      ipTrie              // CIDR → tags
}

// New creates a ruleset Engine.
func New() *Engine {
	return &Engine{
		tags:        make(map[string]bool),
		domainRules: make(map[string][]string),
	}
}

// LoadRules loads RuleSet configurations into in-memory data structures.
func (e *Engine) LoadRules(rulesets []config.RuleSet) error {
	e.tags = make(map[string]bool)
	e.domainRules = make(map[string][]string)
	e.ipTrie.reset()

	for _, rs := range rulesets {
		e.tags[rs.Tag] = true
		for _, v := range rs.Rule {
			if err := e.insertRule(rs.Tag, rs.Type, v); err != nil {
				return err
			}
		}
		if rs.File != "" {
			lines, err := readDomainFile(rs.File)
			if err != nil {
				return err
			}
			for _, line := range lines {
				if err := e.insertRule(rs.Tag, rs.Type, line); err != nil {
					return err
				}
			}
		}
	}

	log.Infof("RULESET: %d tags loaded, %d domain suffixes", len(e.tags), len(e.domainRules))
	return nil
}

func (e *Engine) insertRule(tag, typ, value string) error {
	switch typ {
	case "ip":
		_, n, err := net.ParseCIDR(value)
		if err != nil {
			log.Warnf("RULESET: skipping invalid CIDR rule %s=%s: %v", tag, value, err)
			return nil
		}
		e.ipTrie.insert(n, tag)
	case "domain":
		key := domainKey(value)
		e.domainRules[key] = append(e.domainRules[key], tag)
	}
	return nil
}

// Match returns all tags that match the given query name and client IP.
func (e *Engine) Match(qname, ip string) map[string]bool {
	var result map[string]bool

	// Domain: suffix map lookup walking the qname from its full form down
	// to the shortest suffix.  Rules are keyed by their complete name
	// (domainKey), so multi-label rules ("a.b.example.com") match any query
	// that has them as a suffix; all matching levels contribute tags (OR).
	for name := strings.TrimSuffix(strings.ToLower(qname), "."); ; {
		if tags := e.domainRules[name]; len(tags) > 0 {
			if result == nil {
				result = make(map[string]bool, len(tags))
			}
			for _, t := range tags {
				result[t] = true
			}
		}
		idx := strings.IndexByte(name, '.')
		if idx < 0 {
			break
		}
		name = name[idx+1:]
	}

	// IP: binary radix trie O(128).
	parsedIP := net.ParseIP(ip)
	if parsedIP != nil {
		for _, t := range e.ipTrie.match(parsedIP) {
			if result == nil {
				result = make(map[string]bool)
			}
			result[t] = true
		}
	}

	return result
}

// HasIPTag reports whether a tag has CIDR rules for IP-based filtering.
func (e *Engine) HasIPTag(tag string) bool {
	return e.ipTrie.hasTag(tag)
}

// MatchIP checks whether an IP matches a specific tag's CIDR rules.
func (e *Engine) MatchIP(ip, tag string) (matched, exists bool) {
	negate := false
	if tag != "" && tag[0] == '!' {
		negate = true
		tag = tag[1:]
	}
	if !e.tags[tag] {
		return false, false
	}
	if !e.HasIPTag(tag) {
		// Empty rule set: a negated tag matches everything (nothing to
		// negate), a positive tag matches nothing.
		return negate, true
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false, true
	}

	matched = e.ipTrie.matchTag(parsedIP, tag)
	if negate {
		return !matched, true
	}
	return matched, true
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

func domainKey(p string) string {
	p = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(p)), ".")
	p = strings.TrimPrefix(p, "*.")
	return p
}
