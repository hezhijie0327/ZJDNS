// Package ruleset provides tag-based matching for client IP (CIDR) and query
// domain (suffix). Both match types are backed by BadgerDB for consistent
// querying and persistence. Rules are loaded at startup from config.
package ruleset

import (
	"net"
	"os"
	"strings"
	"zjdns/config"
	"zjdns/database"
	"zjdns/internal/log"

	"github.com/dgraph-io/badger/v4"
)

// Engine matches queries against rule sets to produce tags.
// IP rules use an in-memory binary radix trie for O(128) matching.
// Domain rules use BadgerDB prefix scans.
type Engine struct {
	db     *database.DB
	tags   map[string]bool
	ipTrie ipTrie
}

// New creates a ruleset Engine backed by the given database.
func New(db *database.DB) *Engine {
	if db == nil {
		panic("ruleset: nil database")
	}
	return &Engine{
		db:   db,
		tags: make(map[string]bool),
	}
}

// LoadRules stores RuleSet configurations into BadgerDB.
func (e *Engine) LoadRules(rulesets []config.RuleSet) error {
	// Clear existing rules.
	if err := e.db.Badger.DropPrefix([]byte("r:")); err != nil {
		return err
	}

	err := e.db.Badger.Update(func(txn *badger.Txn) error {
		for _, rs := range rulesets {
			for _, v := range rs.Rule {
				if err := insertRule(txn, rs.Tag, rs.Type, v); err != nil {
					return err
				}
			}
			if rs.File != "" {
				lines, err := readDomainFile(rs.File)
				if err != nil {
					return err
				}
				for _, line := range lines {
					if err := insertRule(txn, rs.Tag, rs.Type, line); err != nil {
						return err
					}
				}
			}
			e.tags[rs.Tag] = true
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Count loaded rules.
	var n int
	_ = e.db.Badger.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = []byte("r:")
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			n++
		}
		return nil
	})
	log.Infof("RULESET: %d rules loaded into %d tags", n, len(e.tags))

	e.loadIPRules()
	return nil
}

// loadIPRules loads all CIDR rules from BadgerDB into the in-memory trie.
func (e *Engine) loadIPRules() {
	e.ipTrie.reset()
	_ = e.db.Badger.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = database.RuleSetTypePrefix("ip")
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			k := string(it.Item().Key())
			// Key: r:ip\x00{value}\x00{tag}
			parts := splitRuleSetKey(k)
			if len(parts) < 3 {
				continue
			}
			value, tag := parts[1], parts[2]
			_, n, err := net.ParseCIDR(value)
			if err != nil {
				continue
			}
			e.ipTrie.insert(n, tag)
		}
		return nil
	})
}

// splitRuleSetKey splits a ruleset key "r:{type}\x00{value}\x00{tag}" into parts.
func splitRuleSetKey(k string) []string {
	// Skip the "r:" prefix.
	if !strings.HasPrefix(k, "r:") {
		return nil
	}
	rest := k[2:]
	var parts []string
	start := 0
	for i := 0; i < len(rest); i++ {
		if rest[i] == 0 {
			parts = append(parts, rest[start:i])
			start = i + 1
		}
	}
	parts = append(parts, rest[start:])
	return parts
}

// Match returns all tags that match the given query name and client IP.
func (e *Engine) Match(qname, ip string) map[string]bool {
	var tags map[string]bool

	// Domain: TLD+1 suffix lookup via BadgerDB prefix scan.
	key := tldPlusOne(qname)
	_ = e.db.Badger.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = database.RuleSetTypeValuePrefix("domain", key)
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			k := string(it.Item().Key())
			parts := splitRuleSetKey(k)
			if len(parts) >= 3 {
				tag := parts[2]
				if tag != "" {
					if tags == nil {
						tags = make(map[string]bool)
					}
					tags[tag] = true
				}
			}
		}
		return nil
	})

	// IP: binary radix trie — O(128) regardless of rule count.
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return tags
	}
	for _, t := range e.ipTrie.match(parsedIP) {
		if tags == nil {
			tags = make(map[string]bool)
		}
		tags[t] = true
	}

	return tags
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
		return false, true
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

// insertRule validates and inserts a single ruleset entry into a transaction.
func insertRule(txn *badger.Txn, tag, typ, value string) error {
	if typ == "ip" {
		if _, _, err := net.ParseCIDR(value); err != nil {
			log.Warnf("RULESET: skipping invalid CIDR rule %s=%s: %v", tag, value, err)
			return nil
		}
	}
	entryKey := value
	if typ == "domain" {
		entryKey = domainKey(value)
	}
	key := database.RuleSetKey(typ, entryKey, tag)
	return txn.Set(key, nil)
}

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

// tldPlusOne extracts the effective TLD+1 (registrable domain) for domain matching.
func tldPlusOne(name string) string {
	n := strings.TrimSuffix(strings.ToLower(name), ".")

	last := strings.LastIndexByte(n, '.')
	if last < 0 {
		return n
	}

	secondLast := strings.LastIndexByte(n[:last], '.')
	if secondLast < 0 {
		return n
	}
	return n[secondLast+1:]
}
