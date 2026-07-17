// Package ruleset provides tag-based matching for client IP (CIDR) and query
// domain (suffix). Both match types are backed by SQLite for consistent
// querying and persistence. Rules are loaded at startup from config and
// reloaded on restart — there is no in-memory rebuild step.
package ruleset

import (
	"database/sql"
	"net"
	"os"
	"strings"
	"zjdns/config"
	"zjdns/internal/log"
)

// RuleSetStorage provides SQL operations needed by the ruleset engine.
// *database.DB satisfies this interface implicitly.
type RuleSetStorage interface {
	SQLExec(query string, args ...any) (sql.Result, error)
	SQLQueryRow(query string, args ...any) *sql.Row
	SQLQuery(query string, args ...any) (*sql.Rows, error)
	BeginTx() (*sql.Tx, error)
}

// Engine matches queries against rule sets to produce tags.
// All matching is done via SQLite queries with PK-optimised index seeks.
// The ruleset_entries PK is (type, tag, value), so WHERE type=? uses a PK
// prefix seek (not a full scan).
type Engine struct {
	db   RuleSetStorage
	tags map[string]bool // all known tags from config
}

// New creates an Engine backed by the given database.
func New(db RuleSetStorage) *Engine {
	return &Engine{db: db, tags: make(map[string]bool)}
}

// LoadRules stores RuleSet configurations into SQLite.  Rules are reloaded
// from config on every startup — SQLite is the authoritative store.
func (e *Engine) LoadRules(rulesets []config.RuleSet) error {
	tx, err := e.db.BeginTx()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(`DELETE FROM ruleset_entries`); err != nil {
		return err
	}

	for _, rs := range rulesets {
		for _, v := range rs.Rule {
			if err := insertRule(tx, rs.Tag, rs.Type, v); err != nil {
				return err
			}
		}
		if rs.File != "" {
			lines, err := readDomainFile(rs.File)
			if err != nil {
				return err
			}
			for _, line := range lines {
				if err := insertRule(tx, rs.Tag, rs.Type, line); err != nil {
					return err
				}
			}
		}
		e.tags[rs.Tag] = true
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	var n int
	_ = e.db.SQLQueryRow("SELECT COUNT(*) FROM ruleset_entries").Scan(&n)
	log.Infof("RULESET: %d rules loaded into %d tags", n, len(e.tags))
	return nil
}

// Match returns all tags that match the given query name and client IP.
func (e *Engine) Match(qname, ip string) map[string]bool {
	var tags map[string]bool

	// Domain: TLD+1 suffix lookup.
	key := tldPlusOne(qname)
	var tag string
	if err := e.db.SQLQueryRow(
		"SELECT tag FROM ruleset_entries WHERE type='domain' AND value=? LIMIT 1",
		key,
	).Scan(&tag); err == nil && tag != "" {
		tags = make(map[string]bool)
		tags[tag] = true
	}

	// IP: load all CIDR rules.
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return tags
	}

	rows, err := e.db.SQLQuery("SELECT tag, value FROM ruleset_entries WHERE type='ip'")
	if err != nil {
		return tags
	}
	defer rows.Close() //nolint:errcheck // best-effort

	for rows.Next() {
		var t, cidr string
		if err := rows.Scan(&t, &cidr); err != nil {
			continue
		}
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if n.Contains(parsedIP) {
			if tags == nil {
				tags = make(map[string]bool)
			}
			tags[t] = true
		}
	}

	return tags
}

// HasIPTag reports whether a tag has CIDR rules for IP-based filtering.
func (e *Engine) HasIPTag(tag string) bool {
	var n int
	_ = e.db.SQLQueryRow(
		"SELECT COUNT(*) FROM ruleset_entries WHERE type='ip' AND tag=?",
		tag,
	).Scan(&n)
	return n > 0
}

// MatchIP checks whether an IP matches a specific tag's CIDR rules.
// Tags prefixed with ! are negated.
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

	rows, err := e.db.SQLQuery(
		"SELECT value FROM ruleset_entries WHERE type='ip' AND tag=?",
		tag,
	)
	if err != nil {
		return false, true
	}
	defer rows.Close() //nolint:errcheck // best-effort

	for rows.Next() {
		var cidr string
		if err := rows.Scan(&cidr); err != nil {
			continue
		}
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		matched = n.Contains(parsedIP)
		if matched {
			break
		}
	}

	if negate {
		return !matched, true
	}
	return matched, true
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// insertRule validates and inserts a single ruleset entry into a transaction.
// For IP rules it validates the CIDR; for domain rules it normalises to a
// TLD+1 key before insertion.
func insertRule(tx *sql.Tx, tag, typ, value string) error {
	if typ == "ip" {
		if _, _, err := net.ParseCIDR(value); err != nil {
			return nil //nolint:nilerr // invalid CIDRs are skipped, same as original continue
		}
	}
	key := value
	if typ == "domain" {
		key = domainKey(value)
	}
	_, err := tx.Exec(
		`INSERT OR REPLACE INTO ruleset_entries (tag, type, value) VALUES (?, ?, ?)`,
		tag, typ, key,
	)
	return err
}

// readFile reads a file from disk.  The path comes from config, not user input.
func readFile(path string) ([]byte, error) {
	return os.ReadFile(path) //nolint:gosec // G304: path from config, not user input
}

// readDomainFile reads a line-delimited domain file, skipping comments.
func readDomainFile(path string) ([]string, error) {
	data, err := readFile(path)
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

// tldPlusOne extracts the effective suffix for domain matching.
func tldPlusOne(name string) string {
	n := strings.TrimSuffix(strings.ToLower(name), ".")
	last := strings.LastIndexByte(n, '.')
	if last < 0 {
		return n
	}
	prev := strings.LastIndexByte(n[:last], '.')
	if prev < 0 {
		return n
	}
	return n[prev+1:]
}
