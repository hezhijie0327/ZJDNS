// Package ruleset provides tag-based matching for client IP (CIDR) and query
// domain (suffix). A ruleset combines both match types under a single tag.
// Match(qname, ip) returns all matching tags for use in upstream selection,
// zone rules, and CIDR filtering.
package ruleset

import (
	"database/sql"

	"zjdns/config"
	"zjdns/internal/log"
)

// RuleSetStorage provides SQL operations needed by the ruleset engine.
// *database.DB satisfies this interface implicitly.
type RuleSetStorage interface {
	SQLExec(query string, args ...any) (sql.Result, error)
	SQLQueryRow(query string, args ...any) *sql.Row
	LoadRuleSetEntries() (*sql.Rows, error)
}

// Engine matches queries against rule sets to produce tags.
type Engine struct {
	ip     *ipMatcher
	domain *domainMatcher
	tags   map[string]bool // all known tags from config
}

// New creates an empty Engine.
func New() *Engine {
	return &Engine{tags: make(map[string]bool)}
}

// LoadRules stores RuleSet configurations into SQLite and rebuilds the
// in-memory engine from the database. This follows the same pattern as
// zone.Evaluator.LoadRules.
func (e *Engine) LoadRules(db RuleSetStorage, rulesets []config.RuleSet) error {
	// Clear existing entries and rebuild from config.
	if _, err := db.SQLExec(`DELETE FROM ruleset_entries`); err != nil {
		return err
	}

	for _, rs := range rulesets {
		for _, v := range rs.Rule {
			key := v
			if rs.Type == "domain" {
				key = domainKey(v)
			}
			if _, err := db.SQLExec(
				`INSERT OR REPLACE INTO ruleset_entries (tag, type, value) VALUES (?, ?, ?)`,
				rs.Tag, rs.Type, key,
			); err != nil {
				return err
			}
		}
		if rs.File != "" {
			lines, ferr := readDomainFile(rs.File)
			if ferr != nil {
				return ferr
			}
			for _, line := range lines {
				key := line
				if rs.Type == "domain" {
					key = domainKey(line)
				}
				if _, err := db.SQLExec(
					`INSERT OR REPLACE INTO ruleset_entries (tag, type, value) VALUES (?, ?, ?)`,
					rs.Tag, rs.Type, key,
				); err != nil {
					return err
				}
			}
		}
		e.tags[rs.Tag] = true
	}

	log.Infof("RULESET: %d rules loaded into %d tags", e.countRules(db), len(e.tags))
	// Rebuild in-memory engine from SQLite rows.
	return e.rebuild(db)
}

// rebuild reconstructs the in-memory matchers from ruleset_entries.
func (e *Engine) countRules(db RuleSetStorage) int {
	var n int
	if err := db.SQLQueryRow("SELECT COUNT(*) FROM ruleset_entries").Scan(&n); err != nil {
		return 0
	}
	return n
}

func (e *Engine) rebuild(db RuleSetStorage) error {
	rows, err := db.LoadRuleSetEntries()
	if err != nil {
		return err
	}
	defer rows.Close() //nolint:errcheck // best-effort

	ipByTag := make(map[string][]string)
	dm := &domainMatcher{suffix: make(map[string]string)}

	for rows.Next() {
		var tag, typ, value string
		if err := rows.Scan(&tag, &typ, &value); err != nil {
			continue
		}
		switch typ {
		case "ip":
			ipByTag[tag] = append(ipByTag[tag], value)
		case "domain":
			dm.suffix[value] = tag
		}
	}

	var ipConfigs []ipRule
	for tag, cidrs := range ipByTag {
		ipConfigs = append(ipConfigs, ipRule{tag: tag, cidrs: cidrs})
	}

	if len(ipConfigs) > 0 {
		var merr error
		e.ip, merr = newIPMatcher(ipConfigs)
		if merr != nil {
			return merr
		}
	} else {
		e.ip = nil
	}
	e.domain = dm
	return nil
}

// Match returns all tags that match the given query name and client IP.
// Returns nil when no tags match, avoiding allocation on the common path.
func (e *Engine) Match(qname, ip string) map[string]bool {
	var tags map[string]bool
	if e.ip != nil {
		for _, t := range e.ip.match(ip) {
			if tags == nil {
				tags = make(map[string]bool)
			}
			tags[t] = true
		}
	}
	if e.domain != nil {
		if t := e.domain.match(qname); t != "" {
			if tags == nil {
				tags = make(map[string]bool)
			}
			tags[t] = true
		}
	}
	return tags
}

// MatchIP checks whether an IP matches a specific tag. Used for response
// record filtering. Tags prefixed with ! are negated.
// HasIPTag reports whether a tag has CIDR rules for IP-based filtering.
func (e *Engine) HasIPTag(tag string) bool {
	if e == nil || e.ip == nil {
		return false
	}
	_, ok := e.ip.tags[tag]
	return ok
}

func (e *Engine) MatchIP(ip, tag string) (matched, exists bool) {
	if e == nil {
		return false, false
	}
	negate := false
	if tag != "" && tag[0] == '!' {
		negate = true
		tag = tag[1:]
	}
	// Tag must exist in config — if not, refuse the response (config error).
	if !e.tags[tag] {
		return false, false
	}
	if e.ip == nil {
		return false, true // tag exists but no IP rules: skip (domain-only)
	}
	m, ok := e.ip.matchTag(ip, tag)
	if !ok {
		return false, true // tag exists but no IP rules for it
	}
	if negate {
		return !m, true
	}
	return m, true
}
