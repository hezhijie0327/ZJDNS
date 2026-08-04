// Package zone provides DNS zone-file-style query matching backed by SQLite.
// Rules are loaded into a SQLite database at startup and queried
// via B-tree indexed prepared statements — O(log n) per lookup with near-zero
// Go heap footprint regardless of rule count.
package zone

import (
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"zjdns/config"
	"zjdns/database"
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
	Domain     string
	Matched    bool
	Rcode      int
	Answer     []dns.RR
	Authority  []dns.RR
	Additional []dns.RR
	CreatedAt  int64 // LoadRules timestamp for TTL cycling

	cachable bool // internal: true when the winning rule has no match_tags
}

// dynamicEntry holds a dynamic content function and its record configs.
type dynamicEntry struct {
	fn      func() []string
	configs []config.ZoneRecord
}

// ZoneStorage is the interface for zone rule storage, following the same
// pattern as ruleset.RuleSetStorage.  It allows zone.Evaluator to depend on
// an abstraction rather than the concrete *database.DB type.
type ZoneStorage interface {
	Exec(query string, args ...any) (sql.Result, error)
	Begin() (*sql.Tx, error)
	QueryZoneExact(qname string, qtype, qclass int) (*sql.Rows, error)
	QueryZoneWildcard(args []any) (*sql.Rows, error)
	Close() error
}

// Evaluator manages zone rules backed by a ZoneStorage implementation.

type Evaluator struct {
	db        ZoneStorage
	loadedAt  atomic.Int64
	ruleCount atomic.Int64
	// rulesMu guards dynamics/bypass: LoadRules rewrites them, Evaluate
	// reads them on the query path (RLock). A runtime reload must not race
	// in-flight queries (M27).
	rulesMu  sync.RWMutex
	dynamics map[string]*dynamicEntry // qname → dynamic content
	bypass   [][]matchTag             // global bypass rules (only Match, no Name/File)
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// wildcardPrefix marks a domain as a wildcard rule.
const wildcardPrefix = "*."

// maxWildcardLabels caps the number of suffix candidates in a wildcard batch
// query.  DNS hostnames have at most 127 labels; 16 is a practical bound.  The
// SQL statement uses a fixed placeholder count so SQLite can reuse the compiled
// query plan across calls (P4).
const maxWildcardLabels = 16

var wildcardArgsPool = sync.Pool{New: func() any { a := make([]any, maxWildcardLabels+2); return &a }}

// New creates an Evaluator backed by the given database.
// The caller is responsible for opening the database via database.Open()
// before calling New. Panics if db is nil (caller must provide a valid
// database handle).
func New(db *database.DB) *Evaluator {
	if db == nil {
		panic("zone: nil database")
	}
	return &Evaluator{
		db:       db,
		dynamics: make(map[string]*dynamicEntry),
	}
}

// Close releases SQLite resources.
func (e *Evaluator) Close() error {
	return e.db.Close()
}

// HasRules reports whether any zone rules are currently loaded.
func (e *Evaluator) HasRules() bool { return e.ruleCount.Load() > 0 }

// ---------------------------------------------------------------------------
// LoadRules
// ---------------------------------------------------------------------------

// LoadRules validates and loads zone rules into the SQLite database.
func (e *Evaluator) LoadRules(rules []config.ZoneRule) error {
	e.rulesMu.Lock()
	defer e.rulesMu.Unlock()

	if _, err := e.db.Exec(`DELETE FROM zone_entries`); err != nil {
		return fmt.Errorf("zone: clear: %w", err)
	}
	// Clear dynamic content registrations.
	e.dynamics = make(map[string]*dynamicEntry)

	tx, err := e.db.Begin()
	if err != nil {
		return fmt.Errorf("zone: begin tx: %w", err)
	}

	// Collect global bypass rules: only Match, no Name/File/Answer/DynamicContent.
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
			n, err := e.loadFile(tx, rule)
			if err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("zone file %q: %w", rule.File, err)
			}
			total += int64(n)
			log.Infof("ZONE: loaded %d entries from %s", n, rule.File)
			continue
		}
		n, err := e.loadInline(tx, rule)
		if err != nil {
			_ = tx.Rollback()
			return err
		}
		total += int64(n)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("zone: commit: %w", err)
	}

	e.ruleCount.Store(total)
	e.loadedAt.Store(log.NowUnix())
	log.Infof("ZONE: %d zone entries loaded", total)
	return nil
}

func (e *Evaluator) loadInline(tx *sql.Tx, rule *config.ZoneRule) (int, error) {
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
		e.dynamics[normalizedName] = &dynamicEntry{fn: rule.DynamicContent, configs: rule.Answer}
	}
	matchTags := serializeMatchTags(rule.Match)
	isWildcard := strings.HasPrefix(rule.Name, wildcardPrefix)
	if isWildcard {
		normalizedName = normalizedName[len(wildcardPrefix):]
	}

	groups := groupRecordsByTypeClass(rule.Answer)
	count := 0

	if len(groups) > 0 {
		for _, g := range groups {
			aw := packRRs(rule.Name, g.records)
			auth := packRRs(rule.Name, rule.Authority)
			addl := packRRs(rule.Name, rule.Additional)
			if err := e.insertRow(tx, normalizedName, g.qtype, g.qclass, rule.Rcode, aw, auth, addl, matchTags, isWildcard); err != nil {
				return 0, err
			}
			count++
		}
	} else if rule.Rcode != dns.RcodeSuccess || rule.DynamicContent != nil {
		// Sentinel entry for rcode-only or dynamic rules.
		auth := packRRs(rule.Name, rule.Authority)
		addl := packRRs(rule.Name, rule.Additional)
		if err := e.insertRow(tx, normalizedName, 0, 0, rule.Rcode, nil, auth, addl, matchTags, isWildcard); err != nil {
			return 0, err
		}
		count++
	}

	return count, nil
}

func (e *Evaluator) insertRow(tx *sql.Tx, qname string, qtype, qclass uint16, rcode int, answer, authority, additional []byte, matchTags string, isWildcard bool) error {
	w := 0
	if isWildcard {
		w = 1
	}
	_, err := tx.Exec(
		`INSERT OR REPLACE INTO zone_entries
		 (is_wildcard, qname, qtype, qclass, rcode, answer, authority, additional, match_tags)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		w, qname, qtype, qclass, rcode, answer, authority, additional, matchTags,
	)
	return err
}

// ---------------------------------------------------------------------------
// Evaluate
// ---------------------------------------------------------------------------

// Evaluate checks a query against loaded zone rules.
// matchedTags is the set of ruleset tags the client IP/domain matched.
// nil or empty map means no CIDR matching is active.
func (e *Evaluator) Evaluate(qname string, qtype, qclass uint16, matchedTags map[string]bool) Result {
	if qclass == 0 {
		qclass = dns.ClassINET
	}
	if len(qname) > config.MaxDomainLength {
		return Result{Rcode: dns.RcodeSuccess}
	}

	e.rulesMu.RLock()
	defer e.rulesMu.RUnlock()

	// 0. Check global bypass rules — if any matches, skip zone entirely.
	for i, tags := range e.bypass {
		score := matchScore(tags, matchedTags)
		log.Debugf("ZONE: bypass[%d] tags=%v client_tags=%v score=%d", i, tags, matchedTags, score)
		if score > 0 {
			log.Debugf("ZONE: bypass matched, skipping zone for %s", qname)
			return Result{Rcode: dns.RcodeSuccess}
		}
	}

	if e.ruleCount.Load() == 0 && len(e.bypass) == 0 {
		return Result{Rcode: dns.RcodeSuccess}
	}

	qname = dnsutil.Canonical(qname)

	// 1. Check dynamic content (Go map, not SQL).
	if de, ok := e.dynamics[qname]; ok {
		return e.evalDynamic(qname, qtype, qclass, de)
	}

	loadedAt := e.loadedAt.Load()

	// 3. Exact composite key lookup.
	if r := e.queryExact(qname, qtype, qclass, matchedTags, loadedAt); r.Matched {
		return r
	}

	// 4. Sentinel key (rcode-only rules).
	if r := e.queryExact(qname, 0, 0, matchedTags, loadedAt); r.Matched {
		return r
	}

	// 5. Wildcard suffix batch — single IN query replaces N per-label queries.
	// ORDER BY length(qname) DESC, qtype DESC ensures the most specific
	// suffix and the concrete qtype match (over qtype=0 sentinel) win.
	r := e.queryWildcardBatch(qname, qtype, qclass, matchedTags, loadedAt)

	return r
}

func (e *Evaluator) queryExact(qname string, qtype, qclass uint16, matchedTags map[string]bool, loadedAt int64) Result {
	rows, err := e.db.QueryZoneExact(qname, int(qtype), int(qclass))
	if err != nil {
		return Result{Rcode: dns.RcodeSuccess}
	}
	defer func() { _ = rows.Close() }()

	var bestScore int
	var best Result
	for rows.Next() {
		var rcode int
		var answerBlob, authBlob, addlBlob []byte
		var tagsText string
		if err := rows.Scan(&rcode, &answerBlob, &authBlob, &addlBlob, &tagsText); err != nil {
			continue
		}

		score := matchScore(parseMatchTagsText(tagsText), matchedTags)
		if score < 0 {
			continue
		}
		if score <= bestScore && best.Matched {
			continue // not better than current best
		}

		bestScore = score
		best = Result{
			Domain:     qname,
			Matched:    true,
			Rcode:      rcode,
			Answer:     unpackRRs(answerBlob),
			Authority:  unpackRRs(authBlob),
			Additional: unpackRRs(addlBlob),
			CreatedAt:  loadedAt,
			cachable:   score == 0,
		}
	}

	if !best.Matched {
		return Result{Rcode: dns.RcodeSuccess}
	}
	return best
}

// queryWildcardBatch collects all suffix candidates from qname, issues a single
// IN query ordered by specificity, and returns the first tag-matching row.
// Replaces the per-label N-query loop (2 per suffix level) with one SQL query.
func (e *Evaluator) queryWildcardBatch(qname string, qtype, qclass uint16, matchedTags map[string]bool, loadedAt int64) Result {
	// Collect suffix candidates (e.g. "b.c.example.com", "c.example.com", "example.com").
	suffixes := make([]string, 0, 8)
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
	if len(suffixes) == 0 {
		return Result{Rcode: dns.RcodeSuccess}
	}

	// Cap at maxWildcardLabels and pad with empty strings so SQLite can
	// reuse the compiled query plan across calls with different suffix counts.
	if len(suffixes) > maxWildcardLabels {
		suffixes = suffixes[:maxWildcardLabels]
	}
	argsPtr, ok := wildcardArgsPool.Get().(*[]any)
	if !ok {
		a := make([]any, maxWildcardLabels+2)
		argsPtr = &a
	}
	args := (*argsPtr)[:maxWildcardLabels+2]
	defer func() { wildcardArgsPool.Put(argsPtr) }()
	for i := range maxWildcardLabels {
		if i < len(suffixes) {
			args[i] = suffixes[i]
		} else {
			args[i] = ""
		}
	}
	args[maxWildcardLabels] = int(qtype)
	args[maxWildcardLabels+1] = int(qclass)

	rows, err := e.db.QueryZoneWildcard(args)
	if err != nil {
		return Result{Rcode: dns.RcodeSuccess}
	}
	defer func() { _ = rows.Close() }()

	var bestScore int
	var best Result
	for rows.Next() {
		var matchedQname string
		var rcode int
		var answerBlob, authBlob, addlBlob []byte
		var tagsText string
		if err := rows.Scan(&matchedQname, &rcode, &answerBlob, &authBlob, &addlBlob, &tagsText); err != nil {
			continue
		}

		score := matchScore(parseMatchTagsText(tagsText), matchedTags)
		if score < 0 {
			continue
		}
		if score <= bestScore && best.Matched {
			continue // not better than current best
		}

		bestScore = score
		best = Result{
			Domain:     matchedQname,
			Matched:    true,
			Rcode:      rcode,
			Answer:     unpackRRs(answerBlob),
			Authority:  unpackRRs(authBlob),
			Additional: unpackRRs(addlBlob),
			CreatedAt:  loadedAt,
			cachable:   score == 0,
		}
	}

	if !best.Matched {
		return Result{Rcode: dns.RcodeSuccess}
	}
	return best
}

func (e *Evaluator) evalDynamic(qname string, qtype, qclass uint16, de *dynamicEntry) Result {
	var contents []string
	if len(de.configs) == 0 {
		// No config records — invoke the dynamic function for every
		// query (e.g. ZJDNS.cache.clear rules that have no static
		// answer records, only a DynamicContent function).
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

func serializeMatchTags(raw []string) string {
	if len(raw) == 0 {
		return ""
	}
	return strings.Join(raw, ",")
}

func parseMatchTagsText(text string) []matchTag {
	if text == "" {
		return nil
	}
	parts := strings.Split(text, ",")
	tags, err := parseMatchTags(parts)
	if err != nil {
		log.Warnf("ZONE: invalid match tags %q: %v", text, err)
	}
	return tags
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
