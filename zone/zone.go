// Package zone provides DNS zone-file-style query matching backed by BadgerDB.
// Rules are loaded into BadgerDB at startup and queried via prefix scans.
package zone

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"zjdns/config"
	"zjdns/database"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/dgraph-io/badger/v4"
)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// matchTag is a parsed CIDR tag condition.
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

	cachable bool
}

// dynamicEntry holds a dynamic content function and its record configs.
type dynamicEntry struct {
	fn      func() []string
	configs []config.ZoneRecord
}

// Evaluator manages zone rules backed by BadgerDB.
type Evaluator struct {
	db        *database.DB
	loadedAt  atomic.Int64
	ruleCount atomic.Int64
	dynamics  map[string]*dynamicEntry
	bypass    [][]matchTag
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const wildcardPrefix = "*."

const maxWildcardLabels = 16

// New creates an Evaluator backed by the given database.
func New(db *database.DB) *Evaluator {
	if db == nil {
		panic("zone: nil database")
	}
	return &Evaluator{
		db:       db,
		dynamics: make(map[string]*dynamicEntry),
	}
}

// Close releases resources. The underlying database is shared and should not be
// closed here; this is a no-op provided for backward compatibility with tests.
func (e *Evaluator) Close() error { return nil }

// HasRules reports whether any zone rules are currently loaded.
func (e *Evaluator) HasRules() bool { return e.ruleCount.Load() > 0 }

// ---------------------------------------------------------------------------
// LoadRules
// ---------------------------------------------------------------------------

// LoadRules validates and loads zone rules into BadgerDB.
func (e *Evaluator) LoadRules(rules []config.ZoneRule) error {
	// Clear existing rules.
	if err := e.db.Badger.DropPrefix([]byte("z:")); err != nil {
		return fmt.Errorf("zone: clear: %w", err)
	}
	e.dynamics = make(map[string]*dynamicEntry)

	// Collect global bypass rules.
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
	err := e.db.Badger.Update(func(txn *badger.Txn) error {
		for i := range content {
			rule := &content[i]
			if rule.File != "" {
				n, err := e.loadFile(txn, rule)
				if err != nil {
					return fmt.Errorf("zone file %q: %w", rule.File, err)
				}
				total += int64(n)
				log.Infof("ZONE: loaded %d entries from %s", n, rule.File)
				continue
			}
			n, err := e.loadInline(txn, rule)
			if err != nil {
				return err
			}
			total += int64(n)
		}
		return nil
	})
	if err != nil {
		return err
	}

	e.ruleCount.Store(total)
	e.loadedAt.Store(log.NowUnix())
	log.Infof("ZONE: %d zone entries loaded", total)
	return nil
}

func (e *Evaluator) loadInline(txn *badger.Txn, rule *config.ZoneRule) (int, error) {
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
			if err := e.insertRow(txn, normalizedName, g.qtype, g.qclass, rule.Rcode, aw, auth, addl, matchTags, isWildcard); err != nil {
				return 0, err
			}
			count++
		}
	}
	// Dynamic content rules always get a sentinel (qtype=0, qclass=0) so they
	// are discoverable regardless of the query's DNS class (CHAOS vs IN).
	if rule.DynamicContent != nil {
		auth := packRRs(rule.Name, rule.Authority)
		addl := packRRs(rule.Name, rule.Additional)
		if err := e.insertRow(txn, normalizedName, 0, 0, rule.Rcode, nil, auth, addl, matchTags, isWildcard); err != nil {
			return 0, err
		}
		count++
	} else if rule.Rcode != dns.RcodeSuccess && len(groups) == 0 {
		// Rcode-only rule: sentinel entry matches any qtype/qclass.
		auth := packRRs(rule.Name, rule.Authority)
		addl := packRRs(rule.Name, rule.Additional)
		if err := e.insertRow(txn, normalizedName, 0, 0, rule.Rcode, nil, auth, addl, matchTags, isWildcard); err != nil {
			return 0, err
		}
		count++
	}

	return count, nil
}

func (e *Evaluator) insertRow(txn *badger.Txn, qname string, qtype, qclass uint16, rcode int, answer, authority, additional []byte, matchTags string, isWildcard bool) error {
	key := database.ZoneEntryKey(isWildcard, qname, qtype, qclass, matchTags)
	val := database.EncodeZoneValue(rcode, answer, authority, additional)
	return txn.Set(key, val)
}

// ---------------------------------------------------------------------------
// Evaluate
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
			log.Debugf("ZONE: bypass matched, skipping zone for %s", qname)
			return Result{Rcode: dns.RcodeSuccess}
		}
	}

	if e.ruleCount.Load() == 0 && len(e.bypass) == 0 {
		return Result{Rcode: dns.RcodeSuccess}
	}

	qname = dnsutil.Canonical(qname)

	if de, ok := e.dynamics[qname]; ok {
		return e.evalDynamic(qname, qtype, qclass, de)
	}

	loadedAt := e.loadedAt.Load()

	// Exact composite key lookup.
	if r := e.queryExact(qname, qtype, qclass, matchedTags, loadedAt); r.Matched {
		return r
	}

	// Sentinel key (rcode-only rules).
	if r := e.queryExact(qname, 0, 0, matchedTags, loadedAt); r.Matched {
		return r
	}

	// Wildcard suffix batch.
	return e.queryWildcardBatch(qname, qtype, qclass, matchedTags, loadedAt)
}

func (e *Evaluator) queryExact(qname string, qtype, qclass uint16, matchedTags map[string]bool, loadedAt int64) Result {
	var bestScore int
	var best Result

	prefix := database.ZoneExactPrefix(qname, qtype, qclass)
	_ = e.db.Badger.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		opts.PrefetchValues = true
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			_ = item.Value(func(v []byte) error {
				rcode, answerBlob, authBlob, addlBlob := database.DecodeZoneValue(v)
				tagsText := extractMatchTagsFromZoneKey(string(item.Key()))
				score := matchScore(parseMatchTagsText(tagsText), matchedTags)
				if score < 0 {
					return nil
				}
				if score <= bestScore && best.Matched {
					return nil
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
				return nil
			})
		}
		return nil
	})

	if !best.Matched {
		return Result{Rcode: dns.RcodeSuccess}
	}
	return best
}

func (e *Evaluator) queryWildcardBatch(qname string, qtype, qclass uint16, matchedTags map[string]bool, loadedAt int64) Result {
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
	if len(suffixes) > maxWildcardLabels {
		suffixes = suffixes[:maxWildcardLabels]
	}

	var bestScore int
	var best Result

	_ = e.db.Badger.View(func(txn *badger.Txn) error {
		for _, suffix := range suffixes {
			prefix := database.ZoneWildcardPrefix(suffix)
			opts := badger.DefaultIteratorOptions
			opts.Prefix = prefix
			opts.PrefetchValues = true
			it := txn.NewIterator(opts)
			defer it.Close() //nolint:gocritic // defer in loop is required for per-suffix iteration

			for it.Rewind(); it.Valid(); it.Next() {
				item := it.Item()
				k := string(item.Key())
				kqtype, kqclass := parseZoneKeyTypeClass(k)
				// Match qtype/qclass: concrete matches or sentinel (0/0).
				if (kqtype != qtype || kqclass != qclass) && (kqtype != 0 || kqclass != 0) {
					continue
				}
				_ = item.Value(func(v []byte) error {
					rcode, answerBlob, authBlob, addlBlob := database.DecodeZoneValue(v)
					tagsText := extractMatchTagsFromZoneKey(k)
					score := matchScore(parseMatchTagsText(tagsText), matchedTags)
					if score < 0 {
						return nil
					}
					if score <= bestScore && best.Matched {
						return nil
					}
					bestScore = score
					best = Result{
						Domain:     suffix,
						Matched:    true,
						Rcode:      rcode,
						Answer:     unpackRRs(answerBlob),
						Authority:  unpackRRs(authBlob),
						Additional: unpackRRs(addlBlob),
						CreatedAt:  loadedAt,
						cachable:   score == 0,
					}
					return nil
				})
			}
			it.Close()
		}
		return nil
	})

	if !best.Matched {
		return Result{Rcode: dns.RcodeSuccess}
	}
	return best
}

// extractMatchTagsFromZoneKey parses the match_tags suffix from a zone key.
// Key format: z:{w:1B}\x00{qname}\x00{qtype:2B}\x00{qclass:2B}\x00{match_tags}
func extractMatchTagsFromZoneKey(key string) string {
	qnameEnd := 4
	for qnameEnd < len(key) && key[qnameEnd] != 0 {
		qnameEnd++
	}
	// match_tags starts after: qnameEnd(NUL) + 1 + qtype(2) + NUL(1) + qclass(2) + NUL(1) = qnameEnd+7
	tagsOff := qnameEnd + 7
	if tagsOff < len(key) {
		return key[tagsOff:]
	}
	return ""
}

// parseZoneKeyTypeClass extracts qtype and qclass from a zone key.
// Key format: z:{w:1B}\x00{qname}\x00{qtype:2B BE}\x00{qclass:2B BE}\x00{match_tags}
// Uses offset-based parsing to avoid ambiguity from 0x00 bytes inside binary fields.
func parseZoneKeyTypeClass(key string) (qtype, qclass uint16) {
	// Skip "z:" (2) + wildcard byte (1) + NUL (1) = 4 bytes, then find qname end.
	qnameEnd := 4
	for qnameEnd < len(key) && key[qnameEnd] != 0 {
		qnameEnd++
	}
	// qtype starts at qnameEnd+1, 2 bytes BE.
	qtypeOff := qnameEnd + 1
	if qtypeOff+2 <= len(key) {
		qtype = binary.BigEndian.Uint16([]byte(key[qtypeOff : qtypeOff+2]))
	}
	// qclass starts at qtypeOff+2 (skip qtype) + 1 (skip NUL) = qtypeOff+3, 2 bytes BE.
	qclassOff := qtypeOff + 3
	if qclassOff+2 <= len(key) {
		qclass = binary.BigEndian.Uint16([]byte(key[qclassOff : qclassOff+2]))
	}
	return qtype, qclass
}

func (e *Evaluator) evalDynamic(qname string, qtype, qclass uint16, de *dynamicEntry) Result {
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

// matchScore returns a match quality score.
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
