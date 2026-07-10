// Package zone provides DNS zone-file-style query matching backed by SQLite.
// Rules are loaded into an in-memory SQLite database at startup and queried
// via B-tree indexed prepared statements — O(log n) per lookup with near-zero
// Go heap footprint regardless of rule count.
package zone

import (
	"bufio"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"zjdns/config"
	"zjdns/database"
	"zjdns/internal/log"

	zdnsutil "zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// wildcardPrefix marks a domain as a wildcard rule.
const wildcardPrefix = "*."

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
}

// dynamicEntry holds a dynamic content function and its record configs.
type dynamicEntry struct {
	fn      func() []string
	configs []config.ZoneRecord
}

// Evaluator manages zone rules backed by a SQLite database.
type Evaluator struct {
	db         *database.DB
	loadedAt   atomic.Int64
	ruleCount  atomic.Int64
	dynamics   map[string]*dynamicEntry // qname → dynamic content
	bypassTags map[string]struct{}      // tags that bypass all zone rules
}

// New creates an Evaluator backed by the given database.
// The caller is responsible for opening the database via database.Open()
// before calling New.
func New(db *database.DB) *Evaluator {
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

// SetBypassTags sets tags that cause zone evaluation to be skipped entirely.
// Clients matching any of these tags will never match zone rules.
func (e *Evaluator) SetBypassTags(tags []string) {
	e.bypassTags = make(map[string]struct{}, len(tags))
	for _, t := range tags {
		e.bypassTags[t] = struct{}{}
	}
}

// Bypass reports whether zone evaluation should be skipped for the given tags.
func (e *Evaluator) Bypass(matchedTags map[string]bool) bool {
	if len(e.bypassTags) == 0 || len(matchedTags) == 0 {
		return false
	}
	for tag := range e.bypassTags {
		if matchedTags[tag] {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// LoadRules
// ---------------------------------------------------------------------------

// LoadRules validates and loads zone rules into the SQLite database.
func (e *Evaluator) LoadRules(rules []config.ZoneRule) error {
	if _, err := e.db.Exec(`DELETE FROM zone_entries`); err != nil {
		return fmt.Errorf("zone: clear: %w", err)
	}
	// Clear dynamic content registrations.
	e.dynamics = make(map[string]*dynamicEntry)

	tx, err := e.db.Begin()
	if err != nil {
		return fmt.Errorf("zone: begin tx: %w", err)
	}

	total := int64(0)
	for i := range rules {
		rule := &rules[i]
		if rule.File != "" {
			n, err := e.loadFile(rule)
			if err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("zone file %q: %w", rule.File, err)
			}
			total += int64(n)
			log.Infof("ZONE: loaded %d entries from %s", n, rule.File)
			continue
		}
		n, err := e.loadInline(rule)
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

func (e *Evaluator) loadInline(rule *config.ZoneRule) (int, error) {
	if rule.Name == "" {
		return 0, errors.New("zone rule: name is required")
	}
	if len(rule.Name) > config.MaxDomainLength {
		log.Warnf("ZONE: rule name too long, skipping")
		return 0, nil
	}

	// Dynamic content: store function in Go map.
	normalizedName := zdnsutil.NormalizeDomain(rule.Name)

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
			if err := e.insertRow(normalizedName, g.qtype, g.qclass, rule.Rcode, aw, auth, addl, matchTags, isWildcard); err != nil {
				return 0, err
			}
			count++
		}
	} else if rule.Rcode != dns.RcodeSuccess || rule.DynamicContent != nil {
		// Sentinel entry for rcode-only or dynamic rules.
		auth := packRRs(rule.Name, rule.Authority)
		addl := packRRs(rule.Name, rule.Additional)
		if err := e.insertRow(normalizedName, 0, 0, rule.Rcode, nil, auth, addl, matchTags, isWildcard); err != nil {
			return 0, err
		}
		count++
	}

	return count, nil
}

func (e *Evaluator) insertRow(qname string, qtype, qclass uint16, rcode int, answer, authority, additional []byte, matchTags string, isWildcard bool) error {
	w := 0
	if isWildcard {
		w = 1
	}
	_, err := e.db.StmtZoneInsert.Exec(qname, qtype, qclass, rcode, answer, authority, additional, matchTags, w)
	return err
}

// ---------------------------------------------------------------------------
// Evaluate
// ---------------------------------------------------------------------------

// Evaluate checks a query against loaded zone rules.
// matchedTags is the set of CIDR tags the client IP matched (from cidr.Filter).
// nil or empty map means no CIDR matching is active.
func (e *Evaluator) Evaluate(qname string, qtype, qclass uint16, matchedTags map[string]bool) Result {
	if qclass == 0 {
		qclass = dns.ClassINET
	}
	if len(qname) > config.MaxDomainLength {
		return Result{Rcode: dns.RcodeSuccess}
	}
	if e.ruleCount.Load() == 0 {
		return Result{Rcode: dns.RcodeSuccess}
	}

	qname = zdnsutil.NormalizeDomain(qname)

	// 1. Check dynamic content (Go map, not SQL).
	if de, ok := e.dynamics[qname]; ok {
		return e.evalDynamic(qname, qtype, qclass, de)
	}

	loadedAt := e.loadedAt.Load()

	// 2. Exact composite key lookup.
	if r := e.query(e.db.StmtZoneExact, qname, qtype, qclass, matchedTags, loadedAt); r.Matched {
		return r
	}

	// 3. Sentinel key (rcode-only rules).
	if r := e.query(e.db.StmtZoneExact, qname, 0, 0, matchedTags, loadedAt); r.Matched {
		return r
	}

	// 4. Wildcard suffix walk.
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
		if r := e.query(e.db.StmtZoneWild, rest, qtype, qclass, matchedTags, loadedAt); r.Matched {
			return r
		}
		if r := e.query(e.db.StmtZoneWild, rest, 0, 0, matchedTags, loadedAt); r.Matched {
			return r
		}
	}

	return Result{Rcode: dns.RcodeSuccess}
}

func (e *Evaluator) query(stmt *sql.Stmt, qname string, qtype, qclass uint16, matchedTags map[string]bool, loadedAt int64) Result {
	var rcode int
	var answerBlob, authBlob, addlBlob []byte
	var tagsText string
	if err := stmt.QueryRow(qname, qtype, qclass).Scan(&rcode, &answerBlob, &authBlob, &addlBlob, &tagsText); err != nil {
		return Result{Rcode: dns.RcodeSuccess}
	}

	// Check match tags before unpacking RRs.
	if tagsText != "" && !matchTagsOK(parseMatchTagsText(tagsText), matchedTags) {
		return Result{Rcode: dns.RcodeSuccess}
	}

	return Result{
		Domain:     qname,
		Matched:    true,
		Rcode:      rcode,
		Answer:     unpackRRs(answerBlob),
		Authority:  unpackRRs(authBlob),
		Additional: unpackRRs(addlBlob),
		CreatedAt:  loadedAt,
	}
}

func (e *Evaluator) evalDynamic(qname string, qtype, qclass uint16, de *dynamicEntry) Result {
	var contents []string
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

func matchTagsOK(entryTags []matchTag, matchedTags map[string]bool) bool {
	if len(entryTags) == 0 {
		return true
	}
	if matchedTags == nil {
		return false
	}
	for _, mt := range entryTags {
		matched, exists := matchedTags[mt.tag]
		if !exists {
			return false
		}
		if mt.negate == matched {
			return false
		}
	}
	return true
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
	tags, _ := parseMatchTags(parts)
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
		tag := strings.TrimPrefix(s, "!")
		if tag == "" {
			return nil, fmt.Errorf("invalid match tag %q", s)
		}
		tags = append(tags, matchTag{tag: tag, negate: negate})
	}
	return tags, nil
}

// ---------------------------------------------------------------------------
// Zone file import — domain headers + record lines
// ---------------------------------------------------------------------------

// loadFile parses a zone file and inserts entries directly into SQL.
func (e *Evaluator) loadFile(parent *config.ZoneRule) (int, error) {
	f, err := os.Open(parent.File) //nolint:gosec // G304: user-configured file path
	if err != nil {
		return 0, fmt.Errorf("open: %w", err)
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	count := 0

	var (
		curDomain   string
		curRawName  string // un-normalized, for buildRecord
		curWildcard bool
		curRcode    int
		curTags     string
		curRecords  []config.ZoneRecord
		curAuth     []config.ZoneRecord
		curAddl     []config.ZoneRecord
	)

	flush := func() {
		if curDomain == "" {
			return
		}
		groups := groupRecordsByTypeClass(curRecords)
		if len(groups) > 0 {
			for _, g := range groups {
				aw := packRRs(curRawName, g.records)
				auth := packRRs(curRawName, curAuth)
				addl := packRRs(curRawName, curAddl)
				_ = e.insertRow(curDomain, g.qtype, g.qclass, curRcode, aw, auth, addl, curTags, curWildcard)
				count++
			}
		} else if curRcode != dns.RcodeSuccess {
			auth := packRRs(curRawName, curAuth)
			addl := packRRs(curRawName, curAddl)
			_ = e.insertRow(curDomain, 0, 0, curRcode, nil, auth, addl, curTags, curWildcard)
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
			flush()

			isWildcard := line[0] == '*'
			if isWildcard {
				curRawName = line[2:]
			} else {
				curRawName = line[1:]
			}

			fields := strings.Fields(curRawName)
			curDomain = zdnsutil.NormalizeDomain(fields[0])
			curWildcard = isWildcard
			curRcode = parent.Rcode
			curTags = serializeMatchTags(parent.Match)
			curRecords = nil
			curAuth = nil
			curAddl = nil

			for _, f := range fields[1:] {
				if strings.HasPrefix(f, "rcode=") {
					if n, err := strconv.Atoi(f[6:]); err == nil {
						curRcode = n
					}
				} else if strings.HasPrefix(f, "match=") {
					curTags = f[6:] // store raw, validated at query time
				}
			}
			continue
		}

		// Record line: must start with a digit.
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
			curAuth = append(curAuth, rec)
		case "additional":
			curAddl = append(curAddl, rec)
		default:
			curRecords = append(curRecords, rec)
		}
	}
	flush()

	if err := sc.Err(); err != nil {
		return 0, fmt.Errorf("read: %w", err)
	}
	return count, nil
}

// parseRecordLine parses a zone record line: TYPE CONTENT [TTL] [key=value ...]
// Content may be double-quoted if it contains spaces (e.g. SOA rdata).
func parseRecordLine(line string) (config.ZoneRecord, string, error) {
	fields := tokenize(line)
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

// tokenize splits a line by whitespace, preserving double-quoted strings.
func tokenize(line string) []string {
	var tokens []string
	i := 0
	for i < len(line) {
		// Skip whitespace.
		for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		if i >= len(line) {
			break
		}
		if line[i] == '"' {
			// Quoted string.
			i++ // skip opening quote
			j := i
			for j < len(line) && line[j] != '"' {
				j++
			}
			tokens = append(tokens, line[i:j])
			i = j + 1 // skip closing quote
		} else {
			j := i
			for j < len(line) && line[j] != ' ' && line[j] != '\t' {
				j++
			}
			tokens = append(tokens, line[i:j])
			i = j
		}
	}
	return tokens
}

// groupRecordsByTypeClass groups records sharing the same (Type, Class).
func groupRecordsByTypeClass(records []config.ZoneRecord) []recordGroup {
	if len(records) == 0 {
		return nil
	}
	type kk struct{ qt, qc uint16 }
	groups := make([]recordGroup, 0, len(records))
	seen := make(map[kk]int)
	for _, rec := range records {
		qclass := rec.Class
		if qclass == 0 {
			qclass = dns.ClassINET
		}
		idxKey := kk{qt: rec.Type, qc: qclass}
		if idx, ok := seen[idxKey]; ok {
			groups[idx].records = append(groups[idx].records, rec)
		} else {
			seen[idxKey] = len(groups)
			groups = append(groups, recordGroup{qtype: rec.Type, qclass: qclass, records: []config.ZoneRecord{rec}})
		}
	}
	return groups
}

type recordGroup struct {
	qtype   uint16
	qclass  uint16
	records []config.ZoneRecord
}

// ---------------------------------------------------------------------------
// Wire encoding: zstd(dns.Msg.Pack())
// ---------------------------------------------------------------------------

// packRRs builds RRs from config, packs into a dns.Msg, and compresses.
func packRRs(domain string, records []config.ZoneRecord) []byte {
	rrs := buildRRs(domain, records)
	if len(rrs) == 0 {
		return nil
	}
	msg := &dns.Msg{Answer: rrs}
	if err := msg.Pack(); err != nil {
		return nil
	}
	return database.Compress(msg.Data)
}

// unpackRRs decompresses a blob and unpacks the RRs from the dns.Msg.
func unpackRRs(blob []byte) []dns.RR {
	if len(blob) == 0 {
		return nil
	}
	wire, err := database.Decompress(blob)
	if err != nil {
		return nil
	}
	msg := &dns.Msg{}
	msg.Data = wire
	if err := msg.Unpack(); err != nil {
		return nil
	}
	return msg.Answer
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
	return &dns.RFC3597{
		Hdr:     dns.Header{Name: name, Class: class, TTL: ttl},
		RFC3597: rdata.RFC3597{RRType: record.Type, Data: record.Content},
	}
}
