package zone

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"zjdns/config"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

type recordGroup struct {
	qtype   uint16
	qclass  uint16
	records []config.ZoneRecord
}

// ---------------------------------------------------------------------------
// Zone file import — domain headers + record lines
// ---------------------------------------------------------------------------

// loadFile parses a zone file and inserts entries into in-memory maps.
func (e *Evaluator) loadFile(parent *config.ZoneRule) (int, error) {
	//nolint:gosec // G304: user-configured file path
	f, err := os.Open(parent.File)
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

	var flushErr error
	flush := func() error {
		if flushErr != nil {
			return flushErr
		}
		if curDomain == "" {
			return nil
		}
		tags, err := parseMatchTagsText(curTags)
		if err != nil {
			flushErr = fmt.Errorf("invalid match tags %q for %s: %w", curTags, curDomain, err)
			return flushErr
		}
		groups := groupRecordsByTypeClass(curRecords)
		if len(groups) > 0 {
			for _, g := range groups {
				aw := packRRs(curRawName, g.records)
				auth := packRRs(curRawName, curAuth)
				addl := packRRs(curRawName, curAddl)
				e.store(curWildcard, exactKey(curDomain, g.qtype, g.qclass), zoneRule{matchTags: tags, rcode: curRcode, answer: aw, authority: auth, additional: addl})
				count++
			}
		} else if curRcode != dns.RcodeSuccess {
			auth := packRRs(curRawName, curAuth)
			addl := packRRs(curRawName, curAddl)
			e.store(curWildcard, exactKey(curDomain, 0, 0), zoneRule{matchTags: tags, rcode: curRcode, authority: auth, additional: addl})
			count++
		}
		return nil
	}

	// File-level defaults: an attribute-only header (". rcode=3") updates
	// these, and every subsequent domain header inherits them.
	defaultRcode := parent.Rcode
	defaultTags := serializeMatchTags(parent.Match)

	resetState := func() {
		curDomain = ""
		curRawName = ""
		curWildcard = false
		curRcode = defaultRcode
		curTags = defaultTags
		curRecords = nil
		curAuth = nil
		curAddl = nil
	}

	applyAttrs := func(fields []string, toDefaults bool) error {
		for _, f := range fields {
			if strings.HasPrefix(f, "rcode=") {
				if n, err := strconv.Atoi(f[6:]); err == nil {
					curRcode = n
					if toDefaults {
						defaultRcode = n
					}
				} else {
					return fmt.Errorf("invalid rcode attribute %q", f)
				}
			} else if strings.HasPrefix(f, "match=") {
				curTags = f[6:] // validated at flush time
				if toDefaults {
					defaultTags = f[6:]
				}
			}
		}
		return nil
	}

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}

		// Domain header: starts with . or *.
		if line[0] == '.' || (len(line) > 1 && line[0] == '*' && line[1] == '.') {
			if err := flush(); err != nil {
				return 0, err
			}

			isWildcard := line[0] == '*'
			if isWildcard {
				curRawName = line[2:]
			} else {
				curRawName = line[1:]
			}

			fields := strings.Fields(curRawName)
			if len(fields) == 0 {
				// Bare "." or "*." header — reset ALL parsing state so a
				// stray record after it cannot leak into the previous
				// domain.
				resetState()
				continue
			}

			// Attribute-only header (". rcode=3" / ". match=tag"): reset
			// state and update the FILE-LEVEL defaults — every subsequent
			// domain header inherits them. fields[0] is an attribute, not
			// a domain name.
			if strings.HasPrefix(fields[0], "rcode=") || strings.HasPrefix(fields[0], "match=") {
				resetState()
				if err := applyAttrs(fields, true); err != nil {
					return 0, err
				}
				continue
			}

			curDomain = dnsutil.Canonical(fields[0])
			curRawName = fields[0] // strip extra params (rcode= / match=) from domain
			if isWildcard {
				curRawName = "*." + curRawName
			}
			curWildcard = isWildcard
			curRcode = defaultRcode
			curTags = defaultTags
			curRecords = nil
			curAuth = nil
			curAddl = nil

			if err := applyAttrs(fields[1:], false); err != nil {
				return 0, err
			}
			continue
		}

		// Record line: must start with a digit.
		if line[0] < '0' || line[0] > '9' {
			continue
		}
		if curDomain == "" {
			log.Warnf("ZONE: record line without a preceding domain header, skipping: %s", line)
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

	// Check the scanner error BEFORE flushing — an aborted scan must not
	// persist the partially-parsed state as a complete rule.
	if err := sc.Err(); err != nil {
		return 0, fmt.Errorf("read: %w", err)
	}
	if err := flush(); err != nil {
		return 0, err
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

// tokenize splits a line by whitespace, preserving double-quoted strings and
// honouring backslash escapes inside quotes (\" and \\).
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
			var sb strings.Builder
			for i < len(line) && line[i] != '"' {
				if line[i] == '\\' && i+1 < len(line) {
					// Keep the backslash: the DNS parser resolves the
					// escape (\" and \\) from the reconstructed record.
					sb.WriteByte('\\')
					sb.WriteByte(line[i+1])
					i += 2
					continue
				}
				sb.WriteByte(line[i])
				i++
			}
			tokens = append(tokens, sb.String())
			if i < len(line) {
				i++ // skip closing quote
			}
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
