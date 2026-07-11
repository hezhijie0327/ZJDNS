package zone

import (
	"bufio"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"zjdns/config"
	"zjdns/internal/log"

	zdnsutil "zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
)

type recordGroup struct {
	qtype   uint16
	qclass  uint16
	records []config.ZoneRecord
}

// ---------------------------------------------------------------------------
// Zone file import — domain headers + record lines
// ---------------------------------------------------------------------------

// loadFile parses a zone file and inserts entries directly into SQL.
func (e *Evaluator) loadFile(tx *sql.Tx, parent *config.ZoneRule) (int, error) {
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
				_ = e.insertRow(tx, curDomain, g.qtype, g.qclass, curRcode, aw, auth, addl, curTags, curWildcard)
				count++
			}
		} else if curRcode != dns.RcodeSuccess {
			auth := packRRs(curRawName, curAuth)
			addl := packRRs(curRawName, curAddl)
			_ = e.insertRow(tx, curDomain, 0, 0, curRcode, nil, auth, addl, curTags, curWildcard)
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
			curRawName = fields[0] // strip extra params (rcode= / match=) from domain
			if isWildcard {
				curRawName = "*." + curRawName
			}
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
