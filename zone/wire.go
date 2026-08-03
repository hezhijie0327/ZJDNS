package zone

import (
	"encoding/hex"
	"strconv"
	"strings"
	"zjdns/config"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// ---------------------------------------------------------------------------
// Wire encoding: raw DNS wire format (dns.Msg.Pack()).
// ---------------------------------------------------------------------------

// packRRs builds RRs from config, packs into a dns.Msg, and compresses.
func packRRs(domain string, records []config.ZoneRecord) []byte {
	rrs := buildRRs(domain, records)
	if len(rrs) == 0 {
		return nil
	}
	msg := &dns.Msg{Answer: rrs}
	if err := msg.Pack(); err != nil {
		log.Warnf("ZONE: packing records for %s failed: %v", domain, err)
		return nil
	}
	return msg.Data
}

// unpackRRs decompresses a blob and unpacks the RRs from the dns.Msg.
func unpackRRs(blob []byte) []dns.RR {
	if len(blob) == 0 {
		return nil
	}
	msg := &dns.Msg{}
	msg.Data = blob
	if err := msg.Unpack(); err != nil {
		log.Warnf("ZONE: unpacking stored records failed: %v", err)
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
		// A relative record name is joined to the enclosing zone domain
		// (e.g. "www" under "example.com" → "www.example.com."); an
		// absolute name (trailing dot) is used as-is.
		if strings.HasSuffix(record.Name, ".") {
			name = dnsutil.Fqdn(record.Name)
		} else {
			base := strings.TrimPrefix(domain, "*.")
			name = dnsutil.Fqdn(record.Name + "." + base)
		}
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

	// dns.New() may succeed for empty content (e.g. TXT with no strings)
	// but produce an RR that fails to pack.  Skip empty-content records
	// silently — they are incomplete config, not actionable errors.
	content := strings.TrimSpace(record.Content)
	if content == "" {
		return nil
	}

	// RFC 3597 fallback for unknown types: content must be the generic
	// representation "\# <length> <hex>". Anything else is a record-level
	// error — do not emit a malformed record.
	if len(content) >= 2 && content[0] == '\\' && content[1] == '#' {
		fields := strings.Fields(content[2:])
		if len(fields) == 2 {
			if n, err := strconv.ParseUint(fields[0], 10, 16); err == nil {
				// RFC 3597: the declared length must match the hex data —
				// a mismatch would pack a wire record with a wrong rdata
				// length. Mismatched content falls through to the warn
				// below rather than emitting a malformed record.
				if len(fields[1]) == 2*int(n) {
					if _, err := hex.DecodeString(fields[1]); err == nil {
						return &dns.RFC3597{
							Hdr:     dns.Header{Name: name, Class: class, TTL: ttl},
							RFC3597: rdata.RFC3597{RRType: record.Type, Data: fields[1]},
						}
					}
				}
			}
		}
	}
	log.Warnf("ZONE: invalid RFC3597 content for type %d at %s: %q", record.Type, name, record.Content)
	return nil
}
