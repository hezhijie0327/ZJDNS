package zone

import (
	"strconv"
	"strings"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// ---------------------------------------------------------------------------
// RR construction — records are parsed once at load time; every match clones
// the winning rule's RRs (the zone middleware mutates them in place:
// rewriteOwnerNames, TTL deduction), so shared RRs would corrupt each other
// across queries.
// ---------------------------------------------------------------------------

// cloneRRs deep-copies an RR slice so callers can mutate headers freely.
func cloneRRs(rrs []dns.RR) []dns.RR {
	return zdnsutil.CloneRRs(rrs)
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
	// dns.New failed: the only packable fallback is RFC 3597 rdata, whose
	// wire form is hex-decoded verbatim from the Data field.  Any other
	// content (a typo'd address, a malformed rdata chunk) must be dropped
	// here — the old blanket fallback silently accepted it and failed to
	// pack on EVERY serve of the rule.
	data, ok := rfc3597Rdata(record.Content)
	if !ok {
		log.Warnf("ZONE: dropping unparseable record for %s type %s: content %q is neither valid rdata nor RFC 3597 hex", domain, typeStr, record.Content)
		return nil
	}
	return &dns.RFC3597{
		Hdr:     dns.Header{Name: name, Class: class, TTL: ttl},
		RFC3597: rdata.RFC3597{RRType: record.Type, Data: data},
	}
}

// rfc3597Rdata validates RFC 3597 presentation content — `\# <rdlength>
// <hex>` with contiguous hex — or a bare contiguous hex string, returning
// the bare hex payload (the wire packer hex-decodes Data as-is, so the
// `\# <rdlength>` prefix must not survive).
func rfc3597Rdata(content string) (string, bool) {
	fields := strings.Fields(content)
	if len(fields) >= 2 && fields[0] == `\#` {
		if len(fields) > 3 {
			return "", false
		}
		rdlength, err := strconv.Atoi(fields[1])
		if err != nil || rdlength < 0 {
			return "", false
		}
		data := ""
		if len(fields) == 3 {
			data = fields[2]
		}
		if len(data) != rdlength*2 || !isHexData(data) {
			return "", false
		}
		return data, true
	}
	if len(fields) == 1 && isHexData(fields[0]) {
		return fields[0], true
	}
	return "", false
}

// isHexData reports whether s is an even-length contiguous hex string
// (possibly empty — zero-length rdata).
func isHexData(s string) bool {
	if len(s)%2 != 0 {
		return false
	}
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}
