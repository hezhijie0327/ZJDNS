package zone

import (
	"strconv"
	"strings"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"

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
	return &dns.RFC3597{
		Hdr:     dns.Header{Name: name, Class: class, TTL: ttl},
		RFC3597: rdata.RFC3597{RRType: record.Type, Data: record.Content},
	}
}
