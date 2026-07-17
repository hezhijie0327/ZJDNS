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
	return zdnsutil.Compress(msg.Data)
}

// unpackRRs decompresses a blob and unpacks the RRs from the dns.Msg.
func unpackRRs(blob []byte) []dns.RR {
	if len(blob) == 0 {
		return nil
	}
	wire, err := zdnsutil.Decompress(blob)
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
