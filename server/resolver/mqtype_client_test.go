package resolver

import (
	"net/netip"
	"testing"
	"zjdns/cache"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

func mqTestMsg() *dns.Msg {
	msg := new(dns.Msg)
	msg.Question = []dns.RR{&dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}}}
	return msg
}

func mqA(ip string) *dns.A {
	return &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr(ip)}}
}

func mqAAAA(ip string) *dns.AAAA {
	return &dns.AAAA{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, AAAA: rdata.AAAA{Addr: netip.MustParseAddr(ip)}}
}

// TestAttachMQType_Subtraction verifies the attach rule: configured types
// minus the primary QTYPE, attached only when the remainder is non-empty.
func TestAttachMQType_Subtraction(t *testing.T) {
	cases := []struct {
		name    string
		mqtype  []uint16
		primary uint16
		want    []uint16 // nil = no option
	}{
		{"A query bundles AAAA", []uint16{dns.TypeA, dns.TypeAAAA}, dns.TypeA, []uint16{dns.TypeAAAA}},
		{"AAAA query bundles A", []uint16{dns.TypeA, dns.TypeAAAA}, dns.TypeAAAA, []uint16{dns.TypeA}},
		{"no remainder", []uint16{dns.TypeA}, dns.TypeA, nil},
		{"unconfigured", nil, dns.TypeA, nil},
		{"meta primary skipped", []uint16{dns.TypeA, dns.TypeAAAA}, dns.TypeANY, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := mqTestMsg()
			attachMQType(msg, tc.mqtype, tc.primary)
			if tc.want == nil {
				if len(msg.Pseudo) != 0 {
					t.Fatalf("expected no MQTYPE-Query, got %v", msg.Pseudo)
				}
				return
			}
			var mq *dns.MQQUERY
			for _, rr := range msg.Pseudo {
				if q, ok := rr.(*dns.MQQUERY); ok {
					mq = q
				}
			}
			if mq == nil {
				t.Fatalf("expected an MQTYPE-Query, got %v", msg.Pseudo)
			}
			if len(mq.Types) != len(tc.want) || mq.Types[0] != tc.want[0] {
				t.Fatalf("types = %v, want %v", mq.Types, tc.want)
			}
		})
	}
}

// TestParseMQResponse_Valid returns the single MQTYPE-Response.
func TestParseMQResponse_Valid(t *testing.T) {
	resp := mqTestMsg()
	resp.Pseudo = append(resp.Pseudo, &dns.MQRESPONSE{Types: []uint16{dns.TypeAAAA}})
	mqr, invalid := parseMQResponse(resp)
	if invalid || mqr == nil || len(mqr.Types) != 1 || mqr.Types[0] != dns.TypeAAAA {
		t.Fatalf("valid response misparsed: mqr=%v invalid=%t", mqr, invalid)
	}
}

// TestParseMQResponse_Absent reports unsupported, not invalid.
func TestParseMQResponse_Absent(t *testing.T) {
	resp := mqTestMsg()
	mqr, invalid := parseMQResponse(resp)
	if invalid || mqr != nil {
		t.Fatalf("absent option misparsed: mqr=%v invalid=%t", mqr, invalid)
	}
}

// TestParseMQResponse_MQQueryInResponse — §3.5: an MQTYPE-Query in a
// response means the extension is unsupported.
func TestParseMQResponse_MQQueryInResponse(t *testing.T) {
	resp := mqTestMsg()
	resp.Pseudo = append(resp.Pseudo, &dns.MQQUERY{Types: []uint16{dns.TypeAAAA}})
	mqr, invalid := parseMQResponse(resp)
	if invalid || mqr != nil {
		t.Fatalf("MQTYPE-Query in response misparsed: mqr=%v invalid=%t", mqr, invalid)
	}
}

// TestParseMQResponse_Duplicate — §3.5: a duplicated MQTYPE-Response
// invalidates the answer.
func TestParseMQResponse_Duplicate(t *testing.T) {
	resp := mqTestMsg()
	resp.Pseudo = append(resp.Pseudo,
		&dns.MQRESPONSE{Types: []uint16{dns.TypeAAAA}},
		&dns.MQRESPONSE{Types: []uint16{dns.TypeHTTPS}})
	_, invalid := parseMQResponse(resp)
	if !invalid {
		t.Fatal("duplicated MQTYPE-Response not flagged invalid")
	}
}

// TestParseMQResponse_QTxDuplicatesPrimary — §3.5: a QTx duplicating the
// primary QTYPE invalidates the answer.
func TestParseMQResponse_QTxDuplicatesPrimary(t *testing.T) {
	resp := mqTestMsg()
	resp.Pseudo = append(resp.Pseudo, &dns.MQRESPONSE{Types: []uint16{dns.TypeA}})
	_, invalid := parseMQResponse(resp)
	if !invalid {
		t.Fatal("QTx duplicating the primary not flagged invalid")
	}
}

// TestParseMQResponse_QTxDuplicate — §3.5: duplicated QTx values invalidate
// the answer.
func TestParseMQResponse_QTxDuplicate(t *testing.T) {
	resp := mqTestMsg()
	resp.Pseudo = append(resp.Pseudo, &dns.MQRESPONSE{Types: []uint16{dns.TypeAAAA, dns.TypeAAAA}})
	_, invalid := parseMQResponse(resp)
	if !invalid {
		t.Fatal("duplicated QTx not flagged invalid")
	}
}

// TestStripMQBundled strips merged types + their RRSIGs at the qname while
// keeping the primary answer and CNAME-chain records.
func TestStripMQBundled(t *testing.T) {
	sig := &dns.RRSIG{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, RRSIG: rdata.RRSIG{TypeCovered: dns.TypeAAAA}}
	answer := []dns.RR{
		mqA("192.0.2.1"),
		mqAAAA("2001:db8::1"),
		sig,
		&dns.CNAME{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, CNAME: rdata.CNAME{Target: "www.example.net."}},
		&dns.AAAA{Hdr: dns.Header{Name: "www.example.net.", Class: dns.ClassINET, TTL: 300}, AAAA: rdata.AAAA{Addr: netip.MustParseAddr("2001:db8::2")}}, // chain target record — different owner
	}
	out := stripMQBundled(answer, "example.com.", []uint16{dns.TypeAAAA})
	if len(out) != 3 {
		t.Fatalf("stripped answer = %d records, want 3", len(out))
	}
	for _, rr := range out {
		switch rr.(type) {
		case *dns.AAAA:
			if rr.Header().Name == "example.com." {
				t.Fatal("merged AAAA at qname survived strip")
			}
		case *dns.RRSIG:
			t.Fatal("merged RRSIG survived strip")
		}
	}
}

// TestWarmFromMQResponse_Positive caches the merged records (with RRSIGs).
func TestWarmFromMQResponse_Positive(t *testing.T) {
	r := &Resolver{cache: cache.New(0, 0)}
	sig := &dns.RRSIG{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, RRSIG: rdata.RRSIG{TypeCovered: dns.TypeAAAA}}
	resp := mqTestMsg()
	resp.Answer = append(resp.Answer, mqA("192.0.2.1"), mqAAAA("2001:db8::1"), sig)
	mqr := &dns.MQRESPONSE{Types: []uint16{dns.TypeAAAA}}
	r.warmFromMQResponse(resp, "example.com.", dns.ClassINET, mqr, nil, true)
	entry, found, expired := r.cache.Get("example.com.", dns.TypeAAAA, dns.ClassINET, nil)
	if !found || expired {
		t.Fatalf("AAAA not warmed: found=%t expired=%t", found, expired)
	}
	if err := entry.Unpack(); err != nil {
		t.Fatalf("unpack warmed entry: %v", err)
	}
	if len(entry.Answer) != 2 { // AAAA + its RRSIG
		t.Fatalf("warmed answer = %d records, want 2", len(entry.Answer))
	}
}

// TestWarmFromMQResponse_Negative caches NODATA with the denial proofs.
func TestWarmFromMQResponse_Negative(t *testing.T) {
	r := &Resolver{cache: cache.New(0, 0)}
	resp := mqTestMsg()
	resp.Authoritative = true
	resp.Ns = append(resp.Ns, &dns.SOA{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}})
	mqr := &dns.MQRESPONSE{Types: []uint16{dns.TypeAAAA}}
	r.warmFromMQResponse(resp, "example.com.", dns.ClassINET, mqr, nil, true)
	entry, found, expired := r.cache.Get("example.com.", dns.TypeAAAA, dns.ClassINET, nil)
	if !found || expired {
		t.Fatalf("NODATA not warmed: found=%t expired=%t", found, expired)
	}
	if err := entry.Unpack(); err != nil {
		t.Fatalf("unpack warmed entry: %v", err)
	}
	if len(entry.Answer) != 0 || len(entry.Authority) != 1 {
		t.Fatalf("warmed negative = answer %d / authority %d, want 0/1", len(entry.Answer), len(entry.Authority))
	}
}

// TestWarmFromMQResponse_Referral warms nothing — a referral carries NS in
// authority, no SOA, no records.
func TestWarmFromMQResponse_Referral(t *testing.T) {
	r := &Resolver{cache: cache.New(0, 0)}
	resp := mqTestMsg()
	resp.Ns = append(resp.Ns, &dns.NS{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, NS: rdata.NS{Ns: "ns1.example.com."}})
	mqr := &dns.MQRESPONSE{Types: []uint16{dns.TypeAAAA}}
	r.warmFromMQResponse(resp, "example.com.", dns.ClassINET, mqr, nil, true)
	if _, found, _ := r.cache.Get("example.com.", dns.TypeAAAA, dns.ClassINET, nil); found {
		t.Fatal("referral warmed the cache")
	}
}

// TestWarmFromMQResponse_Truncated warms nothing.
func TestWarmFromMQResponse_Truncated(t *testing.T) {
	r := &Resolver{cache: cache.New(0, 0)}
	resp := mqTestMsg()
	resp.Truncated = true
	resp.Answer = append(resp.Answer, mqAAAA("2001:db8::1"))
	mqr := &dns.MQRESPONSE{Types: []uint16{dns.TypeAAAA}}
	r.warmFromMQResponse(resp, "example.com.", dns.ClassINET, mqr, nil, true)
	if _, found, _ := r.cache.Get("example.com.", dns.TypeAAAA, dns.ClassINET, nil); found {
		t.Fatal("truncated response warmed the cache")
	}
}
