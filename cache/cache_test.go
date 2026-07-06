package cache

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
	"net/netip"

	"zjdns/config"
)

func testStore() *SQLiteCache {
	c, err := NewSQLiteCache("", config.DefaultMaxCacheEntries, 0, 0)
	if err != nil {
		panic(err)
	}
	return c
}

// ── Get / Set ─────────────────────────────────────────────────────────────────

func TestSet_Get_RoundTrip(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	rr := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netParseIP("192.0.2.1")}}
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr}, nil, nil, false)

	entry, found, expired := mc.Get("example.com.", dns.TypeA, dns.ClassINET, nil, false)
	if !found {
		t.Fatal("Get returned not found after Set")
	}
	if expired {
		t.Error("entry should not be expired immediately")
	}
	if len(entry.Answer) != 1 {
		t.Fatalf("answer count = %d, want 1", len(entry.Answer))
	}
	if dns.RRToType(entry.Answer[0]) != dns.TypeA {
		t.Errorf("record type = %d, want %d", dns.RRToType(entry.Answer[0]), dns.TypeA)
	}
}

func TestGet_Miss(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	_, found, _ := mc.Get("nonexistent.com.", dns.TypeA, dns.ClassINET, nil, false)
	if found {
		t.Error("Get should return not found for missing key")
	}
}

func TestSet_ValidatedFlag(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	rr := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netParseIP("192.0.2.1")}}
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr}, nil, nil, true)

	entry, found, _ := mc.Get("example.com.", dns.TypeA, dns.ClassINET, nil, false)
	if !found {
		t.Fatal("entry not found")
	}
	if !entry.Validated {
		t.Error("Validated flag not preserved")
	}
}

// ── ECS scoping ──────────────────────────────────────────────────────────────

func TestSet_Get_ECSScoping(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	rr := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netParseIP("192.0.2.1")}}
	ecs := &config.ECSOption{Family: 1, SourcePrefix: 24, ScopePrefix: 0, Address: netParseIP("192.0.2.0").AsSlice()}

	mc.Set("example.com.", dns.TypeA, dns.ClassINET, ecs, false, []dns.RR{rr}, nil, nil, false)

	// Hit with same ECS
	_, found, _ := mc.Get("example.com.", dns.TypeA, dns.ClassINET, ecs, false)
	if !found {
		t.Error("should find entry with matching ECS")
	}

	// Miss with different ECS
	ecs2 := &config.ECSOption{Family: 1, SourcePrefix: 16, ScopePrefix: 0, Address: netParseIP("10.0.0.0").AsSlice()}
	_, found, _ = mc.Get("example.com.", dns.TypeA, dns.ClassINET, ecs2, false)
	if found {
		t.Error("should miss with different ECS")
	}

	// Miss without ECS
	_, found, _ = mc.Get("example.com.", dns.TypeA, dns.ClassINET, nil, false)
	if found {
		t.Error("should miss without ECS when stored with ECS")
	}
}

func TestSet_Get_DNSSECScoping(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	rr := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netParseIP("192.0.2.1")}}

	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, true, []dns.RR{rr}, nil, nil, false)

	_, found, _ := mc.Get("example.com.", dns.TypeA, dns.ClassINET, nil, true)
	if !found {
		t.Error("should find DNSSEC-scoped entry")
	}

	_, found, _ = mc.Get("example.com.", dns.TypeA, dns.ClassINET, nil, false)
	if found {
		t.Error("should miss non-DNSSEC entry when stored with DNSSEC")
	}
}

// ── TTL / Expiry ─────────────────────────────────────────────────────────────

func TestEntry_IsExpired(t *testing.T) {
	past := time.Now().Add(-1 * time.Hour).Unix()
	entry := &Entry{Timestamp: past, TTL: 60}
	if !entry.IsExpired() {
		t.Error("entry in the past should be expired")
	}

	future := time.Now().Unix()
	entry = &Entry{Timestamp: future, TTL: 3600}
	if entry.IsExpired() {
		t.Error("entry with future timestamp should not be expired")
	}
}

func TestEntry_CanServeExpired(t *testing.T) {
	past := time.Now().Add(-1 * time.Hour).Unix()
	entry := &Entry{Timestamp: past, TTL: 300}
	if !entry.CanServeExpired(config.DefaultStaleMaxAge) {
		t.Error("entry within config.DefaultStaleMaxAge should be servable")
	}

	veryOld := time.Now().Add(-time.Duration(config.DefaultStaleMaxAge+3600) * time.Second).Unix()
	entry = &Entry{Timestamp: veryOld, TTL: 60}
	if entry.CanServeExpired(config.DefaultStaleMaxAge) {
		t.Error("entry older than config.DefaultStaleMaxAge should not be servable")
	}
}

func TestEntry_RemainingTTL(t *testing.T) {
	entry := &Entry{Timestamp: time.Now().Unix(), TTL: 300}
	remaining := entry.RemainingTTL()
	if remaining < 299 || remaining > 300 {
		t.Errorf("remaining TTL = %d, want ~300", remaining)
	}
}

// ── ProcessRecords ───────────────────────────────────────────────────────────

func TestProcessRecords_PreservesTTL(t *testing.T) {
	a := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netParseIP("192.0.2.1")}}
	result := ProcessRecords([]dns.RR{a}, 0, false, false)
	if len(result) != 1 {
		t.Fatalf("got %d records, want 1", len(result))
	}
	rec, ok := result[0].(*dns.A)
	if !ok {
		t.Fatal("not an A record")
	}
	if rec.A.String() != "192.0.2.1" {
		t.Errorf("IP = %s, want 192.0.2.1", rec.A.String())
	}
}

func TestProcessRecords_DNSSECFiltering(t *testing.T) {
	aRec := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netParseIP("192.0.2.1")}}
	rrsig := &dns.RRSIG{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300},
		RRSIG: rdata.RRSIG{TypeCovered: dns.TypeA, Algorithm: 8, Labels: 2, OrigTTL: 300,
			Expiration: uint32(time.Now().Add(1 * time.Hour).Unix()),
			Inception:  uint32(time.Now().Add(-1 * time.Hour).Unix()),
			KeyTag:     1234, SignerName: "example.com."}}
	rrs := []dns.RR{aRec, rrsig}

	withDNSSEC := ProcessRecords(rrs, 0, false, true)
	if len(withDNSSEC) != 2 {
		t.Errorf("includeDNSSEC=true: got %d records, want 2", len(withDNSSEC))
	}

	withoutDNSSEC := ProcessRecords(rrs, 0, false, false)
	if len(withoutDNSSEC) != 1 {
		t.Errorf("includeDNSSEC=false: got %d records, want 1 (RRSIG filtered out)", len(withoutDNSSEC))
	}
}

func TestProcessRecords_ElapsedTTL(t *testing.T) {
	a := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netParseIP("192.0.2.1")}}
	result := ProcessRecords([]dns.RR{a}, 100, true, false)
	if len(result) != 1 {
		t.Fatal("expected 1 record")
	}
	if result[0].Header().TTL != 200 {
		t.Errorf("TTL = %d, want 200 (300 - 100 elapsed)", result[0].Header().TTL)
	}
}

// ── Cache TTL floor ──────────────────────────────────────────────────────────

func TestSet_ZeroTTLFloored(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	rr := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 0}, A: rdata.A{Addr: netParseIP("192.0.2.1")}}
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr}, nil, nil, false)

	entry, found, _ := mc.Get("example.com.", dns.TypeA, dns.ClassINET, nil, false)
	if !found {
		t.Fatal("entry not found")
	}
	if entry.TTL != config.DefaultTTL {
		t.Errorf("TTL = %d, want %d (zero TTL floored to default)", entry.TTL, config.DefaultTTL)
	}
}

// ── NSEC/NSEC3 negative caching ──────────────────────────────────────────────

func TestHasNSECOrNSEC3(t *testing.T) {
	soa := &dns.SOA{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 900}}
	if hasNSECOrNSEC3([]dns.RR{soa}) {
		t.Error("SOA alone should not trigger negative cache")
	}
	nsec := &dns.NSEC{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 600}}
	if !hasNSECOrNSEC3([]dns.RR{soa, nsec}) {
		t.Error("NSEC+SOA should trigger negative cache")
	}
}

func TestNegativeTTLCap_NoSOA(t *testing.T) {
	capTTL := negativeTTLCap(nil)
	if capTTL != config.DefaultMaxNegativeTTL {
		t.Errorf("no SOA: cap = %d, want %d", capTTL, config.DefaultMaxNegativeTTL)
	}
}

func TestNegativeTTLCap_SOAMinLower(t *testing.T) {
	soa := &dns.SOA{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 900},
		SOA: rdata.SOA{Ns: "ns1.example.com.", Mbox: "admin.example.com.",
			Serial: 1, Refresh: 1800, Retry: 900, Expire: 604800, Minttl: 600},
	}
	capTTL := negativeTTLCap([]dns.RR{soa})
	if capTTL != 600 {
		t.Errorf("SOA TTL=900, Minttl=600: cap = %d, want 600", capTTL)
	}
}

func TestNegativeTTLCap_MinimumLower(t *testing.T) {
	soa := &dns.SOA{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300},
		SOA: rdata.SOA{Ns: "ns1.example.com.", Mbox: "admin.example.com.",
			Serial: 1, Refresh: 1800, Retry: 900, Expire: 604800, Minttl: 600},
	}
	capTTL := negativeTTLCap([]dns.RR{soa})
	if capTTL != 300 {
		t.Errorf("SOA TTL=300, Minttl=600: cap = %d, want 300", capTTL)
	}
}

func TestNegativeTTLCap_ExceedsDefaultMax(t *testing.T) {
	soa := &dns.SOA{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 99999},
		SOA: rdata.SOA{Ns: "ns1.example.com.", Mbox: "admin.example.com.",
			Serial: 1, Refresh: 1800, Retry: 900, Expire: 604800, Minttl: 99999},
	}
	capTTL := negativeTTLCap([]dns.RR{soa})
	if capTTL != config.DefaultMaxNegativeTTL {
		t.Errorf("should cap at DefaultMaxNegativeTTL=%d, got %d", config.DefaultMaxNegativeTTL, capTTL)
	}
}

func TestNegativeTTLCap_SOAWithNSEC(t *testing.T) {
	soa := &dns.SOA{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 900},
		SOA: rdata.SOA{Ns: "ns1.example.com.", Mbox: "admin.example.com.",
			Serial: 1, Refresh: 1800, Retry: 900, Expire: 604800, Minttl: 600},
	}
	nsec := &dns.NSEC{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 600}}
	capTTL := negativeTTLCap([]dns.RR{soa, nsec})
	if capTTL != 600 {
		t.Errorf("SOA+NSEC: cap = %d, want 600", capTTL)
	}
}

func TestSet_NegativeTTLCapped(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	soa := &dns.SOA{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 900},
		SOA: rdata.SOA{Ns: "ns1.example.com.", Mbox: "admin.example.com.",
			Serial: 1, Refresh: 1800, Retry: 900, Expire: 604800, Minttl: 600},
	}
	nsec := &dns.NSEC{
		Hdr:  dns.Header{Name: "alpha.example.com.", Class: dns.ClassINET, TTL: 86400},
		NSEC: rdata.NSEC{NextDomain: "zulu.example.com."},
	}
	mc.Set("beta.example.com.", dns.TypeA, dns.ClassINET, nil, false, nil, []dns.RR{soa, nsec}, nil, false)

	entry, found, _ := mc.Get("beta.example.com.", dns.TypeA, dns.ClassINET, nil, false)
	if !found {
		t.Fatal("entry not found")
	}
	if entry.TTL > 600 {
		t.Errorf("negative cache TTL = %d, want <= 600", entry.TTL)
	}
}

func TestSet_NegativeTTLUncapped_NoNSEC(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	aRec := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netParseIP("192.0.2.1")}}
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{aRec}, nil, nil, false)

	entry, found, _ := mc.Get("example.com.", dns.TypeA, dns.ClassINET, nil, false)
	if !found {
		t.Fatal("entry not found")
	}
	if entry.TTL != 300 {
		t.Errorf("positive cache TTL = %d, want 300 (no capping)", entry.TTL)
	}
}

// ── DNSKEY/NSAddr cache patterns ──────────────────────────────────────────────

func TestSet_Get_DNSKEY(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	dnskey := &dns.DNSKEY{Hdr: dns.Header{Name: "com.", Class: dns.ClassINET, TTL: 86400}}
	mc.Set("com.", dns.TypeDNSKEY, dns.ClassINET, nil, false, []dns.RR{dnskey}, nil, nil, true)

	entry, found, _ := mc.Get("com.", dns.TypeDNSKEY, dns.ClassINET, nil, false)
	if !found {
		t.Fatal("DNSKEY entry not found")
	}
	if !entry.Validated {
		t.Error("DNSKEY entry should be marked validated")
	}
}

func TestSet_Get_NSAddrTXT(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	txt := &dns.TXT{Hdr: dns.Header{Name: ".", Class: dns.ClassINET, TTL: 900}, TXT: rdata.TXT{Txt: []string{"198.41.0.4:53"}}}
	mc.Set(".", dns.TypeNone, dns.ClassINET, nil, false, []dns.RR{txt}, nil, nil, false)

	entry, found, _ := mc.Get(".", dns.TypeNone, dns.ClassINET, nil, false)
	if !found {
		t.Fatal("NS addr entry not found")
	}
	if len(entry.Answer) != 1 {
		t.Fatalf("answer count = %d, want 1", len(entry.Answer))
	}
}

// ── RecordRequest (request_log table) ──────────────────────────────────────

func TestRecordRequest_Hit(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	rr := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("1.2.3.4")}}
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr}, nil, nil, false)

	// Cache hit via UDP
	mc.RecordRequest(RequestRecord{
		Qname: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET,
		ECS: nil, DNSSECOK: false,
		Protocol: "udp", Result: "hit", Rcode: dns.RcodeSuccess,
	})

	var protocol string
	var hitCount int64
	err := mc.db.QueryRow(
		"SELECT hc.protocol, hc.hit_count FROM entry_hit_counters hc JOIN entries e ON hc.entry_id = e.id WHERE e.qname='example.com'",
	).Scan(&protocol, &hitCount)
	if err != nil {
		t.Fatalf("hit_counters query: %v", err)
	}
	if protocol != "udp" {
		t.Errorf("protocol = %s, want udp", protocol)
	}
	if hitCount != 1 {
		t.Errorf("hit_count = %d, want 1", hitCount)
	}
}

func TestRecordRequest_Stale(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	rr := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("1.2.3.4")}}
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr}, nil, nil, false)

	// Stale serve via TCP
	mc.RecordRequest(RequestRecord{
		Qname: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET,
		ECS: nil, DNSSECOK: false,
		Protocol: "tcp", Result: "stale", Rcode: dns.RcodeSuccess,
	})

	var protocol, result string
	err := mc.db.QueryRow(
		"SELECT rl.protocol, rl.result FROM request_log rl JOIN entries e ON rl.entry_id = e.id WHERE e.qname='example.com'",
	).Scan(&protocol, &result)
	if err != nil {
		t.Fatalf("request_log query: %v", err)
	}
	if protocol != "tcp" {
		t.Errorf("protocol = %s, want tcp", protocol)
	}
	if result != "stale" {
		t.Errorf("result = %s, want stale", result)
	}
}

func TestRecordRequest_MultipleResults(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	rr := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("1.2.3.4")}}
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr}, nil, nil, false)

	mc.RecordRequest(RequestRecord{Qname: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET, Protocol: "udp", Result: "hit", Rcode: dns.RcodeSuccess})
	mc.RecordRequest(RequestRecord{Qname: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET, Protocol: "udp", Result: "hit", Rcode: dns.RcodeSuccess})
	mc.RecordRequest(RequestRecord{Qname: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET, Protocol: "doh", Result: "hit", Rcode: dns.RcodeSuccess})

	var udpHits, dohHits int64
	err := mc.db.QueryRow(
		"SELECT COALESCE(SUM(CASE WHEN protocol='udp' THEN hit_count ELSE 0 END), 0), COALESCE(SUM(CASE WHEN protocol='doh' THEN hit_count ELSE 0 END), 0) FROM entry_hit_counters hc JOIN entries e ON hc.entry_id = e.id WHERE e.qname='example.com'",
	).Scan(&udpHits, &dohHits)
	if err != nil {
		t.Fatalf("hit_counters query: %v", err)
	}
	if udpHits != 2 {
		t.Errorf("udp hits = %d, want 2", udpHits)
	}
	if dohHits != 1 {
		t.Errorf("doh hits = %d, want 1", dohHits)
	}
}

// ── RecordRequest Rewrite ─────────────────────────────────────────────────────

func TestRecordRequest_Rewrite(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	mc.RecordRequest(RequestRecord{Qname: "blocked.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET, Protocol: "", Result: "rewrite", Rcode: dns.RcodeRefused})
	mc.RecordRequest(RequestRecord{Qname: "blocked.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET, Protocol: "", Result: "rewrite", Rcode: dns.RcodeRefused})

	var count int64
	err := mc.db.QueryRow(
		"SELECT COUNT(*) FROM request_log rl JOIN entries e ON rl.entry_id = e.id WHERE e.qname='blocked.com' AND rl.result='rewrite'",
	).Scan(&count)
	if err != nil {
		t.Fatalf("request_log query: %v", err)
	}
	if count != 2 {
		t.Errorf("rewrite count = %d, want 2", count)
	}
}

// ── ReverseLookup (ptr_map) ──────────────────────────────────────────────────

func TestReverseLookup(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	aRec := &dns.A{Hdr: dns.Header{Name: "www.example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("192.0.2.1")}}
	mc.Set("www.example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{aRec}, nil, nil, false)

	results := mc.ReverseLookup("192.0.2.1")
	if len(results) == 0 {
		t.Fatal("ReverseLookup returned no results")
	}
	found := false
	for _, r := range results {
		if r.Name == "www.example.com." {
			found = true
			break
		}
	}
	if !found {
		t.Error("ReverseLookup should find www.example.com for 192.0.2.1")
	}
}

func TestReverseLookup_EmptyIP(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	results := mc.ReverseLookup("")
	if results != nil {
		t.Error("ReverseLookup with empty IP should return nil")
	}
}

// ── UpdateLatency (ip_latency table) ─────────────────────────────────────

func TestUpdateLatency(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	rr := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("8.8.8.8")}}
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr}, nil, nil, false)

	mc.UpdateLatency("8.8.8.8", 42)

	var lat int
	err := mc.db.QueryRow("SELECT latency_ms FROM ip_latency WHERE rdata_ip='8.8.8.8'").Scan(&lat)
	if err != nil {
		t.Fatalf("ip_latency query: %v", err)
	}
	if lat != 42 {
		t.Errorf("latency_ms = %d, want 42", lat)
	}
}

// ── Wire format multi-record round-trip ──────────────────────────────────────

func TestSet_Get_MultipleRecords(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	a1 := &dns.A{Hdr: dns.Header{Name: "multi.example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("10.0.0.1")}}
	a2 := &dns.A{Hdr: dns.Header{Name: "multi.example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("10.0.0.2")}}
	soa := &dns.SOA{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 900},
		SOA: rdata.SOA{Ns: "ns1.example.com.", Mbox: "admin.example.com.", Serial: 1, Refresh: 1800, Retry: 900, Expire: 604800, Minttl: 600}}

	mc.Set("multi.example.com.", dns.TypeA, dns.ClassINET, nil, false,
		[]dns.RR{a1, a2}, []dns.RR{soa}, nil, true)

	entry, found, _ := mc.Get("multi.example.com.", dns.TypeA, dns.ClassINET, nil, false)
	if !found {
		t.Fatal("entry not found")
	}
	if len(entry.Answer) != 2 {
		t.Errorf("answer count = %d, want 2", len(entry.Answer))
	}
	if len(entry.Authority) != 1 {
		t.Errorf("authority count = %d, want 1", len(entry.Authority))
	}
	if !entry.Validated {
		t.Error("Validated flag not preserved")
	}
}

// ── Set/Get round-trip ────────────────────────────────────────────────────

func TestSet_RoundTrip(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	rr := &dns.A{Hdr: dns.Header{Name: "meta.example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("1.1.1.1")}}
	mc.Set("meta.example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr}, nil, nil, true)

	var validated int
	var msgWire []byte
	err := mc.db.QueryRow(
		"SELECT e.validated, e.msg_wire FROM entries e WHERE e.qname='meta.example.com' AND e.qtype=1",
	).Scan(&validated, &msgWire)
	if err != nil {
		t.Fatalf("entries query: %v", err)
	}
	if validated != 1 {
		t.Errorf("validated = %d, want 1", validated)
	}
	if len(msgWire) == 0 {
		t.Error("msg_wire should not be empty")
	}
}

// ── Compression smoke test ───────────────────────────────────────────────────

func TestCompressionRoundTrip(t *testing.T) {
	original := []byte("test wire format data")
	compressed := compress(original)
	if len(compressed) == 0 {
		t.Fatal("compress returned empty")
	}
	decompressed, err := decompress(compressed)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if string(decompressed) != string(original) {
		t.Errorf("round-trip mismatch: got %q, want %q", decompressed, original)
	}
}

func TestCompressEmpty(t *testing.T) {
	if compress(nil) != nil {
		t.Error("compress(nil) should return nil")
	}
	if compress([]byte{}) != nil {
		t.Error("compress([]byte{}) should return nil")
	}
}

func TestDecompressEmpty(t *testing.T) {
	result, err := decompress(nil)
	if err != nil {
		t.Errorf("decompress(nil): %v", err)
	}
	if result != nil {
		t.Error("decompress(nil) should return nil")
	}
	result, err = decompress([]byte{})
	if err != nil {
		t.Errorf("decompress([]byte{}): %v", err)
	}
	if result != nil {
		t.Error("decompress([]byte{}) should return nil")
	}
}

// ── RecordRequest Error ───────────────────────────────────────────────────

func TestRecordRequest_Error(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	mc.RecordRequest(RequestRecord{
		Qname: "error.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET,
		ECS: nil, DNSSECOK: false,
		Protocol: "udp", Result: "error", Rcode: dns.RcodeServerFailure,
		Server: "1.2.3.4:53 (UDP)", ResponseTime: 500,
	})

	var protocol, result string
	var rcode, respTime int
	var server string
	err := mc.db.QueryRow(
		"SELECT rl.protocol, rl.result, rl.rcode, rl.response_time_ms, rl.server FROM request_log rl JOIN entries e ON rl.entry_id = e.id WHERE e.qname='error.example.com'",
	).Scan(&protocol, &result, &rcode, &respTime, &server)
	if err != nil {
		t.Fatalf("request_log query: %v", err)
	}
	if result != "error" {
		t.Errorf("result = %s, want error", result)
	}
	if rcode != dns.RcodeServerFailure {
		t.Errorf("rcode = %d, want %d", rcode, dns.RcodeServerFailure)
	}
	if server != "1.2.3.4:53 (UDP)" {
		t.Errorf("server = %s", server)
	}
}

// ── Summary ──────────────────────────────────────────────────────────────────

func TestStats(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	rr := &dns.A{Hdr: dns.Header{Name: "sum.example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("4.5.6.7")}}
	mc.Set("sum.example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr}, nil, nil, false)
	mc.RecordRequest(RequestRecord{Qname: "sum.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET, Protocol: "udp", Result: "hit", Rcode: dns.RcodeSuccess})

	s := mc.Stats()
	if len(s) == 0 {
		t.Error("Stats should not be empty")
	}
	for i, line := range s {
		if line == "" {
			t.Errorf("Stats[%d] should not be empty", i)
		}
		t.Logf("Stats[%d]: %s", i, line)
	}
}

// ── E2E: full lifecycle with disk-backed DB and real DNS records ─────────────

func TestE2E_FullLifecycle(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "e2e.db")
	mc, err := NewSQLiteCache(dbPath, 500, 4, 1)
	if err != nil {
		t.Fatalf("NewSQLiteCache: %v", err)
	}
	defer func() { _ = mc.Close() }()

	// ── Phase 1: Insert varied DNS records ──────────────────────────────────
	a1 := &dns.A{Hdr: dns.Header{Name: "www.example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("93.184.216.34")}}
	a2 := &dns.A{Hdr: dns.Header{Name: "www.example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("93.184.216.35")}}
	aaaa := &dns.AAAA{Hdr: dns.Header{Name: "www.example.com.", Class: dns.ClassINET, TTL: 300}, AAAA: rdata.AAAA{Addr: netip.MustParseAddr("2606:2800:220:1:248:1893:25c8:1946")}}
	mc.Set("www.example.com.", dns.TypeA, dns.ClassINET, nil, false,
		[]dns.RR{a1, a2}, nil, []dns.RR{aaaa}, true)

	a3 := &dns.A{Hdr: dns.Header{Name: "github.com.", Class: dns.ClassINET, TTL: 60}, A: rdata.A{Addr: netip.MustParseAddr("140.82.121.3")}}
	mc.Set("github.com.", dns.TypeA, dns.ClassINET, nil, false,
		[]dns.RR{a3}, nil, nil, false)

	soa := &dns.SOA{Hdr: dns.Header{Name: "nonexist.example.com.", Class: dns.ClassINET, TTL: 900},
		SOA: rdata.SOA{Ns: "ns1.example.com.", Mbox: "admin.example.com.", Serial: 2025010101, Refresh: 1800, Retry: 900, Expire: 604800, Minttl: 600}}
	nsec := &dns.NSEC{Hdr: dns.Header{Name: "alpha.example.com.", Class: dns.ClassINET, TTL: 600}, NSEC: rdata.NSEC{NextDomain: "zulu.example.com."}}
	mc.Set("beta.example.com.", dns.TypeA, dns.ClassINET, nil, false,
		nil, []dns.RR{soa, nsec}, nil, false)

	mc.Set("error.example.com.", dns.TypeA, dns.ClassINET, nil, false,
		nil, nil, nil, false)
	mc.RecordRequest(RequestRecord{
		Qname: "error.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET,
		ECS: nil, DNSSECOK: false,
		Protocol: "tcp", Result: "error", Rcode: dns.RcodeServerFailure,
		Server: "192.0.2.1:53 (TCP)", Hijack: true, DNSSECStatus: "bogus",
	})

	txt := &dns.TXT{Hdr: dns.Header{Name: ".", Class: dns.ClassINET, TTL: 3600}, TXT: rdata.TXT{Txt: []string{"198.41.0.4:53"}}}
	mc.Set(".", dns.TypeNone, dns.ClassINET, nil, false,
		[]dns.RR{txt}, nil, nil, false)

	// ── Phase 2: Get + verify wire-format round-trip ────────────────────────
	entry, found, expired := mc.Get("www.example.com.", dns.TypeA, dns.ClassINET, nil, false)
	if !found || expired {
		t.Fatalf("www.example.com A: found=%v expired=%v", found, expired)
	}
	if len(entry.Answer) != 2 {
		t.Errorf("answer count = %d, want 2", len(entry.Answer))
	}
	if len(entry.Additional) != 1 {
		t.Errorf("additional count = %d, want 1 (AAAA glue)", len(entry.Additional))
	}
	if !entry.Validated {
		t.Error("validated should be true")
	}
	if dns.RRToType(entry.Additional[0]) != dns.TypeAAAA {
		t.Errorf("additional type = %d, want AAAA", dns.RRToType(entry.Additional[0]))
	}
	// Verify A record IPs survived the compress→decompress→unpack cycle.
	ip1 := entry.Answer[0].(*dns.A).A.String()
	ip2 := entry.Answer[1].(*dns.A).A.String()
	if ip1 != "93.184.216.34" && ip1 != "93.184.216.35" {
		t.Errorf("unexpected IP: %s", ip1)
	}
	if ip2 != "93.184.216.34" && ip2 != "93.184.216.35" {
		t.Errorf("unexpected IP: %s", ip2)
	}

	// ── Phase 3: Negative cache + NXDOMAIN ──────────────────────────────────
	entry, found, _ = mc.Get("beta.example.com.", dns.TypeA, dns.ClassINET, nil, false)
	if !found {
		t.Fatal("negative cache entry not found")
	}
	if entry.TTL > 600 {
		t.Errorf("negative TTL = %d, want <= 600", entry.TTL)
	}
	if len(entry.Authority) != 2 {
		t.Errorf("authority count = %d, want 2 (SOA+NSEC)", len(entry.Authority))
	}

	// ── Phase 4: Verify request_log has error record ────────────────────────
	var errCount int64
	_ = mc.db.QueryRow("SELECT COUNT(*) FROM request_log rl JOIN entries e ON rl.entry_id = e.id WHERE e.qname='error.example.com' AND rl.result='error'").Scan(&errCount)
	if errCount != 1 {
		t.Errorf("error log count = %d, want 1", errCount)
	}

	// ── Phase 5: RecordRequest logs queries ────────────────────────────────
	mc.RecordRequest(RequestRecord{Qname: "www.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET, Protocol: "udp", Result: "hit", Rcode: dns.RcodeSuccess})
	mc.RecordRequest(RequestRecord{Qname: "www.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET, Protocol: "udp", Result: "hit", Rcode: dns.RcodeSuccess})
	mc.RecordRequest(RequestRecord{Qname: "www.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET, Protocol: "doh", Result: "hit", Rcode: dns.RcodeSuccess})
	mc.RecordRequest(RequestRecord{Qname: "www.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET, Protocol: "doq", Result: "stale", Rcode: dns.RcodeSuccess})
	mc.RecordRequest(RequestRecord{Qname: "github.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET, Protocol: "tcp", Result: "hit", Rcode: dns.RcodeSuccess})
	mc.RecordRequest(RequestRecord{Qname: "github.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET, Protocol: "tcp", Result: "stale", Rcode: dns.RcodeSuccess})

	var udpHits, dohHits, doqStale int64
	err = mc.db.QueryRow(
		`SELECT COALESCE(SUM(CASE WHEN hc.protocol='udp' THEN hc.hit_count ELSE 0 END), 0),
		        COALESCE(SUM(CASE WHEN hc.protocol='doh' THEN hc.hit_count ELSE 0 END), 0)
		 FROM entry_hit_counters hc JOIN entries e ON hc.entry_id = e.id WHERE e.qname='www.example.com'`,
	).Scan(&udpHits, &dohHits)
	_ = mc.db.QueryRow(
		`SELECT COALESCE(COUNT(*), 0) FROM request_log rl JOIN entries e ON rl.entry_id = e.id WHERE e.qname='www.example.com' AND rl.result='stale'`,
	).Scan(&doqStale)
	if err != nil {
		t.Fatalf("request_log query: %v", err)
	}
	if udpHits != 2 {
		t.Errorf("udp hits = %d, want 2", udpHits)
	}
	if dohHits != 1 {
		t.Errorf("doh hits = %d, want 1", dohHits)
	}
	if doqStale != 1 {
		t.Errorf("doq stale = %d, want 1", doqStale)
	}

	var gitTCP, gitStale int64
	_ = mc.db.QueryRow(
		`SELECT COALESCE(SUM(CASE WHEN hc.protocol='tcp' THEN hc.hit_count ELSE 0 END), 0)
		 FROM entry_hit_counters hc JOIN entries e ON hc.entry_id = e.id WHERE e.qname='github.com'`,
	).Scan(&gitTCP)
	_ = mc.db.QueryRow(
		`SELECT COALESCE(COUNT(*), 0) FROM request_log rl JOIN entries e ON rl.entry_id = e.id WHERE e.qname='github.com' AND rl.result='stale'`,
	).Scan(&gitStale)
	if gitTCP != 1 {
		t.Errorf("github.com tcp hit = %d, want 1", gitTCP)
	}
	if gitStale != 1 {
		t.Errorf("github.com tcp stale = %d, want 1", gitStale)
	}

	// ── Phase 6: ReverseLookup (ptr_map) ────────────────────────────────────
	results := mc.ReverseLookup("93.184.216.34")
	foundIP := false
	for _, r := range results {
		if r.Name == "www.example.com." {
			foundIP = true
			break
		}
	}
	if !foundIP {
		t.Error("ReverseLookup should find www.example.com for 93.184.216.34")
	}

	// ── Phase 7: UpdateLatency (ip_latency) ─────────────────────────────
	mc.UpdateLatency("93.184.216.34", 15)
	mc.UpdateLatency("93.184.216.35", 42)
	mc.UpdateLatency("198.41.0.4", 8)

	var latA, latB int
	_ = mc.db.QueryRow(`SELECT latency_ms FROM ip_latency WHERE rdata_ip='93.184.216.34'`).Scan(&latA)
	_ = mc.db.QueryRow(`SELECT latency_ms FROM ip_latency WHERE rdata_ip='93.184.216.35'`).Scan(&latB)
	if latA != 15 {
		t.Errorf("latency 93.184.216.34 = %d, want 15", latA)
	}
	if latB != 42 {
		t.Errorf("latency 93.184.216.35 = %d, want 42", latB)
	}

	// ── Phase 8: Entry overwrite (INSERT OR REPLACE) ────────────────────────
	// Re-insert; wire format + ptr_map should update atomically.
	aNew := &dns.A{Hdr: dns.Header{Name: "www.example.com.", Class: dns.ClassINET, TTL: 600}, A: rdata.A{Addr: netip.MustParseAddr("93.184.216.99")}}
	mc.Set("www.example.com.", dns.TypeA, dns.ClassINET, nil, false,
		[]dns.RR{aNew}, nil, nil, false)

	entry, found, _ = mc.Get("www.example.com.", dns.TypeA, dns.ClassINET, nil, false)
	if !found {
		t.Fatal("overwritten entry not found")
	}
	if len(entry.Answer) != 1 {
		t.Errorf("answer count after overwrite = %d, want 1", len(entry.Answer))
	}
	overwrittenIP := entry.Answer[0].(*dns.A).A.String()
	if overwrittenIP != "93.184.216.99" {
		t.Errorf("IP after overwrite = %s, want 93.184.216.99", overwrittenIP)
	}

	// Old IPs should be gone from ptr_map (deleted by REPLACE + ON DELETE CASCADE).
	results = mc.ReverseLookup("93.184.216.34")
	if len(results) != 0 {
		t.Errorf("stale ptr_map entries for 93.184.216.34: got %d, want 0", len(results))
	}
	results = mc.ReverseLookup("93.184.216.99")
	if len(results) == 0 {
		t.Error("new ptr_map entry for 93.184.216.99 not found")
	}

	// ── Phase 9: RecordRequest Rewrite ──────────────────────────────────────
	mc.RecordRequest(RequestRecord{Qname: "rewrite.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET, Protocol: "", Result: "rewrite", Rcode: dns.RcodeRefused})
	mc.RecordRequest(RequestRecord{Qname: "rewrite.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET, Protocol: "", Result: "rewrite", Rcode: dns.RcodeRefused})
	mc.RecordRequest(RequestRecord{Qname: "rewrite.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET, Protocol: "", Result: "rewrite", Rcode: dns.RcodeRefused})
	var rwCount int64
	_ = mc.db.QueryRow(`SELECT COUNT(*) FROM request_log rl JOIN entries e ON rl.entry_id = e.id WHERE e.qname='rewrite.test' AND rl.result='rewrite'`).Scan(&rwCount)
	if rwCount != 3 {
		t.Errorf("rewrite_count = %d, want 3", rwCount)
	}

	// ── Phase 10: Summary ───────────────────────────────────────────────────
	s := mc.Stats()
	if len(s) == 0 {
		t.Error("Stats should not be empty")
	}
	for i, line := range s {
		t.Logf("Stats[%d]: %s", i, line)
	}

	// ── Phase 11: Verify DB file exists and has content ─────────────────────
	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("db file stat: %v", err)
	}
	if info.Size() == 0 {
		t.Error("db file is empty")
	}
	t.Logf("DB file size: %d bytes", info.Size())

	// ── Phase 12: Close and verify clean shutdown ───────────────────────────
	if err := mc.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	// Double-close should be safe.
	if err := mc.Close(); err != nil {
		t.Errorf("double Close: %v", err)
	}
}

// ── E2E: Latency-ordered Get() ────────────────────────────────────────────────

func TestE2E_LatencyOrdering(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	// Simulate a response with CNAME + 3 A records (like www.baidu.com).
	cname := &dns.CNAME{Hdr: dns.Header{Name: "www.example.com.", Class: dns.ClassINET, TTL: 600}, CNAME: rdata.CNAME{Target: "real.example.com."}}
	a1 := &dns.A{Hdr: dns.Header{Name: "real.example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("10.0.0.10")}}
	a2 := &dns.A{Hdr: dns.Header{Name: "real.example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("10.0.0.20")}}
	a3 := &dns.A{Hdr: dns.Header{Name: "real.example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("10.0.0.30")}}
	mc.Set("www.example.com.", dns.TypeA, dns.ClassINET, nil, false,
		[]dns.RR{cname, a1, a2, a3}, nil, nil, false)

	// Before latency data: Get() returns original order.
	entry, found, _ := mc.Get("www.example.com.", dns.TypeA, dns.ClassINET, nil, false)
	if !found {
		t.Fatal("entry not found")
	}
	if len(entry.Answer) != 4 {
		t.Fatalf("answer count = %d, want 4", len(entry.Answer))
	}
	// CNAME must be first.
	if _, ok := entry.Answer[0].(*dns.CNAME); !ok {
		t.Error("CNAME should be first in answer")
	}

	// Store latency: 10.0.0.30 is fastest, 10.0.0.10 is slowest.
	mc.UpdateLatency("10.0.0.10", 100)
	mc.UpdateLatency("10.0.0.20", 50)
	mc.UpdateLatency("10.0.0.30", 5)

	// After latency data: Get() should return A records sorted fastest-first.
	entry, found, _ = mc.Get("www.example.com.", dns.TypeA, dns.ClassINET, nil, false)
	if !found {
		t.Fatal("entry not found")
	}
	if len(entry.Answer) != 4 {
		t.Fatalf("answer count = %d, want 4", len(entry.Answer))
	}
	// CNAME must still be first.
	if _, ok := entry.Answer[0].(*dns.CNAME); !ok {
		t.Error("CNAME should still be first after latency sort")
	}
	// A records should be sorted by latency: 30 (5ms), 20 (50ms), 10 (100ms).
	ips := make([]string, 0, 3)
	for _, rr := range entry.Answer[1:] {
		a, ok := rr.(*dns.A)
		if !ok {
			t.Errorf("expected A record, got %T", rr)
			continue
		}
		ips = append(ips, a.A.String())
	}
	if len(ips) != 3 {
		t.Fatalf("got %d A records, want 3", len(ips))
	}
	if ips[0] != "10.0.0.30" || ips[1] != "10.0.0.20" || ips[2] != "10.0.0.10" {
		t.Errorf("wrong latency order: %v, want [10.0.0.30 10.0.0.20 10.0.0.10]", ips)
	}
}

// ── E2E: Compression efficacy ────────────────────────────────────────────────

func TestE2E_CompressionEfficacy(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "compression.db")
	mc, err := NewSQLiteCache(dbPath, 100, 4, 1)
	if err != nil {
		t.Fatalf("NewSQLiteCache: %v", err)
	}
	defer func() { _ = mc.Close() }()

	// Insert 50 realistic A-record responses (different domain names, multiple IPs).
	for i := range 50 {
		name := fmt.Sprintf("host-%02d.example.com.", i)
		var answers []dns.RR
		for j := range 3 {
			answers = append(answers, &dns.A{
				Hdr: dns.Header{Name: name, Class: dns.ClassINET, TTL: uint32(300 + i)},
				A:   rdata.A{Addr: netip.MustParseAddr(fmt.Sprintf("10.%d.%d.%d", i/256, i%256, j+1))},
			})
		}
		mc.Set(name, dns.TypeA, dns.ClassINET, nil, false, answers, nil, nil, i%2 == 0)
	}

	// Verify all 50 entries round-trip correctly.
	for i := range 50 {
		name := fmt.Sprintf("host-%02d.example.com.", i)
		entry, found, _ := mc.Get(name, dns.TypeA, dns.ClassINET, nil, false)
		if !found {
			t.Errorf("entry %s not found", name)
			continue
		}
		if len(entry.Answer) != 3 {
			t.Errorf("%s: answer count = %d, want 3", name, len(entry.Answer))
		}
	}

	info, _ := os.Stat(dbPath)
	t.Logf("50 entries (3 A records each), DB size: %d bytes (%.1f KB)", info.Size(), float64(info.Size())/1024)

	// Verify hit counters
	var total, udp, tcp int64
	mc.RecordRequest(RequestRecord{Qname: "host-00.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET, ECS: nil, DNSSECOK: false, Protocol: "udp", Result: "hit", Rcode: dns.RcodeSuccess})
	mc.RecordRequest(RequestRecord{Qname: "host-01.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET, ECS: nil, DNSSECOK: false, Protocol: "tcp", Result: "hit", Rcode: dns.RcodeSuccess})
	_ = mc.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(CASE WHEN protocol='udp' THEN hit_count ELSE 0 END),0), COALESCE(SUM(CASE WHEN protocol='tcp' THEN hit_count ELSE 0 END),0) FROM entry_hit_counters`).Scan(&total, &udp, &tcp)
	if total != 2 {
		t.Errorf("total hit counter rows = %d, want 2", total)
	}
	if udp != 1 || tcp != 1 {
		t.Errorf("udp=%d tcp=%d, want udp=1 tcp=1", udp, tcp)
	}
}

// ── Helper ────────────────────────────────────────────────────────────────────

func netParseIP(s string) netip.Addr {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}
	}
	return addr
}
