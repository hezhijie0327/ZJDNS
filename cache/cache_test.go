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
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr}, nil, nil, false, SetOptions{})

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
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr}, nil, nil, true, SetOptions{})

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

	mc.Set("example.com.", dns.TypeA, dns.ClassINET, ecs, false, []dns.RR{rr}, nil, nil, false, SetOptions{})

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

	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, true, []dns.RR{rr}, nil, nil, false, SetOptions{})

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
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr}, nil, nil, false, SetOptions{})

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
	mc.Set("beta.example.com.", dns.TypeA, dns.ClassINET, nil, false, nil, []dns.RR{soa, nsec}, nil, false, SetOptions{})

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
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{aRec}, nil, nil, false, SetOptions{})

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
	mc.Set("com.", dns.TypeDNSKEY, dns.ClassINET, nil, false, []dns.RR{dnskey}, nil, nil, true, SetOptions{})

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
	mc.Set(".", dns.TypeNone, dns.ClassINET, nil, false, []dns.RR{txt}, nil, nil, false, SetOptions{})

	entry, found, _ := mc.Get(".", dns.TypeNone, dns.ClassINET, nil, false)
	if !found {
		t.Fatal("NS addr entry not found")
	}
	if len(entry.Answer) != 1 {
		t.Fatalf("answer count = %d, want 1", len(entry.Answer))
	}
}

// ── RecordServe (entries table — no more metadata subquery) ──────────────────

func TestRecordServe_Fresh(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	rr := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("1.2.3.4")}}
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr}, nil, nil, false, SetOptions{})

	// Fresh serve via UDP
	mc.RecordServe("example.com.", dns.TypeA, dns.ClassINET, nil, false, "UDP", false)

	var hitUDP, lastHit int64
	err := mc.db.QueryRow("SELECT hit_udp, last_hit_time FROM entries WHERE qname='example.com' AND qtype=1").Scan(&hitUDP, &lastHit)
	if err != nil {
		t.Fatalf("entries query: %v", err)
	}
	if hitUDP != 1 {
		t.Errorf("hit_udp = %d, want 1", hitUDP)
	}
	if lastHit == 0 {
		t.Error("last_hit_time should be non-zero")
	}
}

func TestRecordServe_Stale(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	rr := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("1.2.3.4")}}
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr}, nil, nil, false, SetOptions{})

	// Stale serve via TCP
	mc.RecordServe("example.com.", dns.TypeA, dns.ClassINET, nil, false, "TCP", true)

	var hitTCP, staleCount, lastHit int64
	err := mc.db.QueryRow("SELECT hit_tcp, stale_count, last_hit_time FROM entries WHERE qname='example.com' AND qtype=1").Scan(&hitTCP, &staleCount, &lastHit)
	if err != nil {
		t.Fatalf("entries query: %v", err)
	}
	if hitTCP != 1 {
		t.Errorf("hit_tcp = %d, want 1", hitTCP)
	}
	if staleCount != 1 {
		t.Errorf("stale_count = %d, want 1", staleCount)
	}
	if lastHit == 0 {
		t.Error("last_hit_time should be non-zero")
	}
}

func TestRecordServe_MultipleProtocols(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	rr := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("1.2.3.4")}}
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr}, nil, nil, false, SetOptions{})

	mc.RecordServe("example.com.", dns.TypeA, dns.ClassINET, nil, false, "UDP", false)
	mc.RecordServe("example.com.", dns.TypeA, dns.ClassINET, nil, false, "UDP", false)
	mc.RecordServe("example.com.", dns.TypeA, dns.ClassINET, nil, false, "DoH", false)

	var hitUDP, hitDOH int64
	err := mc.db.QueryRow("SELECT hit_udp, hit_doh FROM entries WHERE qname='example.com' AND qtype=1").Scan(&hitUDP, &hitDOH)
	if err != nil {
		t.Fatalf("entries query: %v", err)
	}
	if hitUDP != 2 {
		t.Errorf("hit_udp = %d, want 2", hitUDP)
	}
	if hitDOH != 1 {
		t.Errorf("hit_doh = %d, want 1", hitDOH)
	}
}

// ── RecordRewrite ────────────────────────────────────────────────────────────

func TestRecordRewrite(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	mc.RecordRewrite("blocked.com.", dns.TypeA, dns.ClassINET, nil, false)
	mc.RecordRewrite("blocked.com.", dns.TypeA, dns.ClassINET, nil, false)

	var rewriteCount int64
	err := mc.db.QueryRow("SELECT rewrite_count FROM entries WHERE qname='blocked.com' AND qtype=1").Scan(&rewriteCount)
	if err != nil {
		t.Fatalf("entries query: %v", err)
	}
	if rewriteCount != 2 {
		t.Errorf("rewrite_count = %d, want 2", rewriteCount)
	}
}

// ── ReverseLookup (ptr_map) ──────────────────────────────────────────────────

func TestReverseLookup(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	aRec := &dns.A{Hdr: dns.Header{Name: "www.example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("192.0.2.1")}}
	mc.Set("www.example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{aRec}, nil, nil, false, SetOptions{})

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

// ── UpdateLatency (record_latency table) ─────────────────────────────────────

func TestUpdateLatency(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	rr := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("8.8.8.8")}}
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr}, nil, nil, false, SetOptions{})

	mc.UpdateLatency("example.com.", dns.TypeA, dns.ClassINET, nil, false, "8.8.8.8", 42)

	var lat int
	err := mc.db.QueryRow("SELECT latency_ms FROM record_latency WHERE rdata_ip='8.8.8.8'").Scan(&lat)
	if err != nil {
		t.Fatalf("record_latency query: %v", err)
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
		[]dns.RR{a1, a2}, []dns.RR{soa}, nil, true, SetOptions{})

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

// ── SetOptions metadata round-trip ───────────────────────────────────────────

func TestSet_MetadataRoundTrip(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	rr := &dns.A{Hdr: dns.Header{Name: "meta.example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("1.1.1.1")}}
	mc.Set("meta.example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr}, nil, nil, true,
		SetOptions{Rcode: 0, ResponseTime: 150, Server: "1.2.3.4:53 (UDP)", Dnssec: "secure", Fallback: false, Hijack: true})

	var rcode, respTime, fallback, hijack int64
	var server, dnssec string
	err := mc.db.QueryRow(
		"SELECT rcode, response_time_ms, server, dnssec, fallback, hijack FROM entries WHERE qname='meta.example.com' AND qtype=1",
	).Scan(&rcode, &respTime, &server, &dnssec, &fallback, &hijack)
	if err != nil {
		t.Fatalf("entries query: %v", err)
	}
	if rcode != 0 {
		t.Errorf("rcode = %d, want 0", rcode)
	}
	if respTime != 150 {
		t.Errorf("response_time_ms = %d, want 150", respTime)
	}
	if server != "1.2.3.4:53 (UDP)" {
		t.Errorf("server = %s", server)
	}
	if dnssec != "secure" {
		t.Errorf("dnssec = %s, want 'secure'", dnssec)
	}
	if hijack != 1 {
		t.Errorf("hijack = %d, want 1", hijack)
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

// ── Uncacheable entries (error responses) ─────────────────────────────────────

func TestSet_Uncacheable(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	mc.Set("error.example.com.", dns.TypeA, dns.ClassINET, nil, false, nil, nil, nil, false,
		SetOptions{Uncacheable: true, Rcode: dns.RcodeServerFailure})

	_, found, _ := mc.Get("error.example.com.", dns.TypeA, dns.ClassINET, nil, false)
	if found {
		t.Error("uncacheable entries should not be returned by Get")
	}

	// Verify it's stored in the DB for analytics.
	var rcode int
	err := mc.db.QueryRow("SELECT rcode FROM entries WHERE qname='error.example.com' AND qtype=1 AND cacheable=0").Scan(&rcode)
	if err != nil {
		t.Fatalf("uncacheable entry query: %v", err)
	}
	if rcode != dns.RcodeServerFailure {
		t.Errorf("rcode = %d, want %d", rcode, dns.RcodeServerFailure)
	}
}

// ── Summary ──────────────────────────────────────────────────────────────────

func TestSummary(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	rr := &dns.A{Hdr: dns.Header{Name: "sum.example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("4.5.6.7")}}
	mc.Set("sum.example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr}, nil, nil, false, SetOptions{Rcode: 0, ResponseTime: 42})
	mc.RecordServe("sum.example.com.", dns.TypeA, dns.ClassINET, nil, false, "UDP", false)

	s := mc.Summary()
	if s == "" {
		t.Error("Summary should not be empty")
	}
	// Just verify it doesn't panic and returns non-empty.
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
		[]dns.RR{a1, a2}, nil, []dns.RR{aaaa}, true,
		SetOptions{Rcode: dns.RcodeSuccess, ResponseTime: 23, Server: "1.1.1.1:53 (UDP)", Dnssec: "secure"})

	a3 := &dns.A{Hdr: dns.Header{Name: "github.com.", Class: dns.ClassINET, TTL: 60}, A: rdata.A{Addr: netip.MustParseAddr("140.82.121.3")}}
	mc.Set("github.com.", dns.TypeA, dns.ClassINET, nil, false,
		[]dns.RR{a3}, nil, nil, false,
		SetOptions{Rcode: dns.RcodeSuccess, ResponseTime: 87, Server: "8.8.8.8:53 (UDP)", Dnssec: "insecure"})

	soa := &dns.SOA{Hdr: dns.Header{Name: "nonexist.example.com.", Class: dns.ClassINET, TTL: 900},
		SOA: rdata.SOA{Ns: "ns1.example.com.", Mbox: "admin.example.com.", Serial: 2025010101, Refresh: 1800, Retry: 900, Expire: 604800, Minttl: 600}}
	nsec := &dns.NSEC{Hdr: dns.Header{Name: "alpha.example.com.", Class: dns.ClassINET, TTL: 600}, NSEC: rdata.NSEC{NextDomain: "zulu.example.com."}}
	mc.Set("beta.example.com.", dns.TypeA, dns.ClassINET, nil, false,
		nil, []dns.RR{soa, nsec}, nil, false,
		SetOptions{Rcode: dns.RcodeNameError, ResponseTime: 12, Server: "builtin_recursive", Dnssec: "secure", Hijack: false})

	mc.Set("error.example.com.", dns.TypeA, dns.ClassINET, nil, false,
		nil, nil, nil, false,
		SetOptions{Uncacheable: true, Rcode: dns.RcodeServerFailure, ResponseTime: 5000, Server: "192.0.2.1:53 (TCP)", Dnssec: "bogus", Hijack: true})

	txt := &dns.TXT{Hdr: dns.Header{Name: ".", Class: dns.ClassINET, TTL: 3600}, TXT: rdata.TXT{Txt: []string{"198.41.0.4:53"}}}
	mc.Set(".", dns.TypeNone, dns.ClassINET, nil, false,
		[]dns.RR{txt}, nil, nil, false,
		SetOptions{Rcode: dns.RcodeSuccess, ResponseTime: 5, Server: "builtin_recursive"})

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

	// ── Phase 4: Uncacheable entry must not be served ───────────────────────
	_, found, _ = mc.Get("error.example.com.", dns.TypeA, dns.ClassINET, nil, false)
	if found {
		t.Error("uncacheable entry should not be returned")
	}

	// ── Phase 5: RecordServe updates counters ───────────────────────────────
	mc.RecordServe("www.example.com.", dns.TypeA, dns.ClassINET, nil, false, "UDP", false)
	mc.RecordServe("www.example.com.", dns.TypeA, dns.ClassINET, nil, false, "UDP", false)
	mc.RecordServe("www.example.com.", dns.TypeA, dns.ClassINET, nil, false, "DoH", false)
	mc.RecordServe("www.example.com.", dns.TypeA, dns.ClassINET, nil, false, "DoQ", true)
	mc.RecordServe("github.com.", dns.TypeA, dns.ClassINET, nil, false, "TCP", false)
	mc.RecordServe("github.com.", dns.TypeA, dns.ClassINET, nil, false, "TCP", true)

	var hitUDP, hitDOH, hitDOQ, staleTotal int64
	err = mc.db.QueryRow(
		`SELECT hit_udp, hit_doh, hit_doq, stale_count FROM entries WHERE qname='www.example.com' AND qtype=1`,
	).Scan(&hitUDP, &hitDOH, &hitDOQ, &staleTotal)
	if err != nil {
		t.Fatalf("counter query: %v", err)
	}
	if hitUDP != 2 {
		t.Errorf("hit_udp = %d, want 2", hitUDP)
	}
	if hitDOH != 1 {
		t.Errorf("hit_doh = %d, want 1", hitDOH)
	}
	if hitDOQ != 1 {
		t.Errorf("hit_doq = %d, want 1", hitDOQ)
	}
	if staleTotal != 1 {
		t.Errorf("stale_count = %d, want 1", staleTotal)
	}

	var gitTCP, gitStale int64
	_ = mc.db.QueryRow(
		`SELECT hit_tcp, stale_count FROM entries WHERE qname='github.com' AND qtype=1`,
	).Scan(&gitTCP, &gitStale)
	if gitTCP != 2 {
		t.Errorf("github.com hit_tcp = %d, want 2", gitTCP)
	}
	if gitStale != 1 {
		t.Errorf("github.com stale_count = %d, want 1", gitStale)
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

	// ── Phase 7: UpdateLatency (record_latency) ─────────────────────────────
	mc.UpdateLatency("www.example.com.", dns.TypeA, dns.ClassINET, nil, false, "93.184.216.34", 15)
	mc.UpdateLatency("www.example.com.", dns.TypeA, dns.ClassINET, nil, false, "93.184.216.35", 42)
	mc.UpdateLatency(".", dns.TypeNone, dns.ClassINET, nil, false, "198.41.0.4", 8)

	var latA, latB int
	_ = mc.db.QueryRow(`SELECT latency_ms FROM record_latency WHERE rdata_ip='93.184.216.34'`).Scan(&latA)
	_ = mc.db.QueryRow(`SELECT latency_ms FROM record_latency WHERE rdata_ip='93.184.216.35'`).Scan(&latB)
	if latA != 15 {
		t.Errorf("latency 93.184.216.34 = %d, want 15", latA)
	}
	if latB != 42 {
		t.Errorf("latency 93.184.216.35 = %d, want 42", latB)
	}

	// ── Phase 8: Entry overwrite (INSERT OR REPLACE) ────────────────────────
	// Re-insert with new metadata; wire format + ptr_map should update atomically.
	aNew := &dns.A{Hdr: dns.Header{Name: "www.example.com.", Class: dns.ClassINET, TTL: 600}, A: rdata.A{Addr: netip.MustParseAddr("93.184.216.99")}}
	mc.Set("www.example.com.", dns.TypeA, dns.ClassINET, nil, false,
		[]dns.RR{aNew}, nil, nil, false,
		SetOptions{Rcode: dns.RcodeSuccess, ResponseTime: 99, Server: "9.9.9.9:53 (DoT)", Dnssec: "secure"})

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

	// ── Phase 9: RecordRewrite ──────────────────────────────────────────────
	mc.RecordRewrite("rewrite.test.", dns.TypeA, dns.ClassINET, nil, false)
	mc.RecordRewrite("rewrite.test.", dns.TypeA, dns.ClassINET, nil, false)
	mc.RecordRewrite("rewrite.test.", dns.TypeA, dns.ClassINET, nil, false)
	var rwCount int64
	_ = mc.db.QueryRow(`SELECT rewrite_count FROM entries WHERE qname='rewrite.test' AND qtype=1`).Scan(&rwCount)
	if rwCount != 3 {
		t.Errorf("rewrite_count = %d, want 3", rwCount)
	}

	// ── Phase 10: Summary ───────────────────────────────────────────────────
	s := mc.Summary()
	if s == "" {
		t.Error("Summary should not be empty")
	}
	t.Logf("Summary: %s", s)

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
		[]dns.RR{cname, a1, a2, a3}, nil, nil, false, SetOptions{})

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
	mc.UpdateLatency("www.example.com.", dns.TypeA, dns.ClassINET, nil, false, "10.0.0.10", 100)
	mc.UpdateLatency("www.example.com.", dns.TypeA, dns.ClassINET, nil, false, "10.0.0.20", 50)
	mc.UpdateLatency("www.example.com.", dns.TypeA, dns.ClassINET, nil, false, "10.0.0.30", 5)

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
		mc.Set(name, dns.TypeA, dns.ClassINET, nil, false, answers, nil, nil, i%2 == 0,
			SetOptions{Rcode: dns.RcodeSuccess, ResponseTime: int64(10 + i), Server: "1.1.1.1:53 (UDP)"})
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

	// Verify all counters via SQL (single-table — no JOIN).
	var total, udp, tcp int64
	mc.RecordServe("host-00.example.com.", dns.TypeA, dns.ClassINET, nil, false, "UDP", false)
	mc.RecordServe("host-01.example.com.", dns.TypeA, dns.ClassINET, nil, false, "TCP", false)
	_ = mc.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(hit_udp),0), COALESCE(SUM(hit_tcp),0) FROM entries`).Scan(&total, &udp, &tcp)
	if total != 50 {
		t.Errorf("total entries = %d, want 50", total)
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
