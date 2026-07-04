package cache

import (
	"net"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
	"net/netip"

	"zjdns/config"
)

type testQ struct {
	Name   string
	Qtype  uint16
	Qclass uint16
}

func testStore() *MemoryCache {
	return New(config.CacheSettings{Size: config.DefaultCacheSize})
}

// ── BuildCacheKey ────────────────────────────────────────────────────────────────

func TestBuildCacheKey_Basic(t *testing.T) {
	q := testQ{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	key := BuildCacheKey(q.Name, q.Qtype, q.Qclass, nil, false)
	if key == "" {
		t.Fatal("empty key")
	}
	if key[:4] != "dns:" {
		t.Errorf("key prefix = %q, want dns:", key[:4])
	}
}

func TestBuildCacheKey_DNSSEC(t *testing.T) {
	q := testQ{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	keyNo := BuildCacheKey(q.Name, q.Qtype, q.Qclass, nil, false)
	keyYes := BuildCacheKey(q.Name, q.Qtype, q.Qclass, nil, true)
	if keyNo == keyYes {
		t.Error("DNSSEC flag should affect cache key")
	}
}

func TestBuildCacheKey_ECS(t *testing.T) {
	q := testQ{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	keyNo := BuildCacheKey(q.Name, q.Qtype, q.Qclass, nil, false)
	keyECS := BuildCacheKey(q.Name, q.Qtype, q.Qclass, &config.ECSOption{
		Family:       1,
		SourcePrefix: 24,
		ScopePrefix:  0,
		Address:      net.IP(netParseIP("192.0.2.0").AsSlice()),
	}, false)
	if keyNo == keyECS {
		t.Error("ECS should affect cache key")
	}
	if keyECS != "dns:example.com:1:1:ecs:192.0.2.0/24" {
		t.Errorf("ECS key = %q", keyECS)
	}
}

func TestBuildCacheKey_DifferentTypes(t *testing.T) {
	a := testQ{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	aaaa := testQ{Name: "example.com.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}
	if BuildCacheKey(a.Name, a.Qtype, a.Qclass, nil, false) == BuildCacheKey(aaaa.Name, aaaa.Qtype, aaaa.Qclass, nil, false) {
		t.Error("A and AAAA should have different keys")
	}
}

// ── Get / Set / SetEntry ──────────────────────────────────────────────────────────

func TestSet_Get_RoundTrip(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	rr := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netParseIP("192.0.2.1")}}
	key := BuildCacheKey("example.com.", dns.TypeA, dns.ClassINET, nil, false)
	mc.Set(key, []dns.RR{rr}, nil, nil, false, nil)

	entry, found, expired := mc.Get(key)
	if !found {
		t.Fatal("Get returned not found after Set")
	}
	if expired {
		t.Error("entry should not be expired immediately")
	}
	if len(entry.Answer) != 1 {
		t.Fatalf("answer count = %d, want 1", len(entry.Answer))
	}
	if entry.Answer[0].Type != dns.TypeA {
		t.Errorf("record type = %d, want %d", entry.Answer[0].Type, dns.TypeA)
	}
}

func TestGet_Miss(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	_, found, _ := mc.Get("nonexistent")
	if found {
		t.Error("Get should return not found for missing key")
	}
}

func TestSetEntry_CustomEntry(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	now := time.Now().Unix()
	entry := &Entry{
		Timestamp:  now,
		AccessTime: now,
		TTL:        60,

		Validated: true,
		Answer: []*CompactRecord{
			{Text: "example.com.\t300\tIN\tA\t192.0.2.1", OrigTTL: 300, Type: dns.TypeA},
		},
	}
	mc.SetEntry("custom-key", entry)

	retrieved, found, _ := mc.Get("custom-key")
	if !found {
		t.Fatal("SetEntry entry not found")
	}
	if !retrieved.Validated {
		t.Error("Validated flag not preserved")
	}
}

// ── TTL / Expiry ──────────────────────────────────────────────────────────────────

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

// ── Expand / Process Records ──────────────────────────────────────────────────────

func TestExpandAndProcessRecords_PreservesTTL(t *testing.T) {
	crs := []*CompactRecord{
		{Text: "example.com.\t300\tIN\tA\t192.0.2.1", OrigTTL: 300, Type: dns.TypeA},
	}
	result := ExpandAndProcessRecords(crs, 0, false, false)
	if len(result) != 1 {
		t.Fatalf("got %d records, want 1", len(result))
	}
	a, ok := result[0].(*dns.A)
	if !ok {
		t.Fatal("not an A record")
	}
	if a.A.String() != "192.0.2.1" {
		t.Errorf("IP = %s, want 192.0.2.1", a.A.String())
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

func TestExpandAndProcessRecords_ElapsedTTL(t *testing.T) {
	crs := []*CompactRecord{
		{Text: "example.com.\t300\tIN\tA\t192.0.2.1", OrigTTL: 300, Type: dns.TypeA},
	}
	result := ExpandAndProcessRecords(crs, 100, true, false)
	if len(result) != 1 {
		t.Fatal("expected 1 record")
	}
	if result[0].Header().TTL != 200 {
		t.Errorf("TTL = %d, want 200 (300 - 100 elapsed)", result[0].Header().TTL)
	}
}

// ── Cache TTL floor ───────────────────────────────────────────────────────────────

func TestSet_ZeroTTLFloored(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	// Record with TTL=0 should be floored to config.DefaultTTL
	rr := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 0}, A: rdata.A{Addr: netParseIP("192.0.2.1")}}
	key := BuildCacheKey("example.com.", dns.TypeA, dns.ClassINET, nil, false)
	mc.Set(key, []dns.RR{rr}, nil, nil, false, nil)

	entry, found, _ := mc.Get(key)
	if !found {
		t.Fatal("entry not found")
	}
	if entry.TTL != config.DefaultTTL {
		t.Errorf("TTL = %d, want %d (zero TTL floored to default)", entry.TTL, config.DefaultTTL)
	}
}

// ── RFC 9077: NSEC/NSEC3 TTL capping ────────────────────────────────────────────────

func TestHasNSECOrNSEC3(t *testing.T) {
	if hasNSECOrNSEC3(nil) {
		t.Error("nil authority should return false")
	}
	if hasNSECOrNSEC3([]dns.RR{}) {
		t.Error("empty authority should return false")
	}

	aRec := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netParseIP("192.0.2.1")}}
	if hasNSECOrNSEC3([]dns.RR{aRec}) {
		t.Error("A record should not trigger NSEC detection")
	}

	nsec := &dns.NSEC{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}}
	if !hasNSECOrNSEC3([]dns.RR{nsec}) {
		t.Error("NSEC record should be detected")
	}

	nsec3 := &dns.NSEC3{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}}
	if !hasNSECOrNSEC3([]dns.RR{nsec3}) {
		t.Error("NSEC3 record should be detected")
	}
}

func TestNegativeTTLCap_NoSOA(t *testing.T) {
	capTTL := negativeTTLCap(nil)
	if capTTL != config.DefaultMaxNegativeTTL {
		t.Errorf("no SOA: cap = %d, want %d (DefaultMaxNegativeTTL)", capTTL, config.DefaultMaxNegativeTTL)
	}
}

func TestNegativeTTLCap_SOAMinLower(t *testing.T) {
	// SOA TTL=900, MINIMUM=86400 → SOA-based cap = 900
	soa := &dns.SOA{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 900},
		SOA: rdata.SOA{Ns: "ns1.example.com.", Mbox: "admin.example.com.",
			Serial: 1, Refresh: 1800, Retry: 900, Expire: 604800, Minttl: 86400},
	}
	capTTL := negativeTTLCap([]dns.RR{soa})
	if capTTL != 900 {
		t.Errorf("SOA TTL=900 MINIMUM=86400: cap = %d, want 900", capTTL)
	}
}

func TestNegativeTTLCap_MinimumLower(t *testing.T) {
	// SOA TTL=86400, MINIMUM=900 → SOA-based cap = 900
	soa := &dns.SOA{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 86400},
		SOA: rdata.SOA{Ns: "ns1.example.com.", Mbox: "admin.example.com.",
			Serial: 1, Refresh: 1800, Retry: 900, Expire: 604800, Minttl: 900},
	}
	capTTL := negativeTTLCap([]dns.RR{soa})
	if capTTL != 900 {
		t.Errorf("SOA TTL=86400 MINIMUM=900: cap = %d, want 900", capTTL)
	}
}

func TestNegativeTTLCap_ExceedsDefaultMax(t *testing.T) {
	// SOA TTL=86400, MINIMUM=172800 → SOA-based cap = 86400,
	// but DefaultMaxNegativeTTL = 10800 should win.
	soa := &dns.SOA{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 86400},
		SOA: rdata.SOA{Ns: "ns1.example.com.", Mbox: "admin.example.com.",
			Serial: 1, Refresh: 1800, Retry: 900, Expire: 604800, Minttl: 172800},
	}
	capTTL := negativeTTLCap([]dns.RR{soa})
	if capTTL != config.DefaultMaxNegativeTTL {
		t.Errorf("SOA TTL=86400 MINIMUM=172800: cap = %d, want %d (DefaultMaxNegativeTTL)", capTTL, config.DefaultMaxNegativeTTL)
	}
}

func TestNegativeTTLCap_SOAWithNSEC(t *testing.T) {
	// Realistic negative response: NSEC + SOA in authority.
	soa := &dns.SOA{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 900},
		SOA: rdata.SOA{Ns: "ns1.example.com.", Mbox: "admin.example.com.",
			Serial: 1, Refresh: 1800, Retry: 900, Expire: 604800, Minttl: 600},
	}
	nsec := &dns.NSEC{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 600}}
	capTTL := negativeTTLCap([]dns.RR{soa, nsec})
	// min(SOA TTL=900, Minttl=600) = 600
	if capTTL != 600 {
		t.Errorf("SOA+NSEC: cap = %d, want 600", capTTL)
	}
}

func TestSet_NegativeTTLCapped(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	// Negative response with NSEC (TTL=86400) and SOA (TTL=900, Minttl=600).
	// The cache entry TTL should be capped at 600, not 86400.
	soa := &dns.SOA{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 900},
		SOA: rdata.SOA{Ns: "ns1.example.com.", Mbox: "admin.example.com.",
			Serial: 1, Refresh: 1800, Retry: 900, Expire: 604800, Minttl: 600},
	}
	nsec := &dns.NSEC{
		Hdr:  dns.Header{Name: "alpha.example.com.", Class: dns.ClassINET, TTL: 86400},
		NSEC: rdata.NSEC{NextDomain: "zulu.example.com."},
	}
	key := BuildCacheKey("beta.example.com.", dns.TypeA, dns.ClassINET, nil, false)
	mc.Set(key, nil, []dns.RR{soa, nsec}, nil, false, nil)

	entry, found, _ := mc.Get(key)
	if !found {
		t.Fatal("entry not found")
	}
	// The TTL should be capped at the SOA-based value (600), not the NSEC TTL (86400)
	// and not the SOA TTL (900).
	if entry.TTL > 600 {
		t.Errorf("negative cache TTL = %d, want ≤ 600 (capped by min(SOA TTL=900, Minttl=600))", entry.TTL)
	}
}

func TestSet_NegativeTTLUncapped_NoNSEC(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	// Positive response (no NSEC/NSEC3) — should NOT be capped.
	aRec := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netParseIP("192.0.2.1")}}
	key := BuildCacheKey("example.com.", dns.TypeA, dns.ClassINET, nil, false)
	mc.Set(key, []dns.RR{aRec}, nil, nil, false, nil)

	entry, found, _ := mc.Get(key)
	if !found {
		t.Fatal("entry not found")
	}
	if entry.TTL != 300 {
		t.Errorf("positive cache TTL = %d, want 300 (no capping)", entry.TTL)
	}
}

// ── Helper ─────────────────────────────────────────────────────────────────────────

func netParseIP(s string) netip.Addr {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}
	}
	return addr
}
