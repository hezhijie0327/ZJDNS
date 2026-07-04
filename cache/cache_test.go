package cache

import (
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

// ── Helper ────────────────────────────────────────────────────────────────────

func netParseIP(s string) netip.Addr {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}
	}
	return addr
}
