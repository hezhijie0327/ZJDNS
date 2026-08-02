package cache

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
	"zjdns/config"
	"zjdns/database"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

func testStore() *Cache {
	db, err := database.Open("", nil)
	if err != nil {
		panic(err)
	}
	return New(db)
}

func netParseIP(s string) netip.Addr { return netip.MustParseAddr(s) }

// ── Get / Set ─────────────────────────────────────────────────────────────────

func TestSet_Get_RcodeRoundTrip(t *testing.T) {
	// Negative responses (NXDOMAIN) must be cached and served with their
	// rcode — otherwise every NXDOMAIN comes back as a NOERROR NODATA.
	mc := testStore()
	defer func() { _ = mc.Close() }()

	soa := &dns.SOA{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, SOA: rdata.SOA{Ns: "ns.example.com.", Mbox: "root.example.com."}}
	mc.Set("nonexistent.example.com.", dns.TypeA, dns.ClassINET, nil, false, nil, []dns.RR{soa}, nil, false, dns.RcodeNameError)

	entry, found, _ := mc.Get("nonexistent.example.com.", dns.TypeA, dns.ClassINET, nil, false)
	if !found {
		t.Fatal("Get returned not found after Set")
	}
	if entry.Rcode != dns.RcodeNameError {
		t.Errorf("entry.Rcode = %d, want NXDOMAIN", entry.Rcode)
	}
}

func TestSet_Get_RoundTrip(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	rr := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netParseIP("192.0.2.1")}}
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr}, nil, nil, false, dns.RcodeSuccess)

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
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr}, nil, nil, true, dns.RcodeSuccess)

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

	mc.Set("example.com.", dns.TypeA, dns.ClassINET, ecs, false, []dns.RR{rr}, nil, nil, false, dns.RcodeSuccess)

	_, found, _ := mc.Get("example.com.", dns.TypeA, dns.ClassINET, ecs, false)
	if !found {
		t.Error("should find entry with matching ECS")
	}

	ecs2 := &config.ECSOption{Family: 1, SourcePrefix: 16, ScopePrefix: 0, Address: netParseIP("10.0.0.0").AsSlice()}
	_, found, _ = mc.Get("example.com.", dns.TypeA, dns.ClassINET, ecs2, false)
	if found {
		t.Error("should miss with different ECS")
	}

	_, found, _ = mc.Get("example.com.", dns.TypeA, dns.ClassINET, nil, false)
	if found {
		t.Error("should miss without ECS when stored with ECS")
	}
}

func TestGet_ECSFallback(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	rr := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netParseIP("10.0.0.1")}}
	ecs16 := &config.ECSOption{Family: 1, SourcePrefix: 16, ScopePrefix: 0, Address: netParseIP("1.2.0.0").AsSlice()}
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, ecs16, false, []dns.RR{rr}, nil, nil, false, dns.RcodeSuccess)

	_, found, _ := mc.Get("example.com.", dns.TypeA, dns.ClassINET, ecs16, false)
	if !found {
		t.Error("should hit with exact /16")
	}

	ecs24 := &config.ECSOption{Family: 1, SourcePrefix: 24, ScopePrefix: 0, Address: netParseIP("1.2.3.0").AsSlice()}
	_, found, _ = mc.Get("example.com.", dns.TypeA, dns.ClassINET, ecs24, false)
	if !found {
		t.Error("should fallback from /24 to /16")
	}
}

func TestGet_ECSFallback_ExactPreferred(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	rrBroad := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netParseIP("10.0.0.1")}}
	ecs16 := &config.ECSOption{Family: 1, SourcePrefix: 16, ScopePrefix: 0, Address: netParseIP("1.2.0.0").AsSlice()}
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, ecs16, false, []dns.RR{rrBroad}, nil, nil, false, dns.RcodeSuccess)

	rrSpecific := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netParseIP("10.0.0.2")}}
	ecs24 := &config.ECSOption{Family: 1, SourcePrefix: 24, ScopePrefix: 0, Address: netParseIP("1.2.3.0").AsSlice()}
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, ecs24, false, []dns.RR{rrSpecific}, nil, nil, false, dns.RcodeSuccess)

	entry, found, _ := mc.Get("example.com.", dns.TypeA, dns.ClassINET, ecs24, false)
	if !found {
		t.Fatal("should find entry")
	}
	if a, ok := entry.Answer[0].(*dns.A); ok && a.A.String() != "10.0.0.2" {
		t.Errorf("exact /24 should return specific IP, got %s", a.A.String())
	}
}

func TestSet_DNSSECScoping(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	rr := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netParseIP("192.0.2.1")}}
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, true, []dns.RR{rr}, nil, nil, false, dns.RcodeSuccess)

	_, found, _ := mc.Get("example.com.", dns.TypeA, dns.ClassINET, nil, true)
	if !found {
		t.Error("should find with matching DNSSEC OK")
	}

	_, found, _ = mc.Get("example.com.", dns.TypeA, dns.ClassINET, nil, false)
	if found {
		t.Error("should not find without DNSSEC OK")
	}
}

func TestSet_DefaultTTLFallback(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	rr := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 0}, A: rdata.A{Addr: netParseIP("192.0.2.1")}}
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr}, nil, nil, false, dns.RcodeSuccess)

	// RFC 8767 §7: TTL=0 data must not be cached.
	_, found, _ := mc.Get("example.com.", dns.TypeA, dns.ClassINET, nil, false)
	if found {
		t.Fatal("TTL=0 entry should not be cached (RFC 8767 §7)")
	}
}

func TestSet_MaxCacheableTTLCapped(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	hugeTTL := uint32(config.DefaultMaxCacheableTTL + 3600)
	rr := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: hugeTTL}, A: rdata.A{Addr: netParseIP("192.0.2.1")}}
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr}, nil, nil, false, dns.RcodeSuccess)

	entry, found, _ := mc.Get("example.com.", dns.TypeA, dns.ClassINET, nil, false)
	if !found {
		t.Fatal("entry not found")
	}
	if entry.TTL != config.DefaultMaxCacheableTTL {
		t.Errorf("TTL = %d, want %d (capped)", entry.TTL, config.DefaultMaxCacheableTTL)
	}
}

func TestClose(t *testing.T) {
	mc := testStore()
	if err := mc.Close(); err != nil {
		t.Errorf("Close error: %v", err)
	}
	if !mc.db.IsClosed() {
		t.Error("db should be closed")
	}
	_ = mc.Close()
}

func TestEntry_IsExpired(t *testing.T) {
	e := &Entry{Timestamp: time.Now().Unix() - 100, TTL: 10}
	if !e.IsExpired() {
		t.Error("entry should be expired")
	}
}

func TestEntry_CanServeExpired(t *testing.T) {
	e := &Entry{Timestamp: time.Now().Unix() - 40, TTL: 10}
	if !e.CanServeExpired(60) {
		t.Error("entry should be serveable within 60s window")
	}
	if e.CanServeExpired(20) {
		t.Error("entry should not be serveable within 20s window")
	}
}

func TestEntry_ShouldPrefetch(t *testing.T) {
	e := &Entry{Timestamp: time.Now().Unix() - 5, TTL: 100}
	if e.ShouldPrefetch(10) {
		t.Error("fresh entry should not trigger prefetch")
	}
	e2 := &Entry{Timestamp: time.Now().Unix() - 95, TTL: 100}
	if !e2.ShouldPrefetch(10) {
		t.Error("near-expiry entry should trigger prefetch")
	}
}

func TestEntry_RemainingTTL(t *testing.T) {
	e := &Entry{Timestamp: time.Now().Unix() - 5, TTL: 100}
	remaining := e.RemainingTTL()
	if remaining > 100 || remaining < 90 {
		t.Errorf("remaining TTL = %d, want ~95", remaining)
	}
}

func TestSet_FlushDB_Cache(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	rr := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netParseIP("192.0.2.1")}}
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr}, nil, nil, false, dns.RcodeSuccess)

	_, err := mc.FlushDB("cache")
	if err != nil {
		t.Fatalf("FlushDB cache: %v", err)
	}

	_, found, _ := mc.Get("example.com.", dns.TypeA, dns.ClassINET, nil, false)
	if found {
		t.Error("entry should be gone after FlushDB cache")
	}
}

func TestFlushDB_UnknownTarget(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()
	_, err := mc.FlushDB("nonexistent")
	if err == nil {
		t.Error("expected error for unknown target")
	}
}

func TestDiskPersistence(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	db, err := database.Open(dbPath, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	mc := &Cache{db: db}

	rr := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netParseIP("192.0.2.1")}}
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr}, nil, nil, false, dns.RcodeSuccess)
	_ = mc.Close()

	db2, err := database.Open(dbPath, nil)
	if err != nil {
		t.Fatalf("Reopen: %v", err)
	}
	defer func() { _ = db2.Close() }()
	mc2 := &Cache{db: db2}

	entry, found, _ := mc2.Get("example.com.", dns.TypeA, dns.ClassINET, nil, false)
	if !found {
		t.Fatal("data not persisted")
	}
	if len(entry.Answer) != 1 {
		t.Errorf("answer count = %d, want 1", len(entry.Answer))
	}
}

func TestMaskIP_IPv4(t *testing.T) {
	result := maskIP(netParseIP("192.0.2.1").AsSlice(), 24)
	if result.String() != "192.0.2.0" {
		t.Errorf("masked = %s, want 192.0.2.0", result.String())
	}
}

func TestMaskIP_IPv6(t *testing.T) {
	result := maskIP(netParseIP("2001:db8:1:2::1").AsSlice(), 48)
	if result.String() != "2001:db8:1::" {
		t.Errorf("masked = %s, want 2001:db8:1::", result.String())
	}
}

func TestECSFallbackCandidates_Nil(t *testing.T) {
	candidates := ecsFallbackCandidates(nil)
	if len(candidates) != 3 {
		t.Fatalf("nil ECS should return 3 candidates (no-ECS + IPv4 /0 + IPv6 /0): got %d: %+v", len(candidates), candidates)
	}
	if candidates[0].addr != "" || candidates[0].prefix != 0 {
		t.Errorf("first candidate should be no-ECS: %+v", candidates[0])
	}
	if candidates[1].addr != "0.0.0.0" || candidates[1].prefix != 0 {
		t.Errorf("second candidate should be IPv4 /0: %+v", candidates[1])
	}
	if candidates[2].addr != "::" || candidates[2].prefix != 0 {
		t.Errorf("third candidate should be IPv6 /0: %+v", candidates[2])
	}
}

func BenchmarkStoreSetGet(b *testing.B) {
	db, _ := database.Open("", nil)
	mc := &Cache{db: db}
	defer func() { _ = mc.Close() }()

	b.ResetTimer()
	for range b.N {
		rr := &dns.A{Hdr: dns.Header{Name: "www.example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netParseIP("1.2.3.4")}}
		mc.Set("www.example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr}, nil, nil, false, dns.RcodeSuccess)
		mc.Get("www.example.com.", dns.TypeA, dns.ClassINET, nil, false)
	}
}

func BenchmarkStoreParallel(b *testing.B) {
	db, _ := database.Open("", nil)
	mc := &Cache{db: db}
	defer func() { _ = mc.Close() }()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			name := fmt.Sprintf("host%d.example.com.", i)
			rr := &dns.A{Hdr: dns.Header{Name: name, Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netParseIP("1.2.3.4")}}
			mc.Set(name, dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr}, nil, nil, false, dns.RcodeSuccess)
			mc.Get(name, dns.TypeA, dns.ClassINET, nil, false)
			i++
		}
	})
}

// ── Native BadgerDB optimisations (894449f + 408c77b) ────────────────────────

func TestSet_Get_TimestampDerived(t *testing.T) {
	// 894449f: Timestamp is NOT stored in the value — it is derived from
	// BadgerDB's native ExpiresAt() at read time.
	// expiresAt = timestamp + entryTTL + staleMaxAge
	// → timestamp = expiresAt - entryTTL - staleMaxAge
	mc := testStore()
	defer func() { _ = mc.Close() }()

	beforeSet := time.Now().Unix()
	rr := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netParseIP("192.0.2.1")}}
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr}, nil, nil, false, dns.RcodeSuccess)
	afterSet := time.Now().Unix()

	entry, found, _ := mc.Get("example.com.", dns.TypeA, dns.ClassINET, nil, false)
	if !found {
		t.Fatal("entry not found")
	}
	if entry.Timestamp < beforeSet-5 || entry.Timestamp > afterSet+5 {
		t.Errorf("Timestamp = %d, want ≈ [%d, %d] (derived from ExpiresAt)", entry.Timestamp, beforeSet, afterSet)
	}
	if entry.TTL != 300 {
		t.Errorf("TTL = %d, want 300", entry.TTL)
	}
}

func TestSet_Get_EntryTTLFromWire(t *testing.T) {
	// This PR: entryTTL is derived from the unpacked DNS wire via minTTL(),
	// not stored separately. The minimum positive TTL across all sections
	// should be returned as Entry.TTL.
	mc := testStore()
	defer func() { _ = mc.Close() }()

	answer := []dns.RR{
		&dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 600}, A: rdata.A{Addr: netParseIP("192.0.2.1")}},
	}
	authority := []dns.RR{
		&dns.NS{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 100}, NS: rdata.NS{Ns: "ns1.example.com."}},
	}
	additional := []dns.RR{
		&dns.A{Hdr: dns.Header{Name: "ns1.example.com.", Class: dns.ClassINET, TTL: 200}, A: rdata.A{Addr: netParseIP("10.0.0.1")}},
	}

	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, false, answer, authority, additional, false, dns.RcodeSuccess)

	entry, found, _ := mc.Get("example.com.", dns.TypeA, dns.ClassINET, nil, false)
	if !found {
		t.Fatal("entry not found")
	}
	// Minimum across all sections: min(600, 100, 200) = 100.
	if entry.TTL != 100 {
		t.Errorf("TTL = %d, want 100 (min across all sections derived from wire)", entry.TTL)
	}
}

func TestSet_Get_RawWireFidelity(t *testing.T) {
	// This PR: the value is raw DNS wire — no header. RRs must survive
	// the Set → Get round-trip with all fields intact.
	mc := testStore()
	defer func() { _ = mc.Close() }()

	answer := []dns.RR{
		&dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netParseIP("192.0.2.1")}},
		&dns.AAAA{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, AAAA: rdata.AAAA{Addr: netParseIP("2001:db8::1")}},
	}
	authority := []dns.RR{
		&dns.NS{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 3600}, NS: rdata.NS{Ns: "ns1.example.com."}},
	}

	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, false, answer, authority, nil, false, dns.RcodeSuccess)

	entry, found, _ := mc.Get("example.com.", dns.TypeA, dns.ClassINET, nil, false)
	if !found {
		t.Fatal("entry not found")
	}
	if len(entry.Answer) != 2 {
		t.Fatalf("Answer count = %d, want 2", len(entry.Answer))
	}
	if dns.RRToType(entry.Answer[0]) != dns.TypeA {
		t.Errorf("Answer[0] type = %d, want A", dns.RRToType(entry.Answer[0]))
	}
	if dns.RRToType(entry.Answer[1]) != dns.TypeAAAA {
		t.Errorf("Answer[1] type = %d, want AAAA", dns.RRToType(entry.Answer[1]))
	}
	if len(entry.Authority) != 1 {
		t.Fatalf("Authority count = %d, want 1", len(entry.Authority))
	}
	if dns.RRToType(entry.Authority[0]) != dns.TypeNS {
		t.Errorf("Authority[0] type = %d, want NS", dns.RRToType(entry.Authority[0]))
	}
}

func TestSet_Get_CNAMERecords(t *testing.T) {
	// CNAME records are common in DNS; verify they survive the raw-wire round-trip.
	mc := testStore()
	defer func() { _ = mc.Close() }()

	answer := []dns.RR{
		&dns.CNAME{Hdr: dns.Header{Name: "www.example.com.", Class: dns.ClassINET, TTL: 600}, CNAME: rdata.CNAME{Target: "example.com."}},
		&dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netParseIP("192.0.2.1")}},
	}

	mc.Set("www.example.com.", dns.TypeA, dns.ClassINET, nil, false, answer, nil, nil, false, dns.RcodeSuccess)

	entry, found, _ := mc.Get("www.example.com.", dns.TypeA, dns.ClassINET, nil, false)
	if !found {
		t.Fatal("entry not found")
	}
	if len(entry.Answer) != 2 {
		t.Fatalf("Answer count = %d, want 2", len(entry.Answer))
	}
	if dns.RRToType(entry.Answer[0]) != dns.TypeCNAME {
		t.Errorf("Answer[0] type = %d, want CNAME", dns.RRToType(entry.Answer[0]))
	}
	if dns.RRToType(entry.Answer[1]) != dns.TypeA {
		t.Errorf("Answer[1] type = %d, want A", dns.RRToType(entry.Answer[1]))
	}
}

func TestDBSize_AfterClose(t *testing.T) {
	mc := testStore()
	_ = mc.Close()

	lsm, vlog := mc.DBSize()
	if lsm != 0 || vlog != 0 {
		t.Errorf("DBSize after close = (%d, %d), want (0, 0)", lsm, vlog)
	}

	lsm2, vlog2 := mc.DBEstimateSize(database.EntryKeyPrefix())
	if lsm2 != 0 || vlog2 != 0 {
		t.Errorf("DBEstimateSize after close = (%d, %d), want (0, 0)", lsm2, vlog2)
	}
}

func TestProcessRecords_NoDNSSEC(t *testing.T) {
	rrs := []dns.RR{
		&dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netParseIP("1.2.3.4")}},
	}
	// Test TTL adjustment.
	result := ProcessRecords(rrs, 10, false, false)
	if len(result) != 1 {
		t.Fatalf("expected 1 record, got %d", len(result))
	}
	if result[0].Header().TTL != 10 {
		t.Errorf("TTL = %d, want 10", result[0].Header().TTL)
	}
}
