package cache

import (
	"bytes"
	"fmt"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
	"zjdns/config"
	"zjdns/database"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"

	zdnsutil "zjdns/internal/dnsutil"
)

func testStore() *Cache {
	db, err := database.Open("", 0, 0, 0)
	if err != nil {
		panic(err)
	}
	return &Cache{db: db}
}

func netParseIP(s string) netip.Addr { return netip.MustParseAddr(s) }

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
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, ecs16, false, []dns.RR{rr}, nil, nil, false)

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
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, ecs16, false, []dns.RR{rrBroad}, nil, nil, false)

	rrSpecific := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netParseIP("10.0.0.2")}}
	ecs24 := &config.ECSOption{Family: 1, SourcePrefix: 24, ScopePrefix: 0, Address: netParseIP("1.2.3.0").AsSlice()}
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, ecs24, false, []dns.RR{rrSpecific}, nil, nil, false)

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
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, true, []dns.RR{rr}, nil, nil, false)

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
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr}, nil, nil, false)

	entry, found, _ := mc.Get("example.com.", dns.TypeA, dns.ClassINET, nil, false)
	if !found {
		t.Fatal("entry not found")
	}
	if entry.TTL != config.DefaultTTL {
		t.Errorf("TTL = %d, want %d (DefaultTTL)", entry.TTL, config.DefaultTTL)
	}
}

func TestSet_MaxCacheableTTLCapped(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	hugeTTL := uint32(config.DefaultMaxCacheableTTL + 3600)
	rr := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: hugeTTL}, A: rdata.A{Addr: netParseIP("192.0.2.1")}}
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr}, nil, nil, false)

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

func TestAsyncWriter_RecordAndFlush(t *testing.T) {
	db, err := database.Open("", 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}

	mc := New(db)
	defer func() { _ = mc.Close() }()

	rr := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netParseIP("192.0.2.1")}}
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr}, nil, nil, false)

	mc.RecordRequest(&RequestRecord{
		Qname: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET,
		Protocol: "udp", Result: "hit", Rcode: dns.RcodeSuccess,
	})
	mc.Flush()
}

func TestAsyncWriter_CloseDrain(t *testing.T) {
	db, err := database.Open("", 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}

	mc := New(db)
	for range 100 {
		mc.RecordRequest(&RequestRecord{
			Qname: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET,
			Protocol: "udp", Result: "hit", Rcode: dns.RcodeSuccess,
		})
	}
	if err := mc.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
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
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr}, nil, nil, false)

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

	db, err := database.Open(dbPath, 500, 0, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	mc := &Cache{db: db}

	rr := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netParseIP("192.0.2.1")}}
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr}, nil, nil, false)
	_ = mc.Close()

	db2, err := database.Open(dbPath, 500, 0, 0)
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

func TestCompression_RoundTrip(t *testing.T) {
	data := []byte("test data for compression round trip " + string(bytes.Repeat([]byte{0x41}, 100)))
	compressed := zdnsutil.Compress(data)
	if len(compressed) == 0 {
		t.Fatal("compression produced empty output")
	}
	decompressed, err := zdnsutil.Decompress(compressed)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if !bytes.Equal(decompressed, data) {
		t.Error("compression round-trip mismatch")
	}
}

func TestCompression_NilInput(t *testing.T) {
	if zdnsutil.Compress(nil) != nil {
		t.Error("Compress(nil) should return nil")
	}
	d, err := zdnsutil.Decompress(nil)
	if err != nil || d != nil {
		t.Error("Decompress(nil) should return nil, nil")
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
	if len(candidates) != 1 || candidates[0].addr != "" || candidates[0].prefix != 0 {
		t.Errorf("nil ECS should return single zero-value candidate: %+v", candidates)
	}
}

func BenchmarkStoreSetGet(b *testing.B) {
	db, _ := database.Open("", 0, 0, 0)
	mc := &Cache{db: db}
	defer func() { _ = mc.Close() }()

	b.ResetTimer()
	for range b.N {
		rr := &dns.A{Hdr: dns.Header{Name: "www.example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netParseIP("1.2.3.4")}}
		mc.Set("www.example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr}, nil, nil, false)
		mc.Get("www.example.com.", dns.TypeA, dns.ClassINET, nil, false)
	}
}

func BenchmarkStoreParallel(b *testing.B) {
	db, _ := database.Open("", 0, 0, 0)
	mc := &Cache{db: db}
	defer func() { _ = mc.Close() }()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			name := fmt.Sprintf("host%d.example.com.", i)
			rr := &dns.A{Hdr: dns.Header{Name: name, Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netParseIP("1.2.3.4")}}
			mc.Set(name, dns.TypeA, dns.ClassINET, nil, false, []dns.RR{rr}, nil, nil, false)
			mc.Get(name, dns.TypeA, dns.ClassINET, nil, false)
			i++
		}
	})
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
