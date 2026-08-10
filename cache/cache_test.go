package cache

import (
	"bytes"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"
	"zjdns/config"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"

	zdnsutil "zjdns/internal/dnsutil"
)

func testStore() *Cache {
	return New(0, 0)
}

// ── Get / Set ─────────────────────────────────────────────────────────────────

func TestSet_Get_RoundTrip(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	rr := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netParseIP("192.0.2.1")}}
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, []dns.RR{rr}, nil, nil, false, 0)

	entry, found, expired := mc.Get("example.com.", dns.TypeA, dns.ClassINET, nil)
	if !found {
		t.Fatal("Get returned not found after Set")
	}
	if expired {
		t.Error("entry should not be expired immediately")
	}
	// Pre-packed format: ResponseWire is set, Answer/Authority/Additional are nil.
	if entry.ResponseWire == nil {
		t.Fatal("ResponseWire is nil — expected pre-packed response wire")
	}
	if len(entry.TTLOffsets) < 1 {
		t.Fatalf("TTLOffsets = %d, want at least 1", len(entry.TTLOffsets))
	}
}

func TestGet_Miss(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	_, found, _ := mc.Get("nonexistent.com.", dns.TypeA, dns.ClassINET, nil)
	if found {
		t.Error("Get should return not found for missing key")
	}
}

func TestSet_ValidatedFlag(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	rr := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netParseIP("192.0.2.1")}}
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, []dns.RR{rr}, nil, nil, true, 0)

	entry, found, _ := mc.Get("example.com.", dns.TypeA, dns.ClassINET, nil)
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

	mc.Set("example.com.", dns.TypeA, dns.ClassINET, ecs, []dns.RR{rr}, nil, nil, false, 0)

	// Hit with same ECS
	_, found, _ := mc.Get("example.com.", dns.TypeA, dns.ClassINET, ecs)
	if !found {
		t.Error("should find entry with matching ECS")
	}

	// Miss with different ECS
	ecs2 := &config.ECSOption{Family: 1, SourcePrefix: 16, ScopePrefix: 0, Address: netParseIP("10.0.0.0").AsSlice()}
	_, found, _ = mc.Get("example.com.", dns.TypeA, dns.ClassINET, ecs2)
	if found {
		t.Error("should miss with different ECS")
	}

	// Miss without ECS
	_, found, _ = mc.Get("example.com.", dns.TypeA, dns.ClassINET, nil)
	if found {
		t.Error("should miss without ECS when stored with ECS")
	}
}

// ── ECS prefix fallback ──────────────────────────────────────────────────────

func TestGet_ECSFallback(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	// Store at /16
	rr := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netParseIP("10.0.0.1")}}
	ecs16 := &config.ECSOption{Family: 1, SourcePrefix: 16, ScopePrefix: 0, Address: netParseIP("1.2.0.0").AsSlice()}
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, ecs16, []dns.RR{rr}, nil, nil, false, 0)

	// Exact match with /16
	_, found, _ := mc.Get("example.com.", dns.TypeA, dns.ClassINET, ecs16)
	if !found {
		t.Error("should hit with exact /16")
	}

	// Fallback from /24 to /16 within same range
	ecs24 := &config.ECSOption{Family: 1, SourcePrefix: 24, ScopePrefix: 0, Address: netParseIP("1.2.3.0").AsSlice()}
	entry, found, _ := mc.Get("example.com.", dns.TypeA, dns.ClassINET, ecs24)
	if err := entry.Unpack(); err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Error("should fallback from /24 to /16")
	}
	if len(entry.Answer) == 1 {
		if a, ok := entry.Answer[0].(*dns.A); ok && a.A.String() != "10.0.0.1" {
			t.Errorf("fallback returned wrong IP: %s, want 10.0.0.1", a.A.String())
		}
	}

	// Another /24 in same /16 range should also hit
	ecs24b := &config.ECSOption{Family: 1, SourcePrefix: 24, ScopePrefix: 0, Address: netParseIP("1.2.255.0").AsSlice()}
	_, found, _ = mc.Get("example.com.", dns.TypeA, dns.ClassINET, ecs24b)
	if !found {
		t.Error("should fallback from different /24 to same /16")
	}

	// Completely different /16 should miss
	ecsOther := &config.ECSOption{Family: 1, SourcePrefix: 24, ScopePrefix: 0, Address: netParseIP("10.0.0.0").AsSlice()}
	_, found, _ = mc.Get("example.com.", dns.TypeA, dns.ClassINET, ecsOther)
	if found {
		t.Error("should miss with different IP range")
	}
}

func TestGet_ECSFallback_ExactPreferred(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	// Store broad answer at /16
	rrBroad := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netParseIP("10.0.0.1")}}
	ecs16 := &config.ECSOption{Family: 1, SourcePrefix: 16, ScopePrefix: 0, Address: netParseIP("1.2.0.0").AsSlice()}
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, ecs16, []dns.RR{rrBroad}, nil, nil, false, 0)

	// Store specific answer at /24
	rrSpecific := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netParseIP("10.0.0.2")}}
	ecs24 := &config.ECSOption{Family: 1, SourcePrefix: 24, ScopePrefix: 0, Address: netParseIP("1.2.3.0").AsSlice()}
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, ecs24, []dns.RR{rrSpecific}, nil, nil, false, 0)

	// Query with /24 should hit exact entry, not the /16 fallback
	entry, found, _ := mc.Get("example.com.", dns.TypeA, dns.ClassINET, ecs24)
	if err := entry.Unpack(); err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("should find entry")
	}
	if a, ok := entry.Answer[0].(*dns.A); ok && a.A.String() != "10.0.0.2" {
		t.Errorf("exact /24 should return specific IP, got %s", a.A.String())
	}

	// Query with different /24 in same /16 should fallback to /16
	ecs24b := &config.ECSOption{Family: 1, SourcePrefix: 24, ScopePrefix: 0, Address: netParseIP("1.2.4.0").AsSlice()}
	entry, found, _ = mc.Get("example.com.", dns.TypeA, dns.ClassINET, ecs24b)
	if err := entry.Unpack(); err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("should fallback to /16")
	}
	if a, ok := entry.Answer[0].(*dns.A); ok && a.A.String() != "10.0.0.1" {
		t.Errorf("fallback should return broad IP, got %s", a.A.String())
	}
}

func TestGet_ECSFallback_IPv6(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	// Store at /48
	rr := &dns.AAAA{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, AAAA: rdata.AAAA{Addr: netParseIP("2001:db8::1")}}
	ecs48 := &config.ECSOption{Family: 2, SourcePrefix: 48, ScopePrefix: 0, Address: netParseIP("2001:db8:1::").AsSlice()}
	mc.Set("example.com.", dns.TypeAAAA, dns.ClassINET, ecs48, []dns.RR{rr}, nil, nil, false, 0)

	// Exact match with /48
	_, found, _ := mc.Get("example.com.", dns.TypeAAAA, dns.ClassINET, ecs48)
	if !found {
		t.Error("should hit with exact /48")
	}

	// Fallback from /56 to /48
	ecs56 := &config.ECSOption{Family: 2, SourcePrefix: 56, ScopePrefix: 0, Address: netParseIP("2001:db8:1:ff00::").AsSlice()}
	_, found, _ = mc.Get("example.com.", dns.TypeAAAA, dns.ClassINET, ecs56)
	if !found {
		t.Error("should fallback from /56 to /48")
	}

	// Different /48 range should miss
	ecsOther := &config.ECSOption{Family: 2, SourcePrefix: 56, ScopePrefix: 0, Address: netParseIP("2001:db8:2::").AsSlice()}
	_, found, _ = mc.Get("example.com.", dns.TypeAAAA, dns.ClassINET, ecsOther)
	if found {
		t.Error("should miss with different IPv6 range")
	}
}

func TestECSFallbackCandidates(t *testing.T) {
	// nil ECS
	c := ecsFallbackCandidates(nil)
	if len(c) != 1 || c[0].addr != "" || c[0].prefix != 0 {
		t.Errorf("nil ECS: got %+v, want [(, 0)]", c)
	}

	// IPv4 /24
	ecs24 := &config.ECSOption{Family: 1, SourcePrefix: 24, Address: netParseIP("1.2.3.0").AsSlice()}
	c = ecsFallbackCandidates(ecs24)
	if len(c) != 4 {
		t.Fatalf("IPv4 /24: got %d candidates, want 4", len(c))
	}
	if c[0].prefix != 24 || c[1].prefix != 16 || c[2].prefix != 8 || c[3].prefix != 0 {
		t.Errorf("prefix order wrong: %v", c)
	}
	if c[0].addr != "1.2.3.0" || c[1].addr != "1.2.0.0" || c[2].addr != "1.0.0.0" || c[3].addr != "0.0.0.0" {
		t.Errorf("addr order wrong: %v", c)
	}

	// IPv4 /16
	ecs16 := &config.ECSOption{Family: 1, SourcePrefix: 16, Address: netParseIP("1.2.0.0").AsSlice()}
	c = ecsFallbackCandidates(ecs16)
	if len(c) != 3 {
		t.Fatalf("IPv4 /16: got %d candidates, want 3", len(c))
	}
	if c[0].prefix != 16 || c[1].prefix != 8 || c[2].prefix != 0 {
		t.Errorf("prefix order wrong: %v", c)
	}

	// IPv4 /0
	ecs0 := &config.ECSOption{Family: 1, SourcePrefix: 0, Address: netParseIP("0.0.0.0").AsSlice()}
	c = ecsFallbackCandidates(ecs0)
	if len(c) != 1 || c[0].prefix != 0 {
		t.Errorf("IPv4 /0: got %+v, want [(0.0.0.0, 0)]", c)
	}

	// IPv6 /56
	ecs56 := &config.ECSOption{Family: 2, SourcePrefix: 56, Address: netParseIP("2001:db8:1:ff00::").AsSlice()}
	c = ecsFallbackCandidates(ecs56)
	if len(c) != 4 {
		t.Fatalf("IPv6 /56: got %d candidates, want 4", len(c))
	}
	if c[0].prefix != 56 || c[1].prefix != 48 || c[2].prefix != 32 || c[3].prefix != 0 {
		t.Errorf("prefix order wrong: %v", c)
	}
}

// TestSet_Get_DNSSECKeyUnified verifies the cache key does not split on the
// client's DO bit: outbound queries always carry DO=1, the stored wire always
// holds the full DNSSEC data, and DO=0 filtering happens at serve time — so a
// single entry serves both DO variants.
func TestSet_Get_DNSSECKeyUnified(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	rr := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netParseIP("192.0.2.1")}}

	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, []dns.RR{rr}, nil, nil, false, 0)

	_, found, _ := mc.Get("example.com.", dns.TypeA, dns.ClassINET, nil)
	if !found {
		t.Error("should find entry")
	}

	_, found, _ = mc.Get("example.com.", dns.TypeA, dns.ClassINET, nil)
	if !found {
		t.Error("DO=0 lookup should hit the same entry (key does not split on DO)")
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
	// Use the same cached clock as RemainingTTL (log.NowUnix, refreshed by a
	// 1s ticker).  A real-clock timestamp can straddle a second boundary that
	// the cache has not ticked across yet, making remaining = 301 and flaking
	// the assertion.
	entry := &Entry{Timestamp: log.NowUnix(), TTL: 300}
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
	rrsig := &dns.RRSIG{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300},
		RRSIG: rdata.RRSIG{
			TypeCovered: dns.TypeA, Algorithm: 8, Labels: 2, OrigTTL: 300,
			Expiration: uint32(time.Now().Add(1 * time.Hour).Unix()),  //nolint:gosec // G115: DNS TTL — protocol-bounded uint32
			Inception:  uint32(time.Now().Add(-1 * time.Hour).Unix()), //nolint:gosec // G115: DNS TTL — protocol-bounded uint32
			KeyTag:     1234, SignerName: "example.com.",
		},
	}
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
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, []dns.RR{rr}, nil, nil, false, 0)

	entry, found, _ := mc.Get("example.com.", dns.TypeA, dns.ClassINET, nil)
	if !found {
		t.Fatal("entry not found")
	}
	if entry.TTL != config.DefaultTTL {
		t.Errorf("TTL = %d, want %d (zero TTL floored to default)", entry.TTL, config.DefaultTTL)
	}
}

// ── DNSKEY/NSAddr cache patterns ──────────────────────────────────────────────

func TestSet_Get_DNSKEY(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	dnskey := &dns.DNSKEY{Hdr: dns.Header{Name: "com.", Class: dns.ClassINET, TTL: 86400}}
	mc.Set("com.", dns.TypeDNSKEY, dns.ClassINET, nil, []dns.RR{dnskey}, nil, nil, true, 0)

	entry, found, _ := mc.Get("com.", dns.TypeDNSKEY, dns.ClassINET, nil)
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
	mc.Set(".", dns.TypeNone, dns.ClassINET, nil, []dns.RR{txt}, nil, nil, false, 0)

	entry, found, _ := mc.Get(".", dns.TypeNone, dns.ClassINET, nil)
	if err := entry.Unpack(); err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("NS addr entry not found")
	}
	if len(entry.Answer) != 1 {
		t.Fatalf("answer count = %d, want 1", len(entry.Answer))
	}
}

// ── RecordRequest (in-memory stats + per-RCODE journal) ─────────────────────

func TestRecordRequest_Hit(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	rr := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("1.2.3.4")}}
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, []dns.RR{rr}, nil, nil, false, 0)

	// Cache hit via UDP
	mc.RecordRequest(&RequestRecord{
		Qname: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET,
		Protocol: "udp", Result: "hit", Rcode: dns.RcodeSuccess,
	})

	snap := mc.statsMgr.Snapshot(0)
	if snap.Total != 1 || snap.Hits != 1 {
		t.Fatalf("counters total/hits = %d/%d, want 1/1", snap.Total, snap.Hits)
	}
	if snap.UDP != 1 {
		t.Errorf("udp = %d, want 1", snap.UDP)
	}
	// Hits must not enter the per-RCODE journal.
	if len(snap.TopByRcode) != 0 {
		t.Errorf("journal has entries for hits: %+v", snap.TopByRcode)
	}
}

func TestRecordRequest_Stale(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	rr := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("1.2.3.4")}}
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, []dns.RR{rr}, nil, nil, false, 0)

	// Stale serve via TCP
	mc.RecordRequest(&RequestRecord{
		Qname: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET,
		Protocol: "tcp", Result: "stale", Rcode: dns.RcodeSuccess,
	})

	snap := mc.statsMgr.Snapshot(0)
	if snap.Stales != 1 || snap.TCP != 1 {
		t.Fatalf("counters stales/tcp = %d/%d, want 1/1", snap.Stales, snap.TCP)
	}
	top := snap.TopByRcode[dns.RcodeSuccess]
	if len(top) != 1 || top[0].Key != "example.com." || top[0].Count != 1 {
		t.Fatalf("journal top = %+v, want [example.com. 1]", top)
	}
}

func TestRecordRequest_MultipleResults(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	rr := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("1.2.3.4")}}
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, []dns.RR{rr}, nil, nil, false, 0)

	mc.RecordRequest(&RequestRecord{Qname: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET, Protocol: "udp", Result: "hit", Rcode: dns.RcodeSuccess})
	mc.RecordRequest(&RequestRecord{Qname: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET, Protocol: "udp", Result: "hit", Rcode: dns.RcodeSuccess})
	mc.RecordRequest(&RequestRecord{Qname: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET, Protocol: "https", Result: "hit", Rcode: dns.RcodeSuccess})

	snap := mc.statsMgr.Snapshot(0)
	if snap.Hits != 3 {
		t.Errorf("hits = %d, want 3", snap.Hits)
	}
	if snap.UDP != 2 {
		t.Errorf("udp hits = %d, want 2", snap.UDP)
	}
	if snap.HTTPS != 1 {
		t.Errorf("doh hits = %d, want 1", snap.HTTPS)
	}
}

// ── RecordRequest Zone ─────────────────────────────────────────────────────

func TestRecordRequest_Zone(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	mc.RecordRequest(&RequestRecord{Qname: "blocked.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET, Protocol: "", Result: "zone", Rcode: dns.RcodeRefused})
	mc.RecordRequest(&RequestRecord{Qname: "blocked.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET, Protocol: "", Result: "zone", Rcode: dns.RcodeRefused})

	snap := mc.statsMgr.Snapshot(0)
	if snap.Zones != 2 {
		t.Errorf("zones = %d, want 2", snap.Zones)
	}
	top := snap.TopByRcode[dns.RcodeRefused]
	if len(top) != 1 || top[0].Key != "blocked.com." || top[0].Count != 2 {
		t.Fatalf("journal top = %+v, want [blocked.com. 2]", top)
	}
}

// ── UpdateLatency (in-memory latency map) ─────────────────────────────────

func TestUpdateLatency(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	rr := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("8.8.8.8")}}
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, []dns.RR{rr}, nil, nil, false, 0)

	mc.UpdateLatency("8.8.8.8", 42)

	e, ok := mc.latencies.Get("8.8.8.8")
	if !ok {
		t.Fatal("latency entry not stored")
	}
	if e.latency != 42 {
		t.Errorf("latency = %d, want 42", e.latency)
	}
	if ts, ok := mc.LatencyLastProbe("8.8.8.8"); !ok || ts == 0 {
		t.Errorf("LatencyLastProbe = (%d, %v), want (probe time, true)", ts, ok)
	}
	if _, ok := mc.LatencyLastProbe("9.9.9.9"); ok {
		t.Error("LatencyLastProbe for unknown IP should return false")
	}
}

// ── Wire format multi-record round-trip ──────────────────────────────────────

func TestSet_Get_MultipleRecords(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	a1 := &dns.A{Hdr: dns.Header{Name: "multi.example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("10.0.0.1")}}
	a2 := &dns.A{Hdr: dns.Header{Name: "multi.example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("10.0.0.2")}}
	soa := &dns.SOA{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 900},
		SOA: rdata.SOA{Ns: "ns1.example.com.", Mbox: "admin.example.com.", Serial: 1, Refresh: 1800, Retry: 900, Expire: 604800, Minttl: 600},
	}

	mc.Set("multi.example.com.", dns.TypeA, dns.ClassINET, nil,
		[]dns.RR{a1, a2}, []dns.RR{soa}, nil, true, 0)

	entry, found, _ := mc.Get("multi.example.com.", dns.TypeA, dns.ClassINET, nil)
	if err := entry.Unpack(); err != nil {
		t.Fatal(err)
	}
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
	mc.Set("meta.example.com.", dns.TypeA, dns.ClassINET, nil, []dns.RR{rr}, nil, nil, true, 0)

	entry, found, _ := mc.Get("meta.example.com.", dns.TypeA, dns.ClassINET, nil)
	if !found || entry == nil {
		t.Fatal("entry not found after Set")
	}
	if !entry.Validated {
		t.Error("Validated flag not preserved")
	}
	if len(entry.ResponseWire) == 0 {
		t.Error("ResponseWire should not be empty")
	}
}

// ── Compression smoke test ───────────────────────────────────────────────────

func TestCompressionRoundTrip(t *testing.T) {
	original := []byte("test wire format data")
	compressed := zdnsutil.Compress(original)
	if len(compressed) == 0 {
		t.Fatal("compress returned empty")
	}
	decompressed, err := zdnsutil.Decompress(compressed, nil)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if !bytes.Equal(decompressed, original) {
		t.Errorf("round-trip mismatch: got %q, want %q", decompressed, original)
	}
}

func TestCompressEmpty(t *testing.T) {
	if zdnsutil.Compress(nil) != nil {
		t.Error("zdnsutil.Compress(nil) should return nil")
	}
	if zdnsutil.Compress([]byte{}) != nil {
		t.Error("zdnsutil.Compress([]byte{}) should return nil")
	}
}

func TestDecompressEmpty(t *testing.T) {
	result, err := zdnsutil.Decompress(nil, nil)
	if err != nil {
		t.Errorf("zdnsutil.Decompress(nil, nil): %v", err)
	}
	if result != nil {
		t.Error("zdnsutil.Decompress(nil, nil) should return nil")
	}
	result, err = zdnsutil.Decompress([]byte{}, nil)
	if err != nil {
		t.Errorf("zdnsutil.Decompress([]byte{}, nil): %v", err)
	}
	if result != nil {
		t.Error("zdnsutil.Decompress([]byte{}, nil) should return nil")
	}
}

// ── RecordRequest Error ───────────────────────────────────────────────────

func TestRecordRequest_Error(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	mc.RecordRequest(&RequestRecord{
		Qname: "error.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET,
		Protocol: "udp", Result: "error", Rcode: dns.RcodeServerFailure,
		Server: "1.2.3.4:53 (UDP)", ResponseTime: 500,
	})

	snap := mc.statsMgr.Snapshot(0)
	if snap.Errors != 1 || snap.UDP != 1 {
		t.Fatalf("counters errors/udp = %d/%d, want 1/1", snap.Errors, snap.UDP)
	}
	if snap.TotalMS != 500 {
		t.Errorf("TotalMS = %d, want 500", snap.TotalMS)
	}
	top := snap.TopByRcode[dns.RcodeServerFailure]
	if len(top) != 1 || top[0].Key != "error.example.com." || top[0].Count != 1 {
		t.Fatalf("journal top = %+v, want [error.example.com. 1]", top)
	}
}

// ── Summary ──────────────────────────────────────────────────────────────────

func TestStats(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	rr := &dns.A{Hdr: dns.Header{Name: "sum.example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("4.5.6.7")}}
	mc.Set("sum.example.com.", dns.TypeA, dns.ClassINET, nil, []dns.RR{rr}, nil, nil, false, 0)
	mc.RecordRequest(&RequestRecord{Qname: "sum.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET, Protocol: "udp", Result: "hit", Rcode: dns.RcodeSuccess})

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
	mc := New(0, 0)
	defer func() { _ = mc.Close() }()

	// ── Phase 1: Insert varied DNS records ──────────────────────────────────
	a1 := &dns.A{Hdr: dns.Header{Name: "www.example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("93.184.216.34")}}
	a2 := &dns.A{Hdr: dns.Header{Name: "www.example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("93.184.216.35")}}
	aaaa := &dns.AAAA{Hdr: dns.Header{Name: "www.example.com.", Class: dns.ClassINET, TTL: 300}, AAAA: rdata.AAAA{Addr: netip.MustParseAddr("2606:2800:220:1:248:1893:25c8:1946")}}
	mc.Set("www.example.com.", dns.TypeA, dns.ClassINET, nil,
		[]dns.RR{a1, a2}, nil, []dns.RR{aaaa}, true, 0)

	a3 := &dns.A{Hdr: dns.Header{Name: "github.com.", Class: dns.ClassINET, TTL: 60}, A: rdata.A{Addr: netip.MustParseAddr("140.82.121.3")}}
	mc.Set("github.com.", dns.TypeA, dns.ClassINET, nil,
		[]dns.RR{a3}, nil, nil, false, 0)

	soa := &dns.SOA{
		Hdr: dns.Header{Name: "nonexist.example.com.", Class: dns.ClassINET, TTL: 900},
		SOA: rdata.SOA{Ns: "ns1.example.com.", Mbox: "admin.example.com.", Serial: 2025010101, Refresh: 1800, Retry: 900, Expire: 604800, Minttl: 600},
	}
	nsec := &dns.NSEC{Hdr: dns.Header{Name: "alpha.example.com.", Class: dns.ClassINET, TTL: 600}, NSEC: rdata.NSEC{NextDomain: "zulu.example.com."}}
	mc.Set("beta.example.com.", dns.TypeA, dns.ClassINET, nil,
		nil, []dns.RR{soa, nsec}, nil, false, 0)

	mc.Set("error.example.com.", dns.TypeA, dns.ClassINET, nil,
		nil, nil, nil, false, 0)
	mc.RecordRequest(&RequestRecord{
		Qname: "error.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET,
		Protocol: "tcp", Result: "error", Rcode: dns.RcodeServerFailure,
		Server: "192.0.2.1:53 (TCP)", Poisoned: true, DNSSECStatus: "bogus",
	})

	txt := &dns.TXT{Hdr: dns.Header{Name: ".", Class: dns.ClassINET, TTL: 3600}, TXT: rdata.TXT{Txt: []string{"198.41.0.4:53"}}}
	mc.Set(".", dns.TypeNone, dns.ClassINET, nil,
		[]dns.RR{txt}, nil, nil, false, 0)

	// ── Phase 2: Get + verify wire-format round-trip ────────────────────────
	entry, found, expired := mc.Get("www.example.com.", dns.TypeA, dns.ClassINET, nil)
	if err := entry.Unpack(); err != nil {
		t.Fatal(err)
	}
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
	entry, found, _ = mc.Get("beta.example.com.", dns.TypeA, dns.ClassINET, nil)
	if err := entry.Unpack(); err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("negative cache entry not found")
	}
	if entry.TTL > 600 {
		t.Errorf("negative TTL = %d, want <= 600", entry.TTL)
	}
	if len(entry.Authority) != 2 {
		t.Errorf("authority count = %d, want 2 (SOA+NSEC)", len(entry.Authority))
	}

	// ── Phase 4: Verify error record in the per-RCODE journal ──────────────
	errSnap := mc.statsMgr.Snapshot(0)
	if errSnap.Errors != 1 {
		t.Errorf("error count = %d, want 1", errSnap.Errors)
	}
	errorTop := errSnap.TopByRcode[dns.RcodeServerFailure]
	if len(errorTop) != 1 || errorTop[0].Key != "error.example.com." {
		t.Errorf("error journal top = %+v, want [error.example.com. 1]", errorTop)
	}

	// ── Phase 5: RecordRequest logs queries ────────────────────────────────
	mc.RecordRequest(&RequestRecord{Qname: "www.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET, Protocol: "udp", Result: "hit", Rcode: dns.RcodeSuccess})
	mc.RecordRequest(&RequestRecord{Qname: "www.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET, Protocol: "udp", Result: "hit", Rcode: dns.RcodeSuccess})
	mc.RecordRequest(&RequestRecord{Qname: "www.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET, Protocol: "https", Result: "hit", Rcode: dns.RcodeSuccess})
	mc.RecordRequest(&RequestRecord{Qname: "www.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET, Protocol: "quic", Result: "stale", Rcode: dns.RcodeSuccess})
	mc.RecordRequest(&RequestRecord{Qname: "github.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET, Protocol: "tcp", Result: "hit", Rcode: dns.RcodeSuccess})
	mc.RecordRequest(&RequestRecord{Qname: "github.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET, Protocol: "tcp", Result: "stale", Rcode: dns.RcodeSuccess})

	snap := mc.statsMgr.Snapshot(0)
	if snap.Hits != 4 {
		t.Errorf("hits = %d, want 4", snap.Hits)
	}
	if snap.UDP != 2 {
		t.Errorf("udp hits = %d, want 2", snap.UDP)
	}
	if snap.HTTPS != 1 {
		t.Errorf("doh hits = %d, want 1", snap.HTTPS)
	}
	// tcp covers hit + stale + error records (protocol totals span results).
	if snap.TCP != 3 {
		t.Errorf("tcp = %d, want 3", snap.TCP)
	}
	if snap.Stales != 2 {
		t.Errorf("stales = %d, want 2", snap.Stales)
	}
	top := snap.TopByRcode[dns.RcodeSuccess]
	counts := map[string]uint64{}
	for _, e := range top {
		counts[e.Key] = e.Count
	}
	if counts["www.example.com."] != 1 {
		t.Errorf("www.example.com. stale journal count = %d, want 1", counts["www.example.com."])
	}
	if counts["github.com."] != 1 {
		t.Errorf("github.com. stale journal count = %d, want 1", counts["github.com."])
	}

	// ── Phase 6: UpdateLatency (in-memory latency map) ─────────────────────
	mc.UpdateLatency("93.184.216.34", 15)
	mc.UpdateLatency("93.184.216.35", 42)
	mc.UpdateLatency("198.41.0.4", 8)

	lat34, ok34 := mc.latencies.Get("93.184.216.34")
	lat35, ok35 := mc.latencies.Get("93.184.216.35")
	if !ok34 || lat34.latency != 15 {
		t.Errorf("latency 93.184.216.34 = %+v (ok=%v), want latency 15", lat34, ok34)
	}
	if !ok35 || lat35.latency != 42 {
		t.Errorf("latency 93.184.216.35 = %+v (ok=%v), want latency 42", lat35, ok35)
	}

	// ── Phase 7: Entry overwrite (INSERT OR REPLACE) ────────────────────────
	// Re-insert; the wire format should update atomically.
	aNew := &dns.A{Hdr: dns.Header{Name: "www.example.com.", Class: dns.ClassINET, TTL: 600}, A: rdata.A{Addr: netip.MustParseAddr("93.184.216.99")}}
	mc.Set("www.example.com.", dns.TypeA, dns.ClassINET, nil,
		[]dns.RR{aNew}, nil, nil, false, 0)

	entry, found, _ = mc.Get("www.example.com.", dns.TypeA, dns.ClassINET, nil)
	if err := entry.Unpack(); err != nil {
		t.Fatal(err)
	}
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

	// ── Phase 9: RecordRequest Zone ──────────────────────────────────────
	mc.RecordRequest(&RequestRecord{Qname: "zone.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET, Protocol: "", Result: "zone", Rcode: dns.RcodeRefused})
	mc.RecordRequest(&RequestRecord{Qname: "zone.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET, Protocol: "", Result: "zone", Rcode: dns.RcodeRefused})
	mc.RecordRequest(&RequestRecord{Qname: "zone.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET, Protocol: "", Result: "zone", Rcode: dns.RcodeRefused})

	snap2 := mc.statsMgr.Snapshot(0)
	if snap2.Zones != 3 {
		t.Errorf("zone_count = %d, want 3", snap2.Zones)
	}
	zoneTop := snap2.TopByRcode[dns.RcodeRefused]
	if len(zoneTop) != 1 || zoneTop[0].Key != "zone.test." || zoneTop[0].Count != 3 {
		t.Errorf("zone journal top = %+v, want [zone.test. 3]", zoneTop)
	}

	// ── Phase 10: Summary ───────────────────────────────────────────────────
	s := mc.Stats()
	if len(s) == 0 {
		t.Error("Stats should not be empty")
	}
	for i, line := range s {
		t.Logf("Stats[%d]: %s", i, line)
	}

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
	mc.Set("www.example.com.", dns.TypeA, dns.ClassINET, nil,
		[]dns.RR{cname, a1, a2, a3}, nil, nil, false, 0)

	// Before latency data: Get() returns original order.
	entry, found, _ := mc.Get("www.example.com.", dns.TypeA, dns.ClassINET, nil)
	if err := entry.Unpack(); err != nil {
		t.Fatal(err)
	}
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

	// Re-Set to trigger Set-time latency sort with the new data.
	mc.Set("www.example.com.", dns.TypeA, dns.ClassINET, nil,
		[]dns.RR{cname, a1, a2, a3}, nil, nil, false, 0)

	// After latency data: Get() should return A records sorted fastest-first.
	entry, found, _ = mc.Get("www.example.com.", dns.TypeA, dns.ClassINET, nil)
	if err := entry.Unpack(); err != nil {
		t.Fatal(err)
	}
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
	mc := New(0, 0)
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
		mc.Set(name, dns.TypeA, dns.ClassINET, nil, answers, nil, nil, i%2 == 0, 0)
	}

	// Verify all 50 entries round-trip correctly.
	for i := range 50 {
		name := fmt.Sprintf("host-%02d.example.com.", i)
		entry, found, _ := mc.Get(name, dns.TypeA, dns.ClassINET, nil)
		if err := entry.Unpack(); err != nil {
			t.Fatal(err)
		}
		if !found {
			t.Errorf("entry %s not found", name)
			continue
		}
		if len(entry.Answer) != 3 {
			t.Errorf("%s: answer count = %d, want 3", name, len(entry.Answer))
		}
	}

	// Verify hit counters
	mc.RecordRequest(&RequestRecord{Qname: "host-00.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET, Protocol: "udp", Result: "hit", Rcode: dns.RcodeSuccess})
	mc.RecordRequest(&RequestRecord{Qname: "host-01.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET, Protocol: "tcp", Result: "hit", Rcode: dns.RcodeSuccess})

	snap := mc.statsMgr.Snapshot(0)
	if snap.Total != 2 {
		t.Errorf("total = %d, want 2", snap.Total)
	}
	if snap.UDP != 1 || snap.TCP != 1 {
		t.Errorf("udp=%d tcp=%d, want udp=1 tcp=1", snap.UDP, snap.TCP)
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

// TestSetReplacesExistingKeyWithoutCounterInflation verifies the H7 fix:
// refreshing an existing key (INSERT OR REPLACE) must not increment the
// entry counter — otherwise the counter drifts above the real row count and
// evictIfNeeded deletes valid entries prematurely.
func TestSetReplacesExistingKeyWithoutCounterInflation(t *testing.T) {
	mc := New(0, 0)
	defer func() { _ = mc.Close() }()

	a1 := &dns.A{Hdr: dns.Header{Name: "www.example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("93.184.216.34")}}
	for range 3 {
		mc.Set("www.example.com.", dns.TypeA, dns.ClassINET, nil,
			[]dns.RR{a1}, nil, nil, false, 0)
	}
	mc.Set("other.example.com.", dns.TypeA, dns.ClassINET, nil,
		[]dns.RR{a1}, nil, nil, false, 0)

	// LRU map keeps exactly the two distinct keys — no counter drift possible.
	if got := mc.entries.Len(); got != 2 {
		t.Errorf("entry count = %d after 3 refreshes of one key + 1 new key, want 2", got)
	}
}

// TestSet_Get_NXDOMAINRcode verifies RFC 1035 rcode propagation through the
// pre-packed wire: an entry stored with rcode=NXDOMAIN must serve NXDOMAIN
// on cache hits (SetReply resets rcode to NOERROR — the fix must override it).
func TestSet_Get_NXDOMAINRcode(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	soa := &dns.SOA{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 900},
		SOA: rdata.SOA{Ns: "ns1.example.com.", Mbox: "admin.example.com."},
	}
	mc.Set("nonexist.example.com.", dns.TypeA, dns.ClassINET, nil, nil, []dns.RR{soa}, nil, false, dns.RcodeNameError)

	entry, found, _ := mc.Get("nonexist.example.com.", dns.TypeA, dns.ClassINET, nil)
	if !found {
		t.Fatal("entry not found")
	}
	// The pre-packed wire header carries the rcode in bits 0-3 of byte 3.
	// (ID=0-1, flags=2-3; RCODE is the low nibble of the second flags byte.)
	if got := entry.ResponseWire[3] & 0x0F; got != dns.RcodeNameError {
		t.Errorf("wire rcode = %d, want NXDOMAIN(3)", got)
	}
}

// TestSet_Get_NOERRORRcode verifies default entries stay NOERROR.
func TestSet_Get_NOERRORRcode(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	rr := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netParseIP("192.0.2.1")}}
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, []dns.RR{rr}, nil, nil, false, 0)

	entry, found, _ := mc.Get("example.com.", dns.TypeA, dns.ClassINET, nil)
	if !found {
		t.Fatal("entry not found")
	}
	if got := entry.ResponseWire[3] & 0x0F; got != dns.RcodeSuccess {
		t.Errorf("wire rcode = %d, want NOERROR(0)", got)
	}
}

// ── GetTypes (NS A/AAAA batch) ────────────────────────────────────────────────

func TestGetTypes_AAndAAAA(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	a := &dns.A{Hdr: dns.Header{Name: "ns1.example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netParseIP("192.0.2.1")}}
	aaaa := &dns.AAAA{Hdr: dns.Header{Name: "ns1.example.com.", Class: dns.ClassINET, TTL: 300}, AAAA: rdata.AAAA{Addr: netParseIP("2001:db8::1")}}
	mc.Set("ns1.example.com.", dns.TypeA, dns.ClassINET, nil, []dns.RR{a}, nil, nil, false, 0)
	mc.Set("ns1.example.com.", dns.TypeAAAA, dns.ClassINET, nil, []dns.RR{aaaa}, nil, nil, false, 0)

	entries, found, expired := mc.GetTypes("ns1.example.com.", dns.ClassINET, [2]uint16{dns.TypeA, dns.TypeAAAA})
	if !found[0] || !found[1] {
		t.Fatalf("found = %v, want [true true]", found)
	}
	if expired[0] || expired[1] {
		t.Error("entries should not be expired immediately")
	}
	if entries[0] == nil || entries[1] == nil {
		t.Fatal("entries must be non-nil")
	}
	_ = entries[0].Unpack()
	_ = entries[1].Unpack()
	if len(entries[0].Answer) != 1 || len(entries[1].Answer) != 1 {
		t.Fatalf("answers = %d/%d, want 1/1", len(entries[0].Answer), len(entries[1].Answer))
	}
	if _, ok := entries[0].Answer[0].(*dns.A); !ok {
		t.Errorf("entries[0].Answer[0] = %T, want *dns.A", entries[0].Answer[0])
	}
	if _, ok := entries[1].Answer[0].(*dns.AAAA); !ok {
		t.Errorf("entries[1].Answer[0] = %T, want *dns.AAAA", entries[1].Answer[0])
	}
}

func TestGetTypes_Partial(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	a := &dns.A{Hdr: dns.Header{Name: "ns1.example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netParseIP("192.0.2.1")}}
	mc.Set("ns1.example.com.", dns.TypeA, dns.ClassINET, nil, []dns.RR{a}, nil, nil, false, 0)

	entries, found, _ := mc.GetTypes("ns1.example.com.", dns.ClassINET, [2]uint16{dns.TypeA, dns.TypeAAAA})
	if !found[0] || found[1] {
		t.Fatalf("found = %v, want [true false] (AAAA not stored)", found)
	}
	if entries[0] == nil || entries[1] != nil {
		t.Errorf("entries = %v, want A set / AAAA nil", entries)
	}
}

func TestGetTypes_Miss(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	_, found, _ := mc.GetTypes("nonexistent.com.", dns.ClassINET, [2]uint16{dns.TypeA, dns.TypeAAAA})
	if found[0] || found[1] {
		t.Fatalf("found = %v, want [false false]", found)
	}
}

// ── PruneQueryJournal (no-op: journal is pure memory) ────────────────────────

func TestPruneQueryJournal(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	mc.RecordRequest(&RequestRecord{Qname: "stale.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET, Protocol: "udp", Result: "miss", Rcode: dns.RcodeNameError})

	// The journal is pure memory and bounded, so pruning is a no-op that must
	// neither error nor clear the journal.
	n, err := mc.PruneQueryJournal(2 * 86400)
	if err != nil {
		t.Fatalf("PruneQueryJournal: %v", err)
	}
	if n != 0 {
		t.Errorf("deleted %d rows, want 0 (no-op)", n)
	}
	snap := mc.statsMgr.Snapshot(0)
	if top := snap.TopByRcode[dns.RcodeNameError]; len(top) != 1 || top[0].Key != "stale.com." {
		t.Errorf("journal after prune = %+v, want [stale.com. 1] (prune must not clear)", top)
	}
}

// TestPoolReturnsToIdleAfterLoad hammers the exact hot paths the recursive
// resolver exercises (cache Get/GetTypes/LatencyLastProbe + Set + stats
// RecordRequest + UpdateLatency) under concurrency.
func TestPoolReturnsToIdleAfterLoad(t *testing.T) {
	s := New(0, 0)

	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			for j := range 200 {
				qname := fmt.Sprintf("host%d.example.com.", j%997)
				s.Get(qname, dns.TypeA, dns.ClassINET, nil)
				s.GetTypes(qname, dns.ClassINET, [2]uint16{dns.TypeA, dns.TypeAAAA})
				s.LatencyLastProbe("8.8.8.8")
				s.UpdateLatency("8.8.8.8", 42)
				rr := &dns.A{
					Hdr: dns.Header{Name: qname, Class: dns.ClassINET, TTL: 60},
					A:   rdata.A{Addr: netip.MustParseAddr("192.0.2.1")},
				}
				s.Set(qname, dns.TypeA, dns.ClassINET, nil, []dns.RR{rr}, nil, nil, false, 0)
				s.RecordRequest(&RequestRecord{
					Qname: qname, Qtype: dns.TypeA, Qclass: dns.ClassINET,
					Protocol: "udp", Result: "hit", Rcode: 0,
				})
			}
		})
	}
	wg.Wait()

	// The cache is pure memory — no pool to leak.  The test still hammers the
	// hot paths concurrently; this just exercises the race detector.
	s.Flush()
	if got := s.entries.Len(); got == 0 {
		t.Error("expected entries to be populated by the load")
	}
}
