package cache

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"

	"zjdns/config"
	"zjdns/edns"
)

func testStore() *MemoryCache {
	return New(config.CacheSettings{Size: config.DefaultCacheSize})
}

// ── BuildCacheKey ────────────────────────────────────────────────────────────────

func TestBuildCacheKey_Basic(t *testing.T) {
	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	key := BuildCacheKey(q, nil, false)
	if key == "" {
		t.Fatal("empty key")
	}
	if key[:4] != "dns:" {
		t.Errorf("key prefix = %q, want dns:", key[:4])
	}
}

func TestBuildCacheKey_DNSSEC(t *testing.T) {
	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	keyNo := BuildCacheKey(q, nil, false)
	keyYes := BuildCacheKey(q, nil, true)
	if keyNo == keyYes {
		t.Error("DNSSEC flag should affect cache key")
	}
}

func TestBuildCacheKey_ECS(t *testing.T) {
	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	keyNo := BuildCacheKey(q, nil, false)
	keyECS := BuildCacheKey(q, &edns.ECSOption{
		Family:       1,
		SourcePrefix: 24,
		ScopePrefix:  0,
		Address:      netParseIP("192.0.2.0"),
	}, false)
	if keyNo == keyECS {
		t.Error("ECS should affect cache key")
	}
	if keyECS != "dns:example.com:1:1:ecs:192.0.2.0/24" {
		t.Errorf("ECS key = %q", keyECS)
	}
}

func TestBuildCacheKey_DifferentTypes(t *testing.T) {
	a := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	aaaa := dns.Question{Name: "example.com.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}
	if BuildCacheKey(a, nil, false) == BuildCacheKey(aaaa, nil, false) {
		t.Error("A and AAAA should have different keys")
	}
}

// ── Get / Set / SetEntry ──────────────────────────────────────────────────────────

func TestSet_Get_RoundTrip(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	rr := &dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: netParseIP("192.0.2.1")}
	key := BuildCacheKey(dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, nil, false)
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
	entry := &CacheEntry{
		Timestamp:   now,
		AccessTime:  now,
		TTL:         60,
		OriginalTTL: 60,
		Validated:   true,
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

func TestCacheEntry_IsExpired(t *testing.T) {
	past := time.Now().Add(-1 * time.Hour).Unix()
	entry := &CacheEntry{Timestamp: past, TTL: 60}
	if !entry.IsExpired() {
		t.Error("entry in the past should be expired")
	}

	future := time.Now().Unix()
	entry = &CacheEntry{Timestamp: future, TTL: 3600}
	if entry.IsExpired() {
		t.Error("entry with future timestamp should not be expired")
	}
}

func TestCacheEntry_ShouldRefresh(t *testing.T) {
	past := time.Now().Add(-2 * time.Hour).Unix()
	entry := &CacheEntry{Timestamp: past, TTL: 60, OriginalTTL: 3600}
	if !entry.ShouldRefresh() {
		t.Error("expired entry beyond OriginalTTL should refresh")
	}
}

func TestCacheEntry_CanServeExpired(t *testing.T) {
	past := time.Now().Add(-1 * time.Hour).Unix()
	entry := &CacheEntry{Timestamp: past, TTL: 300, OriginalTTL: 3600}
	if !entry.CanServeExpired(config.DefaultStaleMaxAge) {
		t.Error("entry within config.DefaultStaleMaxAge should be servable")
	}

	veryOld := time.Now().Add(-time.Duration(config.DefaultStaleMaxAge+3600) * time.Second).Unix()
	entry = &CacheEntry{Timestamp: veryOld, TTL: 60, OriginalTTL: 60}
	if entry.CanServeExpired(config.DefaultStaleMaxAge) {
		t.Error("entry older than config.DefaultStaleMaxAge should not be servable")
	}
}

func TestCacheEntry_GetRemainingTTL(t *testing.T) {
	entry := &CacheEntry{Timestamp: time.Now().Unix(), TTL: 300}
	remaining := entry.GetRemainingTTL()
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
	aRec := &dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: netParseIP("192.0.2.1")}
	rrsig := &dns.RRSIG{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
		TypeCovered: dns.TypeA, Algorithm: 8, Labels: 2, OrigTtl: 300,
		Expiration: uint32(time.Now().Add(1 * time.Hour).Unix()),
		Inception:  uint32(time.Now().Add(-1 * time.Hour).Unix()),
		KeyTag:     1234, SignerName: "example.com."}
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
	if result[0].Header().Ttl != 200 {
		t.Errorf("TTL = %d, want 200 (300 - 100 elapsed)", result[0].Header().Ttl)
	}
}

// ── Cache TTL floor ───────────────────────────────────────────────────────────────

func TestSet_ZeroTTLFloored(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	// Record with TTL=0 should be floored to config.DefaultTTL
	rr := &dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}, A: netParseIP("192.0.2.1")}
	key := BuildCacheKey(dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, nil, false)
	mc.Set(key, []dns.RR{rr}, nil, nil, false, nil)

	entry, found, _ := mc.Get(key)
	if !found {
		t.Fatal("entry not found")
	}
	if entry.TTL != config.DefaultTTL {
		t.Errorf("TTL = %d, want %d (zero TTL floored to default)", entry.TTL, config.DefaultTTL)
	}
}

// ── Helper ─────────────────────────────────────────────────────────────────────────

func netParseIP(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		return nil
	}
	return ip.To4()
}
