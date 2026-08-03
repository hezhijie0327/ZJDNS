package cache

import (
	"net/netip"
	"path/filepath"
	"testing"
	"zjdns/config"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

func aRR(name, ip string) *dns.A {
	return &dns.A{Hdr: dns.Header{Name: name, Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr(ip)}}
}

func ecsOption(addr string, prefix uint8) *config.ECSOption {
	return &config.ECSOption{Family: 1, SourcePrefix: prefix, ScopePrefix: 0, Address: netip.MustParseAddr(addr).AsSlice()}
}

// ── Persistence round-trip ────────────────────────────────────────────────────

func TestPersist_RoundTrip(t *testing.T) {
	file := filepath.Join(t.TempDir(), "state.zst")

	mc := New(0, file)
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{aRR("example.com.", "192.0.2.1")}, nil, nil, false, dns.RcodeSuccess)
	if err := mc.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	mc2 := New(0, file)
	defer func() { _ = mc2.Close() }()

	entry, found, _ := mc2.Get("example.com.", dns.TypeA, dns.ClassINET, nil, false)
	if !found {
		t.Fatal("cache entry not persisted")
	}
	if len(entry.Answer) != 1 {
		t.Errorf("answer count = %d, want 1", len(entry.Answer))
	}
	if entry.Validated {
		t.Error("validated = true, want false")
	}
}

func TestPersist_ExpiredFiltered(t *testing.T) {
	file := filepath.Join(t.TempDir(), "state.zst")

	mc := New(0, file)
	// Insert an entry already past its hard removal deadline — Save's Keep
	// filter must drop it (and reload would skip it even if it were written).
	mc.store.Set(entryKey{qname: "example.com.", qtype: dns.TypeA, qclass: dns.ClassINET}, cacheEntry{
		value:     []byte("wire"),
		ts:        log.NowUnix() - 1<<20,
		expiresAt: log.NowUnix() - 1,
	})
	if err := mc.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	mc2 := New(0, file)
	defer func() { _ = mc2.Close() }()
	if mc2.Len() != 0 {
		t.Errorf("expired entry persisted: %d entries", mc2.Len())
	}
}

func TestPersist_ECSAndDNSSECScoping(t *testing.T) {
	file := filepath.Join(t.TempDir(), "state.zst")

	mc := New(0, file)
	mc.Set("ecs.com.", dns.TypeA, dns.ClassINET, ecsOption("198.51.100.0", 24), true,
		[]dns.RR{aRR("ecs.com.", "198.51.100.1")}, nil, nil, true, dns.RcodeSuccess)
	if err := mc.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	mc2 := New(0, file)
	defer func() { _ = mc2.Close() }()

	// Same ECS scope + dnssecOK must hit; the no-ECS key must NOT.
	_, found, _ := mc2.Get("ecs.com.", dns.TypeA, dns.ClassINET, ecsOption("198.51.100.0", 24), true)
	if !found {
		t.Fatal("ECS-scoped entry not found after reload")
	}
	_, found, _ = mc2.Get("ecs.com.", dns.TypeA, dns.ClassINET, nil, true)
	if found {
		t.Fatal("no-ECS lookup must not match the ECS-scoped entry")
	}
}

// ── PTR index ─────────────────────────────────────────────────────────────────

func TestPersist_PTRIndexDerivedOnMissingFile(t *testing.T) {
	// Only cache.zst exists (no ptr.zst) — the index must be derived from
	// the loaded entries.
	dir := t.TempDir()
	file := filepath.Join(dir, "state.zst")

	mc := New(0, file)
	mc.Set("www.example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{aRR("www.example.com.", "192.0.2.55")}, nil, nil, false, dns.RcodeSuccess)
	if err := mc.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	mc2 := New(0, file)
	mc2.SetPtrPersist(filepath.Join(dir, "ptr.zst")) // missing file → derive
	defer func() { _ = mc2.Close() }()

	results := mc2.ReverseLookup("192.0.2.55")
	if len(results) != 1 {
		t.Fatalf("reverse lookup after reload: %d results, want 1", len(results))
	}
	if results[0].Name != "www.example.com." {
		t.Errorf("name = %q, want www.example.com.", results[0].Name)
	}
}

func TestPersist_PTRIndexRoundTrip(t *testing.T) {
	// ptr.zst persisted: the index loads directly, no derivation needed.
	dir := t.TempDir()
	ptrFile := filepath.Join(dir, "ptr.zst")

	mc := New(0, "")
	mc.SetPtrPersist(ptrFile)
	mc.Set("www.example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{aRR("www.example.com.", "192.0.2.55")}, nil, nil, false, dns.RcodeSuccess)
	if err := mc.SavePtrIndex(); err != nil {
		t.Fatalf("SavePtrIndex: %v", err)
	}

	mc2 := New(0, "")
	mc2.SetPtrPersist(ptrFile)
	defer func() { _ = mc2.Close() }()

	results := mc2.ReverseLookup("192.0.2.55")
	if len(results) != 1 {
		t.Fatalf("reverse lookup after ptr reload: %d results, want 1", len(results))
	}
	if results[0].Name != "www.example.com." {
		t.Errorf("name = %q, want www.example.com.", results[0].Name)
	}
}

func TestPersist_ClearPtrIndex(t *testing.T) {
	dir := t.TempDir()
	ptrFile := filepath.Join(dir, "ptr.zst")

	mc := New(0, "")
	mc.SetPtrPersist(ptrFile)
	mc.Set("www.example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{aRR("www.example.com.", "192.0.2.55")}, nil, nil, false, dns.RcodeSuccess)
	if err := mc.SavePtrIndex(); err != nil {
		t.Fatalf("SavePtrIndex: %v", err)
	}
	if len(mc.ReverseLookup("192.0.2.55")) != 1 {
		t.Fatal("index not populated before clear")
	}

	if err := mc.ClearPtrIndex(); err != nil {
		t.Fatalf("ClearPtrIndex: %v", err)
	}
	if len(mc.ReverseLookup("192.0.2.55")) != 0 {
		t.Error("index not cleared in memory")
	}

	// The cleared state must be persisted immediately: a fresh map loading
	// the file (with no cache entries to derive from) stays empty.
	mc2 := New(0, "")
	mc2.SetPtrPersist(ptrFile)
	defer func() { _ = mc2.Close() }()
	if len(mc2.ReverseLookup("192.0.2.55")) != 0 {
		t.Error("cleared ptr.zst not persisted (index restored on load)")
	}
}

func TestPersist_ClearLatency(t *testing.T) {
	dir := t.TempDir()
	latFile := filepath.Join(dir, "latency.zst")

	mc := New(0, "")
	mc.SetLatencyPersist(latFile)
	mc.UpdateLatency("192.0.2.1", 42)
	if err := mc.SaveLatency(); err != nil {
		t.Fatalf("SaveLatency: %v", err)
	}
	if _, ok := mc.LatencyLastProbe("192.0.2.1"); !ok {
		t.Fatal("latency not recorded before clear")
	}

	if err := mc.ClearLatency(); err != nil {
		t.Fatalf("ClearLatency: %v", err)
	}
	if _, ok := mc.LatencyLastProbe("192.0.2.1"); ok {
		t.Error("latency not cleared in memory")
	}

	mc2 := New(0, "")
	mc2.SetLatencyPersist(latFile)
	defer func() { _ = mc2.Close() }()
	if _, ok := mc2.LatencyLastProbe("192.0.2.1"); ok {
		t.Error("cleared latency.zst not persisted (latency restored on load)")
	}
}

// ── Latency ───────────────────────────────────────────────────────────────────

func TestPersist_LatencyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	latFile := filepath.Join(dir, "latency.zst")

	mc := New(0, "")
	mc.SetLatencyPersist(latFile)
	mc.UpdateLatency("192.0.2.1", 42)
	if err := mc.SaveLatency(); err != nil {
		t.Fatalf("SaveLatency: %v", err)
	}

	mc2 := New(0, "")
	mc2.SetLatencyPersist(latFile)
	defer func() { _ = mc2.Close() }()

	if lat, ok := mc2.LatencyLastProbe("192.0.2.1"); !ok || lat <= 0 {
		t.Errorf("LatencyLastProbe after reload = %d, %v; want > 0, true", lat, ok)
	}
	if got := mc2.LookupIPLatencies([]string{"192.0.2.1"})["192.0.2.1"]; got != 42 {
		t.Errorf("LookupIPLatencies after reload = %d, want 42", got)
	}
}

// ── LRU eviction ──────────────────────────────────────────────────────────────

func TestLRU_EvictionBySize(t *testing.T) {
	// Budget 300B with 10 entries of ~40-80B wire each: eviction must keep the
	// total under budget (the size invariant), and it must actually happen.
	mc := New(300, "")
	defer func() { _ = mc.Close() }()

	for i := range 10 {
		name := string(rune('a'+i)) + ".example.com."
		mc.Set(name, dns.TypeA, dns.ClassINET, nil, false, []dns.RR{aRR(name, "192.0.2.1")}, nil, nil, false, dns.RcodeSuccess)
	}
	if mc.SizeBytes() > 300 {
		t.Errorf("size = %d, exceeds 300 budget", mc.SizeBytes())
	}
	if mc.Len() == 10 {
		t.Error("no eviction happened under a 300B budget with 10 entries")
	}
}

func TestLRU_EvictCleansPTRIndex(t *testing.T) {
	mc := New(300, "")
	defer func() { _ = mc.Close() }()

	for i := range 10 {
		name := string(rune('a'+i)) + ".example.com."
		mc.Set(name, dns.TypeA, dns.ClassINET, nil, false, []dns.RR{aRR(name, "192.0.2.1")}, nil, nil, false, dns.RcodeSuccess)
	}

	// Evicted entries must have left no PTR records behind: each surviving
	// entry owns exactly one record (its A answer).
	total := 0
	mc.ptrIndex.Range(func(_ string, recs []*ptrRecord) bool {
		total += len(recs)
		return true
	})
	if total != mc.Len() {
		t.Errorf("ptr records (%d) != cache entries (%d) — eviction leak", total, mc.Len())
	}
}
