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

	identity := make([]byte, 96)
	mc.SetDNSCrypt(identity, []Window{
		{Serial: 7, NotBefore: 100, NotAfter: 200, ResolverSK: make([]byte, 32), ResolverPK: make([]byte, 32)},
	})
	if err := mc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
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

	dc, ok := mc2.DNSCryptState()
	if !ok {
		t.Fatal("dnscrypt state not persisted")
	}
	if len(dc.Identity) != 96 || len(dc.Windows) != 1 || dc.Windows[0].Serial != 7 {
		t.Errorf("dnscrypt state mismatch: identity=%d windows=%d serial=%d", len(dc.Identity), len(dc.Windows), dc.Windows[0].Serial)
	}
}

func TestPersist_ExpiredFiltered(t *testing.T) {
	file := filepath.Join(t.TempDir(), "state.zst")

	mc := New(0, file)
	mc.Set("example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{aRR("example.com.", "192.0.2.1")}, nil, nil, false, dns.RcodeSuccess)
	// Force the entry past its hard removal deadline.
	e := mc.lookup(entryKey{qname: "example.com.", qtype: dns.TypeA, qclass: dns.ClassINET})
	if e == nil {
		t.Fatal("entry not found before expiry tweak")
	}
	e.expiresAt = log.NowUnix() - 1
	if err := mc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	f, err := Load(file)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(f.Entries) != 0 {
		t.Errorf("expired entry persisted: %d entries", len(f.Entries))
	}
}

func TestPersist_ECSAndDNSSECScoping(t *testing.T) {
	file := filepath.Join(t.TempDir(), "state.zst")

	mc := New(0, file)
	mc.Set("ecs.com.", dns.TypeA, dns.ClassINET, ecsOption("198.51.100.0", 24), true,
		[]dns.RR{aRR("ecs.com.", "198.51.100.1")}, nil, nil, true, dns.RcodeSuccess)
	if err := mc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
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

func TestPersist_PTRIndexRebuilt(t *testing.T) {
	file := filepath.Join(t.TempDir(), "state.zst")

	mc := New(0, file)
	mc.Set("www.example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{aRR("www.example.com.", "192.0.2.55")}, nil, nil, false, dns.RcodeSuccess)
	if err := mc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	mc2 := New(0, file)
	defer func() { _ = mc2.Close() }()

	results := mc2.ReverseLookup("192.0.2.55")
	if len(results) != 1 {
		t.Fatalf("reverse lookup after reload: %d results, want 1", len(results))
	}
	if results[0].Name != "www.example.com." {
		t.Errorf("name = %q, want www.example.com.", results[0].Name)
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
	mc.mu.Lock()
	total := 0
	for _, recs := range mc.ptrIndex {
		total += len(recs)
	}
	mc.mu.Unlock()
	if total != mc.Len() {
		t.Errorf("ptr records (%d) != cache entries (%d) — eviction leak", total, mc.Len())
	}
}
