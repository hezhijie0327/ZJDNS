package cache

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"testing"
	"zjdns/config"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

func aRR(name string, ttl uint32) *dns.A {
	return &dns.A{
		Hdr: dns.Header{Name: name, Class: dns.ClassINET, TTL: ttl},
		A:   rdata.A{Addr: netip.MustParseAddr("192.0.2.1")},
	}
}

// spillCache builds a two-tier cache whose spill file lives in a temp dir.
func spillCache(t *testing.T, memLimit, diskLimit int) (c *Cache, path string) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "zjdns.cache")
	c = New(
		config.LimitSettings{Mem: memLimit, Disk: diskLimit},
		config.LimitSettings{Mem: 0, Disk: 0},
		path, "",
	)
	t.Cleanup(func() { _ = c.Close() })
	return c, path
}

func TestSpillEvictPromote(t *testing.T) {
	c, _ := spillCache(t, 2, 0)
	if c.SpillStore() == nil {
		t.Fatal("spill store not enabled")
	}

	// Fill past the mem cap: key1 survives, key0 evicts to spill.
	put := func(name string) {
		c.Set(dnsutil.Canonical(name), dns.TypeA, dns.ClassINET, nil,
			[]dns.RR{aRR(dnsutil.Canonical(name), 300)}, nil, nil, false, 0)
	}
	put("evict-me.example.com")
	put("keep.example.com")
	put("third.example.com") // evicts "evict-me" → spill

	if c.EntryCount() != 2 {
		t.Fatalf("EntryCount = %d, want 2", c.EntryCount())
	}
	if got := c.SpillStore().EntryCount(); got != 1 {
		t.Fatalf("spill EntryCount = %d, want 1", got)
	}

	// The spilled entry is served from disk and promoted back to memory.
	entry, found, expired := c.Get("evict-me.example.com.", dns.TypeA, dns.ClassINET, nil)
	if !found || expired {
		t.Fatalf("spilled entry not served: found=%t expired=%t", found, expired)
	}
	if len(entry.ResponseWire) == 0 || len(entry.TTLOffsets) == 0 {
		t.Fatalf("pre-packed wire missing: wire=%d offsets=%d", len(entry.ResponseWire), len(entry.TTLOffsets))
	}
	if c.EntryCount() != 2 {
		t.Fatalf("EntryCount after promote = %d, want 2", c.EntryCount())
	}
}

func TestSpillStaleWindow(t *testing.T) {
	c, _ := spillCache(t, 2, 0)
	putSpill := func(name string, ts int64) {
		key := buildCacheKey(name, dns.TypeA, dns.ClassINET, "", 0)
		msg := new(dns.Msg)
		dnsutil.SetQuestion(msg, name, dns.TypeA)
		msg.RecursionAvailable = true
		msg.Answer = []dns.RR{aRR(name, 300)}
		if err := msg.Pack(); err != nil {
			t.Fatal(err)
		}
		if err := c.SpillStore().Put(key, ts, 300, false, msg.Data); err != nil {
			t.Fatal(err)
		}
	}
	staleMaxAge := int64(config.DefaultStaleMaxAge)

	// Expired but within the RFC 8767 stale window → served (expired=true),
	// so the middleware can serve-stale.
	putSpill("stale.example.com.", log.NowUnix()-400)
	entry, found, expired := c.Get("stale.example.com.", dns.TypeA, dns.ClassINET, nil)
	if !found || !expired {
		t.Fatalf("within-window entry: found=%t expired=%t, want found+expired", found, expired)
	}
	if len(entry.ResponseWire) == 0 {
		t.Fatal("within-window entry wire missing")
	}

	// Past the stale window → miss, and dropped from the spill index.
	putSpill("gone.example.com.", log.NowUnix()-(300+staleMaxAge+10))
	if _, found, _ := c.Get("gone.example.com.", dns.TypeA, dns.ClassINET, nil); found {
		t.Fatal("past-window spill entry served")
	}
	if got := c.SpillStore().EntryCount(); got != 1 {
		t.Fatalf("past-window entry not dropped from spill index: %d", got)
	}
}

func TestSpillRestartWarmup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "zjdns.cache")
	c := New(config.LimitSettings{Mem: 1000, Disk: 0}, config.LimitSettings{}, path, "")

	for i := range 50 {
		name := dnsutil.Canonical(fmt.Sprintf("d%d.example.com", i))
		c.Set(name, dns.TypeA, dns.ClassINET, nil,
			[]dns.RR{aRR(name, 300)}, nil, nil, false, 0)
	}
	c.Flush() // everything to spill (this cache's mem cap is 1000 — nothing evicted yet)
	_ = c.Close()

	// Reopen with a mem cap of 10: the ten hottest (last stored) load to
	// memory; the rest stay on disk.
	c2 := New(config.LimitSettings{Mem: 10, Disk: 0}, config.LimitSettings{}, path, "")
	defer func() { _ = c2.Close() }()

	if c2.EntryCount() != 10 {
		t.Fatalf("EntryCount after warmup = %d, want 10 (mem cap)", c2.EntryCount())
	}
	hot := dnsutil.Canonical("d49.example.com")
	if _, found, _ := c2.Get(hot, dns.TypeA, dns.ClassINET, nil); !found {
		t.Fatal("hottest entry missing from memory after warmup")
	}
	cold := dnsutil.Canonical("d0.example.com")
	entry, found, _ := c2.Get(cold, dns.TypeA, dns.ClassINET, nil)
	if !found {
		t.Fatal("coldest entry not served from spill")
	}
	if len(entry.ResponseWire) == 0 {
		t.Fatal("coldest entry pre-packed wire missing")
	}
}

func TestLatencySpill(t *testing.T) {
	path := filepath.Join(t.TempDir(), "zjdns.latency")
	c := New(config.LimitSettings{}, config.LimitSettings{Mem: 1, Disk: 0}, "", path)
	defer func() { _ = c.Close() }()
	if c.LatencySpillStore() == nil {
		t.Fatal("latency spill store not enabled")
	}

	c.UpdateLatency("192.0.2.1", 25)
	c.UpdateLatency("192.0.2.2", 30) // evicts 192.0.2.1 → spill
	if got := c.LatencySpillStore().EntryCount(); got != 1 {
		t.Fatalf("latency spill EntryCount = %d, want 1", got)
	}
	if ts, ok := c.LatencyLastProbe("192.0.2.1"); !ok || ts == 0 {
		t.Fatalf("spilled latency not promoted: ts=%d ok=%t", ts, ok)
	}
}

func TestSpillFlushAndClear(t *testing.T) {
	c, _ := spillCache(t, 10, 0)

	// In-memory entries reach the spill only on Flush (shutdown).
	name := dnsutil.Canonical("flush.example.com")
	c.Set(name, dns.TypeA, dns.ClassINET, nil,
		[]dns.RR{aRR(name, 300)}, nil, nil, false, 0)
	if got := c.SpillStore().EntryCount(); got != 0 {
		t.Fatalf("spill written before flush: %d", got)
	}
	c.Flush()
	if got := c.SpillStore().EntryCount(); got != 1 {
		t.Fatalf("spill EntryCount after flush = %d, want 1", got)
	}
	// Flush again must not duplicate the record.
	c.Flush()
	if got := c.SpillStore().EntryCount(); got != 1 {
		t.Fatalf("spill EntryCount after second flush = %d, want 1 (dedup)", got)
	}

	// FlushDB("cache") wipes memory AND the spill file.
	if _, err := c.FlushDB("cache"); err != nil {
		t.Fatal(err)
	}
	if got := c.SpillStore().EntryCount(); got != 0 {
		t.Fatalf("spill not cleared by FlushDB: %d", got)
	}
	if _, found, _ := c.Get(name, dns.TypeA, dns.ClassINET, nil); found {
		t.Fatal("entry served after FlushDB")
	}
}
