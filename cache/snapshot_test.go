package cache

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"zjdns/config"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

func testARec(ip string) *dns.A {
	return &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr(ip)}}
}

func TestSnapshotRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.snap")

	c1 := New(0, 0)
	rr := testARec("192.0.2.1")
	c1.Set("example.com.", dns.TypeA, dns.ClassINET, nil, []dns.RR{rr}, nil, nil, true, 0)
	ecs := &config.ECSOption{Family: 1, SourcePrefix: 24, ScopePrefix: 0, Address: netip.MustParseAddr("192.0.2.0").AsSlice()}
	c1.Set("ecs.example.com.", dns.TypeA, dns.ClassINET, ecs, []dns.RR{rr}, nil, nil, false, 0)
	if err := c1.SaveSnapshot(path); err != nil {
		t.Fatalf("SaveSnapshot: %v", err)
	}

	c2 := New(0, 0)
	if err := c2.LoadSnapshot(path); err != nil {
		t.Fatalf("LoadSnapshot: %v", err)
	}

	entry, found, expired := c2.Get("example.com.", dns.TypeA, dns.ClassINET, nil)
	if !found || expired || entry == nil {
		t.Fatal("example.com entry not restored")
	}
	if !entry.Validated {
		t.Error("validated flag not restored")
	}
	ecsEntry, found, _ := c2.Get("ecs.example.com.", dns.TypeA, dns.ClassINET, ecs)
	if !found || ecsEntry == nil {
		t.Error("ECS-scoped entry not restored")
	}
}

func TestSnapshotMissingFile(t *testing.T) {
	c := New(0, 0)
	if err := c.LoadSnapshot(filepath.Join(t.TempDir(), "nonexistent.snap")); err != nil {
		t.Fatalf("LoadSnapshot missing: %v", err)
	}
}

func TestSnapshotCorrupt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corrupt.snap")
	if err := writeAll(path, []byte("garbage")); err != nil {
		t.Fatal(err)
	}
	c := New(0, 0)
	if err := c.LoadSnapshot(path); err != nil {
		t.Fatalf("LoadSnapshot corrupt: %v", err)
	}
	if c.entries.Len() != 0 {
		t.Error("corrupt snapshot must not load entries")
	}
}

func writeAll(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600) //nolint:gosec // G306: test file
}
