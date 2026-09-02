package cache

import (
	"net/netip"
	"testing"
	"zjdns/internal/log"

	zdnsutil "zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

func init() {
	log.Default.SetLevel(log.Error)
}

// setLegacyWire replaces the stored entry with a legacy format blob
// (<= v3.11.11: zstd-compressed or raw DNS wire, no 0x02 marker), simulating
// an entry written by an older version.  The in-memory cache never produces
// this format, but buildEntry must still serve it defensively.
func setLegacyWire(t *testing.T, mc *Cache, qname string, blob []byte) {
	t.Helper()
	key := buildCacheKey(qname, dns.TypeA, dns.ClassINET, "", 0)
	mc.entries.Set(key, &cacheEntry{msgWire: blob, ts: 1, ttl: 300, validated: false})
}

// packLegacyResponse builds a packed DNS response for the given qname.
func packLegacyResponse(t *testing.T, qname string, id uint16) []byte {
	t.Helper()
	m := new(dns.Msg)
	dnsutil.SetQuestion(m, qname, dns.TypeA) // SetQuestion generates a fresh ID — set ours after
	m.ID = id
	m.Response = true
	m.RecursionAvailable = true
	m.Answer = []dns.RR{&dns.A{
		Hdr:  dns.Header{Name: qname, Class: dns.ClassINET, TTL: 300},
		Addr: netip.MustParseAddr("192.0.2.1"),
	}}
	if err := m.Pack(); err != nil {
		t.Fatalf("pack legacy response: %v", err)
	}
	return m.Data
}

// TestGet_LegacyBLOBRejected: the pre-packed format (0x02 + masked
// num_offsets) is the ONLY live format — bare raw/zstd wires from old
// versions (no compatibility kept, per policy) must be treated as corrupt
// rows: a clean miss, never a panic or a garbled serve.  This covers the
// ID-collision and zstd-header-misparse cases that motivated the old
// discriminator logic.
func TestGet_LegacyBLOBRejected(t *testing.T) {
	for _, tc := range []struct {
		name string
		id   uint16
		zstd bool
	}{
		{"raw", 0x1234, false},
		{"marker collision", 0x0201, false},
		{"zero id low byte", 0x0200, false},
		{"zstd", 0x5a5a, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mc := testStore()
			defer func() { _ = mc.Close() }()

			qname := "legacy-" + tc.name + ".example.com."
			mc.Set(qname, dns.TypeA, dns.ClassINET, nil,
				[]dns.RR{&dns.A{Hdr: dns.Header{Name: qname, Class: dns.ClassINET, TTL: 300}, Addr: netip.MustParseAddr("192.0.2.1")}}, nil, nil, false, 0)

			wire := packLegacyResponse(t, qname, tc.id)
			if tc.zstd {
				wire = zdnsutil.Compress(wire)
			}
			setLegacyWire(t, mc, qname, wire)

			entry, found, _ := mc.Get(qname, dns.TypeA, dns.ClassINET, nil)
			if found || entry != nil {
				t.Fatal("Get must miss on legacy (non-0x02) BLOBs — no compatibility is kept")
			}
		})
	}
}

// TestGet_CorruptOffsetTable: a pre-packed-marker row whose offset count
// overflows the BLOB must return a miss — not a slice-bounds panic.
func TestGet_CorruptOffsetTable(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	qname := "corrupt.example.com."
	mc.Set(qname, dns.TypeA, dns.ClassINET, nil,
		[]dns.RR{&dns.A{Hdr: dns.Header{Name: qname, Class: dns.ClassINET, TTL: 300}, Addr: netip.MustParseAddr("192.0.2.1")}}, nil, nil, false, 0)

	// 0x02 marker + numOffsets=0x00FF (255, high byte 0 passes the marker
	// discriminator) far beyond the 5-byte BLOB — the bounds check must
	// reject it instead of panicking on the offset loop.
	setLegacyWire(t, mc, qname, []byte{cacheFormatPrePacked, 0x00, 0xFF, 0x00, 0x01})

	entry, found, _ := mc.Get(qname, dns.TypeA, dns.ClassINET, nil)
	if found || entry != nil {
		t.Fatal("Get should miss on a corrupt offset table, not panic or serve")
	}
}

// TestGet_PrePacked_StillWorks guards the normal path: the marker check must
// not break fresh pre-packed entries (numOffsets high byte is 0 for any
// realistic RR count).
func TestGet_PrePacked_StillWorks(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	qname := "prepacked.example.com."
	mc.Set(qname, dns.TypeA, dns.ClassINET, nil,
		[]dns.RR{&dns.A{Hdr: dns.Header{Name: qname, Class: dns.ClassINET, TTL: 300}, Addr: netip.MustParseAddr("192.0.2.1")}}, nil, nil, false, 0)

	entry, found, _ := mc.Get(qname, dns.TypeA, dns.ClassINET, nil)
	if !found {
		t.Fatal("Get returned not found for pre-packed entry")
	}
	if len(entry.TTLOffsets) < 1 {
		t.Fatalf("pre-packed entry TTLOffsets = %d, want at least 1", len(entry.TTLOffsets))
	}
	if len(entry.ResponseWire) == 0 {
		t.Fatal("pre-packed entry ResponseWire is empty")
	}
}
