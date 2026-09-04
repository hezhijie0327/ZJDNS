package cache

import (
	"fmt"
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
	key := cacheKey{qname: qname, qtype: dns.TypeA, qclass: dns.ClassINET}
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
// not break fresh pre-packed entries.
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

// TestSet_DNSSECFlagPersisted: the has-DNSSEC BLOB flag is computed from the
// packed wire BEFORE the pooled message is returned — computing it after
// pool.Put read the zeroed struct's nil Data and the flag was never set,
// disabling the DO=0 serve gate for every cached entry (2026-09 D1).
func TestSet_DNSSECFlagPersisted(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	qname := "signed.example.com."
	answer := []dns.RR{
		&dns.A{Hdr: dns.Header{Name: qname, Class: dns.ClassINET, TTL: 300}, Addr: netip.MustParseAddr("192.0.2.1")},
		&dns.RRSIG{
			Hdr:         dns.Header{Name: qname, Class: dns.ClassINET, TTL: 300},
			TypeCovered: dns.TypeA,
			Algorithm:   dns.RSASHA256,
			KeyTag:      1234,
			SignerName:  qname,
			Signature:   "c2lnbmF0dXJl", // valid base64 — Pack rejects garbage
		},
	}
	mc.Set(qname, dns.TypeA, dns.ClassINET, nil, answer, nil, nil, false, 0)

	entry, found, _ := mc.Get(qname, dns.TypeA, dns.ClassINET, nil)
	if !found {
		t.Fatal("Get returned not found for signed entry")
	}
	if !entry.HasDNSSEC {
		t.Fatal("entry.HasDNSSEC = false — the precomputed flag was lost (computed after pool.Put)")
	}
}

// TestSet_ManyRRsRoundTrip: the offset count is a full 15-bit field — answers
// with more than 255 RRs (large DNSKEY/round-robin sets) must stay readable.
// The former reader rejected any count with a nonzero high byte, storing such
// entries permanently unreadable (2026-09 D3).
func TestSet_ManyRRsRoundTrip(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	qname := "big.example.com."
	answer := make([]dns.RR, 0, 300)
	for i := range 300 {
		answer = append(answer, &dns.A{
			Hdr:  dns.Header{Name: qname, Class: dns.ClassINET, TTL: 300},
			Addr: netip.MustParseAddr(fmt.Sprintf("192.0.2.%d", i%254+1)),
		})
	}
	mc.Set(qname, dns.TypeA, dns.ClassINET, nil, answer, nil, nil, false, 0)

	entry, found, _ := mc.Get(qname, dns.TypeA, dns.ClassINET, nil)
	if !found {
		t.Fatal("Get returned not found for a 300-RR entry — offset count >255 must be readable")
	}
	if len(entry.TTLOffsets) != 300 {
		t.Fatalf("TTLOffsets = %d, want 300", len(entry.TTLOffsets))
	}
}

// TestGet_CorruptOffsetValue: a structurally valid header whose offset VALUE
// points past the wire must degrade to a miss, never panic the serve path
// (2026-09 H-M2).
func TestGet_CorruptOffsetValue(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	qname := "corrupt-off.example.com."
	mc.Set(qname, dns.TypeA, dns.ClassINET, nil,
		[]dns.RR{&dns.A{Hdr: dns.Header{Name: qname, Class: dns.ClassINET, TTL: 300}, Addr: netip.MustParseAddr("192.0.2.1")}}, nil, nil, false, 0)

	// Overwrite the stored BLOB's first offset with 0xFFFF — inside the
	// table bound, far beyond the wire.
	key := cacheKey{qname: qname, qtype: dns.TypeA, qclass: dns.ClassINET}
	ce, ok := mc.entries.Get(key)
	if !ok {
		t.Fatal("entry missing after Set")
	}
	blob := ce.msgWire
	blob[3], blob[4] = 0xFF, 0xFF

	entry, found, _ := mc.Get(qname, dns.TypeA, dns.ClassINET, nil)
	if found || entry != nil {
		t.Fatal("Get must miss on an out-of-wire TTL offset, not panic or serve")
	}
	// Self-healing: the corrupt entry must be gone so subsequent reads do
	// not re-hit it (D8).
	if _, still := mc.entries.Get(key); still {
		t.Fatal("corrupt entry was not deleted from the LRU")
	}
}
