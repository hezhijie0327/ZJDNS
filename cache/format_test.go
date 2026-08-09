package cache

import (
	"bytes"
	"net/netip"
	"testing"
	"zjdns/internal/log"

	zdnsutil "zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
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
	key := buildCacheKey(qname, dns.TypeA, dns.ClassINET, "", 0, 0)
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
		Hdr: dns.Header{Name: qname, Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("192.0.2.1")},
	}}
	if err := m.Pack(); err != nil {
		t.Fatalf("pack legacy response: %v", err)
	}
	return m.Data
}

// TestGet_LegacyRawEntry: a bare (uncompressed, unmasked) DNS wire from
// <= v3.11.10 must be served without panicking — no offset table, original
// TTLs, empty TTLOffsets.
func TestGet_LegacyRawEntry(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	qname := "legacy-raw.example.com."
	mc.Set(qname, dns.TypeA, dns.ClassINET, nil, false,
		[]dns.RR{&dns.A{Hdr: dns.Header{Name: qname, Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("192.0.2.1")}}}, nil, nil, false, 0)

	wire := packLegacyResponse(t, qname, 0x1234)
	setLegacyWire(t, mc, qname, wire)

	entry, found, _ := mc.Get(qname, dns.TypeA, dns.ClassINET, nil, false)
	if !found {
		t.Fatal("Get returned not found for legacy raw entry")
	}
	if entry.TTLOffsets != nil {
		t.Errorf("legacy entry TTLOffsets = %v, want nil (no offset table)", entry.TTLOffsets)
	}
	if !bytes.Equal(entry.ResponseWire, wire) {
		t.Errorf("legacy wire mismatch: got %d bytes, want %d", len(entry.ResponseWire), len(wire))
	}
}

// TestGet_LegacyRawEntry_MarkerCollision: a legacy raw wire whose ID high
// byte is exactly 0x02 (the pre-packed marker).  The msgWire[1] (ID low
// byte) discriminator must route it to the legacy path instead of
// misparsing the offset table (previously: garbage numOffsets →
// out-of-bounds panic or corrupted wire).
func TestGet_LegacyRawEntry_MarkerCollision(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	qname := "legacy-collision.example.com."
	mc.Set(qname, dns.TypeA, dns.ClassINET, nil, false,
		[]dns.RR{&dns.A{Hdr: dns.Header{Name: qname, Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("192.0.2.1")}}}, nil, nil, false, 0)

	wire := packLegacyResponse(t, qname, 0x0201) // ID high byte = 0x02, low byte != 0
	if wire[0] != cacheFormatPrePacked {
		t.Fatalf("test setup: wire[0] = %#x, want 0x02 for the collision case", wire[0])
	}
	setLegacyWire(t, mc, qname, wire)

	entry, found, _ := mc.Get(qname, dns.TypeA, dns.ClassINET, nil, false)
	if !found {
		t.Fatal("Get returned not found for legacy marker-collision entry")
	}
	if entry.TTLOffsets != nil {
		t.Errorf("legacy entry TTLOffsets = %v, want nil", entry.TTLOffsets)
	}
	if !bytes.Equal(entry.ResponseWire, wire) {
		t.Errorf("legacy wire mismatch: got %d bytes, want %d", len(entry.ResponseWire), len(wire))
	}
}

// TestGet_LegacyRawEntry_ZeroIDLowByte: the residual collision — legacy raw
// wire with ID high byte 0x02 AND low byte 0x00 passes the marker
// discriminator, but the flags bytes read as numOffsets are always >= 0x8000
// (QR flag set), which the bounds check rejects.  The row must miss — never
// panic, never serve a corrupted wire.
func TestGet_LegacyRawEntry_ZeroIDLowByte(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	qname := "legacy-zero-idlow.example.com."
	mc.Set(qname, dns.TypeA, dns.ClassINET, nil, false,
		[]dns.RR{&dns.A{Hdr: dns.Header{Name: qname, Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("192.0.2.1")}}}, nil, nil, false, 0)

	wire := packLegacyResponse(t, qname, 0x0200) // ID = 0x0200: high byte 0x02, low byte 0x00
	setLegacyWire(t, mc, qname, wire)

	entry, found, _ := mc.Get(qname, dns.TypeA, dns.ClassINET, nil, false)
	if found || entry != nil {
		t.Fatal("Get should miss on the zero-ID-low-byte legacy entry (bounds check), not panic or serve garbage")
	}
}

// TestGet_LegacyZstdEntry: a zstd-compressed bare wire from v3.11.11 must be
// decompressed and served — previously the zstd frame header (0x28B52FFD)
// was read as a pre-packed numOffsets, driving the offset loop out of bounds.
func TestGet_LegacyZstdEntry(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	qname := "legacy-zstd.example.com."
	mc.Set(qname, dns.TypeA, dns.ClassINET, nil, false,
		[]dns.RR{&dns.A{Hdr: dns.Header{Name: qname, Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("192.0.2.1")}}}, nil, nil, false, 0)

	wire := packLegacyResponse(t, qname, 0x5a5a)
	setLegacyWire(t, mc, qname, zdnsutil.Compress(wire))

	entry, found, _ := mc.Get(qname, dns.TypeA, dns.ClassINET, nil, false)
	if !found {
		t.Fatal("Get returned not found for legacy zstd entry")
	}
	if entry.TTLOffsets != nil {
		t.Errorf("legacy entry TTLOffsets = %v, want nil", entry.TTLOffsets)
	}
	if !bytes.Equal(entry.ResponseWire, wire) {
		t.Errorf("legacy zstd wire mismatch: got %d bytes, want %d", len(entry.ResponseWire), len(wire))
	}
}

// TestGet_CorruptOffsetTable: a pre-packed-marker row whose offset count
// overflows the BLOB must return a miss — not a slice-bounds panic.
func TestGet_CorruptOffsetTable(t *testing.T) {
	mc := testStore()
	defer func() { _ = mc.Close() }()

	qname := "corrupt.example.com."
	mc.Set(qname, dns.TypeA, dns.ClassINET, nil, false,
		[]dns.RR{&dns.A{Hdr: dns.Header{Name: qname, Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("192.0.2.1")}}}, nil, nil, false, 0)

	// 0x02 marker + numOffsets=0x00FF (255, high byte 0 passes the marker
	// discriminator) far beyond the 5-byte BLOB — the bounds check must
	// reject it instead of panicking on the offset loop.
	setLegacyWire(t, mc, qname, []byte{cacheFormatPrePacked, 0x00, 0xFF, 0x00, 0x01})

	entry, found, _ := mc.Get(qname, dns.TypeA, dns.ClassINET, nil, false)
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
	mc.Set(qname, dns.TypeA, dns.ClassINET, nil, false,
		[]dns.RR{&dns.A{Hdr: dns.Header{Name: qname, Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("192.0.2.1")}}}, nil, nil, false, 0)

	entry, found, _ := mc.Get(qname, dns.TypeA, dns.ClassINET, nil, false)
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
