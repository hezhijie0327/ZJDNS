package cache

import (
	"slices"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

// parentWire strips the leftmost (original-first) label from a TLD-first
// wire-format name.
func parentWire(wire []byte) []byte {
	if len(wire) <= 1 {
		return wire
	}
	pos := 0
	labels := 0
	for pos < len(wire)-1 {
		labels++
		l := int(wire[pos])
		if l == 0 {
			break
		}
		pos += 1 + l
	}
	if labels <= 1 {
		return []byte{0}
	}
	pos = 0
	for i := 0; i < labels-1; i++ {
		l := int(wire[pos])
		pos += 1 + l
	}
	b := make([]byte, pos+1)
	copy(b, wire[:pos])
	b[pos] = 0
	return b
}

func bytesLT(a, b []byte) bool {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := range n {
		if a[i] < b[i] {
			return true
		}
		if a[i] > b[i] {
			return false
		}
	}
	return len(a) < len(b)
}

func bytesLE(a, b []byte) bool {
	return bytesLT(a, b) || slices.Equal(a, b)
}

func TestToWireName_Basic(t *testing.T) {
	w := toWireName("example.com")
	if len(w) == 0 || w[len(w)-1] != 0 {
		t.Fatal("wire name should be root-terminated")
	}
}

func TestToWireName_WireOrderCanonical(t *testing.T) {
	// Canonical DNS order: shorter names sort before longer ones,
	// labels compared right-to-left (TLD first).
	// "example.com" < "a.example.com" because com=com, example=example,
	// then "example.com" is shorter.
	a := toWireName("a.example.com")
	b := toWireName("example.com")
	if !bytesLE(b, a) {
		t.Errorf("example.com should sort BEFORE a.example.com: %x vs %x", b, a)
	}
	// b.example.com vs c.example.com: same TLD, same 2nd label, compare 3rd
	c := toWireName("b.example.com")
	d := toWireName("c.example.com")
	if !bytesLT(c, d) {
		t.Errorf("b.example.com should sort before c.example.com")
	}
	// com < yahoo.com (both share no labels, shorter wins)
	e := toWireName("com")
	f := toWireName("yahoo.com")
	if !bytesLT(e, f) {
		t.Errorf("com should sort before yahoo.com")
	}
}

func TestToWireName_Root(t *testing.T) {
	w := toWireName(".")
	if len(w) != 1 || w[0] != 0 {
		t.Errorf("root should be single zero byte, got %x", w)
	}
}

func TestParentWire(t *testing.T) {
	w := toWireName("www.example.com")
	p := parentWire(w)
	// "www.example.com" → parent should be "example.com"
	parentName := toWireName("example.com")
	if !slices.Equal(p, parentName) {
		t.Errorf("parent of www.example.com should be example.com: got %x, want %x", p, parentName)
	}

	// Parent of "com" should be root
	p2 := parentWire(toWireName("com"))
	root := toWireName(".")
	if !slices.Equal(p2, root) {
		t.Errorf("parent of com should be root")
	}
}

func TestMarshalTypeBitmap(t *testing.T) {
	types := []uint16{1, 28, 6}
	raw := marshalTypeBitmap(types)
	decoded := unmarshalTypeBitmap(raw)
	if len(decoded) != len(types) {
		t.Fatalf("round-trip length mismatch: %d vs %d", len(decoded), len(types))
	}
	for i, v := range types {
		if decoded[i] != v {
			t.Errorf("index %d: got %d, want %d", i, decoded[i], v)
		}
	}
}

func TestLookupNsecNeg_ParentZoneNotChildZone(t *testing.T) {
	// Regression test: NSEC records from edu.cn zone should NOT prove
	// non-existence of mirrors.cernet.edu.cn (a grandchild, not a direct child).
	store := testStore()
	defer func() { _ = store.Close() }()

	// Index an NSEC record for edu.cn zone: cernet.edu.cn NSEC mail.edu.cn
	soa := &dns.SOA{
		Hdr: dns.Header{Name: "edu.cn.", Class: dns.ClassINET, TTL: 300},
		SOA: rdata.SOA{
			Ns: "ns1.edu.cn.", Mbox: "hostmaster.edu.cn.",
			Serial: 1, Refresh: 3600, Retry: 900, Expire: 604800, Minttl: 86400,
		},
	}
	authority := []dns.RR{
		soa,
		&dns.NSEC{
			Hdr: dns.Header{Name: "cernet.edu.cn.", Class: dns.ClassINET, TTL: 300},
			NSEC: rdata.NSEC{
				NextDomain: "mail.edu.cn.",
				TypeBitMap: []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC},
			},
		},
	}
	store.IndexNsecRecords("nonexistent.edu.cn", dns.TypeA, dns.ClassINET, nil, true, true, authority)

	// Lookup for mirrors.cernet.edu.cn — a grandchild of edu.cn, NOT a direct child.
	// The edu.cn NSEC record covers direct children only, so LookupNsecNeg
	// must return nil (no negative cache hit).
	result := store.LookupNsecNeg("mirrors.cernet.edu.cn.", dns.TypeA)
	if result != nil {
		t.Fatalf("parent-zone NSEC should not cover grandchild: got rcode=%d", result.Rcode)
	}
}

func TestLookupNsecNeg_SameZoneChild(t *testing.T) {
	// NSEC records from cernet.edu.cn zone SHOULD prove non-existence of
	// direct children of cernet.edu.cn.
	store := testStore()
	defer func() { _ = store.Close() }()

	soa := &dns.SOA{
		Hdr: dns.Header{Name: "cernet.edu.cn.", Class: dns.ClassINET, TTL: 300},
		SOA: rdata.SOA{
			Ns: "ns1.cernet.edu.cn.", Mbox: "hostmaster.cernet.edu.cn.",
			Serial: 1, Refresh: 3600, Retry: 900, Expire: 604800, Minttl: 86400,
		},
	}
	authority := []dns.RR{
		soa,
		&dns.NSEC{
			Hdr: dns.Header{Name: "ftp.cernet.edu.cn.", Class: dns.ClassINET, TTL: 300},
			NSEC: rdata.NSEC{
				NextDomain: "www.cernet.edu.cn.",
				TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC},
			},
		},
	}
	store.IndexNsecRecords("nonexistent.cernet.edu.cn", dns.TypeA, dns.ClassINET, nil, true, true, authority)

	// mirrors.cernet.edu.cn falls between ftp and mail → should get NXDOMAIN
	result := store.LookupNsecNeg("mirrors.cernet.edu.cn.", dns.TypeA)
	if result == nil {
		t.Fatal("same-zone NSEC should cover direct child: got nil")
	}
	if result.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN, got rcode=%d", result.Rcode)
	}
}

func TestLookupNsecNeg_ZoneApexNodata(t *testing.T) {
	// NSEC record for the zone apex itself should prove NODATA.
	store := testStore()
	defer func() { _ = store.Close() }()

	soa := &dns.SOA{
		Hdr: dns.Header{Name: "cernet.edu.cn.", Class: dns.ClassINET, TTL: 300},
		SOA: rdata.SOA{
			Ns: "ns1.cernet.edu.cn.", Mbox: "hostmaster.cernet.edu.cn.",
			Serial: 1, Refresh: 3600, Retry: 900, Expire: 604800, Minttl: 86400,
		},
	}
	authority := []dns.RR{
		soa,
		&dns.NSEC{
			Hdr: dns.Header{Name: "cernet.edu.cn.", Class: dns.ClassINET, TTL: 300},
			NSEC: rdata.NSEC{
				NextDomain: "ftp.cernet.edu.cn.",
				TypeBitMap: []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC},
			},
		},
	}
	store.IndexNsecRecords("cernet.edu.cn", dns.TypeAAAA, dns.ClassINET, nil, true, true, authority)

	// Query for AAAA at zone apex — not in type bitmap → NODATA
	result := store.LookupNsecNeg("cernet.edu.cn.", dns.TypeAAAA)
	if result == nil {
		t.Fatal("NSEC zone apex should give NODATA for missing type: got nil")
	}
	if result.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NODATA (RcodeSuccess), got rcode=%d", result.Rcode)
	}
}

func TestBytesLT(t *testing.T) {
	a := []byte{3, 'c', 'o', 'm', 0}
	b := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	if !bytesLT(a, b) {
		t.Errorf("com < example.com in wire order")
	}
	if bytesLT(a, a) {
		t.Error("a < a should be false")
	}
}
