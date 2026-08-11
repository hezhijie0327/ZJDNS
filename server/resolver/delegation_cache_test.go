package resolver

import (
	"path/filepath"
	"strings"
	"testing"
	"zjdns/config"
	"zjdns/internal/lrumap"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// ── Unit tests ───────────────────────────────────────────────────────────────

func TestAncestorZones(t *testing.T) {
	tests := []struct {
		qname string
		want  []string
	}{
		{"www.baidu.com.", []string{"www.baidu.com.", "baidu.com.", "com."}},
		{"baidu.com.", []string{"baidu.com.", "com."}},
		{"com.", []string{"com."}},
		{".", nil},
		{"a.b.c.example.com.", []string{"a.b.c.example.com.", "b.c.example.com.", "c.example.com.", "example.com.", "com."}},
	}

	for _, tt := range tests {
		got := ancestorZones(tt.qname)
		if len(got) != len(tt.want) {
			t.Errorf("ancestorZones(%q) = %v, want %v", tt.qname, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("ancestorZones(%q)[%d] = %q, want %q", tt.qname, i, got[i], tt.want[i])
			}
		}
	}
}

func TestParentSideType(t *testing.T) {
	parentSide := []uint16{dns.TypeDS, dns.TypeNSEC, dns.TypeNSEC3}
	childSide := []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeNS, dns.TypeDNSKEY, dns.TypeCDS, dns.TypeSOA, dns.TypeMX}

	for _, qt := range parentSide {
		if !parentSideType(qt) {
			t.Errorf("parentSideType(%s) = false, want true", dns.TypeToString[qt])
		}
	}
	for _, qt := range childSide {
		if parentSideType(qt) {
			t.Errorf("parentSideType(%s) = true, want false", dns.TypeToString[qt])
		}
	}
}

func TestMinDelegationTTL(t *testing.T) {
	makeNS := func(name string, ttl uint32) *dns.NS {
		return &dns.NS{Hdr: dns.Header{Name: name, Class: dns.ClassINET, TTL: ttl}, NS: rdata.NS{Ns: "ns1." + name}}
	}
	makeDS := func(name string, ttl uint32) *dns.DS {
		return &dns.DS{Hdr: dns.Header{Name: name, Class: dns.ClassINET, TTL: ttl}, DS: rdata.DS{KeyTag: 12345, Algorithm: dns.ECDSAP256SHA256, DigestType: dns.SHA256, Digest: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"}}
	}

	t.Run("min across NS and DS", func(t *testing.T) {
		ttl := minDelegationTTL(
			[]*dns.NS{makeNS("example.com.", 3600)},
			[]*dns.DS{makeDS("example.com.", 1800)},
		)
		if ttl != 1800 {
			t.Errorf("minDelegationTTL = %d, want 1800", ttl)
		}
	})

	t.Run("floor at DefaultTTL", func(t *testing.T) {
		ttl := minDelegationTTL(
			[]*dns.NS{makeNS("example.com.", 2)},
			nil,
		)
		if ttl != config.DefaultTTL {
			t.Errorf("minDelegationTTL = %d, want %d (DefaultTTL)", ttl, config.DefaultTTL)
		}
	})

	t.Run("cap at DefaultMaxCacheableTTL", func(t *testing.T) {
		ttl := minDelegationTTL(
			[]*dns.NS{makeNS("example.com.", uint32(config.DefaultMaxCacheableTTL+10000))},
			nil,
		)
		if ttl != config.DefaultMaxCacheableTTL {
			t.Errorf("minDelegationTTL = %d, want %d (DefaultMaxCacheableTTL)", ttl, config.DefaultMaxCacheableTTL)
		}
	})

	t.Run("empty records returns DefaultMaxCacheableTTL", func(t *testing.T) {
		ttl := minDelegationTTL(nil, nil)
		if ttl != config.DefaultMaxCacheableTTL {
			t.Errorf("minDelegationTTL with no records = %d, want %d", ttl, config.DefaultMaxCacheableTTL)
		}
	})
}

func TestPackUnpackDS(t *testing.T) {
	ds1 := &dns.DS{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 3600}, DS: rdata.DS{KeyTag: 12345, Algorithm: dns.ECDSAP256SHA256, DigestType: dns.SHA256, Digest: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}
	ds2 := &dns.DS{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 3600}, DS: rdata.DS{KeyTag: 54321, Algorithm: dns.ECDSAP256SHA256, DigestType: dns.SHA256, Digest: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"}}

	t.Run("round-trip", func(t *testing.T) {
		wire := packDS([]*dns.DS{ds1, ds2})
		if len(wire) == 0 {
			t.Fatal("packDS returned empty")
		}
		result := unpackDS(wire)
		if len(result) != 2 {
			t.Fatalf("unpackDS returned %d DS records, want 2", len(result))
		}
		for i, d := range result {
			want := ds1
			if i == 1 {
				want = ds2
			}
			if d.KeyTag != want.KeyTag {
				t.Errorf("DS[%d].KeyTag = %d, want %d", i, d.KeyTag, want.KeyTag)
			}
		}
	})

	t.Run("empty input", func(t *testing.T) {
		if wire := packDS(nil); wire != nil {
			t.Error("packDS(nil) should return nil")
		}
		if result := unpackDS(nil); result != nil {
			t.Error("unpackDS(nil) should return nil")
		}
		if result := unpackDS([]byte{}); result != nil {
			t.Error("unpackDS(empty) should return nil")
		}
	})
}

func TestNSNamesFrom(t *testing.T) {
	ns := []*dns.NS{
		{Hdr: dns.Header{Name: "baidu.com.", Class: dns.ClassINET, TTL: 3600}, NS: rdata.NS{Ns: "ns1.baidu.com."}},
		{Hdr: dns.Header{Name: "baidu.com.", Class: dns.ClassINET, TTL: 3600}, NS: rdata.NS{Ns: "ns2.BAIDU.com."}}, // mixed case
		{Hdr: dns.Header{Name: "baidu.com.", Class: dns.ClassINET, TTL: 3600}, NS: rdata.NS{Ns: ""}},               // empty Ns
	}

	names := nsNamesFrom(ns)
	if len(names) != 2 {
		t.Fatalf("nsNamesFrom returned %d names, want 2", len(names))
	}
	if names[0] != "ns1.baidu.com." {
		t.Errorf("names[0] = %q, want ns1.baidu.com.", names[0])
	}
	if names[1] != "ns2.baidu.com." { // canonicalized
		t.Errorf("names[1] = %q, want ns2.baidu.com. (canonical)", names[1])
	}
}

// ── Store / Lookup round-trip (in-memory delegation cache) ────────────────

func TestStoreAndLookupDelegation(t *testing.T) {
	r := &Recursive{resolver: &Resolver{}, delegations: lrumap.New[string, *delegationEntry](10000)}

	nsRecords := []*dns.NS{
		{Hdr: dns.Header{Name: "baidu.com.", Class: dns.ClassINET, TTL: 3600}, NS: rdata.NS{Ns: "ns1.baidu.com."}},
		{Hdr: dns.Header{Name: "baidu.com.", Class: dns.ClassINET, TTL: 3600}, NS: rdata.NS{Ns: "ns2.baidu.com."}},
	}
	dsRecords := []*dns.DS{
		{Hdr: dns.Header{Name: "baidu.com.", Class: dns.ClassINET, TTL: 1800}, DS: rdata.DS{KeyTag: 11111, Algorithm: dns.ECDSAP256SHA256, DigestType: dns.SHA256, Digest: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"}},
	}
	addrs := []string{"1.2.3.4:53", "5.6.7.8:53"}
	chain := &dnssecChain{childDS: dsRecords}

	r.storeDelegation("baidu.com.", "com.", nsRecords, addrs, chain, 0)

	// Lookup should find it
	record, ok := r.lookupDelegation("www.baidu.com.", dns.TypeA)
	if !ok {
		t.Fatal("lookupDelegation should find the stored delegation")
	}
	if record.zone != "baidu.com." {
		t.Errorf("zone = %q, want baidu.com.", record.zone)
	}
	if len(record.nsNames) != 2 {
		t.Errorf("nsNames count = %d, want 2", len(record.nsNames))
	}
	if len(record.addrs) != 2 {
		t.Errorf("addrs count = %d, want 2", len(record.addrs))
	}
	if len(record.ds) != 1 {
		t.Errorf("ds count = %d, want 1", len(record.ds))
	}

	// Lookup with qname exactly at the zone (non-parent-side type)
	_, ok = r.lookupDelegation("baidu.com.", dns.TypeA)
	if !ok {
		t.Error("lookupDelegation for zone=A type=A should find self")
	}

	// Lookup with root qname
	_, ok = r.lookupDelegation(".", dns.TypeA)
	if ok {
		t.Error("lookupDelegation for root should return nothing")
	}
}

func TestLookupDelegationParentSideType(t *testing.T) {
	r := &Recursive{resolver: &Resolver{}, delegations: lrumap.New[string, *delegationEntry](10000)}

	nsRecords := []*dns.NS{
		{Hdr: dns.Header{Name: "baidu.com.", Class: dns.ClassINET, TTL: 3600}, NS: rdata.NS{Ns: "ns1.baidu.com."}},
	}
	chain := &dnssecChain{} // insecure delegation
	r.storeDelegation("baidu.com.", "com.", nsRecords, []string{"1.2.3.4:53"}, chain, 0)

	// DS qtype at zone boundary should skip the cached zone
	_, ok := r.lookupDelegation("baidu.com.", dns.TypeDS)
	if ok {
		t.Error("lookupDelegation for zone=baidu.com. type=DS should skip the cached zone (parent-side)")
	}

	// DS qtype at a subdomain should still work (deepest match is baidu.com.)
	record, ok := r.lookupDelegation("www.baidu.com.", dns.TypeDS)
	if !ok {
		t.Error("lookupDelegation for www.baidu.com. type=DS should find baidu.com. delegation")
	}
	if record.zone != "baidu.com." {
		t.Errorf("zone = %q, want baidu.com.", record.zone)
	}
}

func TestStoreDelegationSkipsUnverifiable(t *testing.T) {
	r := &Recursive{resolver: &Resolver{}, delegations: lrumap.New[string, *delegationEntry](10000)}

	nsRecords := []*dns.NS{
		{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 3600}, NS: rdata.NS{Ns: "ns1.example.com."}},
	}
	chain := &dnssecChain{dsPresentButUnverified: true}
	r.storeDelegation("example.com.", "com.", nsRecords, []string{"1.2.3.4:53"}, chain, 0)

	_, ok := r.lookupDelegation("www.example.com.", dns.TypeA)
	if ok {
		t.Error("unverifiable delegation should not be stored")
	}
}

func TestStoreDelegationSkipsEmptyNS(t *testing.T) {
	r := &Recursive{resolver: &Resolver{}, delegations: lrumap.New[string, *delegationEntry](10000)}
	// No NS records — nothing to store, must not panic.
	r.storeDelegation("example.com.", "com.", nil, nil, &dnssecChain{}, 0)
	if r.delegations.Len() != 0 {
		t.Error("delegation with no NS records should not be stored")
	}
}

func TestAncestorZonesMaxLimit(t *testing.T) {
	// Build a very long qname and verify ancestorZones respects the limit
	labels := make([]string, 20)
	for i := range labels {
		labels[i] = "a"
	}
	qname := strings.Join(labels, ".") + "."
	zones := ancestorZones(qname)
	if len(zones) > config.DefaultDelegationLookupZones {
		t.Errorf("ancestorZones returned %d zones, want at most %d", len(zones), config.DefaultDelegationLookupZones)
	}
	// Verify order: deepest first
	for i := 1; i < len(zones); i++ {
		if !strings.HasSuffix(zones[i-1], "."+zones[i]) && zones[i-1] != zones[i] {
			prevCanon := dnsutil.Canonical(zones[i-1])
			currCanon := dnsutil.Canonical(zones[i])
			if !strings.HasSuffix(prevCanon, "."+currCanon) && prevCanon != currCanon {
				t.Errorf("ancestorZones order: %q is not a suffix of %q", zones[i], zones[i-1])
			}
		}
	}
}

// TestDelegationSpillRoundTrip verifies the delegation cache persists
// through the spill file — including NS names, addresses and DS records —
// and is restored with the freshest entries on reopen.
func TestDelegationSpillRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "delegation.snap")

	r1 := &Recursive{resolver: &Resolver{}, delegations: lrumap.New[string, *delegationEntry](100)}
	nsRecords := []*dns.NS{
		{Hdr: dns.Header{Name: "baidu.com.", Class: dns.ClassINET, TTL: 3600}, NS: rdata.NS{Ns: "ns1.baidu.com."}},
	}
	dsRecords := []*dns.DS{
		{Hdr: dns.Header{Name: "baidu.com.", Class: dns.ClassINET, TTL: 1800}, DS: rdata.DS{KeyTag: 11111, Algorithm: dns.ECDSAP256SHA256, DigestType: dns.SHA256, Digest: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"}},
	}
	chain := &dnssecChain{childDS: dsRecords}
	r1.storeDelegation("baidu.com.", "com.", nsRecords, []string{"1.2.3.4:53"}, chain, 0)
	r1.loadDelegationSpill(path, 0, 100) // enables the spill tier
	r1.flushDelegationSpill()            // memory → spill

	r2 := &Recursive{resolver: &Resolver{}, delegations: lrumap.New[string, *delegationEntry](100)}
	r2.loadDelegationSpill(path, 0, 100)
	rec, ok := r2.lookupDelegation("www.baidu.com.", dns.TypeA)
	if !ok {
		t.Fatal("delegation not restored")
	}
	if len(rec.nsNames) != 1 || rec.nsNames[0] != "ns1.baidu.com." {
		t.Errorf("nsNames = %v, want [ns1.baidu.com.]", rec.nsNames)
	}
	if len(rec.addrs) != 1 || rec.addrs[0] != "1.2.3.4:53" {
		t.Errorf("addrs = %v, want [1.2.3.4:53]", rec.addrs)
	}
	if len(rec.ds) != 1 || rec.ds[0].KeyTag != 11111 {
		t.Errorf("ds = %v, want keytag 11111", rec.ds)
	}
}

// TestDelegationSpillEvictPromote verifies an evicted delegation is served
// from the spill tier and promoted back into memory.
func TestDelegationSpillEvictPromote(t *testing.T) {
	path := filepath.Join(t.TempDir(), "delegation.snap")
	r := &Recursive{resolver: &Resolver{}, delegations: lrumap.New[string, *delegationEntry](2)}
	r.loadDelegationSpill(path, 0, 2)
	if r.spill == nil {
		t.Fatal("spill tier not enabled")
	}

	nsRecords := []*dns.NS{
		{Hdr: dns.Header{Name: "baidu.com.", Class: dns.ClassINET, TTL: 3600}, NS: rdata.NS{Ns: "ns1.baidu.com."}},
	}
	chain := &dnssecChain{}
	r.storeDelegation("baidu.com.", "com.", nsRecords, []string{"1.2.3.4:53"}, chain, 0)
	r.storeDelegation("qq.com.", "com.", nsRecords, []string{"1.2.3.4:53"}, chain, 0)
	r.storeDelegation("taobao.com.", "com.", nsRecords, []string{"1.2.3.4:53"}, chain, 0) // evicts baidu.com → spill

	if got := r.spill.EntryCount(); got != 1 {
		t.Fatalf("spill EntryCount = %d, want 1", got)
	}
	rec, ok := r.lookupDelegation("www.baidu.com.", dns.TypeA)
	if !ok {
		t.Fatal("evicted delegation not served from spill")
	}
	if len(rec.nsNames) != 1 || rec.nsNames[0] != "ns1.baidu.com." {
		t.Errorf("nsNames = %v, want [ns1.baidu.com.]", rec.nsNames)
	}
	// baidu.com promoted back; the cap-2 map still holds two entries (one of
	// the other two spilled in turn).
	if r.delegations.Len() != 2 {
		t.Fatalf("delegations after promote = %d, want 2", r.delegations.Len())
	}
}

// TestCleanupDelegations verifies expired entries are physically removed.
func TestCleanupDelegations(t *testing.T) {
	r := &Recursive{resolver: &Resolver{}, delegations: lrumap.New[string, *delegationEntry](100)}
	nsRecords := []*dns.NS{
		{Hdr: dns.Header{Name: "old.com.", Class: dns.ClassINET, TTL: 1}, NS: rdata.NS{Ns: "ns1.old.com."}},
	}
	chain := &dnssecChain{}
	r.storeDelegation("old.com.", "com.", nsRecords, []string{"1.2.3.4:53"}, chain, 0)
	// Backdate the entry so it is already expired.
	if e, ok := r.delegations.Get("old.com."); ok {
		e.ts -= 3600
	}
	r.CleanupDelegations()
	if r.delegations.Len() != 0 {
		t.Error("expired delegation should be physically removed")
	}
}
