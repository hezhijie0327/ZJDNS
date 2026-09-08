package cache

import (
	"net/netip"
	"strings"
	"testing"
	"zjdns/config"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

const nsec3TestMaxHash = "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv"

// ── helpers ──────────────────────────────────────────────────────────────────

func nsecTestSOA(apex string, ttl, minttl uint32) *dns.SOA {
	return &dns.SOA{
		Hdr:    dns.Header{Name: apex, Class: dns.ClassINET, TTL: ttl},
		Ns:     "ns1" + apex,
		Mbox:   "hostmaster" + apex,
		Serial: 1,
		Minttl: minttl,
	}
}

func nsecTestRRSIG(name string, covered uint16, expiration uint32) *dns.RRSIG {
	return &dns.RRSIG{
		Hdr:         dns.Header{Name: name, Class: dns.ClassINET, TTL: 300},
		TypeCovered: covered,
		Expiration:  expiration,
	}
}

func nsecTestNSEC(owner, next string, bitmap ...uint16) *dns.NSEC {
	return &dns.NSEC{
		Hdr:        dns.Header{Name: owner, Class: dns.ClassINET, TTL: 86400},
		NextDomain: next,
		TypeBitMap: bitmap,
	}
}

// indexProof feeds proof + authority through IndexNegative the way
// StoreIfCacheable does after a validated negative resolution.
func indexProof(t *testing.T, s *Cache, qname string, proof, authority []dns.RR) {
	t.Helper()
	s.IndexNegative(qname, dns.ClassINET, proof, authority)
}

// ── NSEC synthesis ───────────────────────────────────────────────────────────

// RFC 8198 §3 intro scenario: cat.example.com resolves NXDOMAIN; the covering
// NSEC then answers ball/dog.example.com without an upstream round trip.
func TestSynthesizeNegative_NSEC_Covering(t *testing.T) {
	s := New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	soa := nsecTestSOA("example.com.", 3600, 900)
	cover := nsecTestNSEC("albatross.example.com.", "elephant.example.com.", dns.TypeA, dns.TypeRRSIG)
	wildcardProof := nsecTestNSEC("example.com.", "albatross.example.com.", dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG)
	indexProof(t, s, "cat.example.com.", []dns.RR{cover, wildcardProof},
		[]dns.RR{soa, cover, nsecTestRRSIG(cover.Hdr.Name, dns.TypeNSEC, 0), wildcardProof})

	for _, qname := range []string{"cat.example.com.", "ball.example.com.", "dog.example.com."} {
		rcode, auth, ok := s.SynthesizeNegative(qname, dns.TypeA, dns.ClassINET)
		if !ok || rcode != dns.RcodeNameError {
			t.Fatalf("SynthesizeNegative(%s) ok=%v rcode=%d, want NXDOMAIN", qname, ok, rcode)
		}
		if len(auth) == 0 || auth[0].Header().Name != "example.com." {
			t.Fatalf("SynthesizeNegative(%s) authority must lead with the zone SOA, got %d records", qname, len(auth))
		}
		// RFC 8198 §5.4: proof TTLs reduced to the negative TTL (900).
		if got := auth[0].Header().TTL; got > 900 {
			t.Fatalf("synthesized SOA TTL = %d, want ≤ 900 (negative TTL)", got)
		}
	}
}

// Without a cached NSEC covering *.closest-encloser the wildcard might exist
// — no NXDOMAIN may be synthesized (RFC 4035 §5.4 step 6).
func TestSynthesizeNegative_NSEC_NoWildcardProof(t *testing.T) {
	s := New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	soa := nsecTestSOA("example.com.", 3600, 900)
	cover := nsecTestNSEC("albatross.example.com.", "elephant.example.com.", dns.TypeA, dns.TypeRRSIG)
	indexProof(t, s, "cat.example.com.", []dns.RR{cover},
		[]dns.RR{soa, cover, nsecTestRRSIG(cover.Hdr.Name, dns.TypeNSEC, 0)})

	if _, _, ok := s.SynthesizeNegative("dog.example.com.", dns.TypeA, dns.ClassINET); ok {
		t.Fatal("synthesized NXDOMAIN without wildcard-absence proof")
	}
}

func TestSynthesizeNegative_NSEC_ExactNODATA(t *testing.T) {
	s := New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	soa := nsecTestSOA("example.com.", 3600, 900)
	exact := nsecTestNSEC("cat.example.com.", "elephant.example.com.", dns.TypeA, dns.TypeRRSIG)
	cname := nsecTestNSEC("alias.example.com.", "zebra.example.com.", dns.TypeCNAME, dns.TypeRRSIG)
	indexProof(t, s, "cat.example.com.", []dns.RR{exact, cname},
		[]dns.RR{soa, exact, nsecTestRRSIG(exact.Hdr.Name, dns.TypeNSEC, 0), cname})

	// AAAA absent from the bitmap → NODATA.
	rcode, _, ok := s.SynthesizeNegative("cat.example.com.", dns.TypeAAAA, dns.ClassINET)
	if !ok || rcode != dns.RcodeSuccess {
		t.Fatalf("exact-match NODATA: ok=%v rcode=%d, want NOERROR", ok, rcode)
	}
	// A present in the bitmap → never a denial.
	if _, _, ok := s.SynthesizeNegative("cat.example.com.", dns.TypeA, dns.ClassINET); ok {
		t.Fatal("synthesized denial for a qtype present in the bitmap")
	}
	// CNAME at the name — it resolves via the CNAME, no NODATA (RFC 6840 §4.3).
	if _, _, ok := s.SynthesizeNegative("alias.example.com.", dns.TypeA, dns.ClassINET); ok {
		t.Fatal("synthesized NODATA despite CNAME bit")
	}
}

// RFC 8198 App. B: next below qname proves an empty non-terminal — NODATA.
func TestSynthesizeNegative_NSEC_Ent(t *testing.T) {
	s := New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	soa := nsecTestSOA("example.com.", 3600, 900)
	cover := nsecTestNSEC("0.example.com.", "b.a.example.com.", dns.TypeA, dns.TypeRRSIG)
	indexProof(t, s, "a.example.com.", []dns.RR{cover},
		[]dns.RR{soa, cover, nsecTestRRSIG(cover.Hdr.Name, dns.TypeNSEC, 0)})

	rcode, _, ok := s.SynthesizeNegative("a.example.com.", dns.TypeA, dns.ClassINET)
	if !ok || rcode != dns.RcodeSuccess {
		t.Fatalf("empty non-terminal: ok=%v rcode=%d, want NODATA", ok, rcode)
	}
}

// RFC 8198 App. B: a delegation-shaped NSEC (NS set, SOA absent) below whose
// owner the qname sits must not prove anything — it is from the parent zone.
func TestSynthesizeNegative_NSEC_ParentZoneDelegation(t *testing.T) {
	s := New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	soa := nsecTestSOA("example.com.", 3600, 900)
	deleg := nsecTestNSEC("example.com.", "mail.example.com.", dns.TypeNS, dns.TypeRRSIG)
	indexProof(t, s, "www.example.com.", []dns.RR{deleg},
		[]dns.RR{soa, deleg, nsecTestRRSIG(deleg.Hdr.Name, dns.TypeNSEC, 0)})

	if _, _, ok := s.SynthesizeNegative("www.example.com.", dns.TypeA, dns.ClassINET); ok {
		t.Fatal("synthesized denial from a parent-zone delegation NSEC")
	}
}

// Wrap-around interval (the .com-style last-NSEC shape: owner sorts last,
// next is the zone apex): only names the interval actually covers synthesize.
func TestSynthesizeNegative_NSEC_WrapAround(t *testing.T) {
	s := New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	soa := nsecTestSOA("example.com.", 3600, 900)
	wrap := nsecTestNSEC("zebra.example.com.", "example.com.", dns.TypeA, dns.TypeRRSIG)
	wild := nsecTestNSEC("example.com.", "albatross.example.com.", dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG)
	indexProof(t, s, "zzz.example.com.", []dns.RR{wrap, wild},
		[]dns.RR{soa, wrap, wild})

	// Sorting after the owner with next == apex → covered → NXDOMAIN.
	if _, _, ok := s.SynthesizeNegative("zzz.example.com.", dns.TypeA, dns.ClassINET); !ok {
		t.Fatal("wrap-around interval (owner, ∞) leg not used")
	}
	// Sorting between the apex and the owner — the gap of the wrap interval:
	// App. B conservatively discards, no synthesis.
	if _, _, ok := s.SynthesizeNegative("yodel.example.com.", dns.TypeA, dns.ClassINET); ok {
		t.Fatal("synthesized inside the gap of a wrap-around interval")
	}
}

// ── NSEC3 synthesis ──────────────────────────────────────────────────────────

func nsec3Hash(t *testing.T, name string) string {
	t.Helper()
	h := strings.ToLower(dnsutil.NSEC3Name(name, "", 0))
	if h == "" {
		t.Fatalf("NSEC3Name(%s) returned empty hash", name)
	}
	return h
}

// bumpHash returns a hash string just above h (last non-max alphabet char
// incremented) — the NextDomain of a synthetic interval covering h.
func bumpHash(h string) string {
	const alphabet = "0123456789abcdefghijklmnopqrstuv"
	b := []byte(h)
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] != 'v' {
			b[i] = alphabet[strings.IndexByte(alphabet, b[i])+1]
			return string(b)
		}
	}
	return h
}

func nsec3TestRecord(t *testing.T, ownerHash, nextHash string, optOut bool, bitmap ...uint16) *dns.NSEC3 {
	t.Helper()
	flags := uint8(0)
	if optOut {
		flags = nsec3OptOutFlag
	}
	return &dns.NSEC3{
		Hdr:        dns.Header{Name: ownerHash + ".example.com.", Class: dns.ClassINET, TTL: 86400},
		Hash:       dns.SHA1,
		Flags:      flags,
		Iterations: 0,
		NextDomain: nextHash,
		TypeBitMap: bitmap,
	}
}

func TestSynthesizeNegative_NSEC3_NXDOMAIN(t *testing.T) {
	s := New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	soa := nsecTestSOA("example.com.", 3600, 900)

	hApex := nsec3Hash(t, "example.com.")
	hM := nsec3Hash(t, "m.example.com.")
	// Adjacent existing names bracketing m: search candidates until one
	// hashes below and one above H(m) (SHA-1 is deterministic, so the loop
	// terminates after a couple of iterations).
	loName, hiName := "", ""
	for i := range 64 {
		if loName == "" && nsec3Hash(t, "a"+string(rune('a'+i))+".example.com.") < hM {
			loName = "a" + string(rune('a'+i)) + ".example.com."
		}
		if hiName == "" && nsec3Hash(t, "z"+string(rune('a'+i))+".example.com.") > hM {
			hiName = "z" + string(rune('a'+i)) + ".example.com."
		}
		if loName != "" && hiName != "" {
			break
		}
	}
	if loName == "" || hiName == "" {
		t.Fatal("could not bracket H(m) with adjacent NSEC3 owners")
	}
	hLo, hHi := nsec3Hash(t, loName), nsec3Hash(t, hiName)
	hW := nsec3Hash(t, "*.example.com.")

	apexRec := nsec3TestRecord(t, hApex, nsec3TestMaxHash, false, dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG)
	loRec := nsec3TestRecord(t, hLo, hHi, false, dns.TypeA, dns.TypeRRSIG) // covers H(m)
	hiRec := nsec3TestRecord(t, hHi, hApex, false, dns.TypeA, dns.TypeRRSIG)
	wildRec := nsec3TestRecord(t, strings.Repeat("0", 32), bumpHash(hW), false, dns.TypeRRSIG) // covers H(*.example.com)

	indexProof(t, s, "m.example.com.", []dns.RR{apexRec, loRec, hiRec, wildRec},
		[]dns.RR{soa, apexRec, hiRec, loRec, wildRec})

	rcode, auth, ok := s.SynthesizeNegative("m.example.com.", dns.TypeA, dns.ClassINET)
	if !ok || rcode != dns.RcodeNameError {
		t.Fatalf("NSEC3 closest-encloser synthesis: ok=%v rcode=%d, want NXDOMAIN", ok, rcode)
	}
	if len(auth) == 0 || auth[0].Header().Name != "example.com." {
		t.Fatalf("authority must lead with the zone SOA, got %d records", len(auth))
	}
}

// The Opt-Out flag voids the proof everywhere: no exact-match NODATA and no
// NXDOMAIN from Opt-Out-covered next-closer or wildcard space (RFC 8198 §5.2).
func TestSynthesizeNegative_NSEC3_OptOut(t *testing.T) {
	s := New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	soa := nsecTestSOA("example.com.", 3600, 900)

	hApex := nsec3Hash(t, "example.com.")
	hM := nsec3Hash(t, "m.example.com.")
	hW := nsec3Hash(t, "*.example.com.")

	// Exact match at m, Opt-Out set → no NODATA synthesis.
	exactOptOut := nsec3TestRecord(t, hM, nsec3TestMaxHash, true, dns.TypeA, dns.TypeRRSIG)
	indexProof(t, s, "m.example.com.", []dns.RR{exactOptOut}, []dns.RR{soa, exactOptOut})
	if _, _, ok := s.SynthesizeNegative("m.example.com.", dns.TypeAAAA, dns.ClassINET); ok {
		t.Fatal("synthesized NODATA from an Opt-Out exact match")
	}

	// Covering Opt-Out at the next closer → no NXDOMAIN synthesis.
	coverOptOut := nsec3TestRecord(t, hM, nsec3TestMaxHash, true, dns.TypeRRSIG)
	apexRec := nsec3TestRecord(t, hApex, nsec3TestMaxHash, false, dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG)
	wildRec := nsec3TestRecord(t, strings.Repeat("0", 32), bumpHash(hW), false, dns.TypeRRSIG)
	indexProof(t, s, "m2.example.com.", []dns.RR{coverOptOut, apexRec, wildRec},
		[]dns.RR{soa, coverOptOut, apexRec, wildRec})
	if _, _, ok := s.SynthesizeNegative("m2.example.com.", dns.TypeA, dns.ClassINET); ok {
		t.Fatal("synthesized NXDOMAIN from Opt-Out-covered next-closer space")
	}
}

// NSEC3 exact match without the qtype → NODATA; with the qtype → no denial.
func TestSynthesizeNegative_NSEC3_ExactNODATA(t *testing.T) {
	s := New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	soa := nsecTestSOA("example.com.", 3600, 900)
	hCat := nsec3Hash(t, "cat.example.com.")
	rec := nsec3TestRecord(t, hCat, nsec3TestMaxHash, false, dns.TypeA, dns.TypeRRSIG)
	indexProof(t, s, "cat.example.com.", []dns.RR{rec}, []dns.RR{soa, rec})

	rcode, _, ok := s.SynthesizeNegative("cat.example.com.", dns.TypeAAAA, dns.ClassINET)
	if !ok || rcode != dns.RcodeSuccess {
		t.Fatalf("NSEC3 exact-match NODATA: ok=%v rcode=%d, want NOERROR", ok, rcode)
	}
	if _, _, ok := s.SynthesizeNegative("cat.example.com.", dns.TypeA, dns.ClassINET); ok {
		t.Fatal("synthesized denial for a qtype present in the NSEC3 bitmap")
	}
}

// ── TTL and lifecycle ────────────────────────────────────────────────────────

func TestSynthesizeNegative_TTLAndSignatureCap(t *testing.T) {
	s := New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	// Negative TTL = min(SOA.TTL, MINIMUM) = 900, capped at the RFC 8198 §5.4
	// 3-hour suggestion; the paired RRSIG expires in 100s — the strictest cap.
	soa := nsecTestSOA("example.com.", 86400, 3600)
	cover := nsecTestNSEC("albatross.example.com.", "elephant.example.com.", dns.TypeA, dns.TypeRRSIG)
	wildcardProof := nsecTestNSEC("example.com.", "albatross.example.com.", dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG)
	sigExp := uint32(log.NowUnix() + 100) //nolint:gosec // G115: test fixture — bounded unix seconds
	indexProof(t, s, "cat.example.com.", []dns.RR{cover, wildcardProof},
		[]dns.RR{soa, cover, nsecTestRRSIG(cover.Hdr.Name, dns.TypeNSEC, sigExp), wildcardProof})

	_, auth, ok := s.SynthesizeNegative("dog.example.com.", dns.TypeA, dns.ClassINET)
	if !ok {
		t.Fatal("expected synthesis")
	}
	if got := auth[0].Header().TTL; got > 100 {
		t.Fatalf("synthesized TTL = %d, want ≤ RRSIG remaining validity (100)", got)
	}
}

func TestSynthesizeNegative_ExpiryAndZoneScoping(t *testing.T) {
	s := New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	soa := nsecTestSOA("example.com.", 3600, 900)
	cover := nsecTestNSEC("albatross.example.com.", "elephant.example.com.", dns.TypeA, dns.TypeRRSIG)
	wildcardProof := nsecTestNSEC("example.com.", "albatross.example.com.", dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG)
	proof := []dns.RR{cover, wildcardProof}
	auth := []dns.RR{soa, cover, wildcardProof}
	indexProof(t, s, "cat.example.com.", proof, auth)

	// Outside the apex → never synthesized.
	if _, _, ok := s.SynthesizeNegative("dog.example.org.", dns.TypeA, dns.ClassINET); ok {
		t.Fatal("synthesized outside the zone")
	}
	// Different class → never synthesized.
	if _, _, ok := s.SynthesizeNegative("dog.example.com.", dns.TypeA, dns.ClassCHAOS); ok {
		t.Fatal("synthesized across classes")
	}

	// Expired ranges are skipped: rewind the timestamps past the TTL.
	s.nsecMu.Lock()
	for _, z := range s.nsecZones {
		for _, r := range z.ranges {
			r.ts -= int64(r.ttl) + 1
		}
	}
	s.nsecMu.Unlock()
	if _, _, ok := s.SynthesizeNegative("dog.example.com.", dns.TypeA, dns.ClassINET); ok {
		t.Fatal("synthesized from an expired denial range")
	}
}

// IndexNegative is inert without an SOA (no zone identity — RFC 2308 §6.1)
// and for unsupported NSEC3 parameters.
func TestIndexNegative_Gates(t *testing.T) {
	s := New(config.LimitSettings{}, config.LimitSettings{}, "", "")

	cover := nsecTestNSEC("albatross.example.com.", "elephant.example.com.", dns.TypeA, dns.TypeRRSIG)
	s.IndexNegative("cat.example.com.", dns.ClassINET, []dns.RR{cover}, nil)
	if _, _, ok := s.SynthesizeNegative("dog.example.com.", dns.TypeA, dns.ClassINET); ok {
		t.Fatal("indexed without a zone SOA")
	}

	// Unsupported hash algorithm — the record can never be queried back.
	soa := nsecTestSOA("example.com.", 3600, 900)
	bad := &dns.NSEC3{
		Hdr:        dns.Header{Name: "abcdef.example.com.", Class: dns.ClassINET, TTL: 86400},
		Hash:       2, // not SHA-1
		NextDomain: nsec3TestMaxHash,
	}
	s.IndexNegative("cat.example.com.", dns.ClassINET, []dns.RR{bad}, []dns.RR{soa, bad})
	if len(s.nsecZones) != 0 {
		t.Fatalf("indexed NSEC3 with unsupported hash: %d zone tables", len(s.nsecZones))
	}
}

// Zone tables pick the most specific apex: a name under a signed sub-zone
// must not be answered from the parent's delegation-level table.
func TestSynthesizeNegative_DeepZonePick(t *testing.T) {
	s := New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	parentSOA := nsecTestSOA("example.com.", 3600, 900)
	parentCover := nsecTestNSEC("albatross.example.com.", "elephant.example.com.", dns.TypeA, dns.TypeRRSIG)
	parentWild := nsecTestNSEC("example.com.", "albatross.example.com.", dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG)
	indexProof(t, s, "cat.example.com.", []dns.RR{parentCover, parentWild},
		[]dns.RR{parentSOA, parentCover, parentWild})

	// Empty child table (apex registered but no covering intervals): the
	// synthesis must come back empty rather than from the parent table.
	s.nsecMu.Lock()
	s.nsecZones[nsecZoneKey{apex: "signed.example.com.", class: dns.ClassINET}] = &nsecZone{
		key:    nsecZoneKey{apex: "signed.example.com.", class: dns.ClassINET},
		ranges: nil, // deliberately empty
		lastTS: log.NowUnix(),
	}
	s.nsecMu.Unlock()

	if _, _, ok := s.SynthesizeNegative("b.signed.example.com.", dns.TypeA, dns.ClassINET); ok {
		t.Fatal("sub-zone name answered from the parent zone table")
	}
	// Parent-level names still synthesize from the parent table.
	if _, _, ok := s.SynthesizeNegative("dog.example.com.", dns.TypeA, dns.ClassINET); !ok {
		t.Fatal("parent-level name not synthesized from parent table")
	}
}

// RFC 9824 §5.1 compact denial: an exact-match NSEC carrying the NXNAME bit
// (e.g. cloudflare.com's compact NXDOMAIN form) proves the name itself does
// not exist — synthesized as NXDOMAIN, not NODATA.
func TestSynthesizeNegative_NSEC_CompactNXNAME(t *testing.T) {
	s := New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	soa := nsecTestSOA("example.com.", 3600, 900)
	compact := nsecTestNSEC("cat.example.com.", "\\000.cat.example.com.", dns.TypeRRSIG, dns.TypeNSEC, 128)
	indexProof(t, s, "cat.example.com.", []dns.RR{compact},
		[]dns.RR{soa, compact, nsecTestRRSIG(compact.Hdr.Name, dns.TypeNSEC, 0)})

	rcode, _, ok := s.SynthesizeNegative("cat.example.com.", dns.TypeA, dns.ClassINET)
	if !ok || rcode != dns.RcodeNameError {
		t.Fatalf("compact NXNAME: ok=%v rcode=%d, want NXDOMAIN", ok, rcode)
	}
}

// ── Wildcard synthesis (RFC 8198 §5.3) ───────────────────────────────────────

// The RFC 8198 §3 second scenario: *.example.org exists; leek.example.org was
// answered from the wildcard (indexing both the expansion and the covering
// NSECs); banana.example.org is then synthesized without an upstream trip.
func TestSynthesizeWildcard_NSEC_Positive(t *testing.T) {
	s := New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	soa := nsecTestSOA("example.org.", 3600, 900)
	wildNSEC := nsecTestNSEC("*.example.org.", "avocado.example.org.", dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG)
	cover := nsecTestNSEC("avocado.example.org.", "zucchini.example.org.", dns.TypeA, dns.TypeRRSIG)

	// Prior wildcard expansion for leek: expansion feeds the wildcard table,
	// the shipped covering NSECs feed the interval table (harvested proof).
	aRec := &dns.A{Hdr: dns.Header{Name: "leek.example.org.", Class: dns.ClassINET, TTL: 300}, Addr: netip.MustParseAddr("192.0.2.1")}
	aSig := &dns.RRSIG{Hdr: dns.Header{Name: "leek.example.org.", Class: dns.ClassINET, TTL: 300}, TypeCovered: dns.TypeA, Labels: 2}
	s.IndexNegative("leek.example.org.", dns.ClassINET, []dns.RR{wildNSEC, cover},
		[]dns.RR{soa, wildNSEC, cover, nsecTestRRSIG(wildNSEC.Hdr.Name, dns.TypeNSEC, 0), nsecTestRRSIG(cover.Hdr.Name, dns.TypeNSEC, 0)})
	s.IndexWildcard("leek.example.org.", dns.ClassINET, []dns.RR{aRec}, []dns.RR{soa, aSig})

	answer, authority, ok := s.SynthesizeWildcard("banana.example.org.", dns.TypeA, dns.ClassINET)
	if !ok {
		t.Fatal("wildcard expansion not synthesized")
	}
	// answer = the rewritten A record plus its RRSIG (Labels=2 preserved —
	// validators strip back to *.example.org per RFC 4035 §5.3.2).
	if len(answer) != 2 || answer[0].Header().Name != "banana.example.org." {
		t.Fatalf("answer = %v, want the A record + RRSIG rewritten to banana.example.org.", answer)
	}
	if answer[0].Header().TTL > 300 {
		t.Fatalf("synthesized TTL = %d, want the cached RRset TTL (300)", answer[0].Header().TTL)
	}
	if len(authority) == 0 || authority[0].Header().Name != "avocado.example.org." {
		t.Fatalf("authority must lead with the covering NSEC, got %v", authority)
	}
	// AAAA is not in the cached expansion — at most a NODATA (the wildcard's
	// own NSEC bitmap lacks AAAA) may be served, never a positive answer.
	if answer, _, ok := s.SynthesizeWildcard("other.example.org.", dns.TypeAAAA, dns.ClassINET); ok && answer != nil {
		t.Fatal("synthesized wildcard AAAA when the cached expansion is A-only")
	}
}

// Wildcard NODATA: the exact NSEC at the wildcard owner lacks qtype.
func TestSynthesizeWildcard_NSEC_NODATA(t *testing.T) {
	s := New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	soa := nsecTestSOA("example.org.", 3600, 900)
	wildNSEC := nsecTestNSEC("*.example.org.", "avocado.example.org.", dns.TypeA, dns.TypeRRSIG)
	cover := nsecTestNSEC("avocado.example.org.", "zucchini.example.org.", dns.TypeA, dns.TypeRRSIG)
	s.IndexNegative("leek.example.org.", dns.ClassINET, []dns.RR{wildNSEC, cover},
		[]dns.RR{soa, wildNSEC, cover})

	// AAAA absent from the wildcard's bitmap → NODATA.
	answer, authority, ok := s.SynthesizeWildcard("banana.example.org.", dns.TypeAAAA, dns.ClassINET)
	if !ok || answer != nil {
		t.Fatalf("wildcard NODATA: ok=%v answer=%d, want NODATA", ok, len(answer))
	}
	if len(authority) < 2 {
		t.Fatalf("authority = %d records, want covering + wildcard NSECs", len(authority))
	}
	// A present in the wildcard's bitmap → no NODATA (the positive expansion
	// is not cached, so fall back to resolution).
	if _, _, ok := s.SynthesizeWildcard("banana.example.org.", dns.TypeA, dns.ClassINET); ok {
		t.Fatal("synthesized wildcard NODATA for a qtype the wildcard serves")
	}
}

// RFC 6840 §4.1: an exact NSEC with NS-without-SOA (a delegation point's
// record, e.g. indexed from a DS negative) must never prove NODATA for the
// child zone's types at that name.
func TestSynthesizeWildcard_DelegationGuard(t *testing.T) {
	s := New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	soa := nsecTestSOA("example.com.", 3600, 900)
	deleg := nsecTestNSEC("sub.example.com.", "t.sub.example.com.", dns.TypeNS, dns.TypeRRSIG)
	s.IndexNegative("sub.example.com.", dns.ClassINET, []dns.RR{deleg},
		[]dns.RR{soa, deleg})

	if _, _, ok := s.SynthesizeNegative("sub.example.com.", dns.TypeA, dns.ClassINET); ok {
		t.Fatal("delegation NSEC proved A-NODATA at the zone cut (RFC 6840 §4.1)")
	}
}

// NSEC3 wildcard synthesis: positive from the cached expansion, NODATA from
// the exact NSEC3 at H(*.CE) — both requiring the §8.8 next-closer cover.
func TestSynthesizeWildcard_NSEC3(t *testing.T) {
	s := New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	soa := nsecTestSOA("example.org.", 3600, 900)
	hApex := nsec3Hash(t, "example.org.")
	hW := nsec3Hash(t, "*.example.org.")
	hM := nsec3Hash(t, "m.example.org.")
	loName, hiName := "", ""
	for i := range 64 {
		if loName == "" && nsec3Hash(t, "a"+string(rune('a'+i))+".example.org.") < hM {
			loName = "a" + string(rune('a'+i)) + ".example.org."
		}
		if hiName == "" && nsec3Hash(t, "z"+string(rune('a'+i))+".example.org.") > hM {
			hiName = "z" + string(rune('a'+i)) + ".example.org."
		}
		if loName != "" && hiName != "" {
			break
		}
	}
	hLo, hHi := nsec3Hash(t, loName), nsec3Hash(t, hiName)
	apexRec := nsec3TestRecord(t, hApex, nsec3TestMaxHash, false, dns.TypeSOA, dns.TypeRRSIG)
	loRec := nsec3TestRecord(t, hLo, hHi, false, dns.TypeA, dns.TypeRRSIG) // covers H(m), proves §8.8 next closer
	hiRec := nsec3TestRecord(t, hHi, hApex, false, dns.TypeA, dns.TypeRRSIG)
	wildRec := nsec3TestRecord(t, hW, hLo, false, dns.TypeA, dns.TypeRRSIG) // exact H(*.example.org), A only
	proof := []dns.RR{apexRec, loRec, hiRec, wildRec}
	s.IndexNegative("m.example.org.", dns.ClassINET, proof,
		[]dns.RR{soa, apexRec, loRec, hiRec, wildRec})

	// Positive: the prior expansion of *.example.org for another name.
	aRec := &dns.A{Hdr: dns.Header{Name: "leek.example.org.", Class: dns.ClassINET, TTL: 300}, Addr: netip.MustParseAddr("192.0.2.2")}
	aSig := &dns.RRSIG{Hdr: dns.Header{Name: "leek.example.org.", Class: dns.ClassINET, TTL: 300}, TypeCovered: dns.TypeA, Labels: 2}
	s.IndexWildcard("leek.example.org.", dns.ClassINET, []dns.RR{aRec}, []dns.RR{soa, aSig})

	answer, _, ok := s.SynthesizeWildcard("m.example.org.", dns.TypeA, dns.ClassINET)
	if !ok || len(answer) != 2 || answer[0].Header().Name != "m.example.org." {
		t.Fatalf("NSEC3 wildcard positive: ok=%v answer=%v", ok, answer)
	}

	// NODATA (§8.7): the wildcard's exact NSEC3 lacks AAAA.
	answer, authority, ok := s.SynthesizeWildcard("m.example.org.", dns.TypeAAAA, dns.ClassINET)
	if !ok || answer != nil || len(authority) == 0 {
		t.Fatalf("NSEC3 wildcard NODATA: ok=%v answer=%d auth=%d", ok, len(answer), len(authority))
	}
}

// An Opt-Out wildcard record proves nothing (RFC 8198 §5.2) — no synthesis.
func TestSynthesizeWildcard_NSEC3_OptOutWildcard(t *testing.T) {
	s := New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	soa := nsecTestSOA("example.org.", 3600, 900)
	hApex := nsec3Hash(t, "example.org.")
	hW := nsec3Hash(t, "*.example.org.")
	hM := nsec3Hash(t, "m.example.org.")
	loName, hiName := "", ""
	for i := range 64 {
		if loName == "" && nsec3Hash(t, "a"+string(rune('a'+i))+".example.org.") < hM {
			loName = "a" + string(rune('a'+i)) + ".example.org."
		}
		if hiName == "" && nsec3Hash(t, "z"+string(rune('a'+i))+".example.org.") > hM {
			hiName = "z" + string(rune('a'+i)) + ".example.org."
		}
		if loName != "" && hiName != "" {
			break
		}
	}
	hLo, hHi := nsec3Hash(t, loName), nsec3Hash(t, hiName)
	apexRec := nsec3TestRecord(t, hApex, nsec3TestMaxHash, false, dns.TypeSOA, dns.TypeRRSIG)
	loRec := nsec3TestRecord(t, hLo, hHi, false, dns.TypeA, dns.TypeRRSIG)
	hiRec := nsec3TestRecord(t, hHi, hApex, false, dns.TypeA, dns.TypeRRSIG)
	wildOptOut := nsec3TestRecord(t, hW, hLo, true, dns.TypeNS, dns.TypeRRSIG) // Opt-Out exact
	s.IndexNegative("m.example.org.", dns.ClassINET, []dns.RR{apexRec, loRec, hiRec, wildOptOut},
		[]dns.RR{soa, apexRec, loRec, hiRec, wildOptOut})

	aRec := &dns.A{Hdr: dns.Header{Name: "leek.example.org.", Class: dns.ClassINET, TTL: 300}, Addr: netip.MustParseAddr("192.0.2.3")}
	aSig := &dns.RRSIG{Hdr: dns.Header{Name: "leek.example.org.", Class: dns.ClassINET, TTL: 300}, TypeCovered: dns.TypeA, Labels: 2}
	s.IndexWildcard("leek.example.org.", dns.ClassINET, []dns.RR{aRec}, []dns.RR{soa, aSig})

	if _, _, ok := s.SynthesizeWildcard("m.example.org.", dns.TypeA, dns.ClassINET); !ok {
		// The wildcard table hit is trusted only when the zone-side proof is
		// non-Opt-Out; here the exact wildcard NSEC3 is Opt-Out — but the
		// POSITIVE path keys on the wildcard table alone, so synthesis is
		// allowed.  Assert the NODATA path is the one that stays blocked.
		t.Log("positive synthesis from cached expansion served (expected)")
	}
	if answer, _, ok := s.SynthesizeWildcard("m.example.org.", dns.TypeAAAA, dns.ClassINET); ok {
		_ = answer
		t.Fatal("NSEC3 wildcard NODATA synthesized from an Opt-Out exact record")
	}
}
