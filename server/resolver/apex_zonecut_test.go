package resolver

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"zjdns/edns"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// mockUDPWriter routes responses back to the requesting client from the
// server's own socket (same source port), which the fork's pool client
// requires for demultiplexing.  Session() returns a session without OOB so
// Msg.WriteTo takes the WriteMsgUDP path with nil control data.
type mockUDPWriter struct {
	conn   *net.UDPConn
	remote *net.UDPAddr
}

func (w *mockUDPWriter) LocalAddr() net.Addr  { return w.conn.LocalAddr() }
func (w *mockUDPWriter) RemoteAddr() net.Addr { return w.remote }
func (w *mockUDPWriter) Conn() net.Conn       { return w.conn }
func (w *mockUDPWriter) Write(p []byte) (int, error) {
	return w.conn.WriteToUDP(p, w.remote)
}
func (w *mockUDPWriter) Close() error          { return nil }
func (w *mockUDPWriter) Session() *dns.Session { return &dns.Session{Addr: w.remote} }
func (w *mockUDPWriter) Hijack()               {}

// ── isApexSOANODATA ──────────────────────────────────────────────────────────

func TestIsApexSOANODATA(t *testing.T) {
	soa := &dns.SOA{
		Hdr: dns.Header{Name: "com.cn.", Class: dns.ClassINET, TTL: 300},
		SOA: rdata.SOA{Ns: "a.dns.cn.", Mbox: "root.cnnic.cn."},
	}

	// aa + NODATA with SOA at the qname → the qname is a zone apex.
	m := new(dns.Msg)
	m.Authoritative = true
	m.Ns = []dns.RR{soa}
	if !isApexSOANODATA(m, "com.cn.") {
		t.Error("aa+NODATA with SOA at qname should be detected as zone apex")
	}

	// Referral (AA=0) — not an apex signal.
	m = new(dns.Msg)
	m.Authoritative = false
	m.Ns = []dns.RR{soa}
	if isApexSOANODATA(m, "com.cn.") {
		t.Error("non-authoritative response must not be detected as zone apex")
	}

	// SOA at the parent (NXDOMAIN-style denial) — qname is not the apex.
	parentSoa := &dns.SOA{
		Hdr: dns.Header{Name: "cn.", Class: dns.ClassINET, TTL: 300},
		SOA: rdata.SOA{Ns: "a.dns.cn.", Mbox: "root.cnnic.cn."},
	}
	m = new(dns.Msg)
	m.Authoritative = true
	m.Ns = []dns.RR{parentSoa}
	if isApexSOANODATA(m, "com.cn.") {
		t.Error("SOA at parent must not be detected as apex for the qname")
	}

	// Answers present — not a NODATA response.
	m = new(dns.Msg)
	m.Authoritative = true
	m.Answer = []dns.RR{aRec("com.cn.", "192.0.2.1")}
	m.Ns = []dns.RR{soa}
	if isApexSOANODATA(m, "com.cn.") {
		t.Error("response with answers must not be detected as NODATA apex")
	}

	if isApexSOANODATA(nil, "com.cn.") {
		t.Error("nil response must not be detected")
	}
}

// ── collectBestNSMatch: NXDOMAIN rcode ───────────────────────────────────────

func TestCollectBestNSMatch_NXDOMAINRcode(t *testing.T) {
	// A full-QNAME NXDOMAIN response (no NS records) terminates the walk —
	// the QueryResult must carry the NXDOMAIN rcode so the served response
	// and the cache entry are not downgraded to NOERROR/NODATA.
	msg := new(dns.Msg)
	msg.Rcode = dns.RcodeNameError
	msg.Ns = []dns.RR{
		&dns.SOA{
			Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300},
			SOA: rdata.SOA{Ns: "ns.example.com.", Mbox: "root.example.com."},
		},
	}

	_, _, cont, termRes := newTestRecursive().collectBestNSMatch(msg,
		"www.example.com.", "www.example.com.", "www.example.com.", false, false, nil)
	if cont {
		t.Fatal("full-QNAME response should terminate the walk")
	}
	if termRes == nil {
		t.Fatal("expected a terminal result")
	}
	if termRes.Rcode != dns.RcodeNameError {
		t.Errorf("termRes.Rcode = %d, want NXDOMAIN", termRes.Rcode)
	}
}

// ── stripCrossZoneRecords ────────────────────────────────────────────────────

func TestStripCrossZoneRecords_KeepsRRSIGs(t *testing.T) {
	// RFC 4035 §3.1.1: a signed RRset in the Answer section MUST be
	// accompanied by its RRSIGs.  RRSIGs covering stripped (cross-zone)
	// RRsets are dropped with them.
	zoneKey, zonePriv := genTestKey("example.com.", 256)
	otherKey, otherPriv := genTestKey("elsewhere.net.", 256)

	inZone := aRec("www.example.com.", "192.0.2.1")
	inSig := signRRset([]dns.RR{inZone}, "example.com.", zonePriv, zoneKey.KeyTag())

	crossZone := aRec("www.elsewhere.net.", "192.0.2.2")
	crossSig := signRRset([]dns.RR{crossZone}, "elsewhere.net.", otherPriv, otherKey.KeyTag())

	got := stripCrossZoneRecords([]dns.RR{inZone, inSig, crossZone, crossSig}, nil, "example.com.")

	if len(got) != 2 {
		t.Fatalf("got %d records, want 2 (in-zone RRset + its RRSIG)", len(got))
	}
	if got[0] != inZone || got[1] != inSig {
		t.Errorf("kept records = %v, want the in-zone A record and its RRSIG", got)
	}
}

func TestStripCrossZoneRecords_UnsignedUntouched(t *testing.T) {
	// Fully unsigned responses (unsigned zones) pass through unchanged.
	a := aRec("www.example.com.", "192.0.2.1")
	got := stripCrossZoneRecords([]dns.RR{a}, nil, "example.com.")
	if len(got) != 1 || got[0] != a {
		t.Errorf("unsigned response altered: got %v", got)
	}
}

func TestStripCrossZoneRecords_DropsUnsignedInSignedResponse(t *testing.T) {
	// An unsigned RRset inside a signed response is anomalous and dropped;
	// an RRSIG whose covered RRset is absent from the answer is dropped
	// with it.
	zoneKey, zonePriv := genTestKey("example.com.", 256)
	signed := aRec("www.example.com.", "192.0.2.1")
	sig := signRRset([]dns.RR{signed}, "example.com.", zonePriv, zoneKey.KeyTag())
	unsigned := &dns.TXT{
		Hdr: dns.Header{Name: "txt.example.com.", Class: dns.ClassINET, TTL: 300},
		TXT: rdata.TXT{Txt: []string{"unsigned"}},
	}
	orphanTarget := aRec("mx.example.com.", "192.0.2.3")
	orphanSig := signRRset([]dns.RR{orphanTarget}, "example.com.", zonePriv, zoneKey.KeyTag())

	got := stripCrossZoneRecords([]dns.RR{signed, sig, unsigned, orphanSig}, nil, "example.com.")
	if len(got) != 2 {
		t.Fatalf("got %d records, want 2 (signed RRset + its RRSIG)", len(got))
	}
	if got[0] != signed || got[1] != sig {
		t.Errorf("kept records = %v, want the signed A record and its RRSIG", got)
	}
}

func TestStripCrossZoneRecords_UnknownTypesDistinct(t *testing.T) {
	// RFC 3597 unknown types (TYPE1234 / TYPE5678) have no entry in
	// dns.TypeToString — the string-based key collapsed them into a single
	// "name/" entry, so a cross-zone unknown RRset at the same owner could
	// be emitted.  Numeric keys keep the RRsets distinct.
	zoneKey, zonePriv := genTestKey("example.com.", 256)
	otherKey, otherPriv := genTestKey("elsewhere.net.", 256)

	inZone := &dns.RFC3597{
		Hdr:     dns.Header{Name: "www.example.com.", Class: dns.ClassINET, TTL: 300},
		RFC3597: rdata.RFC3597{RRType: 1234, Data: "deadbeef"},
	}
	inSig := signRRset([]dns.RR{inZone}, "example.com.", zonePriv, zoneKey.KeyTag())

	crossZone := &dns.RFC3597{
		Hdr:     dns.Header{Name: "www.example.com.", Class: dns.ClassINET, TTL: 300},
		RFC3597: rdata.RFC3597{RRType: 5678, Data: "cafebabe"},
	}
	crossSig := signRRset([]dns.RR{crossZone}, "elsewhere.net.", otherPriv, otherKey.KeyTag())

	got := stripCrossZoneRecords([]dns.RR{inZone, inSig, crossZone, crossSig}, nil, "example.com.")
	if len(got) != 2 {
		t.Fatalf("got %d records, want 2 (in-zone TYPE1234 + its RRSIG)", len(got))
	}
	if got[0] != inZone || got[1] != inSig {
		t.Errorf("kept records = %v, want the in-zone TYPE1234 RRset and its RRSIG", got)
	}
}

func TestStripCrossZoneRecords_CaseInsensitiveKey(t *testing.T) {
	// The RRSIG owner may differ from the data record's owner in case —
	// the keepRRset key must be canonical so the signature is still
	// emitted (RFC 4035 §3.1.1).
	zoneKey, zonePriv := genTestKey("example.com.", 256)
	inZone := aRec("WWW.EXAMPLE.COM.", "192.0.2.1")
	inSig := signRRset([]dns.RR{inZone}, "example.com.", zonePriv, zoneKey.KeyTag())

	got := stripCrossZoneRecords([]dns.RR{inZone, inSig}, nil, "example.com.")
	if len(got) != 2 {
		t.Fatalf("got %d records, want 2 (RRset + its RRSIG despite case mismatch)", len(got))
	}
	if got[0] != inZone || got[1] != inSig {
		t.Errorf("kept records = %v", got)
	}
}

// ── Mock DNS server ──────────────────────────────────────────────────────────

// startMockDNS starts an in-process UDP DNS server on an ephemeral port and
// returns its "ip:port" address.  The loop is hand-rolled instead of using
// miekg's Server: closing the packet conn must interrupt the read loop, and
// the fork's Server.init races Shutdown when a fast test finishes before
// ListenAndServe scheduled (no ready signal exists).
func startMockDNS(t *testing.T, handler dns.HandlerFunc) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, remote, err := conn.ReadFromUDP(buf)
			if err != nil {
				return // conn closed by cleanup
			}
			req := new(dns.Msg)
			req.Data = buf[:n]
			if err := req.Unpack(); err != nil {
				continue
			}
			handler.ServeDNS(context.Background(), &mockUDPWriter{conn: conn, remote: remote}, req)
		}
	}()
	t.Cleanup(func() { _ = conn.Close() })
	return conn.LocalAddr().String()
}

// replyMsg builds an authoritative NOERROR reply to req.  The fork's server
// writes packed messages; the caller fills the sections before Pack.
func replyMsg(req *dns.Msg) *dns.Msg {
	m := dnsutil.SetReply(new(dns.Msg), req)
	m.Authoritative = true
	return m
}

// writeMsg writes m to w.  Msg.WriteTo handles UDP session routing (the
// fork's server requires WriteMsgUDP with the request's OOB data — a raw
// conn.Write on the unconnected socket never reaches the client).
func writeMsg(w dns.ResponseWriter, m *dns.Msg) {
	_, _ = m.WriteTo(w)
}

// setTestBuildMsg makes newTestRecursive's query client send real questions.
func setTestBuildMsg(rr *Recursive) {
	rr.resolver.buildMsg = func(q Question, ecs *edns.ECSOption, rd, secure bool) *dns.Msg {
		m := new(dns.Msg)
		return dnsutil.SetQuestion(m, q.Name, q.Qtype)
	}
}

// ── verifyNoDSInParent: raced DS ─────────────────────────────────────────────

func TestVerifyNoDSInParent_RacedDS(t *testing.T) {
	parentKey, parentPriv := genTestKey("example.com.", 256)
	childKey, _ := genTestKey("sub.example.com.", 256)
	parentZone := "example.com."
	childZone := "sub.example.com."

	ds := childKey.ToDS(dns.SHA256)
	ds.Hdr = dns.Header{Name: childZone, Class: dns.ClassINET, TTL: 300}
	dsRRSIG := signRRset([]dns.RR{ds}, parentZone, parentPriv, parentKey.KeyTag())

	addr := startMockDNS(t, dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, req *dns.Msg) {
		m := replyMsg(req)
		if len(req.Question) == 1 && dns.RRToType(req.Question[0]) == dns.TypeDS {
			m.Answer = []dns.RR{ds, dsRRSIG}
		}
		writeMsg(w, m)
	}))

	rr := newTestRecursive()
	setTestBuildMsg(rr)
	chain := &dnssecChain{zoneDNSKEYs: []*dns.DNSKEY{parentKey}}

	noDS, raced := rr.verifyNoDSInParent(context.Background(), []string{addr}, childZone, parentZone, chain)
	if !raced {
		t.Error("raced must be true when the DS query returns DS records")
	}
	if noDS {
		t.Error("noDS must be false when the DS query returns DS records")
	}
	if len(chain.childDS) != 1 || chain.childDS[0].KeyTag != ds.KeyTag {
		t.Errorf("chain.childDS = %v, want the raced DS verified", chain.childDS)
	}
	if chain.dsPresentButUnverified {
		t.Error("dsPresentButUnverified must be false after the raced DS verifies")
	}
}

// ── advanceApexZoneCut ───────────────────────────────────────────────────────

// TestAdvanceApexZoneCut reproduces the CNNIC-style parent server that hosts
// both parent and child zones: it answers a minimised query for a delegated
// child with an authoritative NODATA (SOA at the qname) instead of a
// referral.  The walk must fetch the qname's NS RRset at the same servers and
// advance through the zone cut, verifying the raced DS along the way.
func TestAdvanceApexZoneCut(t *testing.T) {
	parentKey, parentPriv := genTestKey("example.com.", 256)
	childKey, _ := genTestKey("sub.example.com.", 256)
	parentZone := "example.com."
	childZone := "sub.example.com."

	ds := childKey.ToDS(dns.SHA256)
	ds.Hdr = dns.Header{Name: childZone, Class: dns.ClassINET, TTL: 300}
	dsRRSIG := signRRset([]dns.RR{ds}, parentZone, parentPriv, parentKey.KeyTag())

	nsRec := &dns.NS{
		Hdr: dns.Header{Name: childZone, Class: dns.ClassINET, TTL: 300},
		NS:  rdata.NS{Ns: "ns." + childZone},
	}
	glue := &dns.A{
		Hdr: dns.Header{Name: "ns." + childZone, Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("127.0.0.1")},
	}

	addr := startMockDNS(t, dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, req *dns.Msg) {
		m := replyMsg(req)
		if len(req.Question) == 1 {
			switch dns.RRToType(req.Question[0]) {
			case dns.TypeNS:
				m.Answer = []dns.RR{nsRec}
				m.Extra = []dns.RR{glue}
			case dns.TypeDS:
				m.Answer = []dns.RR{ds, dsRRSIG}
			}
		}
		writeMsg(w, m)
	}))

	rr := newTestRecursive()
	rr.resolver.DNSSECEnforce = true // raced-DS verification is enforcement-path behavior (no-DS short-circuit applies when off)
	setTestBuildMsg(rr)
	chain := &dnssecChain{zoneDNSKEYs: []*dns.DNSKEY{parentKey}}

	nextNS, nextZone, ok := rr.advanceApexZoneCut(context.Background(), childZone,
		[]string{addr}, parentZone, nil, chain, 0, false, "www."+childZone)

	if !ok {
		t.Fatal("advanceApexZoneCut should establish the zone cut")
	}
	if nextZone != childZone {
		t.Errorf("nextZone = %q, want %q", nextZone, childZone)
	}
	if len(nextNS) == 0 {
		t.Fatal("expected next-level nameservers from glue")
	}
	if len(chain.childDS) != 1 || chain.childDS[0].KeyTag != ds.KeyTag {
		t.Errorf("chain.childDS = %v, want raced DS verified", chain.childDS)
	}
	if chain.dsPresentButUnverified {
		t.Error("dsPresentButUnverified must be false after the raced DS verifies")
	}
	if !dnsutil.IsBelow(dnsutil.Fqdn(parentZone), dnsutil.Fqdn(nextZone)) {
		t.Errorf("nextZone %q must be below parent %q", nextZone, parentZone)
	}
}

// TestResolveZoneCut_RacedDS verifies that a DS found by
// verifyNoDSInParent's re-query (the delegation race) is accepted by
// resolveZoneCut: the zone cut continues with the verified DS instead of
// failing with "no authenticated denial".
func TestResolveZoneCut_RacedDS(t *testing.T) {
	parentKey, parentPriv := genTestKey("example.com.", 256)
	childKey, childPriv := genTestKey("sub.example.com.", 256)
	parentZone := "example.com."
	childZone := "sub.example.com."

	ds := childKey.ToDS(dns.SHA256)
	ds.Hdr = dns.Header{Name: childZone, Class: dns.ClassINET, TTL: 300}
	dsRRSIG := signRRset([]dns.RR{ds}, parentZone, parentPriv, parentKey.KeyTag())

	soa := &dns.SOA{
		Hdr: dns.Header{Name: parentZone, Class: dns.ClassINET, TTL: 300},
		SOA: rdata.SOA{Ns: "ns." + parentZone, Mbox: "root." + parentZone},
	}

	var dsQueries atomic.Int32
	addr := startMockDNS(t, dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, req *dns.Msg) {
		m := replyMsg(req)
		if len(req.Question) == 1 && dns.RRToType(req.Question[0]) == dns.TypeDS {
			if dsQueries.Add(1) == 1 {
				// resolveZoneCut's own DS query: bare NODATA.
				m.Ns = []dns.RR{soa}
			} else {
				// verifyNoDSInParent's re-query: the raced DS.
				m.Answer = []dns.RR{ds, dsRRSIG}
			}
		}
		writeMsg(w, m)
	}))

	// Answer with RRSIGs signed by the child zone → zone cut signer.
	ans := aRec("www."+childZone, "192.0.2.1")
	ansSig := signRRset([]dns.RR{ans}, childZone, childPriv, childKey.KeyTag())
	msg := &dns.Msg{Answer: []dns.RR{ans, ansSig}}

	rr := newTestRecursive()
	setTestBuildMsg(rr)
	chain := &dnssecChain{zoneDNSKEYs: []*dns.DNSKEY{parentKey}}

	_, err := rr.resolveZoneCut(context.Background(), msg, []string{addr},
		Question{Name: "www." + childZone, Qtype: dns.TypeA},
		parentZone, nil, false, chain)

	// The raced DS must be accepted — the cut proceeds to child NS
	// resolution (which fails in the mock) instead of failing early with
	// "no authenticated denial".
	if err == nil {
		t.Fatal("expected an error (child NS resolution fails in the mock)")
	}
	if strings.Contains(err.Error(), "no authenticated denial") {
		t.Errorf("raced DS was rejected: %v", err)
	}
	if len(chain.childDS) != 1 || chain.childDS[0].KeyTag != ds.KeyTag {
		t.Errorf("chain.childDS = %v, want raced DS verified", chain.childDS)
	}
}

// TestAdvanceApexZoneCut_NoNS verifies graceful fallback when the NS query
// finds no records for the zone-cut candidate.
func TestAdvanceApexZoneCut_NoNS(t *testing.T) {
	addr := startMockDNS(t, dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, req *dns.Msg) {
		writeMsg(w, replyMsg(req))
	}))

	rr := newTestRecursive()
	setTestBuildMsg(rr)
	chain := &dnssecChain{}

	nextNS, nextZone, ok := rr.advanceApexZoneCut(context.Background(), "sub.example.com.",
		[]string{addr}, "example.com.", nil, chain, 0, false, "www.sub.example.com.")
	if ok {
		t.Errorf("expected ok=false when no NS records, got zone=%q ns=%v", nextZone, nextNS)
	}
}
