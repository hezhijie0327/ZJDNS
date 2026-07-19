package hijack

import (
	"net/netip"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// ── Helpers ────────────────────────────────────────────────────────────────────

func aRec(name, ip string) *dns.A {
	return &dns.A{
		Hdr: dns.Header{Name: dnsutil.Fqdn(name), Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr(ip)},
	}
}

func nsRec(name, target string) *dns.NS {
	return &dns.NS{
		Hdr: dns.Header{Name: dnsutil.Fqdn(name), Class: dns.ClassINET, TTL: 86400},
		NS:  rdata.NS{Ns: dnsutil.Fqdn(target)},
	}
}

func newDetector() *Detector {
	d := &Detector{}
	d.Enable(true)
	return d
}

// classifyRecord is a test helper that classifies a single record.
func classifyRecord(d *Detector, rr dns.RR, zone, queryName string) Verdict {
	answerName := dnsutil.Canonical(rr.Header().Name)
	queryName = dnsutil.Canonical(queryName)
	zone = dnsutil.Canonical(zone)
	if answerName != queryName {
		return VerdictClean
	}
	return d.classify(zone, queryName, dns.RRToType(rr))
}

// ── Classification (per-record) ───────────────────────────────────────────────

func TestClassify_WithinAuthority(t *testing.T) {
	d := newDetector()
	v := classifyRecord(
		d,
		aRec("www.example.com.", "10.0.0.1"),
		"example.com", "www.example.com",
	)
	if v != VerdictClean && v != VerdictUncertain {
		t.Fatalf("answer within authority should be accepted, got %s", v)
	}
}

func TestClassify_NSInAnswer(t *testing.T) {
	d := newDetector()
	v := classifyRecord(
		d,
		nsRec("sub.example.com.", "ns1.example.com."),
		"example.com", "sub.example.com",
	)
	if v == VerdictHijack {
		t.Fatal("NS records in answer section should not be flagged as hijack")
	}
}

func TestClassify_DSInAnswer(t *testing.T) {
	d := newDetector()
	ds := &dns.DS{
		Hdr: dns.Header{Name: dnsutil.Fqdn("sub.example.com."), Class: dns.ClassINET, TTL: 86400},
	}
	v := classifyRecord(d, ds, "example.com", "sub.example.com")
	if v == VerdictHijack {
		t.Fatal("DS records in answer section should not be flagged as hijack")
	}
}

func TestClassify_DifferentName(t *testing.T) {
	d := newDetector()
	v := classifyRecord(
		d,
		aRec("other.example.com.", "10.0.0.1"),
		"example.com", "www.example.com",
	)
	if v == VerdictHijack {
		t.Fatal("answer for a different name should be accepted")
	}
}

func TestClassify_OutOfAuthority(t *testing.T) {
	d := newDetector()
	v := classifyRecord(
		d,
		aRec("www.example.com.", "10.0.0.1"),
		"com", "www.example.com",
	)
	if v != VerdictHijack {
		t.Fatalf("TLD returning A for subdomain should be VerdictHijack, got %s", v)
	}
}

func TestClassify_RootServerGlue(t *testing.T) {
	d := newDetector()
	v := classifyRecord(
		d,
		aRec("a.root-servers.net.", "198.41.0.4"),
		"", "a.root-servers.net",
	)
	if v == VerdictHijack {
		t.Fatal("root server glue should be accepted")
	}
}

func TestClassify_RootServerUnauthorized(t *testing.T) {
	d := newDetector()
	v := classifyRecord(
		d,
		aRec("www.google.com.", "185.45.5.35"),
		"", "www.google.com",
	)
	if v != VerdictHijack {
		t.Fatalf("root server returning non-glue A should be VerdictHijack, got %s", v)
	}
}

// ── Validate (full response) ──────────────────────────────────────────────────

func TestValidate_NormalAnswer(t *testing.T) {
	d := newDetector()
	resp := &dns.Msg{}
	resp.Answer = []dns.RR{
		aRec("www.example.com.", "10.0.0.1"),
	}
	v := d.Validate("example.com", "www.example.com", resp)
	if v == VerdictHijack {
		t.Fatalf("normal answer should not be hijack, got %s", v)
	}
}

func TestValidate_RootHijack(t *testing.T) {
	d := newDetector()

	resp := &dns.Msg{}
	resp.Answer = []dns.RR{
		aRec("www.google.com.", "185.45.5.35"),
	}

	v := d.Validate("", "www.google.com", resp)
	if v != VerdictHijack {
		t.Fatalf("root server returning A for www.google.com should be VerdictHijack, got %s", v)
	}
}

func TestValidate_TLDHijack(t *testing.T) {
	d := newDetector()

	resp := &dns.Msg{}
	resp.Answer = []dns.RR{
		aRec("www.google.com.", "185.45.5.35"),
	}

	v := d.Validate("com", "www.google.com", resp)
	if v != VerdictHijack {
		t.Fatalf("TLD server returning A for subdomain should be VerdictHijack, got %s", v)
	}
}

func TestValidate_DelegationIsNotHijack(t *testing.T) {
	d := newDetector()

	resp := &dns.Msg{}
	resp.Ns = []dns.RR{
		nsRec("qq.com.cn.", "ns1.qq.com."),
	}
	resp.Extra = []dns.RR{
		aRec("ns1.qq.com.", "1.12.96.10"),
		aRec("ns-cmn1.qq.com.", "43.130.172.24"),
	}

	v := d.Validate("cn", "dns.weixin.qq.com.cn", resp)
	if v == VerdictHijack {
		t.Fatalf("delegation response should not be hijack, got %s", v)
	}
}

func TestValidate_Disabled(t *testing.T) {
	d := &Detector{}
	d.Enable(false)

	resp := &dns.Msg{}
	resp.Answer = []dns.RR{
		aRec("www.google.com.", "185.45.5.35"),
	}

	v := d.Validate("", "www.google.com", resp)
	if v != VerdictClean {
		t.Fatalf("disabled detector should return clean, got %s", v)
	}
}

func TestValidate_NilResponse(t *testing.T) {
	d := newDetector()
	v := d.Validate("example.com", "www.example.com", nil)
	if v != VerdictClean {
		t.Fatalf("nil response should be clean, got %s", v)
	}
}

// ── Real-world regression tests ────────────────────────────────────────────────

func TestHijack_WeixinQQComCN_NotFlagged(t *testing.T) {
	d := newDetector()
	resp := &dns.Msg{}
	resp.Answer = []dns.RR{
		aRec("dns.weixin.qq.com.cn.", "61.151.230.221"),
	}
	resp.Ns = []dns.RR{
		nsRec("qq.com.cn.", "ns1.qq.com."),
	}
	resp.Extra = []dns.RR{
		aRec("ns1.qq.com.", "1.12.96.10"),
		aRec("ns-cmn1.qq.com.", "43.130.172.24"),
	}

	v := d.Validate("qq.com.cn", "dns.weixin.qq.com.cn", resp)
	if v == VerdictHijack {
		t.Fatalf("dns.weixin.qq.com.cn response should not be hijack, got %s", v)
	}
}

func TestHijack_GoogleAtRoot_Flagged(t *testing.T) {
	d := newDetector()
	resp := &dns.Msg{}
	resp.Answer = []dns.RR{
		aRec("www.google.com.", "185.45.5.35"),
	}

	v := d.Validate("", "www.google.com", resp)
	if v != VerdictHijack {
		t.Fatalf("GFW hijack at root level should be VerdictHijack, got %s", v)
	}
}

func TestHijack_GoogleAtComTLD_Flagged(t *testing.T) {
	d := newDetector()
	resp := &dns.Msg{}
	resp.Answer = []dns.RR{
		aRec("www.google.com.", "185.45.5.35"),
	}

	v := d.Validate("com", "www.google.com", resp)
	if v != VerdictHijack {
		t.Fatalf("GFW hijack at TLD level should be VerdictHijack, got %s", v)
	}
}

// ── Delegation section tests (Answer section only) ─────────────────────────────

func TestValidate_LegitimateGlueNotFlagged(t *testing.T) {
	d := newDetector()
	resp := &dns.Msg{}
	resp.Answer = []dns.RR{
		nsRec("youtube.com.", "ns1.google.com."),
		nsRec("youtube.com.", "ns2.google.com."),
	}
	resp.Extra = []dns.RR{
		aRec("ns1.google.com.", "216.239.32.10"),
		aRec("ns2.google.com.", "216.239.34.10"),
		aRec("ns3.google.com.", "216.239.36.10"),
	}

	v := d.Validate("com", "www.youtube.com", resp)
	if v == VerdictHijack {
		t.Fatalf("legitimate glue should not be hijack, got %s", v)
	}
}

func TestValidate_RootServerGlueNotFlagged(t *testing.T) {
	d := newDetector()
	resp := &dns.Msg{}
	resp.Extra = []dns.RR{
		aRec("a.root-servers.net.", "198.41.0.4"),
	}

	v := d.Validate("", "a.root-servers.net", resp)
	if v == VerdictHijack {
		t.Fatalf("root server glue in Additional should not be hijack, got %s", v)
	}
}

func TestValidate_NonMatchingAdditionalNotFlagged(t *testing.T) {
	d := newDetector()
	resp := &dns.Msg{}
	resp.Extra = []dns.RR{
		aRec("www.google.com.", "185.45.5.35"),
	}

	v := d.Validate("", "www.google.com", resp)
	if v == VerdictHijack {
		t.Fatalf("Additional section is not inspected, got %s", v)
	}
}

// ── Helpers ────────────────────────────────────────────────────────────────────

func TestIsTLD_Simple(t *testing.T) {
	d := newDetector()
	if !d.isTLD("com") || !d.isTLD("cn") {
		t.Fatal("'com'/'cn' should be recognized as TLD")
	}
	if d.isTLD("example.com") || d.isTLD("") {
		t.Fatal("'example.com'/'' should not be TLD")
	}
}

func TestIsRootServerGlue(t *testing.T) {
	d := newDetector()
	if !d.isRootServerGlue("a.root-servers.net", dns.TypeA) {
		t.Fatal("root server A glue should be recognized")
	}
	if !d.isRootServerGlue("a.root-servers.net", dns.TypeAAAA) {
		t.Fatal("root server AAAA glue should be recognized")
	}
	if d.isRootServerGlue("evil.com", dns.TypeA) {
		t.Fatal("non-root-server name should not be root glue")
	}
	if d.isRootServerGlue("a.root-servers.net", dns.TypeCNAME) {
		t.Fatal("non-A/AAAA should not be root glue")
	}
}

// ── classifyRoot ───────────────────────────────────────────────────────────────

func TestClassifyRoot_GlueOK(t *testing.T) {
	d := newDetector()
	v := d.classifyRoot("a.root-servers.net", dns.TypeA)
	if v != VerdictClean {
		t.Fatalf("root server glue should be clean, got %s", v)
	}
}

func TestClassifyRoot_EmptyQuery(t *testing.T) {
	d := newDetector()
	v := d.classifyRoot(".", dns.TypeA)
	if v != VerdictClean {
		t.Fatalf("root query domain for root should be clean, got %s", v)
	}
}

func TestClassifyRoot_NonGlueAnswer(t *testing.T) {
	d := newDetector()
	v := d.classifyRoot("www.google.com", dns.TypeA)
	if v != VerdictHijack {
		t.Fatalf("root server returning non-glue A should be VerdictHijack, got %s", v)
	}
}

// ── classifyTLD ────────────────────────────────────────────────────────────────

func TestClassifyTLD_SelfQuery(t *testing.T) {
	d := newDetector()
	v := d.classifyTLD("com", "com")
	if v != VerdictClean {
		t.Fatalf("TLD querying itself should be clean, got %s", v)
	}
}

func TestClassifyTLD_SubdomainAnswer(t *testing.T) {
	d := newDetector()
	v := d.classifyTLD("com", "www.example.com")
	if v != VerdictHijack {
		t.Fatalf("TLD returning A for subdomain should be VerdictHijack, got %s", v)
	}
}

// ── NS record at root level ───────────────────────────────────────────────────

func TestClassify_NSatRootForNonTLD(t *testing.T) {
	// GFW-injected NS record for www.youtube.com at root level.
	d := newDetector()
	v := classifyRecord(
		d,
		nsRec("www.youtube.com.", "fake.gfw.cn."),
		"", "www.youtube.com",
	)
	if v != VerdictHijack {
		t.Fatalf("NS record for non-TLD at root should be VerdictHijack, got %s", v)
	}
}

func TestClassify_NSatRootForTLD(t *testing.T) {
	// Legitimate NS delegation for .com at root level.
	d := newDetector()
	v := classifyRecord(
		d,
		nsRec("com.", "a.gtld-servers.net."),
		"", "com",
	)
	if v == VerdictHijack {
		t.Fatalf("NS record for TLD at root should be clean, got %s", v)
	}
}

// ── Verdict.String ─────────────────────────────────────────────────────────────

func TestVerdict_String(t *testing.T) {
	if s := VerdictClean.String(); s != "clean" {
		t.Fatalf("Clean string: got %q, want %q", s, "clean")
	}
	if s := VerdictHijack.String(); s != "hijack" {
		t.Fatalf("Hijack string: got %q, want %q", s, "hijack")
	}
	if s := VerdictUncertain.String(); s != "uncertain" {
		t.Fatalf("Uncertain string: got %q, want %q", s, "uncertain")
	}
}

// ── Enable / IsEnabled ─────────────────────────────────────────────────────────

func TestDetector_Enable(t *testing.T) {
	d := &Detector{}
	if d.IsEnabled() {
		t.Fatal("new detector should be disabled by default")
	}
	d.Enable(true)
	if !d.IsEnabled() {
		t.Fatal("should be enabled after Enable(true)")
	}
	d.Enable(false)
	if d.IsEnabled() {
		t.Fatal("should be disabled after Enable(false)")
	}
}

// ── Domain normalization round-trip ────────────────────────────────────────────
