package security

import (
	"testing"

	"github.com/miekg/dns"

	"zjdns/internal/dnsutil"
)

// ── Helpers ────────────────────────────────────────────────────────────────────

func nsRec(name, target string) *dns.NS {
	return &dns.NS{
		Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 86400},
		Ns:  dns.Fqdn(target),
	}
}

func newDetector() *Detector {
	d := &Detector{}
	d.Enable(true)
	return d
}

// ── checkRecord ────────────────────────────────────────────────────────────────

func TestCheckRecord_WithinAuthority(t *testing.T) {
	d := newDetector()
	ok, _ := d.checkRecord(
		aRec("www.example.com.", "10.0.0.1"),
		"example.com",
		"www.example.com",
	)
	if !ok {
		t.Fatal("answer within authority should be accepted")
	}
}

func TestCheckRecord_NSInAnswer(t *testing.T) {
	d := newDetector()
	// NS records in answer section are delegation, not hijack.
	ok, _ := d.checkRecord(
		nsRec("sub.example.com.", "ns1.example.com."),
		"example.com",
		"sub.example.com",
	)
	if !ok {
		t.Fatal("NS records in answer section should be accepted")
	}
}

func TestCheckRecord_DSInAnswer(t *testing.T) {
	d := newDetector()
	ds := &dns.DS{
		Hdr: dns.RR_Header{Name: dns.Fqdn("sub.example.com."), Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 86400},
	}
	ok, _ := d.checkRecord(ds, "example.com", "sub.example.com")
	if !ok {
		t.Fatal("DS records in answer section should be accepted")
	}
}

func TestCheckRecord_DifferentName(t *testing.T) {
	d := newDetector()
	// Answer for a different name (e.g. CNAME target) — not suspect.
	ok, _ := d.checkRecord(
		aRec("other.example.com.", "10.0.0.1"),
		"example.com",
		"www.example.com",
	)
	if !ok {
		t.Fatal("answer for a different name should be accepted")
	}
}

func TestCheckRecord_OutOfAuthority(t *testing.T) {
	d := newDetector()
	// TLD server should never return A records for subdomains.
	ok, reason := d.checkRecord(
		aRec("www.example.com.", "10.0.0.1"),
		"com",
		"www.example.com",
	)
	if ok {
		t.Fatalf("TLD returning A for subdomain should be rejected: %s", reason)
	}
}

func TestCheckRecord_RootServerGlue(t *testing.T) {
	d := newDetector()
	ok, _ := d.checkRecord(
		aRec("a.root-servers.net.", "198.41.0.4"),
		"",
		"a.root-servers.net",
	)
	if !ok {
		t.Fatal("root server glue should be accepted")
	}
}

func TestCheckRecord_RootServerUnauthorized(t *testing.T) {
	d := newDetector()
	// Root server returning A for random domain → hijack.
	ok, _ := d.checkRecord(
		aRec("www.google.com.", "185.45.5.35"),
		"",
		"www.google.com",
	)
	if ok {
		t.Fatal("root server returning non-glue A should be rejected")
	}
}

// ── CheckResponse ──────────────────────────────────────────────────────────────

func TestCheckResponse_NormalAnswer(t *testing.T) {
	d := newDetector()
	resp := &dns.Msg{}
	resp.Answer = []dns.RR{
		aRec("www.example.com.", "10.0.0.1"),
	}
	ok, reason := d.CheckResponse("example.com", "www.example.com", resp)
	if !ok {
		t.Fatalf("normal answer should be accepted: %s", reason)
	}
}

func TestCheckResponse_RootHijack(t *testing.T) {
	d := newDetector()

	// GFW intercepts root server query for www.google.com and injects fake A.
	// Root servers should only return delegations (NS), never A for google.com.
	resp := &dns.Msg{}
	resp.Answer = []dns.RR{
		aRec("www.google.com.", "185.45.5.35"),
	}

	ok, reason := d.CheckResponse("", "www.google.com", resp)
	if ok {
		t.Fatalf("root server returning A for www.google.com should be rejected: %s", reason)
	}
}

func TestCheckResponse_TLDHijack(t *testing.T) {
	d := newDetector()

	// GFW intercepts TLD query and injects fake A record.
	resp := &dns.Msg{}
	resp.Answer = []dns.RR{
		aRec("www.google.com.", "185.45.5.35"),
	}

	ok, reason := d.CheckResponse("com", "www.google.com", resp)
	if ok {
		t.Fatalf("TLD server returning A for subdomain should be rejected: %s", reason)
	}
}

func TestCheckResponse_DelegationIsNotHijack(t *testing.T) {
	d := newDetector()

	// Normal delegation: .cn servers return NS for qq.com.cn.
	// Authority/Additional sections carry NS+glue — not checked.
	resp := &dns.Msg{}
	// Answer section is empty except possibly NS/DS for the delegation
	resp.Ns = []dns.RR{
		nsRec("qq.com.cn.", "ns1.qq.com."),
	}
	resp.Extra = []dns.RR{
		aRec("ns1.qq.com.", "1.12.96.10"),
		aRec("ns-cmn1.qq.com.", "43.130.172.24"),
	}

	ok, reason := d.CheckResponse("cn", "dns.weixin.qq.com.cn", resp)
	if !ok {
		t.Fatalf("delegation response should be accepted: %s", reason)
	}
}

func TestCheckResponse_Disabled(t *testing.T) {
	d := &Detector{}
	d.Enable(false)

	resp := &dns.Msg{}
	resp.Answer = []dns.RR{
		aRec("www.google.com.", "185.45.5.35"),
	}

	ok, _ := d.CheckResponse("", "www.google.com", resp)
	if !ok {
		t.Fatal("disabled detector should accept everything")
	}
}

func TestCheckResponse_NilResponse(t *testing.T) {
	d := newDetector()
	ok, _ := d.CheckResponse("example.com", "www.example.com", nil)
	if !ok {
		t.Fatal("nil response should be accepted")
	}
}

// ── Real-world regression tests ────────────────────────────────────────────────

func TestHijack_WeixinQQComCN_NotFlagged(t *testing.T) {
	// Regression: dns.weixin.qq.com.cn delegation was falsely flagged.
	// The .cn → qq.com.cn delegation has NS in authority and
	// cross-zone CDN-pool glue in additional. Neither triggers hijack.
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

	ok, reason := d.CheckResponse("qq.com.cn", "dns.weixin.qq.com.cn", resp)
	if !ok {
		t.Fatalf("dns.weixin.qq.com.cn response should be accepted: %s", reason)
	}
}

func TestHijack_GoogleAtRoot_Flagged(t *testing.T) {
	// GFW intercepts root query for www.google.com.
	// Root servers must not return A records for www.google.com.
	d := newDetector()
	resp := &dns.Msg{}
	resp.Answer = []dns.RR{
		aRec("www.google.com.", "185.45.5.35"),
	}

	ok, _ := d.CheckResponse("", "www.google.com", resp)
	if ok {
		t.Fatal("GFW hijack at root level should be flagged")
	}
}

func TestHijack_GoogleAtComTLD_Flagged(t *testing.T) {
	// GFW intercepts .com TLD query for www.google.com.
	// TLD servers must not return A records for subdomains.
	d := newDetector()
	resp := &dns.Msg{}
	resp.Answer = []dns.RR{
		aRec("www.google.com.", "185.45.5.35"),
	}

	ok, _ := d.CheckResponse("com", "www.google.com", resp)
	if ok {
		t.Fatal("GFW hijack at TLD level should be flagged")
	}
}

// ── isInAuthority ──────────────────────────────────────────────────────────────

func TestIsInAuthority_Exact(t *testing.T) {
	d := newDetector()
	if !d.isInAuthority("example.com", "example.com") {
		t.Fatal("exact match should be in authority")
	}
}

func TestIsInAuthority_Subdomain(t *testing.T) {
	d := newDetector()
	if !d.isInAuthority("www.example.com", "example.com") {
		t.Fatal("subdomain should be in authority")
	}
}

func TestIsInAuthority_Empty(t *testing.T) {
	d := newDetector()
	if !d.isInAuthority("anything", "") {
		t.Fatal("empty authority (root) accepts everything")
	}
}

func TestIsInAuthority_NotInAuthority(t *testing.T) {
	d := newDetector()
	if d.isInAuthority("other.com", "example.com") {
		t.Fatal("different domain should not be in authority")
	}
}

// ── isTLD ──────────────────────────────────────────────────────────────────────

func TestIsTLD_Simple(t *testing.T) {
	d := newDetector()
	if !d.isTLD("com") || !d.isTLD("cn") {
		t.Fatal("'com'/'cn' should be recognized as TLD")
	}
	if d.isTLD("example.com") || d.isTLD("") {
		t.Fatal("'example.com'/'' should not be TLD")
	}
}

// ── isRootServerGlue ───────────────────────────────────────────────────────────

func TestIsRootServerGlue_A(t *testing.T) {
	d := newDetector()
	if !d.isRootServerGlue("a.root-servers.net", dns.TypeA) {
		t.Fatal("root server A glue should be recognized")
	}
}

func TestIsRootServerGlue_AAAA(t *testing.T) {
	d := newDetector()
	if !d.isRootServerGlue("a.root-servers.net", dns.TypeAAAA) {
		t.Fatal("root server AAAA glue should be recognized")
	}
}

func TestIsRootServerGlue_NotGlue(t *testing.T) {
	d := newDetector()
	if d.isRootServerGlue("evil.com", dns.TypeA) {
		t.Fatal("non-root-server name should not be root glue")
	}
	if d.isRootServerGlue("a.root-servers.net", dns.TypeCNAME) {
		t.Fatal("non-A/AAAA should not be root glue")
	}
}

// ── validateRootServer ─────────────────────────────────────────────────────────

func TestValidateRootServer_GlueOK(t *testing.T) {
	d := newDetector()
	ok, _ := d.validateRootServer("a.root-servers.net", dns.TypeA)
	if !ok {
		t.Fatal("root server glue should be accepted")
	}
}

func TestValidateRootServer_EmptyQuery(t *testing.T) {
	d := newDetector()
	ok, _ := d.validateRootServer("", dns.TypeA)
	if !ok {
		t.Fatal("empty query domain for root should be accepted")
	}
}

func TestValidateRootServer_NonGlueAnswer(t *testing.T) {
	d := newDetector()
	ok, _ := d.validateRootServer("www.google.com", dns.TypeA)
	if ok {
		t.Fatal("root server returning non-glue A should be rejected")
	}
}

// ── validateTLDServer ──────────────────────────────────────────────────────────

func TestValidateTLDServer_SelfQuery(t *testing.T) {
	d := newDetector()
	ok, _ := d.validateTLDServer("com", "com", dns.TypeSOA)
	if !ok {
		t.Fatal("TLD querying itself should be accepted")
	}
}

func TestValidateTLDServer_SubdomainAnswer(t *testing.T) {
	d := newDetector()
	ok, _ := d.validateTLDServer("com", "www.example.com", dns.TypeA)
	if ok {
		t.Fatal("TLD returning A for subdomain should be rejected")
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

func TestDomainNormalization(t *testing.T) {
	raw := "ns-cmn1.qq.com."
	normalized := dnsutil.NormalizeDomain(raw)
	if normalized == "" {
		t.Fatal("normalized domain should not be empty")
	}
	if normalized[len(normalized)-1] == '.' {
		t.Fatal("normalized domain should not end with trailing dot")
	}
}
