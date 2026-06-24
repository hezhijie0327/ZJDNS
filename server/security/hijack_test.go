package security

import (
	"net"
	"testing"

	"github.com/miekg/dns"

	"zjdns/internal/dnsutil"
)

// ── Helpers ────────────────────────────────────────────────────────────────────

func aaaaRec(name, ip string) *dns.AAAA {
	return &dns.AAAA{
		Hdr:  dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
		AAAA: net.ParseIP(ip),
	}
}

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

// ── checkGlueRecord ────────────────────────────────────────────────────────────

func TestCheckGlueRecord_InBailiwick(t *testing.T) {
	d := newDetector()

	// Glue within the current zone — always legitimate.
	nsTargets := map[string]bool{}
	ok, reason := d.checkGlueRecord(
		aRec("ns1.example.com.", "10.0.0.1"),
		"example.com",
		nsTargets,
	)
	if !ok {
		t.Fatalf("in-bailiwick glue should be accepted, got: %s", reason)
	}
}

func TestCheckGlueRecord_GlueEqualsCurrentDomain(t *testing.T) {
	d := newDetector()

	// Glue name equals the current domain itself.
	nsTargets := map[string]bool{}
	ok, _ := d.checkGlueRecord(
		aRec("example.com.", "10.0.0.1"),
		"example.com",
		nsTargets,
	)
	if !ok {
		t.Fatal("glue matching current domain should be accepted")
	}
}

func TestCheckGlueRecord_ExactNSMatch(t *testing.T) {
	d := newDetector()

	// Cross-zone delegation: current zone is qq.com.cn but glue
	// matches an NS target exactly (ns1.qq.com).
	nsTargets := map[string]bool{
		"ns1.qq.com": true,
	}
	ok, _ := d.checkGlueRecord(
		aRec("ns1.qq.com.", "10.0.0.1"),
		"qq.com.cn",
		nsTargets,
	)
	if !ok {
		t.Fatal("glue matching an NS target should be accepted")
	}
}

func TestCheckGlueRecord_CDNPoolGlue(t *testing.T) {
	d := newDetector()

	// CDN pool: ns-cmn1.qq.com shares the parent domain (qq.com)
	// with NS target ns1.qq.com.
	nsTargets := map[string]bool{
		"ns1.qq.com":  true,
		"qq.com":      true,
	}
	ok, _ := d.checkGlueRecord(
		aRec("ns-cmn1.qq.com.", "10.0.0.1"),
		"qq.com.cn",
		nsTargets,
	)
	if !ok {
		t.Fatal("CDN pool glue sharing parent domain with NS target should be accepted")
	}
}

func TestCheckGlueRecord_CDNPoolGlueV6(t *testing.T) {
	d := newDetector()

	// Same scenario with AAAA record.
	nsTargets := map[string]bool{
		"ns1.qq.com":  true,
		"qq.com":      true,
	}
	ok, _ := d.checkGlueRecord(
		aaaaRec("ns-cnc1.qq.com.", "2001:db8::1"),
		"qq.com.cn",
		nsTargets,
	)
	if !ok {
		t.Fatal("AAAA CDN pool glue sharing parent domain should be accepted")
	}
}

func TestCheckGlueRecord_UnrelatedGlue(t *testing.T) {
	d := newDetector()

	// Glue for a completely unrelated domain.
	nsTargets := map[string]bool{
		"ns1.example.org": true,
	}
	ok, reason := d.checkGlueRecord(
		aRec("evil.phishing.com.", "10.0.0.1"),
		"example.com",
		nsTargets,
	)
	if ok {
		t.Fatal("unrelated glue should be rejected")
	}
	if reason == "" {
		t.Fatal("rejection should include a reason")
	}
}

func TestCheckGlueRecord_EmptyNSTargets(t *testing.T) {
	d := newDetector()

	// No NS targets — only in-bailiwick should pass.
	nsTargets := map[string]bool{}
	ok, _ := d.checkGlueRecord(
		aRec("sub.example.com.", "10.0.0.1"),
		"example.com",
		nsTargets,
	)
	if !ok {
		t.Fatal("in-bailiwick glue should be accepted even with empty nsTargets")
	}

	ok, _ = d.checkGlueRecord(
		aRec("other.com.", "10.0.0.1"),
		"example.com",
		nsTargets,
	)
	if ok {
		t.Fatal("unrelated glue should be rejected with empty nsTargets")
	}
}

func TestCheckGlueRecord_RootZone(t *testing.T) {
	d := newDetector()

	// Root zone glue for root-servers.net.
	nsTargets := map[string]bool{
		"a.root-servers.net": true,
	}
	ok, _ := d.checkGlueRecord(
		aRec("a.root-servers.net.", "198.41.0.4"),
		".",
		nsTargets,
	)
	if !ok {
		t.Fatal("root zone glue should be accepted (matches current domain '.')")
	}
}

func TestCheckGlueRecord_TLDZone(t *testing.T) {
	d := newDetector()

	// TLD glue: .cn zone returns glue for .cn nameservers.
	nsTargets := map[string]bool{
		"a.dns.cn": true,
	}
	ok, _ := d.checkGlueRecord(
		aRec("a.dns.cn.", "203.119.25.1"),
		"cn",
		nsTargets,
	)
	if !ok {
		t.Fatal("TLD glue within current zone should be accepted")
	}
}

func TestCheckGlueRecord_MultiLabelParentDomain(t *testing.T) {
	d := newDetector()

	// Delegation from co.uk style TLD: sub.example.co.uk delegating
	// to ns1.other.co.uk.
	nsTargets := map[string]bool{
		"ns1.other.co.uk": true,
		"other.co.uk":     true,
	}
	ok, _ := d.checkGlueRecord(
		aRec("ns-cdn1.other.co.uk.", "10.0.0.1"),
		"example.co.uk",
		nsTargets,
	)
	if !ok {
		t.Fatal("glue under multi-label parent domain should be accepted")
	}
}

// ── checkRecord (Answer section) ───────────────────────────────────────────────

func TestCheckRecord_WithinAuthority(t *testing.T) {
	d := newDetector()

	// Answer within the queried zone.
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

	// NS record in answer section is always skipped (delegation response).
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

	// DS record in answer section is always skipped.
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

	// Answer for a different name than queried (e.g. CNAME target in additional).
	ok, _ := d.checkRecord(
		aRec("other.example.com.", "10.0.0.1"),
		"example.com",
		"www.example.com",
	)
	if !ok {
		t.Fatal("answer for a name different from query should be accepted")
	}
}

func TestCheckRecord_OutOfAuthority(t *testing.T) {
	d := newDetector()

	// TLD returning answer for a subdomain.
	ok, reason := d.checkRecord(
		aRec("www.example.com.", "10.0.0.1"),
		"com",
		"www.example.com",
	)
	if ok {
		t.Fatalf("TLD should not return A records for subdomains, but was accepted: %s", reason)
	}
}

func TestCheckRecord_RootServerGlue(t *testing.T) {
	d := newDetector()

	// Root server returning glue A record.
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

	// Root server returning non-glue answer.
	ok, _ := d.checkRecord(
		aRec("www.example.com.", "10.0.0.1"),
		"",
		"www.example.com",
	)
	if ok {
		t.Fatal("root server should not return non-glue answers")
	}
}

// ── checkAuthorityRecord ───────────────────────────────────────────────────────

func TestCheckAuthorityRecord_WithinZone(t *testing.T) {
	d := newDetector()

	// NS record for a subdomain of the current zone.
	ok, _ := d.checkAuthorityRecord(
		nsRec("sub.example.com.", "ns1.sub.example.com."),
		"example.com",
		nil,
	)
	if !ok {
		t.Fatal("NS in authority for subdomain of current zone should be accepted")
	}
}

func TestCheckAuthorityRecord_CurrentZoneNS(t *testing.T) {
	d := newDetector()

	// NS record naming the current zone itself (delegation from parent).
	ok, _ := d.checkAuthorityRecord(
		nsRec("example.com.", "ns1.example.com."),
		"com",
		nil,
	)
	if !ok {
		t.Fatal("NS naming current zone should be accepted when current zone is under the NS name")
	}
}

func TestCheckAuthorityRecord_CNAMEReferral(t *testing.T) {
	d := newDetector()

	// CNAME target zone NS records — standard referral behavior (RFC 1034 §4.3.2).
	ok, _ := d.checkAuthorityRecord(
		nsRec("cdn.example.net.", "ns1.cdn.example.net."),
		"example.com",
		[]string{"cdn.example.net"},
	)
	if !ok {
		t.Fatal("NS for CNAME target zone should be accepted")
	}
}

func TestCheckAuthorityRecord_UnrelatedZone(t *testing.T) {
	d := newDetector()

	// NS for a completely unrelated zone — potential injection.
	ok, _ := d.checkAuthorityRecord(
		nsRec("phishing.com.", "ns1.phishing.com."),
		"example.com",
		nil,
	)
	if ok {
		t.Fatal("NS for unrelated zone should be rejected")
	}
}

func TestCheckAuthorityRecord_NonNSType(t *testing.T) {
	d := newDetector()

	// Non-NS record in authority (SOA, etc.) — not validated here.
	soa := &dns.SOA{
		Hdr: dns.RR_Header{Name: dns.Fqdn("example.com."), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
	}
	ok, _ := d.checkAuthorityRecord(soa, "example.com", nil)
	if !ok {
		t.Fatal("non-NS records in authority should always be accepted")
	}
}

// ── CheckResponse (integration) ────────────────────────────────────────────────

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

func TestCheckResponse_CrossZoneDelegation(t *testing.T) {
	d := newDetector()

	// Simulate qq.com.cn delegating to ns1.qq.com with glue.
	resp := &dns.Msg{}
	resp.Ns = []dns.RR{
		nsRec("qq.com.cn.", "ns1.qq.com."),
		nsRec("qq.com.cn.", "ns2.qq.com."),
	}
	resp.Extra = []dns.RR{
		aRec("ns1.qq.com.", "10.0.0.1"),
		aRec("ns2.qq.com.", "10.0.0.2"),
	}

	ok, reason := d.CheckResponse("cn", "dns.weixin.qq.com.cn", resp)
	if !ok {
		t.Fatalf("cross-zone delegation with matching glue should be accepted: %s", reason)
	}
}

func TestCheckResponse_CDNPoolGlue(t *testing.T) {
	d := newDetector()

	// qq.com.cn response with CDN pool glue records.
	resp := &dns.Msg{}
	resp.Ns = []dns.RR{
		nsRec("qq.com.cn.", "ns1.qq.com."),
		nsRec("qq.com.cn.", "ns2.qq.com."),
	}
	resp.Extra = []dns.RR{
		aRec("ns1.qq.com.", "10.0.0.1"),
		aRec("ns-cmn1.qq.com.", "10.0.0.3"), // CDN pool
		aRec("ns-cnc1.qq.com.", "10.0.0.4"), // CDN pool
	}

	ok, reason := d.CheckResponse("cn", "dns.weixin.qq.com.cn", resp)
	if !ok {
		t.Fatalf("CDN pool glue sharing parent domain should be accepted: %s", reason)
	}
}

func TestCheckResponse_SuspiciousGlue(t *testing.T) {
	d := newDetector()

	// Attacker injects unrelated glue. Use a non-TLD currentDomain
	// so the in-bailiwick check does not cover the attacker domain.
	// (evil.phishing.net is NOT under "example.com").
	resp := &dns.Msg{}
	resp.Ns = []dns.RR{
		nsRec("sub.example.com.", "ns1.sub.example.com."),
	}
	resp.Extra = []dns.RR{
		aRec("ns1.sub.example.com.", "10.0.0.1"),     // OK — matches NS
		aRec("evil.phishing.net.", "192.168.1.1"),    // SUSPICIOUS — different domain
	}

	ok, reason := d.CheckResponse("example.com", "www.sub.example.com", resp)
	if ok {
		t.Fatalf("unrelated glue should be rejected, but was accepted: %s", reason)
	}
	if reason == "" {
		t.Fatal("rejection should include a reason")
	}
}

func TestCheckResponse_Disabled(t *testing.T) {
	d := &Detector{}
	d.Enable(false)

	// All suspicious — but detection is off.
	resp := &dns.Msg{}
	resp.Extra = []dns.RR{
		aRec("evil.phishing.com.", "192.168.1.1"),
	}

	ok, _ := d.CheckResponse("example.com", "www.example.com", resp)
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

func TestCheckResponse_SuspiciousAuthorityNS(t *testing.T) {
	d := newDetector()

	// Authority NS for unrelated zone.
	resp := &dns.Msg{}
	resp.Ns = []dns.RR{
		nsRec("phishing.com.", "ns1.phishing.com."),
	}

	ok, _ := d.CheckResponse("example.com", "www.example.com", resp)
	if ok {
		t.Fatal("authority NS for unrelated zone should be rejected")
	}
}

func TestCheckResponse_TLDServerReturnsSubdomainAnswer(t *testing.T) {
	d := newDetector()

	// A TLD server should never return A records for subdomains.
	resp := &dns.Msg{}
	resp.Answer = []dns.RR{
		aRec("www.example.com.", "10.0.0.1"),
	}

	ok, _ := d.CheckResponse("com", "www.example.com", resp)
	if ok {
		t.Fatal("TLD server returning A record for subdomain should be rejected")
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
		t.Fatal("empty authority (root) should accept everything")
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
	if !d.isTLD("com") {
		t.Fatal("'com' should be recognized as TLD")
	}
	if !d.isTLD("cn") {
		t.Fatal("'cn' should be recognized as TLD")
	}
}

func TestIsTLD_NotTLD(t *testing.T) {
	d := newDetector()
	if d.isTLD("example.com") {
		t.Fatal("'example.com' should not be recognized as TLD")
	}
	if d.isTLD("") {
		t.Fatal("empty string should not be recognized as TLD")
	}
}

// ── isRootServerGlue ───────────────────────────────────────────────────────────

func TestIsRootServerGlue_A(t *testing.T) {
	d := newDetector()
	if !d.isRootServerGlue("a.root-servers.net", dns.TypeA) {
		t.Fatal("a.root-servers.net A should be recognized as root server glue")
	}
}

func TestIsRootServerGlue_AAAA(t *testing.T) {
	d := newDetector()
	if !d.isRootServerGlue("a.root-servers.net", dns.TypeAAAA) {
		t.Fatal("a.root-servers.net AAAA should be recognized as root server glue")
	}
}

func TestIsRootServerGlue_NotAGlue(t *testing.T) {
	d := newDetector()
	if d.isRootServerGlue("a.root-servers.net", dns.TypeCNAME) {
		t.Fatal("non-A/AAAA should not be root server glue")
	}
	if d.isRootServerGlue("evil.com", dns.TypeA) {
		t.Fatal("non-root-server name should not be root server glue")
	}
}

// ── validateRootServer ─────────────────────────────────────────────────────────

func TestValidateRootServer_GlueOK(t *testing.T) {
	d := newDetector()
	ok, _ := d.validateRootServer("a.root-servers.net", dns.TypeA)
	if !ok {
		t.Fatal("root server glue A record should be accepted")
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
	ok, _ := d.validateRootServer("www.example.com", dns.TypeA)
	if ok {
		t.Fatal("root server should not return non-glue A records")
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
		t.Fatal("TLD should not return A records for subdomains")
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
		t.Fatal("detector should be enabled after Enable(true)")
	}
	d.Enable(false)
	if d.IsEnabled() {
		t.Fatal("detector should be disabled after Enable(false)")
	}
}

// ── Normalize round-trip ───────────────────────────────────────────────────────

func TestGlueRecordDomainNormalization(t *testing.T) {
	// Verify that the domain normalization used in checkGlueRecord
	// matches the normalization in CheckResponse's nsTargetDomains build.
	raw := "ns-cmn1.qq.com."
	normalized := dnsutil.NormalizeDomain(raw)
	if normalized == "" {
		t.Fatal("normalized domain should not be empty")
	}
	if normalized[len(normalized)-1] == '.' {
		t.Fatal("normalized domain should not end with a trailing dot")
	}
}

// ── Real-world regression: dns.weixin.qq.com.cn ────────────────────────────────

func TestCheckResponse_WeixinQQComCN(t *testing.T) {
	d := newDetector()

	// Replicate the exact scenario from the qq.com.cn authoritative
	// response that was falsely flagged as hijacking.
	resp := &dns.Msg{}
	resp.Answer = []dns.RR{
		aRec("dns.weixin.qq.com.cn.", "61.151.230.221"),
		aRec("dns.weixin.qq.com.cn.", "106.39.206.21"),
	}
	// Authority section: NS records for the zone
	resp.Ns = []dns.RR{
		nsRec("qq.com.cn.", "ns1.qq.com."),
		nsRec("qq.com.cn.", "ns2.qq.com."),
	}
	// Additional section: glue for NS targets + CDN pool
	resp.Extra = []dns.RR{
		aRec("ns1.qq.com.", "1.12.96.10"),
		aRec("ns-cmn1.qq.com.", "43.130.172.24"), // CDN pool — was flagged
		aRec("ns-cnc1.qq.com.", "43.134.249.22"), // CDN pool — was flagged
	}

	ok, reason := d.CheckResponse("qq.com.cn", "dns.weixin.qq.com.cn", resp)
	if !ok {
		t.Fatalf("dns.weixin.qq.com.cn response should be accepted: %s", reason)
	}
}
