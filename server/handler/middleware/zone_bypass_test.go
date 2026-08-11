package middleware

import (
	"context"
	"net"
	"testing"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/ruleset"
	"zjdns/server/handler"
	"zjdns/zone"

	"codeberg.org/miekg/dns"
)

// TestZone_MatchNegation verifies that match=!tag on a zone rule correctly
// exempts tagged clients: clients WITH the tag never match the rule and fall
// through to normal resolution; clients WITHOUT the tag match and are blocked.
func TestZone_MatchNegation(t *testing.T) {
	engine := ruleset.New()
	if err := engine.LoadRules([]config.RuleSet{
		{Tag: "admin", Type: "ip", Rule: []string{"127.0.0.1/32"}},
	}); err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	// No bypass_tags — use match=!admin on the zone rule.
	evaluator := zone.New()
	if err := evaluator.LoadRules([]config.ZoneRule{
		{Name: "example.com", Match: []string{"!admin"}, Rcode: dns.RcodeNameError},
	}); err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	tagMatcher := func(qname string, ip net.IP) map[string]bool {
		return engine.Match(qname, ip.String())
	}

	z := &Zone{evaluator: evaluator, tagMatcher: tagMatcher, cache: cache.New(config.LimitSettings{}, config.LimitSettings{}, "", "")}

	nextCalled := false
	h := z.Wrap(handler.QueryHandlerFunc(func(_ context.Context, qctx *handler.QueryContext) error {
		nextCalled = true
		return nil
	}))

	newQctx := func(ip string) *handler.QueryContext {
		return &handler.QueryContext{
			Req:      newMsg("example.com.", &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}}),
			ClientIP: net.ParseIP(ip),
		}
	}

	// 127.0.0.1 has "admin" -> !admin NOT satisfied -> rule doesn't match -> falls through.
	qctx := newQctx("127.0.0.1")
	_ = h.ServeDNS(context.Background(), qctx)
	if !nextCalled {
		t.Error("127.0.0.1: should fall through (has admin, !admin negates)")
	}

	// ::1 has no tags -> !admin satisfied -> rule matches -> NXDOMAIN.
	nextCalled = false
	qctx2 := newQctx("::1")
	_ = h.ServeDNS(context.Background(), qctx2)
	if nextCalled {
		t.Error("::1: should be blocked (no admin tag, !admin satisfied)")
	}
	if qctx2.Res == nil || qctx2.Res.Rcode != dns.RcodeNameError {
		t.Errorf("::1: rcode = %d, want NXDOMAIN", qctx2.Res.Rcode)
	}
}

// TestZone_MatchNegation_TwoIPs replicates a common gateway bypass pattern:
// two /32 gateway IPs share a tag, zone rules use match=!tag to block
// everyone except the gateways.
func TestZone_MatchNegation_TwoIPs(t *testing.T) {
	engine := ruleset.New()
	if err := engine.LoadRules([]config.RuleSet{
		{Tag: "net_gateway", Type: "ip", Rule: []string{
			"10.192.0.1/32",
			"10.192.32.1/32",
		}},
	}); err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	evaluator := zone.New()
	if err := evaluator.LoadRules([]config.ZoneRule{
		{Name: "example.com", Match: []string{"!net_gateway"}, Rcode: dns.RcodeNameError},
	}); err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	tagMatcher := func(qname string, ip net.IP) map[string]bool {
		return engine.Match(qname, ip.String())
	}

	z := &Zone{evaluator: evaluator, tagMatcher: tagMatcher, cache: cache.New(config.LimitSettings{}, config.LimitSettings{}, "", "")}

	nextCalled := false
	h := z.Wrap(handler.QueryHandlerFunc(func(_ context.Context, qctx *handler.QueryContext) error {
		nextCalled = true
		return nil
	}))

	newQctx := func(ip string) *handler.QueryContext {
		return &handler.QueryContext{
			Req:      newMsg("example.com.", &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}}),
			ClientIP: net.ParseIP(ip),
		}
	}

	for _, ip := range []string{"10.192.0.1", "10.192.32.1"} {
		nextCalled = false
		qctx := newQctx(ip)
		_ = h.ServeDNS(context.Background(), qctx)
		if !nextCalled {
			t.Errorf("%s: should fall through (has net_gateway, !net_gateway negates)", ip)
		}
	}

	// 10.192.39.1 has no net_gateway tag -> !net_gateway satisfied -> blocked.
	nextCalled = false
	qctx := newQctx("10.192.39.1")
	_ = h.ServeDNS(context.Background(), qctx)
	if nextCalled {
		t.Error("10.192.39.1: should be blocked")
	}
	if qctx.Res == nil || qctx.Res.Rcode != dns.RcodeNameError {
		t.Errorf("10.192.39.1: rcode = %d, want NXDOMAIN", qctx.Res.Rcode)
	}
}
