package upstream

import (
	"context"
	"testing"
	"zjdns/config"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// TestHopGuardConfidentDrivesUncertaintyMark verifies the guard-state
// primitive behind the defense-uncertainty mark: Confident is false while
// the TTL baseline is learning (every response must be flagged Uncertain)
// and true once corroborated samples arm it (responses are TTL-verified,
// mark cleared).
func TestHopGuardConfidentDrivesUncertaintyMark(t *testing.T) {
	c := New()
	const addr = "127.0.0.1:1"
	hg := c.plainClient.HopGuard()
	if hg == nil {
		t.Fatal("hopguard must exist")
	}

	if hg.Confident(addr) {
		t.Fatal("unarmed baseline must not be confident — responses are defense-uncertain")
	}

	// Arm the baseline with corroborated samples (realTTL cluster).
	for range 64 {
		hg.Feed(addr, 57)
	}
	if !hg.Confident(addr) {
		t.Fatal("armed baseline must be confident — responses are TTL-verified")
	}
}

// TestExecuteQuery_UncertaintyMarkMatrix pins the defense-uncertainty mark
// across the guard/verification matrix:
//
//	hopguard learning + collect         → marked (learning is unverified)
//	hopguard armed + collect            → cleared (armed fingerprint + this
//	                                      query ran the collect discipline)
//	hopguard armed + 0x20 echo OK       → cleared (either positive
//	                                      verification suffices)
//	hopguard learning + 0x20 echo OK    → cleared (echo is per-query proof)
//	capsguard unverified retry          → marked (retry carries no entropy)
//	no guards                           → unmarked
func TestExecuteQuery_UncertaintyMarkMatrix(t *testing.T) {
	cases := []struct {
		name       string
		caps       bool
		hop        bool
		lowercase  bool // middlebox rewrites the echoed case → unverified retry
		wantMarked bool
	}{
		{"hopguard learning marks", false, true, false, true},
		{"hopguard armed clears", false, true, false, false}, // armed below
		{"hopguard learning + echo OK clears", true, true, false, false},
		{"capsguard unverified retry marks", true, false, true, true},
		{"no guards unmarked", false, false, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			addr, _, shutdown := startFakeEchoUDPServer(t, c.lowercase)
			defer shutdown()

			client := New()
			defer client.Close()
			server := &config.UpstreamServer{Address: addr, Protocol: config.ProtoUDP, CapsGuard: c.caps, HopGuard: c.hop}

			if c.name == "hopguard armed clears" {
				// Arm from live traffic: the fake server's datagrams carry the
				// platform's real loopback TTL, which Validate compares the
				// final query against — a synthetic Feed value would reject
				// every real packet once armed.
				hg := client.plainClient.HopGuard()
				for range 64 {
					res := client.ExecuteQuery(context.Background(), queryA("arm.example.com."), server)
					if res.Error != nil {
						t.Fatalf("arming query failed: %v", res.Error)
					}
				}
				if !hg.Confident(addr) {
					t.Fatal("pre-flight: baseline did not arm from live TTLs")
				}
			}

			res := client.ExecuteQuery(context.Background(), queryA("case.example.com."), server)
			if res.Error != nil {
				t.Fatalf("ExecuteQuery: %v", res.Error)
			}
			if res.Uncertain != c.wantMarked {
				t.Fatalf("Uncertain = %v, want %v", res.Uncertain, c.wantMarked)
			}
			// A marked UDP result must also be collect-verified-or-marked
			// consistent: single-read (verified=false) responses never clear
			// via hopArmed.
			if !c.wantMarked && c.hop && !client.plainClient.HopGuard().Confident(addr) && !c.caps {
				t.Fatal("learning-phase hopguard without caps cannot clear the mark")
			}
		})
	}
}

// TestExecuteUDP_SingleReadNotVerified pins the plumbing behind the matrix:
// the pooled collect discipline reports verified=true, while the guards-off
// single-read path reports false — the per-query flag hopArmed relies on.
func TestExecuteUDP_SingleReadNotVerified(t *testing.T) {
	addr, _, shutdown := startFakeEchoUDPServer(t, false)
	defer shutdown()

	client := New()
	defer client.Close()

	// Guards off → single-read pooled path.
	msg := queryA("plain.example.com.")
	server := &config.UpstreamServer{Address: addr, Protocol: config.ProtoUDP}
	resp, verified, err := client.plainClient.ExecuteUDP(context.Background(), msg, server)
	if err != nil || resp == nil {
		t.Fatalf("ExecuteUDP: resp=%v err=%v", resp, err)
	}
	if verified {
		t.Fatal("single-read path must report verified=false")
	}

	// Spoofguard on → collect discipline for an A query.
	serverGuarded := &config.UpstreamServer{Address: addr, Protocol: config.ProtoUDP, Spoofguard: true}
	resp2, verified2, err2 := client.plainClient.ExecuteUDP(context.Background(), queryA("guarded.example.com."), serverGuarded)
	if err2 != nil || resp2 == nil {
		t.Fatalf("ExecuteUDP (collect): resp=%v err=%v", resp2, err2)
	}
	if !verified2 {
		t.Fatal("collect-disciplined response must report verified=true")
	}
}

// TestExecuteQuery_NonAQtypeArmedCaches pins the qtype scoping of the
// per-datagram verification requirement: the collect discipline only runs
// for A/AAAA (the injection targets), so a TXT query against an armed
// baseline stays cacheable — requiring per-query verification for qtypes
// that can never run it would mark every non-A response no-cache forever.
func TestExecuteQuery_NonAQtypeArmedCaches(t *testing.T) {
	addr, _, shutdown := startFakeEchoUDPServer(t, false)
	defer shutdown()

	client := New()
	defer client.Close()
	server := &config.UpstreamServer{Address: addr, Protocol: config.ProtoUDP, HopGuard: true}

	// Arm the baseline from live A-query traffic.
	hg := client.plainClient.HopGuard()
	for range 64 {
		res := client.ExecuteQuery(context.Background(), queryA("arm.example.com."), server)
		if res.Error != nil {
			t.Fatalf("arming query failed: %v", res.Error)
		}
	}
	if !hg.Confident(addr) {
		t.Fatal("pre-flight: baseline did not arm")
	}

	txt := new(dns.Msg)
	txt.ID = 0x1234
	dnsutil.SetQuestion(txt, "txt.example.com.", dns.TypeTXT, dns.ClassINET)
	res := client.ExecuteQuery(context.Background(), txt, server)
	if res.Error != nil {
		t.Fatalf("ExecuteQuery: %v", res.Error)
	}
	if res.Uncertain {
		t.Fatal("non-A query against an armed baseline must stay cacheable (no collect discipline exists for it)")
	}
}

// TestExecuteQuery_NonAQtypeArmedWrongTTLMarked pins the per-datagram half
// of the armed-baseline clearing: an armed fingerprint that does NOT match
// this datagram's captured TTL is not a verification — the response must
// carry the no-cache mark.  The baseline is armed at a TTL no loopback
// datagram can carry, so the real captured TTL fails Validate.
func TestExecuteQuery_NonAQtypeArmedWrongTTLMarked(t *testing.T) {
	addr, _, shutdown := startFakeEchoUDPServer(t, false)
	defer shutdown()

	client := New()
	defer client.Close()
	server := &config.UpstreamServer{Address: addr, Protocol: config.ProtoUDP, HopGuard: true}

	// Arm the baseline at an impossible TTL (real loopback datagrams are
	// 255 on macOS / 64 on Linux — 57 matches neither).
	hg := client.plainClient.HopGuard()
	for range 64 {
		hg.Feed(addr, 57)
	}
	if !hg.Confident(addr) {
		t.Fatal("pre-flight: baseline did not arm")
	}

	txt := new(dns.Msg)
	txt.ID = 0x4321
	dnsutil.SetQuestion(txt, "txt-wrongttl.example.com.", dns.TypeTXT, dns.ClassINET)
	res := client.ExecuteQuery(context.Background(), txt, server)
	if res.Error != nil {
		t.Fatalf("ExecuteQuery: %v", res.Error)
	}
	if !res.Uncertain {
		t.Fatal("non-A datagram failing the armed TTL window must be marked no-cache — an armed baseline alone never clears a single-read datagram")
	}
}

// TestExecuteUDP_SingleReadTTLVerified pins the positive half: a single-read
// datagram whose captured TTL passes the armed fingerprint window reports
// verified=true (the per-query proof hopArmed clearing relies on).
func TestExecuteUDP_SingleReadTTLVerified(t *testing.T) {
	addr, _, shutdown := startFakeEchoUDPServer(t, false)
	defer shutdown()

	client := New()
	defer client.Close()

	// Arm from live traffic on the same loopback path the query takes, so
	// the captured TTL class matches.
	server := &config.UpstreamServer{Address: addr, Protocol: config.ProtoUDP, HopGuard: true}
	for range 64 {
		res := client.ExecuteQuery(context.Background(), queryA("ttlarm.example.com."), server)
		if res.Error != nil {
			t.Fatalf("arming query failed: %v", res.Error)
		}
	}
	hg := client.plainClient.HopGuard()
	if !hg.Confident(addr) {
		t.Fatal("pre-flight: baseline did not arm")
	}

	// TXT (non-A) — served by the pooled single-read path; the datagram's
	// TTL passes the armed window.
	txt := new(dns.Msg)
	txt.ID = 0x4322
	dnsutil.SetQuestion(txt, "txt-ok.example.com.", dns.TypeTXT, dns.ClassINET)
	resp, verified, err := client.plainClient.ExecuteUDP(context.Background(), txt, server)
	if err != nil || resp == nil {
		t.Fatalf("ExecuteUDP: resp=%v err=%v", resp, err)
	}
	if !verified {
		t.Fatal("single-read datagram passing the armed TTL window must report verified=true")
	}
}

// TestExecuteQuery_SpoofguardOnlyScoping pins the spoofguard-only marking
// scope (Round C RC-1): the collect discipline is the whole defense there,
// so a collect-verified A response stays cacheable, while the degraded
// single-read path (non-A qtypes never run collect) carries the mark.
func TestExecuteQuery_SpoofguardOnlyScoping(t *testing.T) {
	addr, _, shutdown := startFakeEchoUDPServer(t, false)
	defer shutdown()

	client := New()
	defer client.Close()
	server := &config.UpstreamServer{Address: addr, Protocol: config.ProtoUDP, Spoofguard: true}

	// A query — spoofguard collect discipline runs and verifies.
	resA := client.ExecuteQuery(context.Background(), queryA("spoof-a.example.com."), server)
	if resA.Error != nil {
		t.Fatalf("A query failed: %v", resA.Error)
	}
	if resA.Uncertain {
		t.Fatal("spoofguard-only collect-disciplined A response must stay cacheable — marking every response would collapse the cache for this configuration")
	}

	// TXT query — no collect discipline exists for it; the single-read
	// datagram is the degraded path spoofguard-only marking targets.
	txt := new(dns.Msg)
	txt.ID = 0x4323
	dnsutil.SetQuestion(txt, "spoof-txt.example.com.", dns.TypeTXT, dns.ClassINET)
	resTXT := client.ExecuteQuery(context.Background(), txt, server)
	if resTXT.Error != nil {
		t.Fatalf("TXT query failed: %v", resTXT.Error)
	}
	if !resTXT.Uncertain {
		t.Fatal("spoofguard-only single-read (non-A) response must carry the no-cache mark")
	}
}
