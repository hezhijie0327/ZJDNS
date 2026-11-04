package upstream

import (
	"context"
	"testing"
	"zjdns/config"
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
