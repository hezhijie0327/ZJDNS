package resolver

import (
	"context"
	"testing"
	"time"
	"zjdns/edns"
	"zjdns/server/upstream"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// TestResolve_PoisonProbeOverlapsDataQuery covers the overlapped TLD hijack
// probe.  The probe and the full-QNAME data query hit the same servers, so
// the scripted TLD handler distinguishes them by EDNS presence: walk data
// queries carry an OPT record (buildMsg), the bare probe query does not
// (probeTLDForPoison builds its own message).
//
// The walk is three levels — root → test. (TLD) → child.test. — because the
// poisonguard detector legitimately flags A/AAAA for subdomains coming from
// a TLD zone; the final A answer must come from the child zone's own servers.
//
// Clean case: probe and data query are each delayed 300ms — serializing the
// probe before the query would take ≥600ms; overlapping them takes ~300ms.
// Poisoned case: the injected probe answer must discard the concurrent UDP
// data answer and restart the walk over TCP (Poisoned=true, correct answer).
func TestResolve_PoisonProbeOverlapsDataQuery(t *testing.T) {
	const levelDelay = 300 * time.Millisecond
	qname := "example.child.test."

	cases := []struct {
		name        string
		poisonProbe bool
		wantPoison  bool
	}{
		{"clean probe overlaps the data query", false, false},
		{"poisoned probe discards the UDP answer and restarts over TCP", true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rootHintsOnce.Do(func() {})
			oldHints := rootHints
			rootHints = map[string][]string{"a.root-servers.test.": {"10.9.0.1:53"}}
			t.Cleanup(func() { rootHints = oldHints })

			delayed := func(ctx context.Context, delay time.Duration) bool {
				select {
				case <-time.After(delay):
					return true
				case <-ctx.Done():
					return false
				}
			}

			// Glue addresses per zone level.
			tldNS := func(name string) dns.RR {
				return &dns.NS{Hdr: dns.Header{Name: "test.", Class: dns.ClassINET, TTL: 300}, Ns: name}
			}
			childNS := func(name string) dns.RR {
				return &dns.NS{Hdr: dns.Header{Name: "child.test.", Class: dns.ClassINET, TTL: 300}, Ns: name}
			}

			rootHandler := func(ctx context.Context, msg *dns.Msg) *upstream.Result {
				if len(msg.Question) > 0 && dns.RRToType(msg.Question[0]) == dns.TypeDNSKEY {
					return nsReply(msg, dns.RcodeSuccess)
				}
				resp := dnsutil.SetReply(new(dns.Msg), msg)
				resp.Ns = append(resp.Ns, tldNS("ns1.test."), tldNS("ns2.test."))
				resp.Extra = append(resp.Extra, aRec("ns1.test.", "10.9.0.2"), aRec("ns2.test.", "10.9.0.3"))
				return &upstream.Result{Response: resp}
			}
			mkTLDHandler := func() nsScriptHandler {
				return func(ctx context.Context, msg *dns.Msg) *upstream.Result {
					if len(msg.Pseudo) == 0 {
						// Bare query = the hijack probe.
						if c.poisonProbe {
							resp := dnsutil.SetReply(new(dns.Msg), msg)
							resp.Answer = append(resp.Answer, aRec(qname, "93.46.8.89")) // GFW blackhole injection
							return &upstream.Result{Response: resp}
						}
						if !delayed(ctx, levelDelay) {
							return &upstream.Result{Error: ctx.Err()}
						}
						return nsReply(msg, dns.RcodeSuccess) // clean — no answer records
					}
					// EDNS query = the walk's data query → referral to child zone.
					resp := dnsutil.SetReply(new(dns.Msg), msg)
					resp.Ns = append(resp.Ns, childNS("ns1.child.test."), childNS("ns2.child.test."))
					resp.Extra = append(resp.Extra, aRec("ns1.child.test.", "10.9.0.4"), aRec("ns2.child.test.", "10.9.0.5"))
					return &upstream.Result{Response: resp}
				}
			}
			childHandler := func(ctx context.Context, msg *dns.Msg) *upstream.Result {
				if !delayed(ctx, levelDelay) {
					return &upstream.Result{Error: ctx.Err()}
				}
				resp := dnsutil.SetReply(new(dns.Msg), msg)
				resp.Answer = append(resp.Answer, aRec(qname, "192.0.2.1"))
				return &upstream.Result{Response: resp}
			}

			client := &fakeNSClient{handlers: map[string]nsScriptHandler{
				"10.9.0.1:53": rootHandler,
				"10.9.0.2:53": mkTLDHandler(),
				"10.9.0.3:53": mkTLDHandler(),
				"10.9.0.4:53": childHandler,
				"10.9.0.5:53": childHandler,
			}}
			r := newPrefetchTestRecursive(client)
			r.poisonguard = true
			// Real walk queries carry EDNS — tag them with an OPT record so
			// the scripted TLD handler can tell data queries from bare probes.
			r.resolver.buildMsg = func(question Question, ecs *edns.ECSOption, rd, secure bool) *dns.Msg {
				msg := dnsutil.SetQuestion(new(dns.Msg), dnsutil.Fqdn(question.Name), question.Qtype)
				msg.Pseudo = append(msg.Pseudo, &dns.OPT{Hdr: dns.Header{Name: "."}})
				return msg
			}

			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			start := time.Now()
			qr := r.resolve(ctx, Question{Name: qname, Qtype: dns.TypeA, Qclass: dns.ClassINET}, nil, 0, false)
			elapsed := time.Since(start)

			if qr.Err != nil {
				t.Fatalf("resolve failed: %v", qr.Err)
			}
			if len(qr.Answer) != 1 {
				t.Fatalf("answer = %d records, want 1", len(qr.Answer))
			}
			if a, ok := qr.Answer[0].(*dns.A); !ok || a.Addr.String() != "192.0.2.1" {
				t.Fatalf("answer = %v, want A 192.0.2.1", qr.Answer[0])
			}
			if qr.Poisoned != c.wantPoison {
				t.Fatalf("Poisoned = %t, want %t", qr.Poisoned, c.wantPoison)
			}
			if !c.poisonProbe {
				// Serial probe-before-query would take ≥2×levelDelay; the
				// overlap completes within one delay plus slack.
				if elapsed >= 2*levelDelay {
					t.Fatalf("walk took %v, want < %v (probe serialized before the data query)", elapsed, 2*levelDelay)
				}
			}
		})
	}
}
