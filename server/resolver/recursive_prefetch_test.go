package resolver

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/log"
	"zjdns/internal/lrumap"
	"zjdns/server/defense"
	"zjdns/server/resolver/dnssec"
	"zjdns/server/upstream"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// newPrefetchTestRecursive builds a walk-capable Recursive over a scripted
// upstream client: crypto validation on (the prefetch only fires with a
// Crypto validator), no response cache so NS addresses come from glue.
func newPrefetchTestRecursive(client UpstreamClient) *Recursive {
	ednsHandler, _ := edns.NewHandler(config.ECSConfig{})
	return &Recursive{
		delegations: lrumap.New[string, *delegationEntry](64),
		resolver: &Resolver{
			queryClient: client,
			edns:        ednsHandler,
			buildMsg: func(question Question, ecs *edns.ECSOption, rd, secure bool) *dns.Msg {
				return dnsutil.SetQuestion(new(dns.Msg), dnsutil.Fqdn(question.Name), question.Qtype)
			},
			validator: &Validator{
				Crypto:      dnssec.NewCryptoValidator(nil),
				Poisonguard: defense.Detector{},
			},
		},
	}
}

// TestResolve_FirstIterationDNSKEYPrefetch covers the root-start prefetch:
// a cold walk has no childDS yet, so the original condition never fired and
// updateDNSSECChain paid one serial root-DNSKEY RTT after the first data
// query.  The scripted root server refuses to answer the minimised data query
// until the DNSKEY query arrives — without the prefetch the walk deadlocks on
// the data query and fails on the context timeout.  The negative case guards
// the other half of the condition: a delegation-cache start on an unsigned
// zone must NOT fire a wasted DNSKEY query.
func TestResolve_FirstIterationDNSKEYPrefetch(t *testing.T) {
	cases := []struct {
		name      string
		seedDeleg bool // start from a cached unsigned delegation instead of the root
		wantKeys  bool // expect a DNSKEY query during the walk
	}{
		{"root start prefetches the root DNSKEY in parallel with the data query", false, true},
		{"unsigned delegation-cache start fires no DNSKEY query", true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rootHintsOnce.Do(func() {})
			oldHints := rootHints
			rootHints = map[string][]string{"a.root-servers.test.": {"10.9.0.1:53"}}
			t.Cleanup(func() { rootHints = oldHints })

			var dnskeySeen atomic.Bool
			keyArrived := make(chan struct{})
			var keyOnce sync.Once

			rootHandler := func(ctx context.Context, msg *dns.Msg) *upstream.Result {
				if len(msg.Question) > 0 && dns.RRToType(msg.Question[0]) == dns.TypeDNSKEY {
					dnskeySeen.Store(true)
					keyOnce.Do(func() { close(keyArrived) })
					return nsReply(msg, dns.RcodeSuccess)
				}
				// Minimised data query: hold the answer until the prefetch's
				// DNSKEY query arrives — proof the fetch overlaps this flight
				// instead of serializing after it.
				select {
				case <-keyArrived:
				case <-ctx.Done():
					return &upstream.Result{Error: ctx.Err()}
				}
				resp := dnsutil.SetReply(new(dns.Msg), msg)
				resp.Ns = append(resp.Ns, &dns.NS{
					Hdr: dns.Header{Name: "test.", Class: dns.ClassINET, TTL: 300},
					Ns:  "ns.test.",
				})
				resp.Extra = append(resp.Extra, aRec("ns.test.", "10.9.0.2"))
				return &upstream.Result{Response: resp}
			}
			tldHandler := func(ctx context.Context, msg *dns.Msg) *upstream.Result {
				if len(msg.Question) > 0 && dns.RRToType(msg.Question[0]) == dns.TypeDNSKEY {
					dnskeySeen.Store(true)
				}
				resp := dnsutil.SetReply(new(dns.Msg), msg)
				resp.Answer = append(resp.Answer, aRec("example.test.", "192.0.2.1"))
				return &upstream.Result{Response: resp}
			}

			client := &fakeNSClient{handlers: map[string]nsScriptHandler{
				"10.9.0.1:53": rootHandler,
				"10.9.0.2:53": tldHandler,
			}}
			r := newPrefetchTestRecursive(client)
			if c.seedDeleg {
				r.delegations.Set("test.", &delegationEntry{
					zone:    "test.",
					parent:  ".",
					nsNames: []string{"ns.test."},
					addrs:   []string{"10.9.0.2:53"},
					ts:      log.NowUnix(),
					ttl:     3600,
				})
			}

			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			qr := r.resolve(ctx, Question{Name: "example.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, nil, 0, false)
			if qr.Err != nil {
				t.Fatalf("resolve failed: %v (without the root-start prefetch the data query deadlocks waiting for the DNSKEY query)", qr.Err)
			}
			if len(qr.Answer) != 1 {
				t.Fatalf("answer = %d records, want 1", len(qr.Answer))
			}
			if a, ok := qr.Answer[0].(*dns.A); !ok || a.Addr.String() != "192.0.2.1" {
				t.Fatalf("answer = %v, want A 192.0.2.1", qr.Answer[0])
			}
			if dnskeySeen.Load() != c.wantKeys {
				t.Fatalf("DNSKEY query observed = %t, want %t", dnskeySeen.Load(), c.wantKeys)
			}
		})
	}
}
