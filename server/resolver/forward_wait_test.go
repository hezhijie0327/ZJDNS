package resolver

import (
	"context"
	"testing"
	"time"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/server/upstream"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// newTestResolver builds a Resolver wired for queryUpstream tests: the
// scripted fake client, a minimal EDNS handler (processUpstreamResponse
// parses ECS from responses), and a plain SetQuestion buildMsg.
func newTestResolver(client UpstreamClient) *Resolver {
	ednsHandler, err := edns.NewHandler(config.ECSConfig{})
	if err != nil {
		panic(err)
	}
	return &Resolver{
		queryClient: client,
		edns:        ednsHandler,
		upstream:    &upstreamSet{},
		buildMsg: func(q Question, ecs *edns.ECSOption, rd, secure bool) *dns.Msg {
			return dnsutil.SetQuestion(new(dns.Msg), dnsutil.Fqdn(q.Name), q.Qtype)
		},
	}
}

// TestQueryUpstream_NXDOMAINEarlyReturn verifies the forwarding fan-out no
// longer waits for the slowest upstream on an all-NXDOMAIN result: a 10ms
// NXDOMAIN must win over a 2s-straggling peer (previously a hung resolver's
// 9s timeout stretched every NXDOMAIN answer to its full tail).
func TestQueryUpstream_NXDOMAINEarlyReturn(t *testing.T) {
	client := &fakeNSClient{handlers: map[string]nsScriptHandler{
		"10.0.0.1:53": nsReplyAfter(10*time.Millisecond, dns.RcodeNameError),
		"10.0.0.2:53": nsReplyAfter(2*time.Second, dns.RcodeNameError),
	}}
	r := newTestResolver(client)
	r.ConfigureServers([]config.UpstreamServer{
		{Address: "10.0.0.1:53", Protocol: config.ProtoUDP},
		{Address: "10.0.0.2:53", Protocol: config.ProtoUDP},
	})

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	start := time.Now()
	qr := r.Query(ctx, Question{Name: "nonexistent.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, nil)
	elapsed := time.Since(start)

	if qr.Err != nil {
		t.Fatalf("unexpected error: %v", qr.Err)
	}
	if qr.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %s, want NXDOMAIN", dns.RcodeToString[qr.Rcode])
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("early NXDOMAIN return took %v, want < 500ms (waited for the slowest upstream)", elapsed)
	}
}

// TestQueryUpstream_StragglerCanceled verifies the early NXDOMAIN return
// cancels the fan-out so slow upstreams abort instead of pinning their
// pooled messages.
func TestQueryUpstream_StragglerCanceled(t *testing.T) {
	stragglerCanceled := &atomicBool{ch: make(chan struct{}, 1)}
	client := &fakeNSClient{handlers: map[string]nsScriptHandler{
		"10.0.0.1:53": nsReplyAfter(10*time.Millisecond, dns.RcodeNameError),
		"10.0.0.2:53": func(ctx context.Context, msg *dns.Msg) *upstream.Result {
			select {
			case <-ctx.Done():
				stragglerCanceled.set()
				return &upstream.Result{Error: ctx.Err()}
			case <-time.After(5 * time.Second):
				return nsReply(msg, dns.RcodeSuccess)
			}
		},
	}}
	r := newTestResolver(client)
	r.ConfigureServers([]config.UpstreamServer{
		{Address: "10.0.0.1:53", Protocol: config.ProtoUDP},
		{Address: "10.0.0.2:53", Protocol: config.ProtoUDP},
	})

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	qr := r.Query(ctx, Question{Name: "nonexistent.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, nil)

	if qr.Err != nil || qr.Rcode != dns.RcodeNameError {
		t.Fatalf("qr = %+v, want clean NXDOMAIN", qr)
	}
	if !stragglerCanceled.await(2 * time.Second) {
		t.Fatal("straggler was not canceled after the early NXDOMAIN return")
	}
}

// TestQueryUpstream_MixedRaceNoHang verifies a simultaneous NXDOMAIN +
// NOERROR race terminates with one of the two answers (whichever the
// scheduler delivers first) — never a hang or a deadlocked fan-out.
func TestQueryUpstream_MixedRaceNoHang(t *testing.T) {
	client := &fakeNSClient{handlers: map[string]nsScriptHandler{
		"10.0.0.1:53": nsReplyAfter(10*time.Millisecond, dns.RcodeNameError),
		"10.0.0.2:53": nsReplyAfter(10*time.Millisecond, dns.RcodeSuccess),
	}}
	r := newTestResolver(client)
	r.ConfigureServers([]config.UpstreamServer{
		{Address: "10.0.0.1:53", Protocol: config.ProtoUDP},
		{Address: "10.0.0.2:53", Protocol: config.ProtoUDP},
	})

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	qr := r.Query(ctx, Question{Name: "race.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, nil)

	if qr.Err != nil {
		t.Fatalf("unexpected error: %v", qr.Err)
	}
	if qr.Rcode != dns.RcodeNameError && qr.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR or NXDOMAIN", dns.RcodeToString[qr.Rcode])
	}
}
