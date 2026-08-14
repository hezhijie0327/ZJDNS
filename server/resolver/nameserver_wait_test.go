package resolver

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/server/defense"
	"zjdns/server/upstream"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// ── Scripted UpstreamClient for queryNameserversConcurrent tests ─────────────
// Each address gets its own handler so per-server timing (fast vs slow
// NXDOMAIN, racing NOERROR) can be scripted independently.

type nsScriptHandler func(ctx context.Context, msg *dns.Msg) *upstream.Result

type fakeNSClient struct {
	mu       sync.Mutex
	handlers map[string]nsScriptHandler
}

// atomicBool is a tiny test helper: a channel-backed flag with a bounded wait.
// The channel is created at construction — set() and await() race across
// goroutines, so the channel must exist before either runs.
type atomicBool struct {
	ch chan struct{}
}

func (a *atomicBool) set() {
	select {
	case a.ch <- struct{}{}:
	default:
	}
}

func (a *atomicBool) await(timeout time.Duration) bool {
	select {
	case <-a.ch:
		return true
	case <-time.After(timeout):
		return false
	}
}

func (f *fakeNSClient) ExecuteQuery(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer) *upstream.Result {
	f.mu.Lock()
	h, ok := f.handlers[server.Address]
	f.mu.Unlock()
	if !ok {
		return &upstream.Result{Error: errors.New("unscripted address " + server.Address)}
	}
	return h(ctx, msg)
}

// nsReply builds an rcode response echoing the query's question (the
// responseEchoesQuestion gate rejects anything else).
func nsReply(msg *dns.Msg, rcode int) *upstream.Result {
	resp := dnsutil.SetReply(new(dns.Msg), msg)
	resp.Rcode = uint16(rcode) //nolint:gosec // G115: rcode — protocol-bounded uint16
	return &upstream.Result{Response: resp}
}

// nsReplyAfter answers with the given rcode after a delay, or errors out when
// the context is canceled first (the caller's cancel propagation must abort
// stragglers).
func nsReplyAfter(delay time.Duration, rcode int) nsScriptHandler {
	return func(ctx context.Context, msg *dns.Msg) *upstream.Result {
		select {
		case <-time.After(delay):
			return nsReply(msg, rcode)
		case <-ctx.Done():
			return &upstream.Result{Error: ctx.Err()}
		}
	}
}

func newTestRecursiveNS(client UpstreamClient) *Recursive {
	return &Recursive{
		resolver: &Resolver{
			queryClient: client,
			buildMsg: func(question Question, ecs *edns.ECSOption, rd, secure bool) *dns.Msg {
				return dnsutil.SetQuestion(new(dns.Msg), dnsutil.Fqdn(question.Name), question.Qtype)
			},
		},
	}
}

// TestQueryNameservers_NXDOMAINEarlyReturn verifies that an all-NXDOMAIN level
// is served from the first collected NXDOMAIN instead of waiting for the
// slowest nameserver.  With the default 0 deferral window, a 10ms NXDOMAIN
// must win over a 2s-straggling peer (the old wait-all behaviour stretched
// every level to its slowest server's tail).
func TestQueryNameservers_NXDOMAINEarlyReturn(t *testing.T) {
	client := &fakeNSClient{handlers: map[string]nsScriptHandler{
		"10.0.0.1:53": nsReplyAfter(10*time.Millisecond, dns.RcodeNameError),
		"10.0.0.2:53": nsReplyAfter(2*time.Second, dns.RcodeNameError),
	}}
	r := newTestRecursiveNS(client)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	start := time.Now()
	resp, _, err := r.queryNameserversConcurrent(ctx, []string{"10.0.0.1:53", "10.0.0.2:53"},
		Question{Name: "nonexistent.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		nil, false, "example.com.", defense.Detector{})
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.Rcode != dns.RcodeNameError {
		t.Fatalf("response = %v, want NXDOMAIN", resp)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("early NXDOMAIN return took %v, want < 500ms (waited for the slowest nameserver)", elapsed)
	}
}

// TestQueryNameservers_FastNOERRORNotDelayed verifies first-wins symmetry in
// the other direction: a fast NOERROR is served without waiting for a slow
// NXDOMAIN peer (the old wait-all delayed every level by its slowest server).
func TestQueryNameservers_FastNOERRORNotDelayed(t *testing.T) {
	client := &fakeNSClient{handlers: map[string]nsScriptHandler{
		"10.0.0.1:53": nsReplyAfter(10*time.Millisecond, dns.RcodeSuccess),
		"10.0.0.2:53": nsReplyAfter(2*time.Second, dns.RcodeNameError),
	}}
	r := newTestRecursiveNS(client)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	start := time.Now()
	resp, _, err := r.queryNameserversConcurrent(ctx, []string{"10.0.0.1:53", "10.0.0.2:53"},
		Question{Name: "www.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		nil, false, "example.com.", defense.Detector{})
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("response = %v, want NOERROR", resp)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("fast NOERROR was delayed to %v, want < 500ms", elapsed)
	}
}

// TestQueryNameservers_SemaphoreDoesNotBlockLaunch verifies the launch-loop
// regression: a >6-server batch must not stall on the query cap (errgroup
// SetLimit made g.Go itself block, and the early-return wait loop sits after
// the launch loop — 6 fast NXDOMAINs were never served until the slowest
// queued slot freed, stretching the level to the full 3s timeout).  The
// explicit semaphore launches every goroutine immediately, so the first
// NXDOMAIN at 10ms must win over 9 timeout-stalling peers.
func TestQueryNameservers_SemaphoreDoesNotBlockLaunch(t *testing.T) {
	handlers := make(map[string]nsScriptHandler, 15)
	for i := range 6 {
		handlers[scriptAddr(i)] = nsReplyAfter(10*time.Millisecond, dns.RcodeNameError)
	}
	for i := 6; i < 15; i++ {
		handlers[scriptAddr(i)] = nsReplyAfter(3*time.Second, dns.RcodeNameError)
	}
	r := newTestRecursiveNS(&fakeNSClient{handlers: handlers})

	nameservers := make([]string, 0, 15)
	for i := range 15 {
		nameservers = append(nameservers, scriptAddr(i))
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	start := time.Now()
	resp, _, err := r.queryNameserversConcurrent(ctx, nameservers,
		Question{Name: "ias.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		nil, false, "example.com.", defense.Detector{})
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.Rcode != dns.RcodeNameError {
		t.Fatalf("response = %v, want NXDOMAIN", resp)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("launch loop stalled the level to %v, want < 500ms (semaphore must not block g.Go)", elapsed)
	}
}

// scriptAddr builds a 10.1.0.x test address (dotted-quad string without
// net.JoinHostPort so the fake client keying is deterministic).
func scriptAddr(i int) string {
	return "10.1.0." + scriptItoa(i) + ":53"
}

func scriptItoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// TestQueryNameservers_StragglerCanceled verifies that returning early (win or
// deferral expiry) cancels the batch so slow stragglers abort instead of
// pinning their pooled messages.
func TestQueryNameservers_StragglerCanceled(t *testing.T) {
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
	r := newTestRecursiveNS(client)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	resp, _, err := r.queryNameserversConcurrent(ctx, []string{"10.0.0.1:53", "10.0.0.2:53"},
		Question{Name: "nonexistent.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		nil, false, "example.com.", defense.Detector{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.Rcode != dns.RcodeNameError {
		t.Fatalf("response = %v, want NXDOMAIN", resp)
	}
	// The early return must propagate cancel() so the straggler exits on the
	// context instead of running out its scripted delay.
	if !stragglerCanceled.await(2 * time.Second) {
		t.Fatal("straggler was not canceled after the early NXDOMAIN return")
	}
}
