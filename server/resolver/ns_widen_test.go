package resolver

import (
	"context"
	"testing"
	"time"
	"zjdns/config"
	"zjdns/server/defense"

	"codeberg.org/miekg/dns"
)

// blackholeHandler never answers within the test budget.
func blackholeHandler() nsScriptHandler {
	return nsReplyAfter(30*time.Second, dns.RcodeSuccess)
}

// TestQueryNameservers_InfraWidenOnBlackhole verifies the narrow-fan-out
// safety valve: when the whole latency-ranked first batch is silent, the
// delayed infra widen fires and a later server's answer still wins the level
// — instead of the walk stalling for the full DefaultRecursiveQueryTimeout.
func TestQueryNameservers_InfraWidenOnBlackhole(t *testing.T) {
	r := newTestRecursiveNS(&fakeNSClient{handlers: map[string]nsScriptHandler{
		"10.0.0.1:53": blackholeHandler(), // first batch: blackholed
		"10.0.0.2:53": blackholeHandler(),
		"10.0.0.3:53": blackholeHandler(),
		"10.0.0.4:53": nsReplyAfter(5*time.Millisecond, dns.RcodeSuccess), // widened candidate
	}})

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	start := time.Now()
	resp, _, err := r.queryNameserversConcurrent(ctx, []string{
		"10.0.0.1:53", "10.0.0.2:53", "10.0.0.3:53", "10.0.0.4:53",
	}, Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, nil, false, "example.com.", defense.Detector{}, true)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("infra widen did not rescue the blackholed first batch: %v", err)
	}
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		t.Fatal("expected the widened server's NOERROR answer")
	}
	// The answer must arrive on the widen path (~DefaultInfraFanoutWidenDelay),
	// nowhere near the level budget that a never-widening batch would hit.
	if elapsed > 3*config.DefaultInfraFanoutWidenDelay {
		t.Fatalf("level answered in %v — widen delay not effective", elapsed)
	}
}

// TestQueryNameservers_InfraWidenCancelledOnWin verifies the churn side of
// the trade: when the first batch answers, the win lands immediately — well
// before the widen timer could fire — so no widened candidate is contacted.
func TestQueryNameservers_InfraWidenCancelledOnWin(t *testing.T) {
	r := newTestRecursiveNS(&fakeNSClient{handlers: map[string]nsScriptHandler{
		"10.0.0.1:53": nsReplyAfter(5*time.Millisecond, dns.RcodeSuccess), // first batch answers
		"10.0.0.2:53": blackholeHandler(),
		"10.0.0.3:53": blackholeHandler(),
		"10.0.0.4:53": blackholeHandler(),
	}})

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	start := time.Now()
	resp, _, err := r.queryNameserversConcurrent(ctx, []string{
		"10.0.0.1:53", "10.0.0.2:53", "10.0.0.3:53", "10.0.0.4:53",
	}, Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, nil, false, "example.com.", defense.Detector{}, true)
	if err != nil {
		t.Fatalf("first-batch win failed: %v", err)
	}
	if resp == nil {
		t.Fatal("no response")
	}
	if elapsed := time.Since(start); elapsed > config.DefaultInfraFanoutWidenDelay/2 {
		t.Fatalf("first-batch win took %v — widen timer leaked into the win path", elapsed)
	}
}
