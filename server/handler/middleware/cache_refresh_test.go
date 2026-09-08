package middleware

import (
	"testing"
	"time"
	"zjdns/internal/pending"
	"zjdns/server/handler"

	"codeberg.org/miekg/dns"
)

// TestRefreshCoordinator_StartThrottled_ReleasesGateOnCooldownRefusal locks
// the gate-release discipline: when the cooldown refuses, the in-flight gate
// acquired by tryStart must be released — a leaked gate would block every
// future refresh for the key until the entry evicts.
func TestRefreshCoordinator_StartThrottled_ReleasesGateOnCooldownRefusal(t *testing.T) {
	c := &refreshCoordinator{
		inFlight: pending.NewGroup[handler.PendingKey](),
		cooldown: handler.NewPrefetchCooldown(),
	}
	// Burn the cooldown window: ShouldStart records the timestamp side
	// effect, so a consult within the window is refused.  Use the same
	// clock startThrottled reads (Unix nanoseconds, now).
	now := time.Now().UnixNano()
	c.cooldown.ShouldStart("example.com.", dns.TypeA, now, 10_000_000_000)
	if c.startThrottled("example.com.", dns.TypeA, dns.ClassINET, nil) {
		t.Fatal("cooldown window active — startThrottled must refuse")
	}
	if !c.tryStart("example.com.", dns.TypeA, dns.ClassINET, nil) {
		t.Fatal("gate must be free after a cooldown refusal — it was leaked")
	}
	c.finish("example.com.", dns.TypeA, dns.ClassINET, nil)
}
