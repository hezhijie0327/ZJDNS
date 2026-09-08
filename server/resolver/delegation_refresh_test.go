package resolver

import (
	"context"
	"testing"
	"time"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/internal/log"
	"zjdns/internal/lrumap"

	"codeberg.org/miekg/dns"
)

// newRefreshTestRecursive builds a Recursive whose refresh walks start at a
// scripted ancestor delegation: the walk for "…example.com." NS queries the
// fake address directly instead of the root (loadHints may resolve
// named.root over the network), keeping the test hermetic and fast.
func newRefreshTestRecursive(t *testing.T) *Recursive {
	t.Helper()
	r := newTestRecursiveNS(&fakeNSClient{handlers: map[string]nsScriptHandler{
		"10.0.0.99:53": nsReplyAfter(5*time.Millisecond, dns.RcodeSuccess),
	}})
	r.ctx = context.Background()
	// Pre-filled root cache + real store: getRootServers runs before the
	// delegation branch on every walk — without these it falls to
	// allRootAddrs/loadHints, which may resolve named.root over the network.
	store := cache.New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	t.Cleanup(func() { _ = store.Close() })
	r.cache = store
	r.rootCache = []string{"10.0.0.99:53"}
	r.rootCacheTime = log.NowUnix()
	r.delegations = lrumap.New[string, *delegationEntry](16)
	r.delegations.Set("example.com.", &delegationEntry{
		zone: "example.com.", parent: ".", addrs: []string{"10.0.0.99:53"},
		ts: log.NowUnix(), ttl: 3600,
	})
	r.resolver.validator = &Validator{}
	return r
}

// insideWindow builds an entry resting inside the refresh window (remaining
// = ttl/4 - 10 < ttl/4).
func insideWindow(zone string) *delegationEntry {
	e := &delegationEntry{zone: zone, ts: log.NowUnix(), ttl: 3600}
	e.ts -= 3600 - 3600/config.DefaultDelegationRefreshFraction + 10
	return e
}

// TestDelegationRefresh_SpawnWindow verifies the refresh-ahead window: an
// entry inside the last DefaultDelegationRefreshFraction of its TTL spawns
// exactly one background walk; an entry outside the window spawns none.
func TestDelegationRefresh_SpawnWindow(t *testing.T) {
	r := newRefreshTestRecursive(t)

	fresh := &delegationEntry{zone: "fresh.example.com.", ts: log.NowUnix(), ttl: 3600}
	r.maybeRefreshDelegation(fresh)
	if got := r.refreshInflight.Load(); got != 0 {
		t.Fatalf("refresh spawned outside the refresh window (inflight=%d)", got)
	}

	window := insideWindow("window.example.com.")
	r.maybeRefreshDelegation(window)
	if got := r.refreshInflight.Load(); got != 1 {
		t.Fatalf("refresh walk not spawned inside the window (inflight=%d)", got)
	}
	if !window.refreshing.Load() {
		t.Fatal("refreshing guard not set on the entry")
	}
	// The CAS guard: a second trigger for the same entry must not spawn.
	r.maybeRefreshDelegation(window)
	if got := r.refreshInflight.Load(); got != 1 {
		t.Fatalf("second refresh spawned for the same entry (inflight=%d)", got)
	}
	// The walk completes quickly (scripted address) — the guards must reset.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if r.refreshInflight.Load() == 0 && !window.refreshing.Load() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("refresh walk did not complete and release its guards")
}

// TestDelegationRefresh_InflightCap verifies the global refresh cap: more
// expiring delegations than DefaultDelegationRefreshMaxInflight do not spawn
// additional walks.
func TestDelegationRefresh_InflightCap(t *testing.T) {
	r := newRefreshTestRecursive(t)

	// Hold every slot by pre-filling the counter — no goroutine needed.
	r.refreshInflight.Store(config.DefaultDelegationRefreshMaxInflight)
	inside := insideWindow("capped.example.com.")
	r.maybeRefreshDelegation(inside)
	if got := r.refreshInflight.Load(); got != config.DefaultDelegationRefreshMaxInflight {
		t.Fatalf("refresh spawned over the inflight cap (inflight=%d)", got)
	}
	if inside.refreshing.Load() {
		t.Fatal("CAS guard left set after the cap rejection")
	}
}
