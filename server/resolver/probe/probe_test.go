package probe

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/pending"

	"codeberg.org/miekg/dns"
)

// stubCacheSetter is a no-op CacheSetter with controllable LatencyLastProbe.
type stubCacheSetter struct {
	lastProbe int64
	ok        bool
}

// multiAAnswer builds n A records with distinct public IPs.
func multiAAnswer(n int) []dns.RR {
	out := make([]dns.RR, 0, n)
	for i := range n {
		out = append(out, &dns.A{
			Hdr:  dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300},
			Addr: netip.MustParseAddr(fmt.Sprintf("203.0.113.%d", i+1)),
		})
	}
	return out
}

func TestPendingProbes_LeaderAndFollower(t *testing.T) {
	pp := pending.NewGroup[probeKey]()

	qname := "example.com."
	qtype := dns.TypeA

	key := probeKey{qname, qtype}

	if !pp.Start(key) {
		t.Fatal("expected leader for first call")
	}
	if pp.Start(key) {
		t.Fatal("expected follower rejection for duplicate key")
	}

	pp.Done(key)

	if !pp.Start(key) {
		t.Fatal("expected leader after Done")
	}
	pp.Done(key)
}

func TestPendingProbes_DifferentKeys(t *testing.T) {
	pp := pending.NewGroup[probeKey]()

	keyA := probeKey{"example.com.", dns.TypeA}
	keyAAAA := probeKey{"example.com.", dns.TypeAAAA}
	keyOther := probeKey{"other.com.", dns.TypeA}

	if !pp.Start(keyA) {
		t.Fatal("expected leader for type A")
	}
	if !pp.Start(keyAAAA) {
		t.Fatal("expected leader for type AAAA (different qtype)")
	}
	if !pp.Start(keyOther) {
		t.Fatal("expected leader for different qname")
	}

	pp.Done(keyA)
	pp.Done(keyAAAA)
	pp.Done(keyOther)
}

func TestPendingProbes_ConcurrentSameKey(t *testing.T) {
	pp := pending.NewGroup[probeKey]()
	key := probeKey{"concurrent.example.com.", dns.TypeA}

	const goroutines = 50
	var leaders atomic.Int32
	var followers atomic.Int32
	completed := make(chan struct{}, goroutines)
	allSpawned := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			<-allSpawned
			if pp.Start(key) {
				leaders.Add(1)
			} else {
				followers.Add(1)
			}
			completed <- struct{}{}
		}()
	}

	close(allSpawned)

	for range goroutines {
		<-completed
	}

	if n := leaders.Load(); n != 1 {
		t.Errorf("expected exactly 1 leader, got %d", n)
	}

	pp.Done(key)

	wg.Wait()

	if n := followers.Load(); n != int32(goroutines-1) {
		t.Errorf("expected %d followers, got %d", goroutines-1, n)
	}
}

func TestPendingProbes_MultipleFollowers(t *testing.T) {
	pp := pending.NewGroup[probeKey]()
	key := probeKey{"example.com.", dns.TypeAAAA}

	if !pp.Start(key) {
		t.Fatal("expected leader")
	}

	const numFollowers = 10
	var rejected atomic.Int32
	completed := make(chan struct{}, numFollowers)

	var wg sync.WaitGroup
	for range numFollowers {
		wg.Go(func() {
			if !pp.Start(key) {
				rejected.Add(1)
			}
			completed <- struct{}{}
		})
	}

	for range numFollowers {
		<-completed
	}

	if n := rejected.Load(); n != int32(numFollowers) {
		t.Errorf("followers rejected = %d, want %d", n, numFollowers)
	}

	pp.Done(key)
	wg.Wait()
}

func TestPendingProbes_DoneWithoutStart(t *testing.T) {
	pp := pending.NewGroup[probeKey]()
	pp.Done(probeKey{"no-such-key.", dns.TypeA})
}

func TestPendingProbes_LeaderDoneFollowerCanProceed(t *testing.T) {
	pp := pending.NewGroup[probeKey]()
	key := probeKey{"test.example.com.", dns.TypeA}

	if !pp.Start(key) {
		t.Fatal("expected leader")
	}

	followerStarted := make(chan struct{})
	followerDone := make(chan struct{})
	go func() {
		close(followerStarted)
		for pp.Start(key) == false {
			time.Sleep(time.Microsecond)
		}
		pp.Done(key)
		close(followerDone)
	}()

	<-followerStarted

	pp.Done(key)

	select {
	case <-followerDone:
	case <-time.After(time.Second):
		t.Fatal("follower never became leader after Done")
	}
}

// --- NS probe dedup tests ---

func TestTryStartNSProbe_LeaderAndFollower(t *testing.T) {
	key := "10.0.0.1,10.0.0.2"

	if !nsPending.Start(key) {
		t.Fatal("expected leader")
	}
	if nsPending.Start(key) {
		t.Fatal("expected follower rejection")
	}

	nsPending.Done(key)

	if !nsPending.Start(key) {
		t.Fatal("expected leader after finish")
	}
	nsPending.Done(key)
}

func TestTryStartNSProbe_DifferentKeys(t *testing.T) {
	if !nsPending.Start("1.1.1.1,2.2.2.2") {
		t.Fatal("expected leader for key A")
	}
	if !nsPending.Start("3.3.3.3,4.4.4.4") {
		t.Fatal("expected leader for key B")
	}

	nsPending.Done("1.1.1.1,2.2.2.2")
	nsPending.Done("3.3.3.3,4.4.4.4")
}

func TestBuildNSProbeKey_SortsDeterministically(t *testing.T) {
	ips := []net.IP{
		net.ParseIP("10.0.0.3"),
		net.ParseIP("10.0.0.1"),
		net.ParseIP("10.0.0.2"),
	}
	key1 := buildNSProbeKey(ips)
	key2 := buildNSProbeKey(ips)

	if key1 != key2 {
		t.Errorf("expected identical keys, got %q and %q", key1, key2)
	}
	if key1 != "10.0.0.1,10.0.0.2,10.0.0.3" {
		t.Errorf("expected sorted key, got %q", key1)
	}
}

func TestTryStartNSProbe_DoneWithoutStart(t *testing.T) {
	nsPending.Done("no-such-key")
}

func TestTryStartNSProbe_ConcurrentSameKey(t *testing.T) {
	key := "192.168.0.1,192.168.0.2"
	const goroutines = 20

	var leaders atomic.Int32
	var followers atomic.Int32
	completed := make(chan struct{}, goroutines)
	allSpawned := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			<-allSpawned
			if nsPending.Start(key) {
				leaders.Add(1)
			} else {
				followers.Add(1)
			}
			completed <- struct{}{}
		}()
	}

	close(allSpawned)

	for range goroutines {
		<-completed
	}

	if n := leaders.Load(); n != 1 {
		t.Errorf("expected exactly 1 leader, got %d", n)
	}

	nsPending.Done(key)
	wg.Wait()

	if n := followers.Load(); n != int32(goroutines-1) {
		t.Errorf("expected %d followers, got %d", goroutines-1, n)
	}
}

func (s *stubCacheSetter) Set(string, uint16, uint16, *edns.ECSOption, []dns.RR, []dns.RR, []dns.RR, bool, uint16) {
}

func (s *stubCacheSetter) UpdateLatency(string, int)         {}
func (s *stubCacheSetter) UpdateLatencyBatch(map[string]int) {}

func (s *stubCacheSetter) LatencyLastProbe(string) (int64, bool) {
	return s.lastProbe, s.ok
}

// TestStart_RoundCapBoundedSpawn pins the round-cap admission gate: a flood
// of distinct multi-A qnames must not queue unbounded probe rounds — bgGroup
// invocations are capped at DefaultLatencyProbeMaxRounds while rounds are
// in flight (the goroutine/memory amplification vector).
func TestStart_RoundCapBoundedSpawn(t *testing.T) {
	started := make(chan struct{}, 64)
	block := make(chan struct{})
	var invocations atomic.Int32
	p := New(&stubCacheSetter{}, func(fn func() error) {
		// Asynchronous like the production errgroup.Go — a synchronous
		// body would deadlock the caller inside Start.
		invocations.Add(1)
		go func() {
			started <- struct{}{}
			<-block  // hold the round in flight
			_ = fn() // _ = error: stub round, result intentionally discarded
		}()
	}, t.Context(), []config.LatencyProbeStep{{Protocol: config.ProtoDNS, Port: 53, Timeout: 10}})

	const flood = 50
	for i := range flood {
		p.Start(fmt.Sprintf("flood%d.example.com.", i), dns.TypeA, multiAAnswer(4), nil, nil, false, nil)
	}

	for range config.DefaultLatencyProbeMaxRounds {
		<-started
	}
	select {
	case <-started:
		t.Fatalf("bgGroup spawned %d rounds, want ≤ %d — queued rounds grow without bound under a distinct-qname flood",
			invocations.Load(), config.DefaultLatencyProbeMaxRounds)
	default:
	}
	close(block)
}

// TestStart_PendingReleasedOnCapDrop pins that a round-cap-dropped probe
// releases its pending key — the same qname must be probeable again later.
func TestStart_PendingReleasedOnCapDrop(t *testing.T) {
	started := make(chan struct{}, 64)
	block := make(chan struct{})
	p := New(&stubCacheSetter{}, func(fn func() error) {
		go func() {
			started <- struct{}{}
			<-block
			_ = fn() // _ = error: stub round, result intentionally discarded
		}()
	}, t.Context(), []config.LatencyProbeStep{{Protocol: config.ProtoDNS, Port: 53, Timeout: 10}})

	p.Start("cap.example.com.", dns.TypeA, multiAAnswer(4), nil, nil, false, nil)
	<-started

	// Cap is full — this call must be dropped AND release the pending key.
	for i := range 10 {
		p.Start(fmt.Sprintf("drop%d.example.com.", i), dns.TypeA, multiAAnswer(4), nil, nil, false, nil)
	}
	close(block)
	// All rounds exit; after drain the same qname must be startable again.
	deadline := time.After(2 * time.Second)
	for {
		if p.pending.Start(probeKey{qname: "cap.example.com.", qtype: dns.TypeA}) {
			p.pending.Done(probeKey{qname: "cap.example.com.", qtype: dns.TypeA})
			break // not stuck — pending was released on the cap drop
		}
		select {
		case <-deadline:
			t.Fatal("pending key still held after cap drop — later probes for this qname are locked out forever")
		case <-time.After(10 * time.Millisecond):
		}
	}
}
