package handler

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"zjdns/edns"
	"zjdns/internal/pending"
	"zjdns/server/resolver"

	"codeberg.org/miekg/dns"
)

func TestPendingRequests_LeaderAndFollower(t *testing.T) {
	pr := NewPendingRequests()

	qname := "example.com."
	qtype := dns.TypeA
	qclass := uint16(dns.ClassINET)

	// Leader.
	_, follower := pr.Join(qname, qtype, qclass, nil, false)
	if follower {
		t.Fatal("expected leader")
	}

	// Follower: start goroutine, wait for it to be blocked in Join(),
	// then call Done().
	followerJoined := make(chan struct{})
	var followerResult *resolver.QueryResult
	var wg sync.WaitGroup
	wg.Go(func() {
		close(followerJoined)
		r, f := pr.Join(qname, qtype, qclass, nil, false)
		if !f {
			t.Error("expected follower (follower=true)")
		}
		followerResult = r
	})

	<-followerJoined

	expected := &resolver.QueryResult{Server: "test-server"}
	pr.Done(qname, qtype, qclass, nil, false, expected)

	wg.Wait()

	if followerResult == nil {
		t.Fatal("follower should have received a result")
	}
	if followerResult.Server != expected.Server {
		t.Errorf("follower server = %q, want %q", followerResult.Server, expected.Server)
	}
}

func TestPendingRequests_MultipleFollowers(t *testing.T) {
	pr := NewPendingRequests()

	qname := "example.com."
	qtype := dns.TypeAAAA
	qclass := uint16(dns.ClassINET)

	_, follower := pr.Join(qname, qtype, qclass, nil, false)
	if follower {
		t.Fatal("expected leader")
	}

	const numFollowers = 10
	var wg sync.WaitGroup
	var received atomic.Int32
	entered := make(chan struct{}, numFollowers)

	for range numFollowers {
		wg.Go(func() {
			entered <- struct{}{}
			_, f := pr.Join(qname, qtype, qclass, nil, false)
			if !f {
				t.Error("expected follower")
			}
			received.Add(1)
		})
	}

	for range numFollowers {
		<-entered
	}
	time.Sleep(time.Millisecond)

	pr.Done(qname, qtype, qclass, nil, false, &resolver.QueryResult{Server: "shared"})

	wg.Wait()

	if n := received.Load(); n != int32(numFollowers) {
		t.Errorf("followers completed = %d, want %d", n, numFollowers)
	}
}

func TestPendingRequests_DifferentKeys(t *testing.T) {
	pr := NewPendingRequests()
	qclass := uint16(dns.ClassINET)

	_, f := pr.Join("example.com.", dns.TypeA, qclass, nil, false)
	if f {
		t.Fatal("expected leader for key A")
	}
	_, f = pr.Join("example.com.", dns.TypeAAAA, qclass, nil, false)
	if f {
		t.Fatal("expected leader for key B (different qtype)")
	}

	ecsOpt := &edns.ECSOption{Address: net.ParseIP("1.1.1.1"), SourcePrefix: 24}
	_, f = pr.Join("example.com.", dns.TypeA, qclass, ecsOpt, false)
	if f {
		t.Fatal("expected leader for key C (different ECS)")
	}

	_, f = pr.Join("example.com.", dns.TypeA, qclass, nil, true)
	if f {
		t.Fatal("expected leader for key D (different DNSSEC)")
	}

	pr.Done("example.com.", dns.TypeA, qclass, nil, false, &resolver.QueryResult{Server: "A"})
	pr.Done("example.com.", dns.TypeAAAA, qclass, nil, false, &resolver.QueryResult{Server: "B"})
	pr.Done("example.com.", dns.TypeA, qclass, ecsOpt, false, &resolver.QueryResult{Server: "C"})
	pr.Done("example.com.", dns.TypeA, qclass, nil, true, &resolver.QueryResult{Server: "D"})
}

func TestPendingRequests_DoneWithoutJoin(t *testing.T) {
	pr := NewPendingRequests()
	pr.Done("no-such-key.", dns.TypeA, uint16(dns.ClassINET), nil, false, &resolver.QueryResult{})
}

func TestPendingRequests_ECSVariation(t *testing.T) {
	pr := NewPendingRequests()
	qclass := uint16(dns.ClassINET)

	ecs1 := &edns.ECSOption{Address: net.ParseIP("10.0.0.1"), SourcePrefix: 24}
	ecs2 := &edns.ECSOption{Address: net.ParseIP("10.0.0.2"), SourcePrefix: 24}
	ecs3 := &edns.ECSOption{Address: net.ParseIP("10.0.0.1"), SourcePrefix: 16}

	for _, tc := range []struct {
		name   string
		qname  string
		qtype  uint16
		ecsOpt *edns.ECSOption
	}{
		{"ecs1", "example.com.", dns.TypeA, ecs1},
		{"ecs2-different-ip", "example.com.", dns.TypeA, ecs2},
		{"ecs3-different-prefix", "example.com.", dns.TypeA, ecs3},
	} {
		_, f := pr.Join(tc.qname, tc.qtype, qclass, tc.ecsOpt, false)
		if f {
			t.Errorf("%s: expected leader, got follower", tc.name)
		}
		pr.Done(tc.qname, tc.qtype, qclass, tc.ecsOpt, false, &resolver.QueryResult{})
	}
}

func TestPendingRequests_ConcurrentSameKey(t *testing.T) {
	pr := NewPendingRequests()
	qname := "concurrent.example.com."
	qclass := uint16(dns.ClassINET)

	const goroutines = 50
	var leaders atomic.Int32
	var followers atomic.Int32
	entered := make(chan struct{}, goroutines)
	allSpawned := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			<-allSpawned
			entered <- struct{}{}
			_, f := pr.Join(qname, dns.TypeA, qclass, nil, false)
			if f {
				followers.Add(1)
			} else {
				leaders.Add(1)
			}
		}()
	}

	close(allSpawned)

	for range goroutines {
		<-entered
	}
	time.Sleep(time.Millisecond)

	if n := leaders.Load(); n != 1 {
		t.Errorf("expected exactly 1 leader, got %d", n)
	}

	pr.Done(qname, dns.TypeA, qclass, nil, false, &resolver.QueryResult{Server: "upstream"})

	wg.Wait()

	if n := followers.Load(); n != int32(goroutines-1) {
		t.Errorf("expected %d followers, got %d", goroutines-1, n)
	}
}

func TestPendingRequests_NilECSAndZeroECSAreSameKey(t *testing.T) {
	pr := NewPendingRequests()
	qclass := uint16(dns.ClassINET)

	var nilECS *edns.ECSOption
	zeroECS := &edns.ECSOption{}

	_, f := pr.Join("example.com.", dns.TypeA, qclass, nilECS, false)
	if f {
		t.Fatal("expected leader for nil ECS")
	}

	started := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		close(started)
		_, f := pr.Join("example.com.", dns.TypeA, qclass, zeroECS, false)
		if !f {
			t.Error("expected follower for zero-value ECS (same key as nil ECS)")
		}
	})

	<-started
	time.Sleep(time.Millisecond)
	pr.Done("example.com.", dns.TypeA, qclass, nilECS, false, &resolver.QueryResult{Server: "done"})
	wg.Wait()
}

// ── Refresh group tests (pending.Group, skip-follower) ──────────────────────

func TestPendingRefreshes_LeaderAndFollower(t *testing.T) {
	pr := pending.NewGroup[PendingKey]()

	qname := "example.com."
	qtype := dns.TypeA
	qclass := uint16(dns.ClassINET)

	key := BuildPendingKey(qname, qtype, qclass, nil, false)

	if !pr.Start(key) {
		t.Fatal("expected leader for first call")
	}

	if pr.Start(key) {
		t.Fatal("expected follower rejection for duplicate key")
	}

	pr.Done(key)

	if !pr.Start(key) {
		t.Fatal("expected leader after Done")
	}
	pr.Done(key)
}

func TestPendingRefreshes_DifferentKeys(t *testing.T) {
	pr := pending.NewGroup[PendingKey]()

	keyA := BuildPendingKey("example.com.", dns.TypeA, uint16(dns.ClassINET), nil, false)
	keyAAAA := BuildPendingKey("example.com.", dns.TypeAAAA, uint16(dns.ClassINET), nil, false)
	keyOther := BuildPendingKey("other.com.", dns.TypeA, uint16(dns.ClassINET), nil, false)

	if !pr.Start(keyA) {
		t.Fatal("expected leader for type A")
	}
	if !pr.Start(keyAAAA) {
		t.Fatal("expected leader for type AAAA (different qtype)")
	}
	if !pr.Start(keyOther) {
		t.Fatal("expected leader for different qname")
	}

	pr.Done(keyA)
	pr.Done(keyAAAA)
	pr.Done(keyOther)
}

func TestPendingRefreshes_ECSVariation(t *testing.T) {
	pr := pending.NewGroup[PendingKey]()
	qclass := uint16(dns.ClassINET)

	ecsKey := BuildPendingKey("example.com.", dns.TypeA, qclass, &edns.ECSOption{Address: nil, SourcePrefix: 24}, false)
	nilKey := BuildPendingKey("example.com.", dns.TypeA, qclass, nil, false)

	if !pr.Start(ecsKey) {
		t.Fatal("expected leader for ECS")
	}
	if pr.Start(nilKey) {
		t.Fatal("expected follower for nil ECS (same as empty ECS)")
	}

	pr.Done(ecsKey)
}

func TestPendingRefreshes_ConcurrentSameKey(t *testing.T) {
	pr := pending.NewGroup[PendingKey]()
	key := BuildPendingKey("concurrent.example.com.", dns.TypeA, uint16(dns.ClassINET), nil, false)

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
			if pr.Start(key) {
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

	pr.Done(key)

	wg.Wait()

	if n := followers.Load(); n != int32(goroutines-1) {
		t.Errorf("expected %d followers, got %d", goroutines-1, n)
	}
}

func TestPendingRefreshes_MultipleFollowers(t *testing.T) {
	pr := pending.NewGroup[PendingKey]()
	key := BuildPendingKey("example.com.", dns.TypeAAAA, uint16(dns.ClassINET), nil, false)

	if !pr.Start(key) {
		t.Fatal("expected leader")
	}

	const numFollowers = 10
	var rejected atomic.Int32
	completed := make(chan struct{}, numFollowers)

	var wg sync.WaitGroup
	for range numFollowers {
		wg.Go(func() {
			if !pr.Start(key) {
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

	pr.Done(key)
	wg.Wait()
}

func TestPendingRefreshes_DoneWithoutStart(t *testing.T) {
	pr := pending.NewGroup[PendingKey]()
	pr.Done(BuildPendingKey("no-such-key.", dns.TypeA, uint16(dns.ClassINET), nil, false))
}

func TestPendingRefreshes_DNSSECKeyIsolation(t *testing.T) {
	pr := pending.NewGroup[PendingKey]()
	qclass := uint16(dns.ClassINET)

	keyWithDNSSEC := BuildPendingKey("example.com.", dns.TypeA, qclass, nil, true)
	keyWithoutDNSSEC := BuildPendingKey("example.com.", dns.TypeA, qclass, nil, false)

	if !pr.Start(keyWithDNSSEC) {
		t.Fatal("expected leader for dnssecOK=true")
	}
	if !pr.Start(keyWithoutDNSSEC) {
		t.Fatal("expected leader for dnssecOK=false (different key)")
	}

	pr.Done(keyWithDNSSEC)
	pr.Done(keyWithoutDNSSEC)
}

func TestPendingRefreshes_LeaderDoneFollowerCanProceed(t *testing.T) {
	pr := pending.NewGroup[PendingKey]()
	key := BuildPendingKey("test.example.com.", dns.TypeA, uint16(dns.ClassINET), nil, false)

	if !pr.Start(key) {
		t.Fatal("expected leader")
	}

	followerStarted := make(chan struct{})
	followerDone := make(chan struct{})
	go func() {
		close(followerStarted)
		for pr.Start(key) == false {
			time.Sleep(time.Microsecond)
		}
		pr.Done(key)
		close(followerDone)
	}()

	<-followerStarted

	pr.Done(key)

	select {
	case <-followerDone:
	case <-time.After(time.Second):
		t.Fatal("follower never became leader after Done")
	}
}

// ── R3-M4: LRU-evicted in-flight call ─────────────────────────────────────────
// The eviction-wake semantics are tested in internal/pending (TestCallGroup_
// EvictionWakesFollower).  Here we verify the handler layer maps the sentinel
// error correctly.

func TestPendingRequests_EvictedErrorMapping(t *testing.T) {
	// Verify that PendingRequests.Join maps pending.ErrEvicted → errPendingEvicted.
	// Capacity-1 so the second key evicts the first.
	pr := &PendingRequests{
		cg: pending.NewCallGroup[PendingKey, *resolver.QueryResult](
			1,
			10*time.Second,
			nil,
		),
	}

	// Leader for key A.
	_, follower := pr.Join("a.example.com.", dns.TypeA, dns.ClassINET, nil, false)
	if follower {
		t.Fatal("first join must be the leader")
	}

	// Follower for key A.
	got := make(chan *resolver.QueryResult, 1)
	go func() {
		qr, f := pr.Join("a.example.com.", dns.TypeA, dns.ClassINET, nil, false)
		if f {
			got <- qr
		} else {
			got <- nil
		}
	}()
	time.Sleep(100 * time.Millisecond)

	// Evict key A by joining key B.
	_, follower = pr.Join("b.example.com.", dns.TypeA, dns.ClassINET, nil, false)
	if follower {
		t.Fatal("second join must be the leader")
	}

	select {
	case qr := <-got:
		if qr == nil {
			t.Fatal("follower became leader instead of observing eviction")
		}
		if !errors.Is(qr.Err, errPendingEvicted) {
			t.Errorf("expected errPendingEvicted, got %v", qr.Err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("follower never woke")
	}
	// Cleanup.
	pr.Done("b.example.com.", dns.TypeA, dns.ClassINET, nil, false, &resolver.QueryResult{})
}
