package handler

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"codeberg.org/miekg/dns"

	"zjdns/edns"
	"zjdns/server/resolver"
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
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Signal that we're about to call Join.  The leader waits
		// for this before Done() so the follower definitely finds
		// the pending key.
		close(followerJoined)
		r, f := pr.Join(qname, qtype, qclass, nil, false)
		if !f {
			t.Error("expected follower (follower=true)")
		}
		followerResult = r
	}()

	<-followerJoined // follower goroutine is about to call Join()
	time.Sleep(time.Millisecond)

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
	var entered atomic.Int32

	for i := 0; i < numFollowers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			entered.Add(1) // about to block in Join()
			_, f := pr.Join(qname, qtype, qclass, nil, false)
			if !f {
				t.Error("expected follower")
			}
			received.Add(1)
		}()
	}

	// Ensure all followers get a chance to enter Join() before Done().
	// In production, the upstream resolution (50+ ms) provides this
	// window naturally.
	for entered.Load() < int32(numFollowers) {
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
	var entered atomic.Int32
	var leaders atomic.Int32
	var followers atomic.Int32
	allSpawned := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			<-allSpawned
			entered.Add(1) // about to call Join()
			_, f := pr.Join(qname, dns.TypeA, qclass, nil, false)
			if f {
				followers.Add(1)
			} else {
				leaders.Add(1)
			}
		}()
	}

	close(allSpawned) // all goroutines surge toward Join()

	// Wait for the leader to emerge and for all goroutines to have
	// called Join() (followers are blocked inside, leader returned).
	for entered.Load() < int32(goroutines) || leaders.Load() < 1 {
	}
	time.Sleep(time.Millisecond)

	// Exactly one goroutine got past the mutex without finding a key.
	if n := leaders.Load(); n != 1 {
		t.Errorf("expected exactly 1 leader, got %d", n)
	}

	// Leader completes — wakes all blocked followers.
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

	// Follower runs in a goroutine because it blocks until Done().
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, f := pr.Join("example.com.", dns.TypeA, qclass, zeroECS, false)
		if !f {
			t.Error("expected follower for zero-value ECS (same key as nil ECS)")
		}
	}()

	time.Sleep(time.Millisecond)
	pr.Done("example.com.", dns.TypeA, qclass, nilECS, false, &resolver.QueryResult{Server: "done"})
	wg.Wait()
}
