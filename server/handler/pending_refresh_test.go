package handler

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"codeberg.org/miekg/dns"

	"zjdns/edns"
)

func TestPendingRefreshes_LeaderAndFollower(t *testing.T) {
	pr := NewPendingRefreshes()

	qname := "example.com."
	qtype := dns.TypeA
	qclass := uint16(dns.ClassINET)

	key := buildPendingKey(qname, qtype, qclass, nil, false)

	// Leader.
	if !pr.Start(key) {
		t.Fatal("expected leader for first call")
	}

	// Follower: same key, should be rejected.
	if pr.Start(key) {
		t.Fatal("expected follower rejection for duplicate key")
	}

	// Leader completes.
	pr.Done(key)

	// After Done, a new call should become leader again.
	if !pr.Start(key) {
		t.Fatal("expected leader after Done")
	}
	pr.Done(key)
}

func TestPendingRefreshes_DifferentKeys(t *testing.T) {
	pr := NewPendingRefreshes()

	keyA := buildPendingKey("example.com.", dns.TypeA, uint16(dns.ClassINET), nil, false)
	keyAAAA := buildPendingKey("example.com.", dns.TypeAAAA, uint16(dns.ClassINET), nil, false)
	keyOther := buildPendingKey("other.com.", dns.TypeA, uint16(dns.ClassINET), nil, false)

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
	pr := NewPendingRefreshes()
	qclass := uint16(dns.ClassINET)

	ecsKey := buildPendingKey("example.com.", dns.TypeA, qclass, &edns.ECSOption{Address: nil, SourcePrefix: 24}, false)
	nilKey := buildPendingKey("example.com.", dns.TypeA, qclass, nil, false)

	if !pr.Start(ecsKey) {
		t.Fatal("expected leader for ECS")
	}
	// nil ECS and zero-value ECS produce the same key (both have ecsAddr="").
	if pr.Start(nilKey) {
		t.Fatal("expected follower for nil ECS (same as empty ECS)")
	}

	pr.Done(ecsKey)
}

func TestPendingRefreshes_ConcurrentSameKey(t *testing.T) {
	pr := NewPendingRefreshes()
	key := buildPendingKey("concurrent.example.com.", dns.TypeA, uint16(dns.ClassINET), nil, false)

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
			entered.Add(1)
			if pr.Start(key) {
				leaders.Add(1)
			} else {
				followers.Add(1)
			}
		}()
	}

	close(allSpawned)

	for entered.Load() < int32(goroutines) || leaders.Load() < 1 {
	}
	time.Sleep(time.Millisecond)

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
	pr := NewPendingRefreshes()
	key := buildPendingKey("example.com.", dns.TypeAAAA, uint16(dns.ClassINET), nil, false)

	if !pr.Start(key) {
		t.Fatal("expected leader")
	}

	const numFollowers = 10
	var entered atomic.Int32
	var rejected atomic.Int32

	var wg sync.WaitGroup
	for i := 0; i < numFollowers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			entered.Add(1)
			if !pr.Start(key) {
				rejected.Add(1)
			}
		}()
	}

	for entered.Load() < int32(numFollowers) || rejected.Load() < int32(numFollowers) {
	}
	time.Sleep(time.Millisecond)

	if n := rejected.Load(); n != int32(numFollowers) {
		t.Errorf("followers rejected = %d, want %d", n, numFollowers)
	}

	pr.Done(key)
	wg.Wait()
}

func TestPendingRefreshes_DoneWithoutStart(t *testing.T) {
	pr := NewPendingRefreshes()
	pr.Done(buildPendingKey("no-such-key.", dns.TypeA, uint16(dns.ClassINET), nil, false))
}

func TestPendingRefreshes_DNSSECKeyIsolation(t *testing.T) {
	pr := NewPendingRefreshes()
	qclass := uint16(dns.ClassINET)

	keyWithDNSSEC := buildPendingKey("example.com.", dns.TypeA, qclass, nil, true)
	keyWithoutDNSSEC := buildPendingKey("example.com.", dns.TypeA, qclass, nil, false)

	if !pr.Start(keyWithDNSSEC) {
		t.Fatal("expected leader for dnssecOK=true")
	}
	// Different dnssecOK — should be independent keys.
	if !pr.Start(keyWithoutDNSSEC) {
		t.Fatal("expected leader for dnssecOK=false (different key)")
	}

	pr.Done(keyWithDNSSEC)
	pr.Done(keyWithoutDNSSEC)
}

func TestPendingRefreshes_LeaderDoneFollowerCanProceed(t *testing.T) {
	pr := NewPendingRefreshes()
	key := buildPendingKey("test.example.com.", dns.TypeA, uint16(dns.ClassINET), nil, false)

	if !pr.Start(key) {
		t.Fatal("expected leader")
	}

	followerDone := make(chan struct{})
	go func() {
		for pr.Start(key) == false {
			time.Sleep(time.Microsecond)
		}
		pr.Done(key)
		close(followerDone)
	}()

	time.Sleep(10 * time.Millisecond)

	pr.Done(key)

	select {
	case <-followerDone:
	case <-time.After(time.Second):
		t.Fatal("follower never became leader after Done")
	}
}
