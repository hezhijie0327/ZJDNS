package probe

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

func TestPendingProbes_LeaderAndFollower(t *testing.T) {
	pp := NewPendingProbes()

	qname := "example.com."
	qtype := dns.TypeA

	// Leader.
	if !pp.Start(qname, qtype) {
		t.Fatal("expected leader for first call")
	}

	// Follower: same key, should be rejected.
	if pp.Start(qname, qtype) {
		t.Fatal("expected follower rejection for duplicate key")
	}

	// Leader completes.
	pp.Done(qname, qtype)

	// After Done, a new call should become leader again.
	if !pp.Start(qname, qtype) {
		t.Fatal("expected leader after Done")
	}
	pp.Done(qname, qtype)
}

func TestPendingProbes_DifferentKeys(t *testing.T) {
	pp := NewPendingProbes()

	if !pp.Start("example.com.", dns.TypeA) {
		t.Fatal("expected leader for type A")
	}
	// Different qtype — should be independent.
	if !pp.Start("example.com.", dns.TypeAAAA) {
		t.Fatal("expected leader for type AAAA (different qtype)")
	}
	// Different qname — should be independent.
	if !pp.Start("other.com.", dns.TypeA) {
		t.Fatal("expected leader for different qname")
	}

	pp.Done("example.com.", dns.TypeA)
	pp.Done("example.com.", dns.TypeAAAA)
	pp.Done("other.com.", dns.TypeA)
}

func TestPendingProbes_ConcurrentSameKey(t *testing.T) {
	pp := NewPendingProbes()
	qname := "concurrent.example.com."
	qtype := dns.TypeA

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
			if pp.Start(qname, qtype) {
				leaders.Add(1)
			} else {
				followers.Add(1)
			}
		}()
	}

	close(allSpawned)

	// Wait for leader to emerge.
	for entered.Load() < int32(goroutines) || leaders.Load() < 1 {
	}
	time.Sleep(time.Millisecond)

	if n := leaders.Load(); n != 1 {
		t.Errorf("expected exactly 1 leader, got %d", n)
	}

	pp.Done(qname, qtype)

	wg.Wait()

	if n := followers.Load(); n != int32(goroutines-1) {
		t.Errorf("expected %d followers, got %d", goroutines-1, n)
	}
}

func TestPendingProbes_MultipleFollowers(t *testing.T) {
	pp := NewPendingProbes()
	qname := "example.com."
	qtype := dns.TypeAAAA

	if !pp.Start(qname, qtype) {
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
			if !pp.Start(qname, qtype) {
				rejected.Add(1)
			}
		}()
	}

	// Wait for all followers to be rejected.
	for entered.Load() < int32(numFollowers) || rejected.Load() < int32(numFollowers) {
	}
	time.Sleep(time.Millisecond)

	if n := rejected.Load(); n != int32(numFollowers) {
		t.Errorf("followers rejected = %d, want %d", n, numFollowers)
	}

	pp.Done(qname, qtype)
	wg.Wait()
}

func TestPendingProbes_DoneWithoutStart(t *testing.T) {
	pp := NewPendingProbes()
	pp.Done("no-such-key.", dns.TypeA) // should not panic
}

func TestPendingProbes_LeaderDoneFollowerCanProceed(t *testing.T) {
	pp := NewPendingProbes()
	qname := "test.example.com."
	qtype := dns.TypeA

	// Leader starts.
	if !pp.Start(qname, qtype) {
		t.Fatal("expected leader")
	}

	// Follower blocked.
	followerDone := make(chan struct{})
	go func() {
		// Busy-wait until leader is done, then try again.
		for pp.Start(qname, qtype) == false {
			time.Sleep(time.Microsecond)
		}
		pp.Done(qname, qtype)
		close(followerDone)
	}()

	// Let follower fail a few times.
	time.Sleep(10 * time.Millisecond)

	// Leader completes — follower can now become leader.
	pp.Done(qname, qtype)

	select {
	case <-followerDone:
		// OK — follower became new leader after original leader finished.
	case <-time.After(time.Second):
		t.Fatal("follower never became leader after Done")
	}
}
