package probe

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"zjdns/internal/pending"

	"codeberg.org/miekg/dns"
)

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
			if pp.Start(key) {
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
	var entered atomic.Int32
	var rejected atomic.Int32

	var wg sync.WaitGroup
	for i := 0; i < numFollowers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			entered.Add(1)
			if !pp.Start(key) {
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

	followerDone := make(chan struct{})
	go func() {
		for pp.Start(key) == false {
			time.Sleep(time.Microsecond)
		}
		pp.Done(key)
		close(followerDone)
	}()

	time.Sleep(10 * time.Millisecond)

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
			if nsPending.Start(key) {
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

	nsPending.Done(key)
	wg.Wait()

	if n := followers.Load(); n != int32(goroutines-1) {
		t.Errorf("expected %d followers, got %d", goroutines-1, n)
	}
}
