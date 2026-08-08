package pending

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"zjdns/internal/lrumap"
)

func TestNewGroup(t *testing.T) {
	g := NewGroup[string]()
	if g == nil {
		t.Fatal("NewGroup returned nil")
	}
	if g.sets == nil {
		t.Fatal("NewGroup sets map is nil")
	}
}

func TestStart_Leader(t *testing.T) {
	g := NewGroup[int]()
	if !g.Start(1) {
		t.Error("first Start should return true (leader)")
	}
}

func TestStart_Follower(t *testing.T) {
	g := NewGroup[int]()
	g.Start(1)
	if g.Start(1) {
		t.Error("second Start for same key should return false (follower)")
	}
}

func TestStart_DifferentKeys(t *testing.T) {
	g := NewGroup[int]()
	if !g.Start(1) {
		t.Error("Start(1) should return true")
	}
	if !g.Start(2) {
		t.Error("Start(2) should return true (different key)")
	}
}

func TestDone_RemovesKey(t *testing.T) {
	g := NewGroup[int]()
	g.Start(1)
	g.Done(1)
	if !g.Start(1) {
		t.Error("Start after Done should return true")
	}
}

func TestDone_UnknownKey(t *testing.T) {
	g := NewGroup[int]()
	g.Done(42)
}

func TestDone_DoubleDone(t *testing.T) {
	g := NewGroup[int]()
	g.Start(1)
	g.Done(1)
	g.Done(1)
}

func TestGroup_Concurrent(t *testing.T) {
	g := NewGroup[int]()
	var wg sync.WaitGroup

	for range 100 {
		wg.Go(func() {
			if g.Start(1) {
				g.Done(1)
			}
		})
	}
	wg.Wait()

	if !g.Start(1) {
		t.Error("Start after all concurrent Done should succeed")
	}
}

func TestGroup_ConcurrentDifferentKeys(t *testing.T) {
	g := NewGroup[int]()
	var wg sync.WaitGroup
	leaders := 0
	var mu sync.Mutex

	for i := range 10 {
		key := i
		wg.Go(func() {
			if g.Start(key) {
				mu.Lock()
				leaders++
				mu.Unlock()
				g.Done(key)
			}
		})
	}
	wg.Wait()

	if leaders != 10 {
		t.Errorf("expected 10 leaders (different keys), got %d", leaders)
	}
}

// ── ResultGroup ─────────────────────────────────────────────────────────────

func TestResultGroup_New(t *testing.T) {
	g := NewResultGroup[string, int]()
	if g == nil {
		t.Fatal("NewResultGroup returned nil")
	}
	if g.calls == nil {
		t.Fatal("NewResultGroup calls map is nil")
	}
}

func TestResultGroup_LeaderRunsOnce(t *testing.T) {
	g := NewResultGroup[string, int]()
	var runs atomic.Int64
	ctx := context.Background()

	v, err, leader := g.Do(ctx, "k", func(context.Context) (int, error) {
		runs.Add(1)
		return 42, nil
	})
	if !leader {
		t.Fatal("first caller should be leader")
	}
	if err != nil || v != 42 {
		t.Fatalf("want (42, nil), got (%d, %v)", v, err)
	}
	if runs.Load() != 1 {
		t.Fatalf("fn should run exactly once, ran %d", runs.Load())
	}
}

func TestResultGroup_FollowerWaitsForLeader(t *testing.T) {
	g := NewResultGroup[string, int]()
	release := make(chan struct{})
	started := make(chan struct{})
	var runs atomic.Int64

	go func() {
		_, _, _ = g.Do(context.Background(), "k", func(context.Context) (int, error) {
			runs.Add(1)
			close(started)
			<-release
			return 7, nil
		})
	}()
	<-started

	var wg sync.WaitGroup
	var gotV int
	var gotLeader bool
	wg.Go(func() {
		gotV, _, gotLeader = g.Do(context.Background(), "k", func(context.Context) (int, error) {
			runs.Add(1)
			return 0, errors.New("follower should not run fn")
		})
	})
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if gotLeader {
		t.Fatal("second caller should be follower")
	}
	if gotV != 7 {
		t.Fatalf("follower should receive leader's result 7, got %d", gotV)
	}
	if runs.Load() != 1 {
		t.Fatalf("fn should run once (leader only), ran %d", runs.Load())
	}
}

func TestResultGroup_FollowerReceivesLeaderError(t *testing.T) {
	g := NewResultGroup[string, int]()
	release := make(chan struct{})
	started := make(chan struct{})
	leaderErr := errors.New("leader failed")

	go func() {
		_, _, _ = g.Do(context.Background(), "k", func(context.Context) (int, error) {
			close(started)
			<-release
			return 0, leaderErr
		})
	}()
	<-started

	var wg sync.WaitGroup
	var gotErr error
	wg.Go(func() {
		_, gotErr, _ = g.Do(context.Background(), "k", func(context.Context) (int, error) {
			return 0, errors.New("follower should not run fn")
		})
	})
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if !errors.Is(gotErr, leaderErr) {
		t.Fatalf("follower should receive leader's error, got %v", gotErr)
	}
}

func TestResultGroup_DifferentKeysIndependent(t *testing.T) {
	g := NewResultGroup[string, int]()
	release := make(chan struct{})
	started := make(chan struct{})
	var runs atomic.Int64

	go func() {
		_, _, _ = g.Do(context.Background(), "a", func(context.Context) (int, error) {
			runs.Add(1)
			close(started)
			<-release
			return 1, nil
		})
	}()
	<-started

	v, err, leader := g.Do(context.Background(), "b", func(context.Context) (int, error) {
		runs.Add(1)
		return 2, nil
	})
	close(release)

	if !leader {
		t.Fatal("different key should be leader")
	}
	if err != nil || v != 2 {
		t.Fatalf("want (2, nil), got (%d, %v)", v, err)
	}
	if runs.Load() != 2 {
		t.Fatalf("fn should run once per key, ran %d", runs.Load())
	}
}

func TestResultGroup_FollowerTimeoutPromotes(t *testing.T) {
	g := NewResultGroup[string, int]()
	release := make(chan struct{})
	started := make(chan struct{})
	var runs atomic.Int64

	go func() {
		_, _, _ = g.Do(context.Background(), "k", func(context.Context) (int, error) {
			runs.Add(1)
			close(started)
			<-release
			return 1, nil
		})
	}()
	<-started
	defer close(release)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	promotedCtxDone := make(chan error, 1)
	v, err, leader := g.Do(ctx, "k", func(workCtx context.Context) (int, error) {
		runs.Add(1)
		// The caller's ctx expired (that is why the promotion fired) — the
		// promoted run must receive a LIVE context, otherwise every
		// operation inside fails instantly with "operation was canceled".
		promotedCtxDone <- workCtx.Err()
		return 2, nil
	})
	if !leader {
		t.Fatal("timed-out follower should be promoted to leader")
	}
	if err != nil || v != 2 {
		t.Fatalf("promoted caller should get its own result (2, nil), got (%d, %v)", v, err)
	}
	if runs.Load() != 2 {
		t.Fatalf("fn should run twice (original leader + promoted), ran %d", runs.Load())
	}
	if got := <-promotedCtxDone; got != nil {
		t.Fatalf("promoted fn must receive a live (uncanceled) ctx, got %v", got)
	}
}

func TestResultGroup_KeyReleasedAfterLeader(t *testing.T) {
	g := NewResultGroup[string, int]()
	ctx := context.Background()

	if _, _, leader := g.Do(ctx, "k", func(context.Context) (int, error) { return 1, nil }); !leader {
		t.Fatal("first call should be leader")
	}
	if _, _, leader := g.Do(ctx, "k", func(context.Context) (int, error) { return 2, nil }); !leader {
		t.Fatal("call after leader completion should be leader again")
	}
}

func TestResultGroup_EvictionWakesFollower(t *testing.T) {
	// Capacity 1 — second key evicts the first.
	g := &ResultGroup[string, int]{
		calls: nil, // set below
	}
	// We need a tiny capacity to trigger eviction.
	// Use a custom constructor since NewResultGroup uses maxPending (10000).
	g.calls = newResultGroupMap[string, int](1)

	release := make(chan struct{})
	started := make(chan struct{})

	go func() {
		_, _, _ = g.Do(context.Background(), "a", func(context.Context) (int, error) {
			close(started)
			<-release // never finishes — forces eviction
			return 1, nil
		})
	}()
	<-started

	// Follower for "a" — should block on the leader.
	followerDone := make(chan struct{})
	var followerErr error
	go func() {
		_, followerErr, _ = g.Do(context.Background(), "a", func(context.Context) (int, error) {
			return 0, errors.New("should not run")
		})
		close(followerDone)
	}()
	time.Sleep(30 * time.Millisecond)

	// Store key "b" — evicts "a" (capacity=1).
	_, _, _ = g.Do(context.Background(), "b", func(context.Context) (int, error) { return 2, nil })

	select {
	case <-followerDone:
		if !errors.Is(followerErr, ErrEvicted) {
			t.Errorf("evicted follower should receive ErrEvicted, got %v", followerErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("follower was never woken after eviction")
	}
	close(release)
}

// newResultGroupMap creates an lrumap.Map with OnEvict set for testing.
func newResultGroupMap[K comparable, V any](capacity int) *lrumap.Map[K, *resultCall[V]] {
	m := lrumap.New[K, *resultCall[V]](capacity)
	m.SetOnEvict(func(_ K, call *resultCall[V]) {
		call.once.Do(func() {
			call.err = ErrEvicted
			close(call.done)
		})
	})
	return m
}

// ── CallGroup ───────────────────────────────────────────────────────────────

func TestCallGroup_New(t *testing.T) {
	cg := NewCallGroup[string, int](100, time.Second, nil)
	if cg == nil {
		t.Fatal("NewCallGroup returned nil")
	}
	if cg.mmap == nil {
		t.Fatal("NewCallGroup mmap is nil")
	}
}

func TestCallGroup_LeaderAndFollower(t *testing.T) {
	cg := NewCallGroup[string, int](100, 5*time.Second, nil)

	// Leader.
	_, _, follower := cg.Join("k")
	if follower {
		t.Fatal("expected leader")
	}

	// Follower: start goroutine, wait for it to be blocked, then call Done.
	followerStarted := make(chan struct{})
	var gotV int
	var gotFollower bool
	var wg sync.WaitGroup
	wg.Go(func() {
		close(followerStarted)
		v, _, f := cg.Join("k")
		gotV = v
		gotFollower = f
	})

	<-followerStarted
	time.Sleep(30 * time.Millisecond)
	cg.Done("k", 42, nil)

	wg.Wait()
	if !gotFollower {
		t.Fatal("expected follower")
	}
	if gotV != 42 {
		t.Fatalf("follower should receive 42, got %d", gotV)
	}
}

func TestCallGroup_CloneIsCalled(t *testing.T) {
	cloneCalled := false
	cg := NewCallGroup[string, *int](100, 5*time.Second, func(v *int) *int {
		cloneCalled = true
		n := *v
		return &n
	})

	_, _, follower := cg.Join("k")
	if follower {
		t.Fatal("expected leader")
	}

	original := 42
	cg.Done("k", &original, nil)

	if !cloneCalled {
		t.Fatal("clone should have been called on Done")
	}
}

func TestCallGroup_FollowerTimeout(t *testing.T) {
	cg := NewCallGroup[string, int](100, 50*time.Millisecond, nil)

	// Leader acquires the key but never calls Done.
	_, _, follower := cg.Join("k")
	if follower {
		t.Fatal("expected leader")
	}

	// Follower times out.
	_, err, follower := cg.Join("k")
	if !follower {
		t.Fatal("expected follower")
	}
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("expected ErrTimeout, got %v", err)
	}
}

func TestCallGroup_DoneThenRejoin(t *testing.T) {
	cg := NewCallGroup[string, int](100, 5*time.Second, nil)

	_, _, follower := cg.Join("a")
	if follower {
		t.Fatal("expected leader for first call")
	}
	cg.Done("a", 1, nil)

	// After Done, a new call should be leader again.
	_, _, follower = cg.Join("a")
	if follower {
		t.Fatal("expected leader after Done")
	}
}

func TestCallGroup_DifferentKeys(t *testing.T) {
	cg := NewCallGroup[string, int](100, 5*time.Second, nil)

	_, _, f := cg.Join("a")
	if f {
		t.Fatal("expected leader for key a")
	}
	_, _, f = cg.Join("b")
	if f {
		t.Fatal("expected leader for key b")
	}

	cg.Done("a", 1, nil)
	cg.Done("b", 2, nil)
}

func TestCallGroup_DoJoin(t *testing.T) {
	cg := NewCallGroup[string, int](100, 5*time.Second, nil)
	var runs atomic.Int64

	v, err := cg.DoJoin("k", func() (int, error) {
		runs.Add(1)
		return 99, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != 99 {
		t.Fatalf("want 99, got %d", v)
	}
	if runs.Load() != 1 {
		t.Fatalf("fn should run once, ran %d", runs.Load())
	}

	// Concurrent DoJoin sharing the same key.
	release := make(chan struct{})
	started := make(chan struct{})
	go func() {
		_, _ = cg.DoJoin("k2", func() (int, error) {
			close(started)
			<-release
			return 7, nil
		})
	}()
	<-started

	var wg sync.WaitGroup
	var gotV int
	wg.Go(func() {
		gotV, _ = cg.DoJoin("k2", func() (int, error) {
			runs.Add(1)
			return 0, errors.New("follower should not run fn")
		})
	})
	time.Sleep(30 * time.Millisecond)
	close(release)
	wg.Wait()

	if gotV != 7 {
		t.Fatalf("follower should receive leader's result 7, got %d", gotV)
	}
}

func TestCallGroup_EvictionWakesFollower(t *testing.T) {
	// Capacity 1 so the second key evicts the first.
	cg := NewCallGroup[string, int](1, 10*time.Second, nil)

	// Leader acquires "a" — never calls Done.
	_, _, follower := cg.Join("a")
	if follower {
		t.Fatal("expected leader for key a")
	}

	// Follower for "a".
	followerWoke := make(chan error, 1)
	go func() {
		_, err, _ := cg.Join("a")
		followerWoke <- err
	}()
	time.Sleep(30 * time.Millisecond)

	// Store "b" — evicts "a".
	_, _ = cg.DoJoin("b", func() (int, error) { return 1, nil })

	select {
	case err := <-followerWoke:
		if !errors.Is(err, ErrEvicted) {
			t.Errorf("evicted follower should receive ErrEvicted, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("follower was never woken after eviction")
	}
}

func TestCallGroup_DoneWithoutJoin(t *testing.T) {
	cg := NewCallGroup[string, int](100, time.Second, nil)
	cg.Done("no-such-key", 0, nil) // must not panic
}

func TestCallGroup_ConcurrentSameKey(t *testing.T) {
	cg := NewCallGroup[string, int](100, 10*time.Second, nil)

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
			_, _, f := cg.Join("k")
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
	time.Sleep(10 * time.Millisecond)

	if n := leaders.Load(); n != 1 {
		t.Errorf("expected exactly 1 leader, got %d", n)
	}

	cg.Done("k", 42, nil)

	wg.Wait()
	if n := followers.Load(); n != int32(goroutines-1) {
		t.Errorf("expected %d followers, got %d", goroutines-1, n)
	}
}
