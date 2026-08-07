package pending

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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
	// After Done, Start should succeed again.
	if !g.Start(1) {
		t.Error("Start after Done should return true")
	}
}

func TestDone_UnknownKey(t *testing.T) {
	g := NewGroup[int]()
	// Should not panic.
	g.Done(42)
}

func TestDone_DoubleDone(t *testing.T) {
	g := NewGroup[int]()
	g.Start(1)
	g.Done(1)
	// Second Done should be a no-op (not panic).
	g.Done(1)
}

func TestGroup_Concurrent(t *testing.T) {
	// The Group pattern is "skip if in-flight" — it does not queue followers.
	// With 100 concurrent Start calls for the same key, some will overlap and
	// become leaders before Done is called. The contract is: no panics, Done
	// properly cleans up so the final Start after all Done always succeeds.
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

	// After all goroutines finish, a new Start for the same key must succeed.
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

	v, err, leader := g.Do(ctx, "k", func() (int, error) {
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
		_, _, _ = g.Do(context.Background(), "k", func() (int, error) {
			runs.Add(1)
			close(started)
			<-release
			return 7, nil
		})
	}()
	<-started

	// Follower blocks until the leader finishes.
	var wg sync.WaitGroup
	var gotV int
	var gotLeader bool
	wg.Go(func() {
		gotV, _, gotLeader = g.Do(context.Background(), "k", func() (int, error) {
			runs.Add(1)
			return 0, errors.New("follower should not run fn")
		})
	})
	time.Sleep(50 * time.Millisecond) // give the follower time to join
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
		_, _, _ = g.Do(context.Background(), "k", func() (int, error) {
			close(started)
			<-release
			return 0, leaderErr
		})
	}()
	<-started

	var wg sync.WaitGroup
	var gotErr error
	wg.Go(func() {
		_, gotErr, _ = g.Do(context.Background(), "k", func() (int, error) {
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
		_, _, _ = g.Do(context.Background(), "a", func() (int, error) {
			runs.Add(1)
			close(started)
			<-release
			return 1, nil
		})
	}()
	<-started

	// A different key runs independently without waiting.
	v, err, leader := g.Do(context.Background(), "b", func() (int, error) {
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
		_, _, _ = g.Do(context.Background(), "k", func() (int, error) {
			runs.Add(1)
			close(started)
			<-release // leader blocks forever (until test cleanup)
			return 1, nil
		})
	}()
	<-started
	defer close(release)

	// Follower with a short ctx is promoted and runs fn itself.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	v, err, leader := g.Do(ctx, "k", func() (int, error) {
		runs.Add(1)
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
}

func TestResultGroup_KeyReleasedAfterLeader(t *testing.T) {
	g := NewResultGroup[string, int]()
	ctx := context.Background()

	if _, _, leader := g.Do(ctx, "k", func() (int, error) { return 1, nil }); !leader {
		t.Fatal("first call should be leader")
	}
	// After the leader finishes, a new call for the same key runs fn again.
	if _, _, leader := g.Do(ctx, "k", func() (int, error) { return 2, nil }); !leader {
		t.Fatal("call after leader completion should be leader again")
	}
}
