package pending

import (
	"sync"
	"testing"
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
