package handler

import (
	"sync"
	"testing"
)

func TestPrefetchCooldown_Window(t *testing.T) {
	pc := NewPrefetchCooldown()
	now := int64(1000)
	if !pc.ShouldStart("a", now, 100) {
		t.Fatal("first start should be allowed")
	}
	if pc.ShouldStart("a", now+50, 100) {
		t.Error("start within cooldown window should be rejected")
	}
	if !pc.ShouldStart("a", now+100, 100) {
		t.Error("start after the cooldown window should be allowed")
	}
}

func TestPrefetchCooldown_DifferentKeys(t *testing.T) {
	pc := NewPrefetchCooldown()
	if !pc.ShouldStart("a", 1000, 100) {
		t.Fatal("a should start")
	}
	if !pc.ShouldStart("b", 1000, 100) {
		t.Error("b should start (different key)")
	}
}

func TestPrefetchCooldown_Cleanup(t *testing.T) {
	pc := NewPrefetchCooldown()
	now := int64(1000)
	pc.ShouldStart("old", now, 100)
	pc.Cleanup(now+200, 100) // both aged past the window — removed
	if !pc.ShouldStart("old", now+200, 100) {
		t.Error("cleaned key should be startable (was evicted by cleanup)")
	}

	// A key still inside its window survives cleanup.
	pc.ShouldStart("live", now+200, 100)
	pc.Cleanup(now+250, 100) // live: 50ms old < 100ms window — kept
	if pc.ShouldStart("live", now+200, 100) {
		t.Error("live key must stay in cooldown after cleanup")
	}
}

func TestPrefetchCooldown_Concurrent(t *testing.T) {
	pc := NewPrefetchCooldown()
	// After the cooldown window passes, concurrent starters must not both
	// pass for an existing expired key (CompareAndDelete exclusivity).
	pc.ShouldStart("hot", 1000, 100)
	var wg sync.WaitGroup
	started := make(chan bool, 8)
	for range 8 {
		wg.Go(func() {
			started <- pc.ShouldStart("hot", 2000, 100)
		})
	}
	wg.Wait()
	close(started)
	passes := 0
	for s := range started {
		if s {
			passes++
		}
	}
	if passes != 1 {
		t.Errorf("concurrent starters passed %d times, want exactly 1", passes)
	}
}
