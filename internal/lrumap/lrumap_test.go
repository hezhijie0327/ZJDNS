package lrumap

import (
	"strconv"
	"sync"
	"testing"
)

func TestNew_ZeroCapacity(t *testing.T) {
	m := New[string, int](0)
	if m.cap != 64 {
		t.Errorf("zero capacity should default to 64, got %d", m.cap)
	}
}

func TestSet_Get(t *testing.T) {
	m := New[string, int](10)
	m.Set("a", 1)
	v, ok := m.Get("a")
	if !ok {
		t.Fatal("Get should find key")
	}
	if v != 1 {
		t.Errorf("value = %d, want 1", v)
	}
}

func TestGet_Miss(t *testing.T) {
	m := New[string, int](10)
	_, ok := m.Get("nonexistent")
	if ok {
		t.Error("Get should not find missing key")
	}
}

func TestSet_Overwrite(t *testing.T) {
	m := New[string, int](10)
	m.Set("a", 1)
	m.Set("a", 2)
	v, _ := m.Get("a")
	if v != 2 {
		t.Errorf("value = %d, want 2 (overwritten)", v)
	}
}

func TestLen(t *testing.T) {
	m := New[string, int](10)
	if m.Len() != 0 {
		t.Errorf("Len = %d, want 0", m.Len())
	}
	m.Set("a", 1)
	m.Set("b", 2)
	if m.Len() != 2 {
		t.Errorf("Len = %d, want 2", m.Len())
	}
}

func TestEviction(t *testing.T) {
	m := New[string, int](10)
	// Insert 15 entries into cap=10 — the first 5 (LRU) should be evicted.
	for i := range 15 {
		m.Set(strconv.Itoa(i), i)
	}
	if m.Len() != 10 {
		t.Errorf("Len = %d, want 10", m.Len())
	}
	// Entries 0-4 are the least recently used and should be gone.
	for i := range 5 {
		if _, ok := m.Get(strconv.Itoa(i)); ok {
			t.Errorf("entry %d should have been evicted (was LRU)", i)
		}
	}
	// Entries 5-14 should still be present.
	for i := 5; i < 15; i++ {
		if _, ok := m.Get(strconv.Itoa(i)); !ok {
			t.Errorf("entry %d should still be present", i)
		}
	}
}

func TestLRU_GetMovesToFront(t *testing.T) {
	m := New[string, int](3)
	m.Set("a", 1)
	m.Set("b", 2)
	m.Set("c", 3) // order: c(most recent), b, a(LRU)

	// Access "a" — it moves to front: a, c, b. Now b is LRU.
	m.Get("a")

	// Insert "d" — evicts b.
	m.Set("d", 4)

	if _, ok := m.Get("b"); ok {
		t.Error("b should have been evicted (became LRU after a was accessed)")
	}
	if _, ok := m.Get("a"); !ok {
		t.Error("a should still be present (was accessed recently)")
	}
	if _, ok := m.Get("c"); !ok {
		t.Error("c should still be present")
	}
	if _, ok := m.Get("d"); !ok {
		t.Error("d should be present")
	}
}

func TestLRU_SetUpdatesMovesToFront(t *testing.T) {
	m := New[string, int](3)
	m.Set("a", 1)
	m.Set("b", 2)
	m.Set("c", 3) // order: c, b, a(LRU)

	// Update "a" — it moves to front: a, c, b. Now b is LRU.
	m.Set("a", 10)

	// Insert "d" — evicts b.
	m.Set("d", 4)

	if _, ok := m.Get("b"); ok {
		t.Error("b should have been evicted")
	}
	if v, ok := m.Get("a"); !ok || v != 10 {
		t.Errorf("a should be present with value 10, got %d", v)
	}
}

func TestDelete(t *testing.T) {
	m := New[string, int](10)
	m.Set("a", 1)
	m.Delete("a")
	_, ok := m.Get("a")
	if ok {
		t.Error("Get should not find deleted key")
	}
	if m.Len() != 0 {
		t.Errorf("Len = %d, want 0 after delete", m.Len())
	}
}

func TestDelete_NonExistent(t *testing.T) {
	m := New[string, int](10)
	// Should not panic.
	m.Delete("nonexistent")
}

func TestConcurrent(t *testing.T) {
	m := New[int, int](1000)
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			for i := range 100 {
				m.Set(i, i*2)
				m.Get(i)
			}
		})
	}
	wg.Wait()
	// Map should not exceed capacity.
	if m.Len() > 1000 {
		t.Errorf("Len = %d, want <= 1000", m.Len())
	}
}

func TestCapacityOne(t *testing.T) {
	m := New[string, int](1)
	m.Set("a", 1)
	if m.Len() != 1 {
		t.Errorf("Len = %d, want 1", m.Len())
	}
	// Setting a new key at capacity evicts the LRU entry.
	m.Set("b", 2)
	if m.Len() != 1 {
		t.Errorf("Len = %d, want 1 after eviction", m.Len())
	}
	// "a" should be evicted (LRU), "b" should be present.
	if _, ok := m.Get("a"); ok {
		t.Error("a should have been evicted")
	}
	if v, ok := m.Get("b"); !ok || v != 2 {
		t.Errorf("b should be present with value 2, got %d", v)
	}
}

func TestCapacityOne_UpdatePreserves(t *testing.T) {
	m := New[string, int](1)
	m.Set("a", 1)
	m.Set("a", 2) // update, not eviction
	if m.Len() != 1 {
		t.Errorf("Len = %d, want 1", m.Len())
	}
	if v, _ := m.Get("a"); v != 2 {
		t.Errorf("value = %d, want 2", v)
	}
}

func TestNoLeak_EvictAllThenRefill(t *testing.T) {
	// Fill a small map, evict everything, refill — verify internal consistency.
	m := New[string, int](5)
	keys := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}

	// Fill → evict cycle: after 10 inserts into cap=5, only last 5 remain.
	for _, k := range keys {
		m.Set(k, 1)
	}
	if m.Len() != 5 {
		t.Fatalf("after fill+evict: Len = %d, want 5", m.Len())
	}
	// First 5 keys should be evicted.
	for _, k := range keys[:5] {
		if _, ok := m.Get(k); ok {
			t.Errorf("key %q should have been evicted", k)
		}
	}
	// Last 5 keys should be present.
	for _, k := range keys[5:] {
		if _, ok := m.Get(k); !ok {
			t.Errorf("key %q should be present", k)
		}
	}

	// Delete all remaining entries.
	for _, k := range keys[5:] {
		m.Delete(k)
	}
	if m.Len() != 0 {
		t.Fatalf("after delete all: Len = %d, want 0", m.Len())
	}

	// Refill — should work without stale state.
	for _, k := range keys[:5] {
		m.Set(k, 2)
	}
	if m.Len() != 5 {
		t.Fatalf("after refill: Len = %d, want 5", m.Len())
	}
	for _, k := range keys[:5] {
		if v, ok := m.Get(k); !ok || v != 2 {
			t.Errorf("refill key %q: ok=%v v=%d, want ok=true v=2", k, ok, v)
		}
	}
}

func TestNoLeak_Churn(t *testing.T) {
	// Rapid insert/delete/evict cycle — verifies list/map consistency.
	m := New[int, int](64)
	for range 1000 {
		for i := range 128 {
			m.Set(i, i)
		}
		for i := range 64 {
			m.Delete(i)
		}
	}
	// Map should be bounded by capacity.
	if m.Len() > 64 {
		t.Errorf("Len = %d, want <= 64 after churn", m.Len())
	}
	// Entries 64-127 should be present (never deleted).
	for i := 64; i < 128; i++ {
		if _, ok := m.Get(i); !ok {
			t.Errorf("key %d should still be present after churn", i)
		}
	}
}

func TestNoLeak_OverwriteNoLeak(t *testing.T) {
	// Repeatedly overwrite the same key — should not leak list nodes.
	m := New[string, int](10)
	for range 10000 {
		m.Set("hot", 42)
	}
	if m.Len() != 1 {
		t.Errorf("Len = %d, want 1 after overwrite loop", m.Len())
	}
	if v, _ := m.Get("hot"); v != 42 {
		t.Errorf("value = %d, want 42", v)
	}
}
