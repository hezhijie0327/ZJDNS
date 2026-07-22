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
	m := New[string, int](10) // evicts to 80% = 8 at capacity
	for i := range 15 {
		m.Set(strconv.Itoa(i), i)
	}
	if m.Len() > 10 {
		t.Errorf("Len = %d, want <= 10 after eviction", m.Len())
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

func TestConcurrent(t *testing.T) {
	m := New[int, int](1000)
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			for i := range 100 {
				m.Set(i, i*2)
				if v, ok := m.Get(i); ok && v != i*2 {
					t.Errorf("value mismatch: got %d, want %d", v, i*2)
				}
			}
		})
	}
	wg.Wait()
}
