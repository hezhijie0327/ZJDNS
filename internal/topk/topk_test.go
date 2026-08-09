package topk

import (
	"sync"
	"testing"
)

func TestIncAndLen(t *testing.T) {
	m := New[string](10)
	if m.Len() != 0 {
		t.Fatalf("fresh map Len = %d, want 0", m.Len())
	}
	m.Inc("a")
	m.Inc("a")
	m.Inc("b")
	if m.Len() != 2 {
		t.Fatalf("Len = %d, want 2", m.Len())
	}
	top := m.TopN(10)
	if len(top) != 2 {
		t.Fatalf("TopN len = %d, want 2", len(top))
	}
	if top[0].Key != "a" || top[0].Count != 2 {
		t.Fatalf("top[0] = %+v, want {a 2}", top[0])
	}
	if top[1].Key != "b" || top[1].Count != 1 {
		t.Fatalf("top[1] = %+v, want {b 1}", top[1])
	}
}

func TestOverflowEvictsMin(t *testing.T) {
	m := New[string](3)
	m.Inc("a") // 1
	m.Inc("b") // 1
	m.Inc("c") // 1
	m.Inc("a") // a=2
	// Full (3 entries): a=2, b=1, c=1. A new key must evict one of b/c (tie).
	m.Inc("d") // d=1
	if m.Len() != 3 {
		t.Fatalf("Len = %d, want 3", m.Len())
	}
	counts := map[string]uint64{}
	for _, e := range m.TopN(10) {
		counts[e.Key] = e.Count
	}
	if counts["a"] != 2 {
		t.Fatalf("a count = %d, want 2 (a must survive eviction)", counts["a"])
	}
	if counts["d"] != 1 {
		t.Fatalf("d count = %d, want 1 (new key must be present)", counts["d"])
	}
	evicted := 0
	for _, k := range []string{"b", "c"} {
		if _, ok := counts[k]; !ok {
			evicted++
		}
	}
	if evicted != 1 {
		t.Fatalf("exactly one of b/c must be evicted, got %d", evicted)
	}
}

func TestEvictsLowestCountNotTies(t *testing.T) {
	m := New[string](2)
	m.Inc("hot")  // hot=1
	m.Inc("cold") // cold=1
	m.Inc("hot")  // hot=2
	m.Inc("new")  // new=1 → must evict cold (count 1), keep hot (count 2)
	if m.Len() != 2 {
		t.Fatalf("Len = %d, want 2", m.Len())
	}
	top := m.TopN(10)
	if top[0].Key != "hot" || top[0].Count != 2 {
		t.Fatalf("top[0] = %+v, want {hot 2}", top[0])
	}
}

func TestTopNLimit(t *testing.T) {
	m := New[string](10)
	for _, k := range []string{"a", "b", "c"} {
		m.Inc(k)
	}
	top := m.TopN(2)
	if len(top) != 2 {
		t.Fatalf("TopN(2) len = %d, want 2", len(top))
	}
	if n := m.TopN(100); len(n) != 3 {
		t.Fatalf("TopN(100) len = %d, want 3 (capped at Len)", len(n))
	}
}

func TestClear(t *testing.T) {
	m := New[string](10)
	m.Inc("a")
	m.Clear()
	if m.Len() != 0 {
		t.Fatalf("Len after Clear = %d, want 0", m.Len())
	}
	if top := m.TopN(10); len(top) != 0 {
		t.Fatalf("TopN after Clear = %+v, want empty", top)
	}
}

func TestDefaultCapacity(t *testing.T) {
	m := New[string](0)
	if m.capacity != defaultCapacity {
		t.Fatalf("capacity = %d, want %d", m.capacity, defaultCapacity)
	}
}

func TestConcurrentInc(t *testing.T) {
	m := New[string](1000)
	const workers, incs = 16, 1000
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for range incs {
				m.Inc("shared")
			}
		})
	}
	wg.Wait()
	if m.Len() != 1 {
		t.Fatalf("Len = %d, want 1", m.Len())
	}
	if top := m.TopN(1); top[0].Count != workers*incs {
		t.Fatalf("count = %d, want %d", top[0].Count, workers*incs)
	}
}

func BenchmarkInc(b *testing.B) {
	m := New[string](10000)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			m.Inc("example.com")
		}
	})
}

func BenchmarkTopN(b *testing.B) {
	m := New[string](10000)
	for range 5000 {
		m.Inc("example.com")
	}
	for i := range 200 {
		m.Inc(string(rune('a' + i%26)))
	}
	b.ResetTimer()
	for range b.N {
		m.TopN(10)
	}
}
