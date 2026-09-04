package lrumap

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestShardedBasics(t *testing.T) {
	m := NewSharded[string, int](10000) // above degenerate threshold → sharded
	if len(m.shards) != defaultShards {
		t.Fatalf("shards = %d, want %d", len(m.shards), defaultShards)
	}
	if _, ok := m.Get("a"); ok {
		t.Fatal("fresh map must miss")
	}
	m.Set("a", 1)
	if v, ok := m.Get("a"); !ok || v != 1 {
		t.Fatalf("Get = %d,%v want 1,true", v, ok)
	}
	m.Set("a", 2)
	if v, _ := m.Get("a"); v != 2 {
		t.Fatalf("overwrite Get = %d, want 2", v)
	}
	if v, loaded := m.LoadOrStore("a", 3); !loaded || v != 2 {
		t.Fatalf("LoadOrStore existing = %d,%v want 2,true", v, loaded)
	}
	if v, loaded := m.LoadOrStore("b", 3); loaded || v != 3 {
		t.Fatalf("LoadOrStore new = %d,%v want 3,false", v, loaded)
	}
	if m.Len() != 2 {
		t.Fatalf("Len = %d, want 2", m.Len())
	}
	n := 0
	m.Range(func(k string, v int) bool { n++; return true })
	if n != 2 {
		t.Fatalf("Range visited %d, want 2", n)
	}
	m.Delete("a")
	if m.Len() != 1 {
		t.Fatalf("Len after Delete = %d, want 1", m.Len())
	}
	m.Clear()
	if m.Len() != 0 {
		t.Fatalf("Len after Clear = %d, want 0", m.Len())
	}
}

func TestShardedEvictionCallback(t *testing.T) {
	m := NewSharded[string, int](10000)
	var evicted atomic.Int64
	m.SetOnEvict(func(k string, v int) { evicted.Add(1) })
	m.Set("a", 1)
	m.Set("a", 2) // overwrite fires OnEvict with the old value
	if evicted.Load() != 1 {
		t.Fatalf("evictions = %d, want 1", evicted.Load())
	}
	m.Delete("a")
	if evicted.Load() != 2 {
		t.Fatalf("evictions after Delete = %d, want 2", evicted.Load())
	}
}

func TestShardedConcurrent(t *testing.T) {
	m := NewSharded[string, int](100000)
	var wg sync.WaitGroup
	for w := range 16 {
		wg.Go(func() {
			for i := range 1000 {
				k := string(rune('a'+w%26)) + itoa(i)
				m.Set(k, i)
				m.Get(k)
				if i%10 == 0 {
					m.Delete(k)
				}
			}
		})
	}
	wg.Wait()
	if m.Len() == 0 {
		t.Fatal("map must not be empty after concurrent fill")
	}
}

func TestShardedSmallCapacityExact(t *testing.T) {
	// Below the degenerate threshold the bound must stay exact.
	m := NewSharded[string, int](3)
	m.Set("a", 1)
	m.Set("b", 2)
	m.Set("c", 3)
	m.Set("d", 4)
	if m.Len() != 3 {
		t.Fatalf("Len = %d, want 3 (exact small-capacity bound)", m.Len())
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func BenchmarkMapGetSharded(b *testing.B) {
	m := NewSharded[string, int](100000)
	m.Set("example.com", 1)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			m.Get("example.com")
		}
	})
}

func BenchmarkMapGetSingle(b *testing.B) {
	m := New[string, int](100000)
	m.Set("example.com", 1)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			m.Get("example.com")
		}
	})
}

func BenchmarkMapGetSpreadSharded(b *testing.B) {
	m := NewSharded[string, int](100000)
	for i := range 4096 {
		m.Set("key-"+itoa(i), i)
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			m.Get("key-" + itoa(i%4096))
			i++
		}
	})
}

func BenchmarkMapGetSpreadSingle(b *testing.B) {
	m := New[string, int](100000)
	for i := range 4096 {
		m.Set("key-"+itoa(i), i)
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			m.Get("key-" + itoa(i%4096))
			i++
		}
	})
}
