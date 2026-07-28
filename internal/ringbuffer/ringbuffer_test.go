package ringbuffer

import (
	"sync"
	"testing"
)

func TestNew(t *testing.T) {
	rb := New[int](10)
	if rb.Cap() != 10 {
		t.Errorf("Cap() = %d, want 10", rb.Cap())
	}
	if rb.Len() != 0 {
		t.Errorf("Len() = %d, want 0", rb.Len())
	}
}

func TestPushAndSnapshot(t *testing.T) {
	rb := New[int](5)
	for i := range 5 {
		rb.Push(i)
	}
	snap := rb.Snapshot()
	if len(snap) != 5 {
		t.Fatalf("Snapshot len = %d, want 5", len(snap))
	}
	// Newest-first: [4, 3, 2, 1, 0]
	want := []int{4, 3, 2, 1, 0}
	for i := range snap {
		if snap[i] != want[i] {
			t.Errorf("Snapshot[%d] = %d, want %d", i, snap[i], want[i])
		}
	}
}

func TestPushOverflow(t *testing.T) {
	rb := New[int](3)
	for i := range 5 {
		rb.Push(i) // pushes 0,1,2,3,4
	}
	if rb.Len() != 3 {
		t.Errorf("Len() = %d, want 3", rb.Len())
	}
	snap := rb.Snapshot()
	// Buffer should contain [2,3,4], newest-first: [4,3,2]
	want := []int{4, 3, 2}
	if len(snap) != len(want) {
		t.Fatalf("Snapshot len = %d, want %d", len(snap), len(want))
	}
	for i := range snap {
		if snap[i] != want[i] {
			t.Errorf("Snapshot[%d] = %d, want %d", i, snap[i], want[i])
		}
	}
}

func TestSnapshotN(t *testing.T) {
	rb := New[int](10)
	for i := range 10 {
		rb.Push(i)
	}

	// n less than size
	snap := rb.SnapshotN(3)
	if len(snap) != 3 {
		t.Fatalf("SnapshotN(3) len = %d, want 3", len(snap))
	}
	want := []int{9, 8, 7}
	for i := range snap {
		if snap[i] != want[i] {
			t.Errorf("SnapshotN(3)[%d] = %d, want %d", i, snap[i], want[i])
		}
	}

	// n > size
	snap2 := rb.SnapshotN(20)
	if len(snap2) != 10 {
		t.Errorf("SnapshotN(20) len = %d, want 10", len(snap2))
	}

	// n = 0
	snap3 := rb.SnapshotN(0)
	if len(snap3) != 0 {
		t.Errorf("SnapshotN(0) len = %d, want 0", len(snap3))
	}

	// n negative
	snap4 := rb.SnapshotN(-1)
	if len(snap4) != 0 {
		t.Errorf("SnapshotN(-1) len = %d, want 0", len(snap4))
	}
}

func TestSnapshotNonDestructive(t *testing.T) {
	rb := New[int](3)
	rb.Push(1)
	rb.Push(2)

	s1 := rb.Snapshot()
	s2 := rb.Snapshot()

	if len(s1) != len(s2) {
		t.Fatal("consecutive snapshots differ in length")
	}
	for i := range s1 {
		if s1[i] != s2[i] {
			t.Errorf("s1[%d] = %d, s2[%d] = %d", i, s1[i], i, s2[i])
		}
	}
}

func TestSnapshotReturnsCopy(t *testing.T) {
	rb := New[int](3)
	rb.Push(1)
	rb.Push(2)

	s1 := rb.Snapshot()
	s1[0] = 999 // mutate copy
	s2 := rb.Snapshot()

	if s2[0] == 999 {
		t.Error("Snapshot should return a copy, not a reference")
	}
}

func TestEmptySnapshot(t *testing.T) {
	rb := New[int](5)
	snap := rb.Snapshot()
	if snap != nil {
		t.Errorf("Snapshot of empty buffer = %v, want nil", snap)
	}
	snapN := rb.SnapshotN(3)
	if snapN != nil {
		t.Errorf("SnapshotN of empty buffer = %v, want nil", snapN)
	}
}

func TestConcurrentPushAndRead(t *testing.T) {
	rb := New[int](100)
	var wg sync.WaitGroup

	// Concurrent writers
	for g := range 10 {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for i := range 100 {
				rb.Push(base*1000 + i)
			}
		}(g)
	}

	// Concurrent reader
	done := make(chan struct{})
	go func() {
		for range 50 {
			_ = rb.Snapshot()
			_ = rb.SnapshotN(10)
		}
		close(done)
	}()

	wg.Wait()
	<-done

	// Should not panic and should have some data
	if rb.Len() == 0 {
		t.Error("Len() = 0 after concurrent writes")
	}
}

func TestSingleElement(t *testing.T) {
	rb := New[string](5)
	rb.Push("hello")

	if rb.Len() != 1 {
		t.Errorf("Len() = %d, want 1", rb.Len())
	}
	snap := rb.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("Snapshot len = %d, want 1", len(snap))
	}
	if snap[0] != "hello" {
		t.Errorf("Snapshot[0] = %q, want %q", snap[0], "hello")
	}
}
