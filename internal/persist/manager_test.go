package persist

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type countingSaver struct {
	count atomic.Int64
	err   error
}

func (c *countingSaver) Save() error {
	c.count.Add(1)
	return c.err
}

func TestManager_SaveAll_CallsAll(t *testing.T) {
	m := NewManager()
	a, b := &countingSaver{}, &countingSaver{}
	m.Register("a", a)
	m.Register("b", b)

	m.SaveAll()
	if a.count.Load() != 1 || b.count.Load() != 1 {
		t.Errorf("counts = (%d, %d), want (1, 1)", a.count.Load(), b.count.Load())
	}
}

func TestManager_SaveAll_ContinuesOnFailure(t *testing.T) {
	m := NewManager()
	failing := &countingSaver{err: errors.New("boom")}
	ok := &countingSaver{}
	m.Register("failing", failing)
	m.Register("ok", ok)

	m.SaveAll() // must not panic; ok still saved
	if ok.count.Load() != 1 {
		t.Errorf("ok saver count = %d, want 1 (continued past failure)", ok.count.Load())
	}
}

func TestManager_RegisterNil_NoPanic(t *testing.T) {
	m := NewManager()
	m.Register("nil", nil)
	m.SaveAll() // no-op
}

func TestManager_Run_Periodic(t *testing.T) {
	m := NewManager()
	a := &countingSaver{}
	m.Register("a", a)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Run(ctx, 10*time.Millisecond) }()

	deadline := time.After(200 * time.Millisecond)
	for a.count.Load() < 2 {
		select {
		case <-deadline:
			t.Fatal("periodic saves did not fire")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
}

func TestManager_Run_FinalSaveOnCancel(t *testing.T) {
	m := NewManager()
	a := &countingSaver{}
	m.Register("a", a)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Run(ctx, 0) }() // shutdown-only

	time.Sleep(20 * time.Millisecond)
	if a.count.Load() != 0 {
		t.Fatalf("saved before cancellation: %d", a.count.Load())
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if a.count.Load() != 1 {
		t.Errorf("final save count = %d, want 1", a.count.Load())
	}
}

func TestManager_ConcurrentSaveAll(t *testing.T) {
	m := NewManager()
	m.Register("shared", &countingSaver{})
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(m.SaveAll)
	}
	wg.Wait() // race detector: concurrent SaveAll must be safe
}
