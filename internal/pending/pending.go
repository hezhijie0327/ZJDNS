// Package pending provides generic singleflight-style deduplication groups.
//
// Group has skip-follower semantics: when multiple callers invoke Start with
// the same key before Done is called, only the first (leader) proceeds; all
// others (followers) are rejected and skip the work entirely.
//
// ResultGroup has wait-for-result semantics: the leader executes fn and every
// concurrent caller with the same key waits for and receives the leader's
// result.  Use it when followers need the result or its side effects (e.g. a
// populated cache) to proceed.
//
// Both groups bound their internal map at maxPending entries to prevent
// unbounded memory growth from leaked keys (keys never released due to panics
// or logic errors).  When the map is full, dedup degrades gracefully: callers
// proceed as leaders rather than starving.
package pending

import (
	"context"
	"sync"
)

// Group deduplicates concurrent work by key.  Start registers a pending
// operation; if an operation for the same key is already in flight, it
// returns false.  Done removes the key, allowing future operations to
// proceed.
//
// The zero value is not usable; use NewGroup to create a valid Group.
type Group[K comparable] struct {
	mu   sync.Mutex
	sets map[K]struct{}
}

// ResultGroup deduplicates concurrent work by key with wait-for-result
// semantics.  The first caller (leader) executes fn; concurrent callers with
// the same key wait for the leader's result and receive it.  Complements
// Group (skip-follower) — use ResultGroup when followers need the result or
// its side effects to proceed.
//
// A follower whose context expires before the leader finishes is promoted to
// leader and runs fn itself: the wait is bounded by ctx, never indefinite.
// The promotion may duplicate fn under a slow leader — that is the same
// graceful degradation as the map-full path.
//
// fn must not call Do with the same key (self-deadlock).
//
// The zero value is not usable; use NewResultGroup to create a valid group.
type ResultGroup[K comparable, V any] struct {
	mu    sync.Mutex
	calls map[K]*resultCall[V]
}

// resultCall holds one in-flight key: the leader's result and a broadcast
// channel.  val/err are written by the leader before done is closed; readers
// observe them through the channel's happens-before edge.
type resultCall[V any] struct {
	done chan struct{}
	once sync.Once
	val  V
	err  error
}

// maxPending is the hard cap on in-flight keys to prevent unbounded memory
// growth when Done is never called (key leakage from panics or missing
// defer g.Done(key) calls).
const maxPending = 10000

// NewGroup creates a Group ready for use.
func NewGroup[K comparable]() *Group[K] {
	return &Group[K]{
		sets: make(map[K]struct{}),
	}
}

// Start registers an operation for key.  Returns true if the caller should
// proceed (leader).  Returns false if an operation for this key is already in
// flight; the caller should skip its work.
//
// When the internal map reaches maxPending entries, Start returns true
// (leader) to prevent starvation — dedup degrades gracefully under overload.
//
// Callers MUST use `defer g.Done(key)` immediately after Start(key) to
// prevent key leakage if the goroutine panics.
func (g *Group[K]) Start(key K) bool {
	g.mu.Lock()
	_, loaded := g.sets[key]
	if loaded {
		g.mu.Unlock()
		return false
	}
	if len(g.sets) >= maxPending {
		// Map is full — cannot track this key for dedup.  Return true
		// (leader) so the caller proceeds without dedup rather than
		// blocking or starving.  Dedup degrades gracefully: concurrent
		// identical queries will each proceed independently.
		g.mu.Unlock()
		return true
	}
	g.sets[key] = struct{}{}
	g.mu.Unlock()
	return true
}

// Done removes the pending key after the operation completes.  Safe to call
// with a key that was never started (no-op).
func (g *Group[K]) Done(key K) {
	g.mu.Lock()
	delete(g.sets, key)
	g.mu.Unlock()
}

// NewResultGroup creates a ResultGroup ready for use.
func NewResultGroup[K comparable, V any]() *ResultGroup[K, V] {
	return &ResultGroup[K, V]{calls: make(map[K]*resultCall[V])}
}

// Do runs fn once for key.  The leader receives (val, err, true); concurrent
// callers with the same key receive the leader's (val, err, false).  When the
// leader is still running when a follower's ctx expires, the follower is
// promoted and runs fn itself, returning (val, err, true).  When the internal
// map is full, every caller runs fn directly — dedup degrades gracefully.
func (g *ResultGroup[K, V]) Do(ctx context.Context, key K, fn func() (V, error)) (V, error, bool) {
	g.mu.Lock()
	if call, ok := g.calls[key]; ok {
		g.mu.Unlock()
		select {
		case <-call.done:
			return call.val, call.err, false
		case <-ctx.Done():
			// Leader is taking too long: promote this caller to run fn
			// itself so the wait is bounded by ctx.
			v, err := fn()
			return v, err, true
		}
	}
	if len(g.calls) >= maxPending {
		g.mu.Unlock()
		v, err := fn()
		return v, err, true
	}
	call := &resultCall[V]{done: make(chan struct{})}
	g.calls[key] = call
	g.mu.Unlock()

	val, err := fn()
	call.once.Do(func() {
		call.val = val
		call.err = err
		close(call.done)
	})
	g.mu.Lock()
	delete(g.calls, key)
	g.mu.Unlock()
	return val, err, true
}
