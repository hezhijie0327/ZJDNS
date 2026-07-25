// Package pending provides a generic singleflight-style deduplication group.
// When multiple callers invoke Start with the same key before Done is called,
// only the first (leader) proceeds; all others (followers) are rejected.
//
// Unlike golang.org/x/sync/singleflight, followers do NOT wait for the
// leader's result — they simply skip the work.  For wait-for-result semantics,
// use server/handler.PendingRequests instead.
//
// The internal map is bounded at maxPending entries to prevent unbounded
// memory growth from leaked keys (keys whose Done is never called due to
// panics or logic errors).  When the map is full, Start returns true
// (leader) to prevent starvation — dedup degrades gracefully under overload.
package pending

import "sync"

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
