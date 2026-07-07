// Package pending provides a generic singleflight-style deduplication group.
// When multiple callers invoke Start with the same key before Done is called,
// only the first (leader) proceeds; all others (followers) are rejected.
//
// Unlike golang.org/x/sync/singleflight, followers do NOT wait for the
// leader's result — they simply skip the work.  For wait-for-result semantics,
// use server/handler.PendingRequests instead.
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
	sets map[K]chan struct{}
}

// NewGroup creates a Group ready for use.
func NewGroup[K comparable]() *Group[K] {
	return &Group[K]{
		sets: make(map[K]chan struct{}),
	}
}

// Start registers an operation for key.  Returns true if the caller should
// proceed (leader).  Returns false if an operation for this key is already in
// flight; the caller should skip its work.
func (g *Group[K]) Start(key K) bool {
	g.mu.Lock()
	_, loaded := g.sets[key]
	if loaded {
		g.mu.Unlock()
		return false
	}
	g.sets[key] = make(chan struct{})
	g.mu.Unlock()
	return true
}

// Done removes the pending key after the operation completes.  Safe to call
// with a key that was never started (no-op).
func (g *Group[K]) Done(key K) {
	g.mu.Lock()
	ch, ok := g.sets[key]
	if !ok {
		g.mu.Unlock()
		return
	}
	delete(g.sets, key)
	g.mu.Unlock()
	close(ch)
}
