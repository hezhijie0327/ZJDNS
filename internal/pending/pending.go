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
// CallGroup has wait-for-result semantics with LRU eviction safety and a
// fixed follower timeout — the dial between ResultGroup (ctx-promotion) and
// the DNS-specific PendingRequests (fixed timeout, eviction-wake semantics).
//
// All groups bound their internal maps via lrumap.Map so old entries are
// auto-evicted when the capacity is reached.  When the map is full, dedup
// degrades gracefully: for Group, the oldest key is evicted (its Start was
// already Done'd or leaked); for ResultGroup/CallGroup, the evicted in‑flight
// call is closed with ErrEvicted, waking any waiting follower.
package pending

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
	"zjdns/internal/lrumap"
)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// Group deduplicates concurrent work by key.  Start registers a pending
// operation; if an operation for the same key is already in flight, it
// returns false.  Done removes the key, allowing future operations to
// proceed.
//
// The zero value is not usable; use NewGroup to create a valid Group.
type Group[K comparable] struct {
	sets *lrumap.Map[K, struct{}]
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
// graceful degradation as the map‑full path.
//
// fn must not call Do with the same key (self‑deadlock).
//
// The zero value is not usable; use NewResultGroup to create a valid group.
type ResultGroup[K comparable, V any] struct {
	calls *lrumap.Map[K, *resultCall[V]]
}

// resultCall holds one in-flight key: the leader's result and a broadcast
// channel.  val/err are written by the leader before done is closed; readers
// observe them through the channel's happens‑before edge.
type resultCall[V any] struct {
	done chan struct{}
	once sync.Once
	val  V
	err  error
}

// callEntry holds one in-flight key for CallGroup.  The leader writes val/err
// then closes done; followers observe them through the channel.
type callEntry[K comparable, V any] struct {
	Done chan struct{}
	Once sync.Once
	Val  V
	Err  error
	key  K
}

// Token identifies the leader's own entry in the group.  Join returns it
// when the caller becomes the leader, and Done must receive the same token
// back — publishing or deleting by key instead would let an evicted
// leader's result land in a replacement entry installed for the same key
// (M6).
type Token[K comparable, V any] struct {
	entry *callEntry[K, V]
}

// CallGroup deduplicates concurrent calls by key with LRU eviction safety and
// a fixed follower timeout.  The first caller (leader) receives (zero, nil,
// false); concurrent callers block on the leader and receive (result, true).
//
// A follower whose timeout expires returns (zero, ErrTimeout, true).  On LRU
// eviction the in‑flight call is closed with ErrEvicted.
//
// The zero value is not usable; use NewCallGroup to create a valid group.
type CallGroup[K comparable, V any] struct {
	mmap            *lrumap.Map[K, *callEntry[K, V]]
	followerTimeout time.Duration
	clone           func(V) V // nil means no clone
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// maxPending is the capacity of the internal LRU maps — a hard cap to prevent
// unbounded memory growth.  Old entries are auto‑evicted when the map is full.
const maxPending = 10000

// ---------------------------------------------------------------------------
// Variables
// ---------------------------------------------------------------------------

// Sentinel errors returned by CallGroup.Join / ResultGroup.Do eviction paths.
var (
	ErrEvicted = errors.New("pending: in-flight call evicted before completion")
	ErrTimeout = errors.New("pending: follower timeout waiting for leader")
)

// ---------------------------------------------------------------------------
// Group — constructors and methods
// ---------------------------------------------------------------------------

// NewGroup creates a Group ready for use.
func NewGroup[K comparable]() *Group[K] {
	return &Group[K]{
		sets: lrumap.New[K, struct{}](maxPending),
	}
}

// Start registers an operation for key.  Returns true if the caller should
// proceed (leader).  Returns false if an operation for this key is already in
// flight; the caller should skip its work.
//
// When the internal map reaches capacity the least‑recently‑used entry is
// auto‑evicted — dedup degrades gracefully under overload.
//
// Callers MUST use `defer g.Done(key)` immediately after Start(key) to
// prevent key leakage.
func (g *Group[K]) Start(key K) bool {
	_, loaded := g.sets.LoadOrStore(key, struct{}{})
	return !loaded
}

// Done removes the pending key after the operation completes.  Safe to call
// with a key that was never started (no‑op).
func (g *Group[K]) Done(key K) {
	g.sets.Delete(key)
}

// ---------------------------------------------------------------------------
// ResultGroup — constructors and methods
// ---------------------------------------------------------------------------

// NewResultGroup creates a ResultGroup ready for use.
func NewResultGroup[K comparable, V any]() *ResultGroup[K, V] {
	rg := &ResultGroup[K, V]{
		calls: lrumap.New[K, *resultCall[V]](maxPending),
	}
	rg.calls.SetOnEvict(func(_ K, call *resultCall[V]) {
		call.once.Do(func() {
			call.err = ErrEvicted
			close(call.done)
		})
	})
	return rg
}

// Do runs fn once for key.  The leader receives (val, err, true); concurrent
// callers with the same key wait for the leader's result and receive
// (val, err, false).
//
// A follower whose ctx expires while the leader is still running returns
// ctx.Err immediately — it NEVER runs fn itself.  Running the shared work
// from a timed-out follower (the old promotion path) multiplied the work
// under load: every follower re-ran the full fn with a deadline-stripped
// context, so any slow leader (slow SQLite pool, slow network) turned one
// in-flight key into hundreds of duplicate runs with no overall deadline —
// a goroutine explosion that also permanently leaked the dnscrypt cert
// fetch (conn.Read with no socket deadline).  The follower's caller has
// already exhausted its own budget; failing it is the correct, bounded
// behaviour.
//
// A leader panic is contained: the entry is closed with the panic error and
// removed so followers wake with an error and future callers become leaders
// again; the panic is then re-raised for the caller's own recovery
// (zdnsutil.HandlePanic).
func (g *ResultGroup[K, V]) Do(ctx context.Context, key K, fn func(context.Context) (V, error)) (V, error, bool) {
	call := &resultCall[V]{done: make(chan struct{})}
	existing, loaded := g.calls.LoadOrStore(key, call)
	if loaded {
		// Follower: wait for the leader's result, bounded by our own ctx.
		select {
		case <-existing.done:
			return existing.val, existing.err, false
		case <-ctx.Done():
			var zero V
			return zero, ctx.Err(), false
		}
	}

	// Leader.
	var val V
	var err error
	defer func() {
		if r := recover(); r != nil {
			// Publish the failure to waiters and free the key BEFORE
			// re-raising: the caller's HandlePanic logs it, and followers
			// observe the closed entry instead of waiting forever.
			err = fmt.Errorf("pending: leader panic for key %v: %v", key, r)
			call.once.Do(func() {
				call.err = err
				close(call.done)
			})
			g.calls.CompareAndDelete(key, call)
			panic(r)
		}
	}()
	val, err = fn(ctx)
	call.once.Do(func() {
		call.val = val
		call.err = err
		close(call.done)
	})
	// Use CompareAndDelete so a Done that raced an eviction (which installs a
	// new call for the same key) never deletes the replacement call.
	g.calls.CompareAndDelete(key, call)
	return val, err, true
}

// ---------------------------------------------------------------------------
// CallGroup — constructors and methods
// ---------------------------------------------------------------------------

// NewCallGroup creates a CallGroup with the given capacity, follower timeout,
// and optional value‑clone hook (called by the leader to produce a copy
// shared with followers — useful when V contains mutable references).
func NewCallGroup[K comparable, V any](capacity int, followerTimeout time.Duration, clone func(V) V) *CallGroup[K, V] {
	if capacity <= 0 {
		capacity = maxPending
	}
	cg := &CallGroup[K, V]{
		mmap:            lrumap.New[K, *callEntry[K, V]](capacity),
		followerTimeout: followerTimeout,
		clone:           clone,
	}
	cg.mmap.SetOnEvict(func(_ K, entry *callEntry[K, V]) {
		entry.Once.Do(func() {
			entry.Err = ErrEvicted
			close(entry.Done)
		})
	})
	return cg
}

// Join checks whether an identical call is already in flight.  If so, it
// blocks until the leader finishes (or the fixed timeout expires) and returns
// the shared result with follower=true.  If not, the caller becomes the
// leader and Join returns (token, zero, nil, false) — Done must be called
// with that same token.
func (g *CallGroup[K, V]) Join(key K) (Token[K, V], V, error, bool) {
	entry := &callEntry[K, V]{Done: make(chan struct{}), key: key}
	existing, loaded := g.mmap.LoadOrStore(key, entry)
	if !loaded {
		var zero V
		return Token[K, V]{entry: entry}, zero, nil, false // leader
	}

	// Follower: wait for leader with fixed timeout.
	timer := time.NewTimer(g.followerTimeout)
	select {
	case <-existing.Done:
		if !timer.Stop() {
			<-timer.C
		}
		return Token[K, V]{}, existing.Val, existing.Err, true
	case <-timer.C:
		// Read nothing from the entry: the leader's Once.Do write of
		// existing.Err has no happens-before edge with this branch (the
		// close(existing.Done) only synchronizes receivers of that channel),
		// so reading it here is a data race.  The follower timed out — the
		// leader's error would be misattributed anyway (H1).
		var zero V
		return Token[K, V]{}, zero, ErrTimeout, true
	}
}

// Done stores the result and wakes all waiting followers.  Must only be
// called by the leader (i.e. after Join returned follower=false), with the
// token Join returned.  When clone is set, it is applied to val before
// sharing with followers — this prevents concurrent mutation of the shared
// value.
func (g *CallGroup[K, V]) Done(tok Token[K, V], val V, err error) {
	entry := tok.entry
	if entry == nil {
		return
	}
	shared := val
	if g.clone != nil && err == nil {
		shared = g.clone(val)
	}
	// Publish BEFORE deleting: the eviction callback (OnEvict) also closes
	// Done via entry.Once, and whichever Once.Do runs first wins — deleting
	// first would publish ErrEvicted to the followers instead of the real
	// result (lrumap Delete/CompareAndDelete now invoke OnEvict).
	entry.Once.Do(func() {
		entry.Val = shared
		entry.Err = err
		close(entry.Done)
	})
	// Delete the leader's own entry only — a replacement call for the same
	// key (installed by a concurrent Join after this entry was LRU-evicted)
	// is never published into or deleted by a stale leader (M6).
	g.mmap.CompareAndDelete(entry.key, entry)
}
