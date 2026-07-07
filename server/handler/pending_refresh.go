package handler

import (
	"sync"

	"zjdns/edns"
	"zjdns/internal/log"
)

// PendingRefreshes deduplicates concurrent stale-cache refresh queries. When
// multiple clients hit the same expired entry, only the first spawns a
// background refresh — followers skip (they already served stale data).
// The key mirrors the cache entry key (qname, qtype, qclass, ecs_addr,
// ecs_prefix, dnssecOK), reusing pendingKey from pending.go.
type PendingRefreshes struct {
	mu   sync.Mutex
	sets map[pendingKey]chan struct{}
}

// NewPendingRefreshes creates a PendingRefreshes ready for use.
func NewPendingRefreshes() *PendingRefreshes {
	return &PendingRefreshes{
		sets: make(map[pendingKey]chan struct{}),
	}
}

// Start registers a refresh for the given key. Returns true if the caller
// should proceed (leader). Returns false if a refresh for this key is already
// in flight and the caller should skip.
func (p *PendingRefreshes) Start(key pendingKey) bool {
	p.mu.Lock()
	_, loaded := p.sets[key]
	if loaded {
		p.mu.Unlock()
		return false
	}
	p.sets[key] = make(chan struct{})
	p.mu.Unlock()
	return true
}

// Done removes the pending refresh key after the refresh completes, allowing
// future refreshes for the same key.
func (p *PendingRefreshes) Done(key pendingKey) {
	p.mu.Lock()
	ch, ok := p.sets[key]
	if !ok {
		p.mu.Unlock()
		return
	}
	delete(p.sets, key)
	p.mu.Unlock()
	close(ch)
}

// tryStartRefresh builds a pendingKey from the given parameters and attempts
// to register a cache refresh. Returns true if the caller should proceed
// (leader), false if a refresh is already in flight. All refresh paths use
// dnssecOK=false since refreshCacheEntry always caches with dnssecOK=false.
func (h *Handler) tryStartRefresh(qname string, qtype, qclass uint16, ecs *edns.ECSOption) bool {
	if h.pendingRefreshes == nil {
		return true
	}
	key := buildPendingKey(qname, qtype, qclass, ecs, false)
	if !h.pendingRefreshes.Start(key) {
		log.Debugf("CACHE: refresh skipped for %s — already in flight", qname)
		return false
	}
	return true
}

// finishRefresh removes the pending refresh key after the refresh goroutine
// completes (whether success or failure).
func (h *Handler) finishRefresh(qname string, qtype, qclass uint16, ecs *edns.ECSOption) {
	if h.pendingRefreshes == nil {
		return
	}
	key := buildPendingKey(qname, qtype, qclass, ecs, false)
	h.pendingRefreshes.Done(key)
}
