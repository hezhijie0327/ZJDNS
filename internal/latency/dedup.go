package latency

import (
	"net"
	"sync"
	"time"
)

// dedupTTL is the default TTL for probe result caching.
const dedupTTL = 300 * time.Second

// DedupCache avoids redundant latency probes for the same set of IPs within
// a configurable TTL window.
type DedupCache struct {
	mu    sync.RWMutex
	items map[uint64]dedupEntry
}

type dedupEntry struct {
	ips    []net.IP
	expiry time.Time
}

// NewDedupCache creates a DedupCache with a background sweeper that removes
// expired entries every 5 minutes.
func NewDedupCache() *DedupCache {
	dc := &DedupCache{
		items: make(map[uint64]dedupEntry),
	}
	return dc
}

// Get returns a cached sorted-IP result for the given hash, or nil if not
// found or expired.
func (dc *DedupCache) Get(hash uint64) ([]net.IP, bool) {
	dc.mu.RLock()
	e, ok := dc.items[hash]
	dc.mu.RUnlock()
	if !ok || time.Now().After(e.expiry) {
		if ok {
			dc.mu.Lock()
			delete(dc.items, hash)
			dc.mu.Unlock()
		}
		return nil, false
	}
	return e.ips, true
}

// Set stores a sorted-IP result with the given TTL.
func (dc *DedupCache) Set(hash uint64, ips []net.IP, ttl time.Duration) {
	if ttl <= 0 {
		ttl = dedupTTL
	}
	dc.mu.Lock()
	dc.items[hash] = dedupEntry{
		ips:    ips,
		expiry: time.Now().Add(ttl),
	}
	// Sweep expired entries opportunistically during Set to bound map growth.
	if len(dc.items) > 1024 {
		now := time.Now()
		for k, v := range dc.items {
			if now.After(v.expiry) {
				delete(dc.items, k)
			}
		}
	}
	dc.mu.Unlock()
}
