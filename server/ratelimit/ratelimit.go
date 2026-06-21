// Package ratelimit provides per-IP token bucket rate limiting for DNS query
// traffic.
package ratelimit

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"zjdns/internal/log"
)

const (
	defaultRate  = 1000
	defaultBurst = 2000
	cleanupEvery = 5 * time.Minute
	numShards    = 64
)

// Limiter implements a sharded token bucket rate limiter keyed by client IP
// address.
type Limiter struct {
	shards [numShards]shard
	rate   int
	burst  int
	done   chan struct{}
	closed atomic.Bool
}

type shard struct {
	mu      sync.Mutex
	clients map[[16]byte]*bucket
}

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

// New creates a new Limiter with the specified rate (tokens per second) and
// burst size. Returns nil when rate is 0, which disables rate limiting.
// Negative values fall back to defaults.
func New(rate, burst int) *Limiter {
	if rate == 0 {
		return nil
	}
	if rate < 0 {
		rate = defaultRate
	}
	if burst <= 0 {
		burst = defaultBurst
	}
	l := &Limiter{
		rate:  rate,
		burst: burst,
		done:  make(chan struct{}),
	}
	for i := range l.shards {
		l.shards[i].clients = make(map[[16]byte]*bucket)
	}
	go l.cleanup()
	return l
}

// Allow checks whether a request from the given IP should be permitted based
// on the current token balance. Returns false if the IP has exceeded the rate
// limit.
func (l *Limiter) Allow(ip net.IP) bool {
	if l == nil {
		return true
	}
	key := ipToKey(ip)
	now := time.Now()
	s := &l.shards[hashIPKey(key)]

	s.mu.Lock()
	b, ok := s.clients[key]
	if !ok {
		b = &bucket{tokens: float64(l.burst)}
		s.clients[key] = b
	}
	elapsed := now.Sub(b.lastSeen).Seconds()
	b.lastSeen = now
	b.tokens += elapsed * float64(l.rate)
	if b.tokens > float64(l.burst) {
		b.tokens = float64(l.burst)
	}
	if b.tokens < 1 {
		s.mu.Unlock()
		log.Debugf("RATELIMIT: request from %s rate-limited (rate=%d qps, burst=%d)", ip.String(), l.rate, l.burst)
		return false
	}
	b.tokens--
	s.mu.Unlock()
	return true
}

// Shutdown stops the background cleanup goroutine for the rate limiter.
func (l *Limiter) Shutdown() {
	if l != nil && l.closed.CompareAndSwap(false, true) {
		close(l.done)
	}
}

func ipToKey(ip net.IP) [16]byte {
	var key [16]byte
	normalized := ip.To16()
	if len(normalized) == 16 {
		copy(key[:], normalized)
	}
	return key
}

func hashIPKey(key [16]byte) uint8 {
	// FNV-1a hash over the full 16-byte key. For IPv4-mapped IPv6
	// addresses (::ffff:x.x.x.x), the zero-padded prefix bytes fold
	// harmlessly through FNV-1a multiplication, and the significant
	// last 4 bytes still produce good distribution across shards.
	h := uint32(2166136261)
	for _, b := range key {
		h ^= uint32(b)
		h *= 16777619
	}
	return uint8(h & (numShards - 1))
}

func (l *Limiter) cleanup() {
	ticker := time.NewTicker(cleanupEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			cutoff := time.Now().Add(-2 * cleanupEvery)
			for i := range l.shards {
				s := &l.shards[i]
				s.mu.Lock()
				for key, b := range s.clients {
					if b.lastSeen.Before(cutoff) {
						delete(s.clients, key)
					}
				}
				s.mu.Unlock()
			}
		case <-l.done:
			return
		}
	}
}
