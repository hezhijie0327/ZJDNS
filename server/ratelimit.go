package server

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"zjdns/internal/log"
)

const (
	defaultRate  = 1000 // queries per second per client
	defaultBurst = 2000
	cleanupEvery = 5 * time.Minute
	numShards    = 64 // Power of 2 — enables fast bitwise modulo
)

// Limiter is a sharded per-client-IP token bucket rate limiter.
// 64 shards eliminate lock contention under high concurrency.
type Limiter struct {
	shards [numShards]limiterShard
	rate   int
	burst  int
	done   chan struct{}
	closed atomic.Bool
}

type limiterShard struct {
	mu      sync.Mutex
	clients map[string]*bucket
}

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

// NewLimiter creates a sharded rate limiter with the given rate (qps) and burst.
func NewLimiter(rate, burst int) *Limiter {
	if rate <= 0 {
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
		l.shards[i].clients = make(map[string]*bucket)
	}
	go l.cleanup()
	return l
}

// Allow reports whether a request from the given IP is allowed.
func (l *Limiter) Allow(ip net.IP) bool {
	if l == nil {
		return true
	}
	key := ip.String()
	now := time.Now()
	s := &l.shards[hashIP(ip)]

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
		log.Debugf("RATELIMIT: request from %s rate-limited (rate=%d qps, burst=%d)", key, l.rate, l.burst)
		return false
	}
	b.tokens--
	s.mu.Unlock()
	return true
}

// Shutdown stops the cleanup goroutine.
func (l *Limiter) Shutdown() {
	if l != nil && l.closed.CompareAndSwap(false, true) {
		close(l.done)
	}
}

// hashIP maps an IP to a shard index using FNV-1a on the normalized 16-byte form.
func hashIP(ip net.IP) uint8 {
	ip = ip.To16()
	if len(ip) == 0 {
		return 0
	}
	h := uint32(0)
	for _, b := range ip {
		h ^= uint32(b)
		h *= 16777619 // FNV-1a prime
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
				for ip, b := range s.clients {
					if b.lastSeen.Before(cutoff) {
						delete(s.clients, ip)
					}
				}
				s.mu.Unlock()
			}
		case <-l.done:
			return
		}
	}
}
