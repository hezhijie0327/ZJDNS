package server

import (
	"net"
	"sync"
	"time"

	"zjdns/internal/log"
)

const (
	defaultRate  = 1000 // queries per second per client
	defaultBurst = 2000
	cleanupEvery = 5 * time.Minute
)

// Limiter is a per-client-IP token bucket rate limiter.
type Limiter struct {
	mu      sync.Mutex
	clients map[string]*bucket
	rate    int
	burst   int
	done    chan struct{}
}

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

// NewLimiter creates a rate limiter with the given rate (qps) and burst.
func NewLimiter(rate, burst int) *Limiter {
	if rate <= 0 {
		rate = defaultRate
	}
	if burst <= 0 {
		burst = defaultBurst
	}
	l := &Limiter{
		clients: make(map[string]*bucket),
		rate:    rate,
		burst:   burst,
		done:    make(chan struct{}),
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

	l.mu.Lock()
	b, ok := l.clients[key]
	if !ok {
		b = &bucket{tokens: float64(l.burst)}
		l.clients[key] = b
	}
	elapsed := now.Sub(b.lastSeen).Seconds()
	b.lastSeen = now
	b.tokens += elapsed * float64(l.rate)
	if b.tokens > float64(l.burst) {
		b.tokens = float64(l.burst)
	}
	if b.tokens < 1 {
		l.mu.Unlock()
		log.Debugf("RATELIMIT: request from %s rate-limited (rate=%d qps, burst=%d)", key, l.rate, l.burst)
		return false
	}
	b.tokens--
	l.mu.Unlock()
	return true
}

// Shutdown stops the cleanup goroutine.
func (l *Limiter) Shutdown() {
	if l != nil {
		close(l.done)
	}
}

func (l *Limiter) cleanup() {
	ticker := time.NewTicker(cleanupEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			l.mu.Lock()
			cutoff := time.Now().Add(-2 * cleanupEvery)
			for ip, b := range l.clients {
				if b.lastSeen.Before(cutoff) {
					delete(l.clients, ip)
				}
			}
			l.mu.Unlock()
		case <-l.done:
			return
		}
	}
}
