// Package perip provides a shared per-IP connection/concurrency limiter
// used by all protocol listeners (UDP, TCP, DoT, DoQ, DoH, DoH3, DNSCrypt).
package perip

import (
	"net"
	"sync"
	"sync/atomic"
)

// Limiter tracks per-key (typically IP address) usage counts and enforces
// a configurable limit. It is safe for concurrent use.
type Limiter struct {
	entries sync.Map // string → *atomic.Int32
}

// Allow checks whether the given key is under the specified limit. If allowed,
// it returns a cleanup function that must be called when the operation
// completes (connection closed, packet handled, etc.). If the limit is
// exceeded, Allow returns nil and the caller should reject/drop.
func (l *Limiter) Allow(key string, max int32) (cleanup func()) {
	if l == nil || key == "" || max <= 0 {
		return func() {}
	}
	val, _ := l.entries.LoadOrStore(key, new(atomic.Int32))
	count := val.(*atomic.Int32)
	if count.Add(1) > max {
		count.Add(-1)
		return nil
	}
	return func() { count.Add(-1) }
}

// Sweep removes entries whose count has dropped to zero or below.
// Call periodically to prevent unbounded map growth.
func (l *Limiter) Sweep() {
	if l == nil {
		return
	}
	l.entries.Range(func(key, value any) bool {
		count, ok := value.(*atomic.Int32)
		if !ok || count == nil || count.Load() <= 0 {
			l.entries.Delete(key)
		}
		return true
	})
}

// Listener wraps a net.Listener and enforces a per-IP connection limit.
// Use this when the accept loop is not under your control (e.g. dns.Server).
type Listener struct {
	net.Listener
	Limiter *Limiter
	Limit   int32
}

// Accept accepts a connection, blocking until one is available and within
// the per-IP limit. Connections exceeding the limit are closed and retried.
func (l *Listener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
		if err != nil {
			return conn, nil
		}
		cleanup := l.Limiter.Allow(host, l.Limit)
		if cleanup == nil {
			_ = conn.Close()
			continue
		}
		return &connWrapper{Conn: conn, cleanup: cleanup}, nil
	}
}

type connWrapper struct {
	net.Conn
	cleanup func()
}

func (c *connWrapper) Close() error {
	c.cleanup()
	return c.Conn.Close()
}
