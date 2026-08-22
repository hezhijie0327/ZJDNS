// Package resolv caches hostname→IP resolution for upstream dials.
//
// A loaded server re-resolved hostname upstreams on every pool dial and
// per-query fallback (190M net.Resolver.lookupIPAddr calls in the pprof
// window).  LookupHost resolves once per hostname per TTL, deduplicating
// concurrent resolutions with a singleflight; DialContext and
// ResolveUDPAddr wrap it for the two dial shapes the upstream clients use.
//
// SNI safety contract: a cached dial IP must never change TLS ServerName
// semantics.  Transports that derive SNI from the dial address (quic-go's
// DoQ/DoH3 when ServerName is empty, pion's DTLS/DTLCP fallback) MUST set
// ServerName explicitly from the original hostname before dialing a cached
// IP; DoT/DoH/TLCP take ServerName from config or the URL and are
// unaffected.
package resolv

import (
	"context"
	"errors"
	"net"
	"time"
	"zjdns/internal/log"
	"zjdns/internal/lrumap"
	"zjdns/internal/pending"
)

// Cache resolves hostnames with a TTL'd LRU and singleflight dedup.
type Cache struct {
	entries *lrumap.Map[string, entry] // lazy expiry on Get (dnscrypt state pattern)
	group   *pending.ResultGroup[string, []net.IP]
	lookup  func(ctx context.Context, host string) ([]net.IP, error) // net.DefaultResolver.LookupIP in New; swappable in tests
}

// entry is one cached resolution.  ips is shared — callers must not mutate
// the returned slice.
type entry struct {
	ips     []net.IP
	expires int64 // log.NowUnix() seconds
}

const (
	defaultCapacity = 128
	defaultTTL      = 60 // seconds — upstream hostnames are stable; re-resolution is cheap
	lookupTimeout   = 2 * time.Second
)

// Default is the process-wide resolution cache shared by all upstream
// dial paths.
var Default = New()

// New creates a resolution cache with the system resolver.
func New() *Cache {
	return &Cache{
		entries: lrumap.New[string, entry](defaultCapacity),
		group:   pending.NewResultGroup[string, []net.IP](),
		lookup: func(ctx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip", host)
		},
	}
}

// LookupHost returns the cached IPs for host, resolving and caching on a
// miss.  Concurrent misses for the same host share one resolution; errors
// are not cached (the next query retries).  The returned slice is owned by
// the cache — callers must not mutate it.
func (c *Cache) LookupHost(ctx context.Context, host string) ([]net.IP, error) {
	if e, ok := c.entries.Get(host); ok && log.NowUnix() < e.expires {
		return e.ips, nil
	}
	ips, err, _ := c.group.Do(ctx, host, func(workCtx context.Context) ([]net.IP, error) {
		if e, ok := c.entries.Get(host); ok && log.NowUnix() < e.expires {
			return e.ips, nil // re-check under the flight (dnscrypt state() discipline)
		}
		// Detach from the leader's query context so a first-wins cancel does
		// not fail the whole flight; bounded by lookupTimeout.
		lookupCtx, cancel := context.WithTimeout(context.WithoutCancel(workCtx), lookupTimeout)
		defer cancel()
		ips, err := c.lookup(lookupCtx, host)
		if err != nil {
			return nil, err
		}
		c.entries.Set(host, entry{ips: ips, expires: log.NowUnix() + defaultTTL})
		return ips, nil
	})
	return ips, err
}

// DialContext resolves any hostname in addr through the cache and dials
// each resolved address in turn until one connects, mirroring net.Dialer's
// sequential fallback (multi-A hosts keep full coverage).  IP-literal
// addrs bypass the cache.  d is any *net.Dialer- or *socks5.Dialer-shaped
// dialer.
func (c *Cache) DialContext(ctx context.Context, network, addr string, d interface {
	DialContext(context.Context, string, string) (net.Conn, error)
},
) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if net.ParseIP(host) != nil {
		return d.DialContext(ctx, network, addr)
	}
	ips, err := c.LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	var firstErr error
	for _, ip := range ips {
		conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		firstErr = errors.New("resolv: no addresses for host")
	}
	return nil, firstErr
}

// ResolveUDPAddr resolves addr (host:port) through the cache to a
// *net.UDPAddr, taking the first address — mirroring net.ResolveUDPAddr's
// single-address semantics.  IP literals bypass the cache.
func (c *Cache) ResolveUDPAddr(ctx context.Context, addr string) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	p, err := net.LookupPort("udp", port)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip != nil {
		return &net.UDPAddr{IP: ip, Port: p}, nil
	}
	ips, err := c.LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, errors.New("resolv: no addresses for host")
	}
	return &net.UDPAddr{IP: ips[0], Port: p}, nil
}
