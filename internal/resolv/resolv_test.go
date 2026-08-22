package resolv

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
)

// fakeDialer implements the DialContext subset resolv needs.
type fakeDialer struct {
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (d *fakeDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.dial(ctx, network, addr)
}

// newTestCache returns a Cache with an injected lookup func and a short TTL.
func newTestCache(t *testing.T, lookup func(ctx context.Context, host string) ([]net.IP, error)) *Cache {
	t.Helper()
	c := New()
	c.lookup = lookup
	return c
}

func TestLookupHost_CachesAndDeduplicates(t *testing.T) {
	var calls atomic.Int64
	c := newTestCache(t, func(_ context.Context, host string) ([]net.IP, error) {
		calls.Add(1)
		return []net.IP{net.IPv4(1, 2, 3, 4)}, nil
	})

	// Two concurrent misses must share one resolution.
	start := make(chan struct{})
	errs := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			ips, err := c.LookupHost(context.Background(), "ns.example.")
			if err == nil && len(ips) != 1 {
				err = errors.New("unexpected IP count")
			}
			errs <- err
		}()
	}
	close(start)
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Errorf("lookup calls = %d, want 1 (singleflight)", calls.Load())
	}

	// A third call is a cache hit — no lookup.
	if _, err := c.LookupHost(context.Background(), "ns.example."); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Errorf("lookup calls after hit = %d, want 1", calls.Load())
	}
}

func TestLookupHost_ExpiryRefetches(t *testing.T) {
	var calls atomic.Int64
	c := newTestCache(t, func(_ context.Context, host string) ([]net.IP, error) {
		calls.Add(1)
		return []net.IP{net.IPv4(1, 2, 3, 4)}, nil
	})

	if _, err := c.LookupHost(context.Background(), "ns.example."); err != nil {
		t.Fatal(err)
	}
	// Force expiry (lazy TTL check on Get), then verify a refetch.
	c.entries.Set("ns.example.", entry{ips: []net.IP{net.IPv4(1, 2, 3, 4)}, expires: 1})
	if _, err := c.LookupHost(context.Background(), "ns.example."); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Errorf("lookup calls = %d, want 2 (expired entry refetched)", calls.Load())
	}
}

func TestLookupHost_ErrorNotCached(t *testing.T) {
	boom := errors.New("resolve failed")
	var calls atomic.Int64
	c := newTestCache(t, func(_ context.Context, host string) ([]net.IP, error) {
		calls.Add(1)
		return nil, boom
	})

	for range 2 {
		if _, err := c.LookupHost(context.Background(), "ns.example."); !errors.Is(err, boom) {
			t.Fatalf("err = %v, want %v", err, boom)
		}
	}
	if calls.Load() != 2 {
		t.Errorf("lookup calls = %d, want 2 (errors must not be cached)", calls.Load())
	}
	if c.entries.Len() != 0 {
		t.Errorf("entries = %d, want 0 (errors must not be cached)", c.entries.Len())
	}
}

func TestDialContext_IPLiteralBypasses(t *testing.T) {
	var lookups atomic.Int64
	c := newTestCache(t, func(_ context.Context, host string) ([]net.IP, error) {
		lookups.Add(1)
		return nil, errors.New("must not be called")
	})

	var dials atomic.Int64
	d := &fakeDialer{dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials.Add(1)
		if addr != "1.2.3.4:53" {
			t.Errorf("dial addr = %s, want 1.2.3.4:53", addr)
		}
		client, _ := net.Pipe()
		return client, nil
	}}
	conn, err := c.DialContext(context.Background(), "udp", "1.2.3.4:53", d)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if lookups.Load() != 0 || dials.Load() != 1 {
		t.Errorf("lookups=%d dials=%d, want 0/1 (IP literal bypasses cache)", lookups.Load(), dials.Load())
	}
}

func TestDialContext_MultiAddrFallback(t *testing.T) {
	c := newTestCache(t, func(_ context.Context, host string) ([]net.IP, error) {
		return []net.IP{net.IPv4(1, 2, 3, 4), net.IPv4(5, 6, 7, 8)}, nil
	})

	var dialed []string
	d := &fakeDialer{dial: func(_ context.Context, _, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		if addr == "1.2.3.4:53" {
			return nil, errors.New("first addr down")
		}
		return nil, nil
	}}
	if _, err := c.DialContext(context.Background(), "udp", "ns.example.:53", d); err != nil {
		t.Fatal(err)
	}
	if len(dialed) != 2 || dialed[0] != "1.2.3.4:53" || dialed[1] != "5.6.7.8:53" {
		t.Errorf("dialed = %v, want [1.2.3.4:53 5.6.7.8:53]", dialed)
	}
}

func TestResolveUDPAddr(t *testing.T) {
	c := newTestCache(t, func(_ context.Context, host string) ([]net.IP, error) {
		if host != "ns.example." {
			t.Errorf("host = %s, want ns.example.", host)
		}
		return []net.IP{net.IPv4(1, 2, 3, 4), net.IPv4(5, 6, 7, 8)}, nil
	})

	ua, err := c.ResolveUDPAddr(context.Background(), "ns.example.:853")
	if err != nil {
		t.Fatal(err)
	}
	if !ua.IP.Equal(net.IPv4(1, 2, 3, 4)) || ua.Port != 853 {
		t.Errorf("ResolveUDPAddr = %v, want 1.2.3.4:853", ua)
	}

	// IP literal bypasses the cache.
	ua, err = c.ResolveUDPAddr(context.Background(), "9.9.9.9:53")
	if err != nil {
		t.Fatal(err)
	}
	if !ua.IP.Equal(net.IPv4(9, 9, 9, 9)) || ua.Port != 53 {
		t.Errorf("ResolveUDPAddr(IP) = %v, want 9.9.9.9:53", ua)
	}
}
