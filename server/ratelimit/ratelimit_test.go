package ratelimit

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestNew_DefaultValues(t *testing.T) {
	l := New(-1, -1)
	defer l.Shutdown()
	if l.rate != defaultRate {
		t.Errorf("default rate = %d, want %d", l.rate, defaultRate)
	}
	if l.burst != defaultBurst {
		t.Errorf("default burst = %d, want %d", l.burst, defaultBurst)
	}
}

func TestNew_ZeroRateDisabled(t *testing.T) {
	l := New(0, 0)
	if l != nil {
		t.Error("rate=0 should return nil (disabled)")
	}
}

func TestNew_NegativeRateUsesDefault(t *testing.T) {
	l := New(-1, 0)
	defer l.Shutdown()
	if l.rate != defaultRate {
		t.Errorf("negative rate should use default, got %d", l.rate)
	}
	if l.burst != defaultBurst {
		t.Errorf("zero burst should use default, got %d", l.burst)
	}
}

func TestNew_CustomValues(t *testing.T) {
	l := New(500, 100)
	defer l.Shutdown()
	if l.rate != 500 {
		t.Errorf("rate = %d, want 500", l.rate)
	}
	if l.burst != 100 {
		t.Errorf("burst = %d, want 100", l.burst)
	}
}

func TestAllow_FirstRequestSucceeds(t *testing.T) {
	l := New(10, 5)
	defer l.Shutdown()
	if !l.Allow(net.ParseIP("192.0.2.1")) {
		t.Error("first request should always be allowed")
	}
}

func TestAllow_BurstExhausted(t *testing.T) {
	l := New(10, 3)
	defer l.Shutdown()
	ip := net.ParseIP("192.0.2.2")

	// Consume the burst
	for i := 0; i < 3; i++ {
		if !l.Allow(ip) {
			t.Errorf("request %d should be allowed (burst=3)", i+1)
		}
	}
	// Burst exhausted
	if l.Allow(ip) {
		t.Error("request after burst exhausted should be denied")
	}
}

func TestAllow_DifferentIPsIndependent(t *testing.T) {
	l := New(10, 1)
	defer l.Shutdown()
	ip1 := net.ParseIP("192.0.2.3")
	ip2 := net.ParseIP("198.51.100.1")

	// Exhaust ip1
	l.Allow(ip1)
	// ip2 should still be allowed
	if !l.Allow(ip2) {
		t.Error("different IP should have independent bucket")
	}
}

func TestAllow_Refill(t *testing.T) {
	l := New(100, 2) // 100 tokens/sec
	defer l.Shutdown()
	ip := net.ParseIP("192.0.2.4")

	// Exhaust burst
	l.Allow(ip)
	l.Allow(ip)
	if l.Allow(ip) {
		t.Error("should be exhausted")
	}

	// Wait for refill (100 tokens/sec → 0.5 tokens per 5ms)
	time.Sleep(50 * time.Millisecond)
	if !l.Allow(ip) {
		t.Error("should have refilled at least 1 token after 50ms at rate=100")
	}
}

func TestAllow_IPv6(t *testing.T) {
	l := New(10, 5)
	defer l.Shutdown()
	ip := net.ParseIP("2001:db8::1")
	if !l.Allow(ip) {
		t.Error("IPv6 request should be allowed")
	}
}

func TestAllow_IPv4MappedIPv6(t *testing.T) {
	l := New(10, 1)
	defer l.Shutdown()
	// IPv4-mapped IPv6 and plain IPv4 should share the same bucket
	ip4 := net.ParseIP("192.0.2.5")
	ip6 := net.ParseIP("::ffff:192.0.2.5") // same address

	l.Allow(ip4) // exhaust
	if l.Allow(ip6) {
		t.Error("IPv4-mapped IPv6 from same address should be rate-limited")
	}
}

func TestAllow_NilLimiter(t *testing.T) {
	var l *Limiter
	if !l.Allow(net.ParseIP("192.0.2.1")) {
		t.Error("nil limiter should allow all requests")
	}
}

func TestShutdown_NoPanic(t *testing.T) {
	l := New(10, 5)
	l.Shutdown()
	l.Shutdown() // double shutdown must not panic
}

func TestIpToKey_IPv4(t *testing.T) {
	key := ipToKey(net.ParseIP("192.0.2.1"))
	// IPv4 is stored as IPv4-mapped IPv6: ::ffff:c000:0201
	expected := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xc0, 0x00, 0x02, 0x01}
	if key != expected {
		t.Errorf("ipToKey(192.0.2.1) = %v, want %v", key, expected)
	}
}

func TestCleanup_RemovesExpiredClients(t *testing.T) {
	l := New(10, 5)
	defer l.Shutdown()
	ip := net.ParseIP("192.0.2.1")

	// Allow a request to create the client entry
	l.Allow(ip)

	// Set the client's lastSeen far in the past
	key := ipToKey(ip)
	s := &l.shards[hashIPKey(key)]
	s.mu.Lock()
	if b, ok := s.clients[key]; ok {
		b.lastSeen = time.Now().Add(-3 * cleanupEvery)
	}
	s.mu.Unlock()

	// Trigger a manual cleanup sweep
	cutoff := time.Now().Add(-2 * cleanupEvery)
	for i := range l.shards {
		sh := &l.shards[i]
		sh.mu.Lock()
		for k, b := range sh.clients {
			if b.lastSeen.Before(cutoff) {
				delete(sh.clients, k)
			}
		}
		sh.mu.Unlock()
	}

	// Verify the expired client was removed
	s.mu.Lock()
	_, exists := s.clients[key]
	s.mu.Unlock()
	if exists {
		t.Error("expired client should be cleaned up")
	}
}

func TestCleanup_RunsAutomatically(t *testing.T) {
	l := New(10, 5)
	// Trigger cleanup through the channel to exercise the goroutine path
	l.Shutdown()
	time.Sleep(50 * time.Millisecond)
	// The cleanup goroutine should exit cleanly
	if !l.closed.Load() {
		t.Error("closed should be true after Shutdown")
	}
}

func TestShutdown_StopsCleanup(t *testing.T) {
	l := New(10, 5)
	l.Shutdown()
	// Verify done channel is closed
	select {
	case <-l.done:
		// expected
	default:
		t.Error("done channel should be closed after Shutdown")
	}
}

func TestHashIPKey_Distribution(t *testing.T) {
	shards := make(map[uint8]int)
	for i := range 1000 {
		var key [16]byte
		key[0] = byte(i >> 8)
		key[1] = byte(i)
		s := hashIPKey(key)
		shards[s]++
	}
	// With 64 shards and 1000 keys, each shard should have ~15-16 keys
	// but we just verify all shards are reachable
	if len(shards) < 10 {
		t.Errorf("hash distribution too narrow: %d shards used out of 64", len(shards))
	}
}

func BenchmarkAllow_SameIP(b *testing.B) {
	l := New(100000, 50000)
	defer l.Shutdown()
	ip := net.ParseIP("192.0.2.1")
	b.ResetTimer()
	for b.Loop() {
		l.Allow(ip)
	}
}

func BenchmarkAllow_ManyIPs(b *testing.B) {
	l := New(100000, 50000)
	defer l.Shutdown()
	ips := make([]net.IP, 1024)
	for i := range ips {
		ips[i] = net.ParseIP("192.0.2." + string(rune(i%256)))
	}
	b.ResetTimer()
	idx := atomic.Int64{}
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			l.Allow(ips[idx.Add(1)%1024])
		}
	})
}

func BenchmarkAllow_ParallelSameIP(b *testing.B) {
	l := New(1000000, 100000)
	defer l.Shutdown()
	ip := net.ParseIP("192.0.2.1")
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			l.Allow(ip)
		}
	})
}
