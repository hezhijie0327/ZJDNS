package cache

import (
	"net/netip"
	"testing"
	"zjdns/config"

	"codeberg.org/miekg/dns"
)

// benchGet prepares one cached A answer with k distinct answer IPs and
// optional latency data, then measures Get (buildEntry incl. latency sort).
func benchGet(b *testing.B, withLatency bool, answers int) {
	c := New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	var ans []dns.RR
	for i := range answers {
		addr := netip.MustParseAddr("1.2.3." + itoaBench(i))
		ans = append(ans, &dns.A{Hdr: dns.Header{Name: "bench.example.com.", Class: dns.ClassINET, TTL: 300}, Addr: addr})
	}
	c.Set("bench.example.com.", dns.TypeA, dns.ClassINET, nil, ans, nil, nil, false, 0)
	if withLatency {
		for i := range answers {
			c.UpdateLatency("1.2.3."+itoaBench(i), 10+i)
		}
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, ok, _ := c.Get("bench.example.com.", dns.TypeA, dns.ClassINET, nil); !ok {
				b.Fatal("miss")
			}
		}
	})
}

func itoaBench(n int) string {
	if n == 0 {
		return "0"
	}
	var b [4]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func BenchmarkCacheGet_LatencySort8(b *testing.B)  { benchGet(b, true, 8) }
func BenchmarkCacheGet_NoLatency8(b *testing.B)    { benchGet(b, false, 8) }
func BenchmarkCacheGet_LatencySort1(b *testing.B)  { benchGet(b, true, 1) }
func BenchmarkCacheGet_NoLatency1(b *testing.B)    { benchGet(b, false, 1) }
func BenchmarkCacheGet_LatencySort16(b *testing.B) { benchGet(b, true, 16) }

// TestLatencySortedWireCache verifies the per-entry sorted-wire cache:
// repeated hits under the same latency generation skip the re-sort, and a
// latency update (generation bump) reorders the served answers.
func TestLatencySortedWireCache(t *testing.T) {
	c := New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	mk := func() []dns.RR {
		return []dns.RR{
			&dns.A{Hdr: dns.Header{Name: "s.example.com.", Class: dns.ClassINET, TTL: 300}, Addr: netip.MustParseAddr("1.2.3.10")},
			&dns.A{Hdr: dns.Header{Name: "s.example.com.", Class: dns.ClassINET, TTL: 300}, Addr: netip.MustParseAddr("1.2.3.20")},
		}
	}
	c.Set("s.example.com.", dns.TypeA, dns.ClassINET, nil, mk(), nil, nil, false, 0)
	// 1.2.3.20 fast, 1.2.3.10 slow → 20 first.
	c.UpdateLatency("1.2.3.10", 200)
	c.UpdateLatency("1.2.3.20", 5)

	order := func() []string {
		e, ok, _ := c.Get("s.example.com.", dns.TypeA, dns.ClassINET, nil)
		if !ok {
			t.Fatal("miss")
		}
		defer ReleaseTTLOffsets(e.TTLOffsets)
		msg := new(dns.Msg)
		msg.Data = e.ResponseWire
		if err := msg.Unpack(); err != nil {
			t.Fatalf("unpack sorted wire: %v", err)
		}
		var ips []string
		for _, rr := range msg.Answer {
			ips = append(ips, rr.(*dns.A).Addr.String())
		}
		return ips
	}

	first := order()
	if len(first) != 2 || first[0] != "1.2.3.20" {
		t.Fatalf("first hit order = %v, want 1.2.3.20 first", first)
	}
	// Second hit must serve the cached sorted wire — same order.
	if again := order(); again[0] != "1.2.3.20" {
		t.Fatalf("cached hit order = %v, want 1.2.3.20 first", again)
	}
	// Latency update flips the order on the next hit (generation bump).
	c.UpdateLatency("1.2.3.10", 1)
	c.UpdateLatency("1.2.3.20", 500)
	if flipped := order(); flipped[0] != "1.2.3.10" {
		t.Fatalf("post-update order = %v, want 1.2.3.10 first", flipped)
	}
}
