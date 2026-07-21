package edns

import (
	"net"
	"testing"
	"zjdns/config"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

func BenchmarkHandler_ApplyToMessage(b *testing.B) {
	log.Default.SetLevel(log.Error)
	h, _ := NewHandler(config.ECSConfig{})
	msg := new(dns.Msg)
	dnsutil.SetQuestion(msg, "bench.example.com.", dns.TypeA)
	ecs := &ECSOption{Family: 1, SourcePrefix: 24, Address: net.IPv4(192, 0, 2, 1)}

	b.ResetTimer()
	for b.Loop() {
		m := msg.Copy()
		h.ApplyToMessage(m, ecs, false, "", nil, false, true, 0)
	}
}

// ── Cookie benchmarks ────────────────────────────────────────────────────────

func BenchmarkCookieGenerator_GenerateServerCookie(b *testing.B) {
	log.Default.SetLevel(log.Error)
	cg := NewCookieGenerator()
	clientIP := net.IPv4(192, 0, 2, 1)
	clientCookie := make([]byte, DefaultCookieClientLen)

	b.ResetTimer()
	for b.Loop() {
		_ = cg.GenerateServerCookie(clientIP, clientCookie)
	}
}

func BenchmarkCookieGenerator_IsServerCookieValid(b *testing.B) {
	log.Default.SetLevel(log.Error)
	cg := NewCookieGenerator()
	clientIP := net.IPv4(192, 0, 2, 1)
	clientCookie := make([]byte, DefaultCookieClientLen)
	serverCookie := cg.GenerateServerCookie(clientIP, clientCookie)

	b.ResetTimer()
	for b.Loop() {
		_ = cg.IsServerCookieValid(clientIP, clientCookie, serverCookie)
	}
}

func BenchmarkBuildCookieResponse(b *testing.B) {
	clientCookie := []byte{0, 1, 2, 3, 4, 5, 6, 7}
	serverCookie := []byte{8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}

	b.ResetTimer()
	for b.Loop() {
		_ = BuildCookieResponse(clientCookie, serverCookie)
	}
}

// ── Padding benchmarks ───────────────────────────────────────────────────────

func BenchmarkHasPaddingOption(b *testing.B) {
	msg := &dns.Msg{
		Pseudo: []dns.RR{&dns.PADDING{Padding: "00"}},
	}
	b.ResetTimer()
	for b.Loop() {
		_ = HasPaddingOption(msg)
	}
}

func BenchmarkHasPaddingOption_NoEDNS(b *testing.B) {
	msg := new(dns.Msg)
	b.ResetTimer()
	for b.Loop() {
		_ = HasPaddingOption(msg)
	}
}

// ── ParseCookie benchmark ────────────────────────────────────────────────────

func BenchmarkHandler_ParseCookie(b *testing.B) {
	log.Default.SetLevel(log.Error)
	h, _ := NewHandler(config.ECSConfig{})
	msg := new(dns.Msg)
	dnsutil.SetQuestion(msg, "bench.example.com.", dns.TypeA)
	cookieVal := BuildCookieResponse(
		[]byte{0, 1, 2, 3, 4, 5, 6, 7},
		[]byte{8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23},
	)
	msg.Pseudo = append(msg.Pseudo, &dns.COOKIE{Cookie: cookieVal})

	b.ResetTimer()
	for b.Loop() {
		_ = h.ParseCookie(msg)
	}
}
