package defense

import (
	"net/netip"
	"testing"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

func BenchmarkDetector_Validate(b *testing.B) {
	log.Default.SetLevel(log.Error)
	det := &Detector{}
	det.Enable(true)

	// Root server response with A record for non-TLD (hijack).
	msg := &dns.Msg{
		Answer: []dns.RR{&dns.A{
			Hdr: dns.Header{Name: "www.google.com.", Class: dns.ClassINET, TTL: 300},
			A:   rdata.A{Addr: netip.MustParseAddr("192.0.2.1")},
		}},
	}
	b.ResetTimer()
	for b.Loop() {
		_ = det.Validate(".", "www.google.com.", msg)
	}
}

func BenchmarkDetector_ValidateClean(b *testing.B) {
	log.Default.SetLevel(log.Error)
	det := &Detector{}
	det.Enable(true)

	// Root server response with TLD NS delegation (clean).
	msg := &dns.Msg{
		Answer: []dns.RR{&dns.NS{
			Hdr: dns.Header{Name: "com.", Class: dns.ClassINET, TTL: 300},
			NS:  rdata.NS{Ns: "a.gtld-servers.net."},
		}},
	}
	b.ResetTimer()
	for b.Loop() {
		_ = det.Validate(".", "com.", msg)
	}
}

func BenchmarkDetector_IsHijackedByTLD(b *testing.B) {
	log.Default.SetLevel(log.Error)
	det := &Detector{}
	det.Enable(true)

	msg := &dns.Msg{
		Answer: []dns.RR{&dns.A{
			Hdr: dns.Header{Name: "www.google.com.", Class: dns.ClassINET, TTL: 300},
			A:   rdata.A{Addr: netip.MustParseAddr("192.0.2.1")},
		}},
	}
	b.ResetTimer()
	for b.Loop() {
		_ = det.IsHijackedByTLD(msg, "www.google.com.")
	}
}
