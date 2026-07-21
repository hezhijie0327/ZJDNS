package dnssec

import (
	"crypto/ecdsa"
	"net/netip"
	"testing"
	"time"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// benchGenKey is an inline key generator for benchmarks.
func benchGenKey(zone string, flags uint16) (*dns.DNSKEY, *ecdsa.PrivateKey) {
	dnskey := &dns.DNSKEY{
		Hdr:    dns.Header{Name: dnsutil.Fqdn(zone), Class: dns.ClassINET, TTL: 3600},
		DNSKEY: rdata.DNSKEY{Flags: flags, Protocol: 3, Algorithm: dns.ECDSAP256SHA256},
	}
	priv, _ := dnskey.Generate(256)
	return dnskey, priv.(*ecdsa.PrivateKey)
}

func BenchmarkCryptoValidator_VerifyRRset(b *testing.B) {
	log.Default.SetLevel(log.Error)
	cv := NewCryptoValidator(nil)
	zone := "bench.example.com"
	ksk, priv := benchGenKey(zone, dns.FlagSEP|dns.FlagZONE)
	a := &dns.A{
		Hdr: dns.Header{Name: dnsutil.Fqdn(zone), Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("192.0.2.1")},
	}
	rrsig := &dns.RRSIG{
		Hdr: dns.Header{Name: dnsutil.Fqdn(zone), Class: dns.ClassINET, TTL: 300},
		RRSIG: rdata.RRSIG{
			TypeCovered: dns.TypeA, Algorithm: dns.ECDSAP256SHA256, Labels: 3, OrigTTL: 300,
			Expiration: uint32(time.Now().Add(24 * time.Hour).Unix()), //nolint:gosec // G115: DNS TTL — protocol-bounded uint32
			Inception:  uint32(time.Now().Add(-1 * time.Hour).Unix()), //nolint:gosec // G115: DNS TTL — protocol-bounded uint32
			KeyTag:     ksk.KeyTag(), SignerName: dnsutil.Fqdn(zone),
		},
	}
	_ = rrsig.Sign(priv, []dns.RR{a}, &dns.SignOption{})

	b.ResetTimer()
	for b.Loop() {
		_ = cv.VerifyRRset([]dns.RR{a}, rrsig, ksk)
	}
}

func BenchmarkCryptoValidator_VerifyDelegationDS(b *testing.B) {
	log.Default.SetLevel(log.Error)
	cv := NewCryptoValidator(nil)
	childZone := "child.bench.example.com"
	ksk, _ := benchGenKey(childZone, dns.FlagSEP|dns.FlagZONE)
	ds := ksk.ToDS(dns.SHA256)

	b.ResetTimer()
	for b.Loop() {
		_, _ = cv.VerifyDelegationDS([]*dns.DS{ds}, []*dns.DNSKEY{ksk})
	}
}

func BenchmarkIsResponseValid(b *testing.B) {
	log.Default.SetLevel(log.Error)
	msg := &dns.Msg{}
	msg.AuthenticatedData = true
	msg.Answer = []dns.RR{
		&dns.RRSIG{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}},
	}
	b.ResetTimer()
	for b.Loop() {
		_ = IsResponseValid(msg, true)
	}
}
