package dnssec

import (
	"testing"

	"codeberg.org/miekg/dns"
)

// TestProvesNoDSAtDelegation pins RFC 4035 §5.2: a no-DS denial at a
// delegation point must show the NS bit (the delegation exists) without DS;
// Opt-Out NSEC3 coverage also proves the insecure delegation (RFC 5155 §9).
func TestProvesNoDSAtDelegation(t *testing.T) {
	child := "sub.example.com."
	nsec := func(bitmap []uint16) *dns.Msg {
		return &dns.Msg{Ns: []dns.RR{&dns.NSEC{
			Hdr:        dns.Header{Name: child, Class: dns.ClassINET, TTL: 300},
			NextDomain: "z.example.com.", TypeBitMap: bitmap,
		}}}
	}
	if !ProvesNoDSAtDelegation(nsec([]uint16{dns.TypeNS, dns.TypeRRSIG}), child) {
		t.Error("NS bit without DS must prove the no-DS delegation")
	}
	if ProvesNoDSAtDelegation(nsec([]uint16{dns.TypeRRSIG, dns.TypeNSEC}), child) {
		t.Error("missing NS bit: an ordinary NODATA must not mark the delegation insecure")
	}
	if ProvesNoDSAtDelegation(nsec([]uint16{dns.TypeNS, dns.TypeDS}), child) {
		t.Error("DS bit present: not a no-DS proof")
	}
}
