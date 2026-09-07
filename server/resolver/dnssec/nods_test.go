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

// TestProvesNoDSAtDelegationOptOut regression: an Opt-Out denial carries NO
// record at the child name (opt-out delegations have no NSEC3 of their own,
// RFC 5155 §9) — the covered shape must be accepted, not demanded to show
// an NS bit. Rejected opt-out no-DS proofs broke every .com/.net-adjacent
// glue chase in the 2026-09 live regression (dnssec.works via udag.net).
func TestProvesNoDSAtDelegationOptOut(t *testing.T) {
	child := "sub.example.com."
	// Opt-Out NSEC3 covering some other hash — nothing matches H(child).
	resp := &dns.Msg{Ns: []dns.RR{&dns.NSEC3{
		Hdr:  dns.Header{Name: "a1rt98bs.example.com.", Class: dns.ClassINET, TTL: 300},
		Hash: dns.SHA1, Flags: 1, Iterations: 0, Salt: "",
		NextDomain: "a1rtlnpg.example.com.", TypeBitMap: []uint16{dns.TypeNS, dns.TypeSOA},
	}}}
	if !ProvesNoDSAtDelegation(resp, child) {
		t.Error("covered opt-out denial must prove the insecure delegation (RFC 5155 §9)")
	}
	// Plain NSEC covering (no exact match) — accepted the same way.
	resp2 := &dns.Msg{Ns: []dns.RR{&dns.NSEC{
		Hdr:        dns.Header{Name: "aaa.example.com.", Class: dns.ClassINET, TTL: 300},
		NextDomain: "zzz.example.com.", TypeBitMap: []uint16{dns.TypeRRSIG, dns.TypeNSEC},
	}}}
	if !ProvesNoDSAtDelegation(resp2, child) {
		t.Error("covered NSEC denial without a child record must be accepted")
	}
}
