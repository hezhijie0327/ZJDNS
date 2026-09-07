package dnssec

import (
	"strings"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// TestNSEC3OptOutSuppressesAD pins RFC 5155 §9.2: an Opt-Out proof is
// cryptographically valid but the response is not AD-eligible — and a
// non-Opt-Out proof of the same shape is.
func TestNSEC3OptOutSuppressesAD(t *testing.T) {
	cv := NewCryptoValidator(nil)
	zone := "optout.example.com"
	zsk, zskPriv := genTestKey(zone, dns.FlagZONE)
	qname := "nx." + zone + "."

	build := func(flags uint8) *dns.Msg {
		hash := strings.ToLower(dnsutil.NSEC3Name(qname, "", 0))
		nsec3 := &dns.NSEC3{
			Hdr:  dns.Header{Name: hash + "." + zone + ".", Class: dns.ClassINET, TTL: 300},
			Hash: dns.SHA1, Flags: flags, Iterations: 0, Salt: "",
			TypeBitMap: []uint16{dns.TypeRRSIG, dns.TypeNSEC3},
		}
		sig := signRRset([]dns.RR{nsec3}, zone, zskPriv, zsk.KeyTag(), dns.ECDSAP256SHA256)
		resp := &dns.Msg{Rcode: dns.RcodeSuccess}
		resp.Ns = []dns.RR{nsec3, sig}
		return resp
	}

	validated, suppressed, _, err := cv.isNODATAValid(build(0), qname, dns.TypeA, []*dns.DNSKEY{zsk})
	if err != nil || !validated || suppressed {
		t.Fatalf("non-Opt-Out: (%t, %t, %v), want (true, false, nil)", validated, suppressed, err)
	}
	validated, suppressed, _, err = cv.isNODATAValid(build(1), qname, dns.TypeA, []*dns.DNSKEY{zsk})
	if err != nil || !validated || !suppressed {
		t.Fatalf("Opt-Out: (%t, %t, %v), want (true, true, nil) — proof holds, AD suppressed", validated, suppressed, err)
	}
}

// TestNSEC3ForeignFlagsIgnored pins RFC 5155 §8.2: NSEC3 RRs with flags
// other than 0 and the Opt-Out bit are ignored — a proof built only from
// them fails.
func TestNSEC3ForeignFlagsIgnored(t *testing.T) {
	cv := NewCryptoValidator(nil)
	zone := "flags.example.com"
	zsk, zskPriv := genTestKey(zone, dns.FlagZONE)
	qname := "nx." + zone + "."
	hash := strings.ToLower(dnsutil.NSEC3Name(qname, "", 0))
	nsec3 := &dns.NSEC3{
		Hdr:  dns.Header{Name: hash + "." + zone + ".", Class: dns.ClassINET, TTL: 300},
		Hash: dns.SHA1, Flags: 0x02, Iterations: 0, Salt: "",
		TypeBitMap: []uint16{dns.TypeRRSIG, dns.TypeNSEC3},
	}
	sig := signRRset([]dns.RR{nsec3}, zone, zskPriv, zsk.KeyTag(), dns.ECDSAP256SHA256)
	resp := &dns.Msg{Rcode: dns.RcodeSuccess, Ns: []dns.RR{nsec3, sig}}
	if validated, _, _, _ := cv.isNODATAValid(resp, qname, dns.TypeA, []*dns.DNSKEY{zsk}); validated {
		t.Fatal("NSEC3 with flags=0x02 must be ignored (RFC 5155 §8.2)")
	}
}
