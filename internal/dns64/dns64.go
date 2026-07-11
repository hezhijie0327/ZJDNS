// Package dns64 implements DNS64 (RFC 6147) — synthesizing AAAA records from
// A records for IPv6-only / NAT64 networks.
package dns64

import (
	"fmt"
	"net/netip"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

// Synthesizer performs DNS64 AAAA synthesis.
type Synthesizer struct {
	pref  netip.Prefix
	bytes [16]byte // prefix as 16 bytes, right-padded with zero
}

const (
	DefaultPrefix = "64:ff9b::/96" // RFC 6052 §2.1 well-known prefix
	maxPrefixLen  = 96             // RFC 6147 §5.2
	maxSynTTL     = 600            // RFC 6147 §5.1.7 cap
	nat64Offset   = 12             // IPv4 embedded at byte 12
)

var validPrefixLens = map[int]bool{32: true, 40: true, 48: true, 56: true, 64: true, 96: true}

func New(prefix string) (*Synthesizer, error) {
	pref, err := netip.ParsePrefix(prefix)
	if err != nil {
		return nil, fmt.Errorf("dns64: parse prefix %q: %w", prefix, err)
	}
	if !pref.Addr().Is6() {
		return nil, fmt.Errorf("dns64: prefix %q is not an IPv6 address", prefix)
	}
	if pref.Bits() > maxPrefixLen {
		return nil, fmt.Errorf("dns64: prefix %q is too long (max %d bits)", prefix, maxPrefixLen)
	}
	if !validPrefixLens[pref.Bits()] {
		return nil, fmt.Errorf("dns64: prefix length /%d is not valid (allowed: 32,40,48,56,64,96)", pref.Bits())
	}
	s := &Synthesizer{pref: pref.Masked()}
	copy(s.bytes[:], pref.Masked().Addr().AsSlice())
	return s, nil
}

func (s *Synthesizer) Prefix() string { return s.pref.String() }

func (s *Synthesizer) MapAddr(ip4 netip.Addr) netip.Addr {
	var ip6 [16]byte
	copy(ip6[:nat64Offset], s.bytes[:nat64Offset])
	ip4b := ip4.As4()
	copy(ip6[nat64Offset:], ip4b[:])
	return netip.AddrFrom16(ip6)
}

func (s *Synthesizer) ExtractIPv4(ip6 netip.Addr) (netip.Addr, bool) {
	if !s.IsSynthesized(ip6) {
		return netip.Addr{}, false
	}
	ip6b := ip6.As16()
	return netip.AddrFrom4([4]byte(ip6b[nat64Offset:])), true
}

func (s *Synthesizer) IsSynthesized(ip6 netip.Addr) bool { return s.pref.Contains(ip6) }

func (s *Synthesizer) Synthesize(
	origAnswer, origAuthority, origAdditional, aAnswer, aAuthority, aAdditional []dns.RR,
	origValidated bool,
) (answer, authority, additional []dns.RR) {
	ttl := minTTL(aAnswer, soaTTL(origAuthority))
	answer = make([]dns.RR, 0, len(aAnswer))
	for _, rr := range aAnswer {
		aRec, ok := rr.(*dns.A)
		if !ok {
			answer = append(answer, rr)
			continue
		}
		answer = append(answer, &dns.AAAA{
			Hdr:  dns.Header{Name: aRec.Hdr.Name, Class: aRec.Hdr.Class, TTL: min(aRec.Hdr.TTL, ttl)},
			AAAA: rdata.AAAA{Addr: s.MapAddr(aRec.Addr)},
		})
	}
	return answer, aAuthority, aAdditional
}

func soaTTL(authority []dns.RR) uint32 {
	for _, rr := range authority {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa.Hdr.TTL
		}
	}
	return maxSynTTL
}

func minTTL(answer []dns.RR, soaTTL uint32) uint32 {
	ttl := soaTTL
	for _, rr := range answer {
		if a, ok := rr.(*dns.A); ok && a.Hdr.TTL < soaTTL {
			ttl = a.Hdr.TTL
		}
	}
	return min(ttl, maxSynTTL)
}
