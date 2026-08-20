// Package dns64 implements DNS64 (RFC 6147) — synthesizing AAAA records from
// A records for IPv6-only / NAT64 networks.
package dns64

import (
	"fmt"
	"net/netip"

	"codeberg.org/miekg/dns"
)

// Synthesizer performs DNS64 AAAA synthesis (RFC 6147) using an RFC 6052
// IPv4-embedded IPv6 prefix.
type Synthesizer struct {
	pref  netip.Prefix
	bytes [16]byte // prefix as 16 bytes, right-padded with zero
}

const (
	defaultPrefix = "64:ff9b::/96" // RFC 6052 §2.1 well-known prefix
	maxPrefixLen  = 96             // RFC 6147 §5.2
	maxSynTTL     = 600            // RFC 6147 §5.1.7 cap
)

var validPrefixLens = map[int]bool{32: true, 40: true, 48: true, 56: true, 64: true, 96: true}

// New creates a Synthesizer for the given IPv6 prefix. The prefix length
// must be one of 32, 40, 48, 56, 64, 96 (RFC 6052 Figure 1).
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

// Prefix returns the configured IPv6 prefix in CIDR notation.
func (s *Synthesizer) Prefix() string { return s.pref.String() }

// MapAddr maps an IPv4 address to its IPv6 form by embedding it at the
// position RFC 6052 Figure 1 defines for the configured prefix length. The
// bits 64-71 (u octet) stay zero for every layout, and the suffix bits are
// zero per RFC 6052 §2.2.
func (s *Synthesizer) MapAddr(ip4 netip.Addr) netip.Addr {
	var ip6 [16]byte
	pl := s.pref.Bits()
	copy(ip6[:pl/8], s.bytes[:pl/8])
	ip4b := ip4.As4()
	switch pl {
	case 32: // bits 32-63
		copy(ip6[4:8], ip4b[:])
	case 40: // bits 40-63 + 72-79
		copy(ip6[5:8], ip4b[:3])
		ip6[9] = ip4b[3]
	case 48: // bits 48-63 + 72-87
		copy(ip6[6:8], ip4b[:2])
		copy(ip6[9:11], ip4b[2:])
	case 56: // bits 56-63 + 72-95
		ip6[7] = ip4b[0]
		copy(ip6[9:12], ip4b[1:])
	case 64: // bits 72-103
		copy(ip6[9:13], ip4b[:])
	default: // 96: bits 96-127
		copy(ip6[12:16], ip4b[:])
	}
	return netip.AddrFrom16(ip6)
}

// Synthesize builds an AAAA response from the A query result, translating
// each A record via MapAddr (RFC 6147 §5.2).  aAnswer/aAuthority/aAdditional
// are the A-query results; origAuthority supplies the SOA TTL cap.  The
// returned RRsets carry no AD flag — synthesized AAAA must not assert
// validation.
func (s *Synthesizer) Synthesize(
	origAuthority, aAnswer, aAuthority, aAdditional []dns.RR,
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
			Addr: s.MapAddr(aRec.Addr),
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
