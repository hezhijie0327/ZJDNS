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
	defaultPrefix = "64:ff9b::/96" // RFC 6052 §2.1 well-known prefix
	maxPrefixLen  = 96             // RFC 6147 §5.2
	maxSynTTL     = 600            // RFC 6147 §5.1.7 cap
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

// v4Offset returns the byte offset where the IPv4 address is embedded for
// this prefix length (RFC 6052 §2.2).
func (s *Synthesizer) v4Offset() int {
	switch s.pref.Bits() {
	case 32:
		return 4
	case 40:
		return 5
	case 48:
		return 6
	case 56, 64:
		return 9
	case 96:
		return 12
	}
	return 12 // unreachable: New rejects all other prefix lengths
}

// MapAddr embeds ip4 at the RFC 6052 §2.2 position for this prefix length
// and zeroes the u octet (byte 8). All non-/96 prefixes embed the FULL 32
// IPv4 bits, split across the reserved u octet: e.g. /40 puts the first 24
// bits right after the prefix (bytes 5-7) and the last 8 after u (byte 9).
func (s *Synthesizer) MapAddr(ip4 netip.Addr) netip.Addr {
	var ip6 [16]byte
	copy(ip6[:], s.bytes[:]) // masked prefix + zero suffix
	ip4b := ip4.As4()
	switch s.pref.Bits() {
	case 32:
		copy(ip6[4:], ip4b[:]) // all 32 bits
	case 40:
		copy(ip6[5:], ip4b[:3]) // first 24 bits
		ip6[9] = ip4b[3]        // last 8 bits after u
	case 48:
		copy(ip6[6:], ip4b[:2]) // first 16 bits
		copy(ip6[9:], ip4b[2:]) // last 16 bits after u
	case 56:
		ip6[7] = ip4b[0]        // first 8 bits right after the prefix
		copy(ip6[9:], ip4b[1:]) // last 24 bits after u
	case 64:
		copy(ip6[9:], ip4b[:]) // all 32 bits after u
	case 96:
		copy(ip6[12:], ip4b[:]) // all 32 bits
	}
	if s.pref.Bits() != 96 {
		ip6[8] = 0 // u octet
	}
	return netip.AddrFrom16(ip6)
}

func (s *Synthesizer) ExtractIPv4(ip6 netip.Addr) (netip.Addr, bool) {
	if !s.IsSynthesized(ip6) {
		return netip.Addr{}, false
	}
	ip6b := ip6.As16()
	// /40, /48 and /56 split the IPv4 address across the u octet (byte 8);
	// reassemble the two halves. /32, /64 and /96 are contiguous.
	var v4 [4]byte
	switch s.pref.Bits() {
	case 40:
		copy(v4[:3], ip6b[5:8])
		v4[3] = ip6b[9]
	case 48:
		copy(v4[:2], ip6b[6:8])
		copy(v4[2:], ip6b[9:11])
	case 56:
		v4[0] = ip6b[7]
		copy(v4[1:], ip6b[9:12])
	default:
		off := s.v4Offset()
		return netip.AddrFrom4([4]byte(ip6b[off : off+4])), true
	}
	return netip.AddrFrom4(v4), true
}

// IsSynthesized reports whether ip6 lies in the prefix AND has the RFC 6052
// §2.2 u octet zero — an address in the prefix with a nonzero u is not a
// synthesized one.
func (s *Synthesizer) IsSynthesized(ip6 netip.Addr) bool {
	if !s.pref.Contains(ip6) {
		return false
	}
	if s.pref.Bits() == 96 {
		return true
	}
	return ip6.As16()[8] == 0
}

func (s *Synthesizer) Synthesize(
	origAnswer, origAuthority, origAdditional, aAnswer, aAuthority, aAdditional []dns.RR,
	checkingDisabled bool,
) (answer, authority, additional []dns.RR) {
	// RFC 6147 §5.5: with the CD bit set the client validates for itself —
	// synthesis MUST NOT happen (it would destroy the signature chain).
	// Without CD, a validating server SHOULD still synthesize; it just
	// must not set AD on the synthesized response (handled by the caller).
	if checkingDisabled {
		return origAnswer, origAuthority, origAdditional
	}
	ttl := minTTL(aAnswer, soaTTL(origAuthority))
	answer = make([]dns.RR, 0, len(aAnswer))
	for _, rr := range aAnswer {
		switch rr.(type) {
		case *dns.CNAME, *dns.DNAME:
			// RFC 6147 §5.1.5: any chains of CNAME or DNAME RRs are
			// included as part of the answer along with the synthetic AAAA.
			answer = append(answer, rr)
			continue
		}
		aRec, ok := rr.(*dns.A)
		if !ok {
			// Strip other record types and RRSIGs — the synthesized AAAA
			// is a new RRset without a valid signature.
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
