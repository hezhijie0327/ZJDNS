package edns

import "codeberg.org/miekg/dns"

// EDEZJDNSFallback marks a response served from a fallback upstream
// (config.UpstreamServer.Fallback).  EDEZJDNSDefenseUncertain marks a
// response served despite an enabled UDP defense guard having been unable
// to positively verify it (hopguard baseline still learning / TTL capture
// unavailable; capsguard unrandomized retry or downgraded address).  Both
// sit in the IANA-unassigned range of the RFC 8914 Extended DNS Errors
// registry (the 0–24 range is IANA-assigned) — ZJDNS private use, never
// registered.  Downstream ZJDNS instances seeing either code must not
// cache the response; the local cache-write gate refuses them too.
const (
	EDEZJDNSFallback         uint16 = 65280
	EDEZJDNSDefenseUncertain uint16 = 65281
)

// FallbackEDEText is the human-readable ExtraText attached to fallback
// responses (RFC 8914 §2 allows arbitrary diagnostic text).
const FallbackEDEText = "ZJDNS fallback response"

// DefenseUncertainEDEText is the ExtraText attached to responses served
// without a positive defense verification.
const DefenseUncertainEDEText = "ZJDNS defense-uncertain response"

// DefenseUncertainEDE builds the ZJDNS-private EDE for a response served
// without a positive defense verification.
func DefenseUncertainEDE() *dns.EDE {
	return &dns.EDE{InfoCode: EDEZJDNSDefenseUncertain, ExtraText: DefenseUncertainEDEText}
}

// IsFallbackEDE reports whether the EDE marks a ZJDNS fallback response.
func IsFallbackEDE(ede *dns.EDE) bool {
	return ede != nil && ede.InfoCode == EDEZJDNSFallback
}

// IsZJDNSNoCacheEDE reports whether the EDE carries a ZJDNS private
// do-not-cache mark (fallback provenance or defense uncertainty).  The
// cache-write gate and the upstream-receive path both refuse these.
func IsZJDNSNoCacheEDE(ede *dns.EDE) bool {
	return ede != nil && (ede.InfoCode == EDEZJDNSFallback || ede.InfoCode == EDEZJDNSDefenseUncertain)
}
