package edns

import "codeberg.org/miekg/dns"

// EDEZJDNSFallback marks a response served from a fallback upstream
// (config.UpstreamServer.Fallback).  65280 sits in the IANA-unassigned
// range of the RFC 8914 Extended DNS Errors registry (0–29 assigned) —
// ZJDNS private use, never registered.  Downstream ZJDNS instances
// seeing this code must not cache the response.
const EDEZJDNSFallback uint16 = 65280

// FallbackEDEText is the human-readable ExtraText attached to fallback
// responses (RFC 8914 §2 allows arbitrary diagnostic text).
const FallbackEDEText = "ZJDNS fallback response"

// IsFallbackEDE reports whether the EDE marks a ZJDNS fallback response.
func IsFallbackEDE(ede *dns.EDE) bool {
	return ede != nil && ede.InfoCode == EDEZJDNSFallback
}
