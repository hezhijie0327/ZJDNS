package dnssec

import (
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
)

// IsResponseValid checks whether a DNS response appears DNSSEC-validated.
// When forwarding, the upstream may not set the AD flag even though it returned
// DNSSEC records (some resolvers omit AD when CD=1).  Presence of RRSIG/NSEC/
// DNSKEY/DS records alone is sufficient evidence that validation occurred.
func IsResponseValid(response *dns.Msg, dnssecOK bool) bool {
	if !dnssecOK || response == nil {
		return false
	}
	if response.AuthenticatedData && hasDNSSECRecords(response) {
		log.Debugf("SECURITY: validated via AD flag + DNSSEC records")
		return true
	}
	// Presence of DNSSEC record types is NOT proof of validation: an
	// arbitrary forwarder (or on-path attacker) can supply RRSIG/NSEC/NSEC3
	// looking records without them being authenticated. Only the
	// cryptographic validator (CryptoValidator.IsResponseValid) can confirm
	// validation, so a missing AD bit stays unvalidated.
	log.Debugf("SECURITY: not DNSSEC-validated (AD=%t, records=%t)", response.AuthenticatedData, hasDNSSECRecords(response))
	return false
}

func hasDNSSECRecords(response *dns.Msg) bool {
	if response == nil {
		return false
	}
	for _, sections := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
		for _, rr := range sections {
			switch rr.(type) {
			case *dns.RRSIG, *dns.NSEC, *dns.NSEC3, *dns.DNSKEY, *dns.DS:
				return true
			}
		}
	}
	return false
}
