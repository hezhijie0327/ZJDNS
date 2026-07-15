package dnssec

import (
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
)

// IsResponseValid checks whether a DNS response appears DNSSEC-validated.
func IsResponseValid(response *dns.Msg, dnssecOK bool) bool {
	if !dnssecOK || response == nil {
		return false
	}
	if response.AuthenticatedData && hasDNSSECRecords(response) {
		log.Debugf("SECURITY: validated via AD flag + DNSSEC record presence")
		return true
	}
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
