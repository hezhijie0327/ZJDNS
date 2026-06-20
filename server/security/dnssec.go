package security

import (
	"github.com/miekg/dns"

	"zjdns/internal/log"
)

// Validator performs DNSSEC validation by checking the Authenticated Data flag
// and the presence of DNSSEC resource records in responses.
type Validator struct{}

// ValidateResponse checks whether a DNS response has been DNSSEC-signed by
// verifying the AD flag or the presence of DNSSEC records.
func (v *Validator) ValidateResponse(response *dns.Msg, dnssecOK bool) bool {
	if !dnssecOK || response == nil {
		return false
	}

	if response.AuthenticatedData {
		log.Debugf("SECURITY: validated via AD flag")
		return true
	}

	if v.hasDNSSECRecords(response) {
		log.Debugf("SECURITY: validated via DNSSEC record presence")
		return true
	}
	log.Debugf("SECURITY: validation failed (no AD flag and no DNSSEC records)")
	return false
}

func (v *Validator) hasDNSSECRecords(response *dns.Msg) bool {
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
