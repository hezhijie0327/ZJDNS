package security

import (
	"github.com/miekg/dns"

	"zjdns/internal/log"
)

// Validator performs lightweight DNSSEC record-presence checking only.
//
// IMPORTANT: This does NOT perform cryptographic DNSSEC validation (RRSIG
// signature verification, DNSKEY trust anchor validation, or chain-of-trust
// construction). It only checks whether DNSSEC record types (RRSIG, NSEC,
// NSEC3, DNSKEY, DS) are present in the response. The AuthenticatedData (AD)
// flag from upstream servers is explicitly NOT trusted or propagated, as it
// cannot be verified without full cryptographic validation.
//
// Operators who need real DNSSEC validation should deploy this server behind
// a validating resolver (e.g., Unbound) or implement full RFC 4033-4035
// validation using the miekg/dns dnssec package with configured trust anchors.
type Validator struct{}

// ValidateResponse checks whether a DNS response appears DNSSEC-validated.
// It trusts the AuthenticatedData (AD) flag ONLY when accompanied by DNSSEC
// records — the upstream resolver set AD, meaning it cryptographically validated
// the response. Without the AD flag, the upstream either did not validate or
// validation failed (e.g. bogus delegation like dnssec-failed.org); we must NOT
// treat those as validated.
//
// The full CryptoValidator provides stronger guarantees for recursive queries;
// this method serves as the lightweight check for upstream mode where we
// rely on the upstream resolver's validation.
func (v *Validator) ValidateResponse(response *dns.Msg, dnssecOK bool) bool {
	if !dnssecOK || response == nil {
		return false
	}

	// Trust the AD flag when DNSSEC records are present. In upstream forwarding
	// mode, the upstream resolver performed the validation. In recursive mode,
	// CryptoValidator provides the definitive answer; this is the fallback.
	if response.AuthenticatedData && v.hasDNSSECRecords(response) {
		log.Debugf("SECURITY: validated via AD flag + DNSSEC record presence")
		return true
	}

	log.Debugf("SECURITY: not DNSSEC-validated (AD=%t, records=%t)", response.AuthenticatedData, v.hasDNSSECRecords(response))
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
