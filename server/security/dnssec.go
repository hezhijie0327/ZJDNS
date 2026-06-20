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

// ValidateResponse checks whether a DNS response contains DNSSEC record types.
// It does NOT perform cryptographic validation. Returns true only when DNSSEC
// record types are present in the response AND the client requested DNSSEC.
func (v *Validator) ValidateResponse(response *dns.Msg, dnssecOK bool) bool {
	if !dnssecOK || response == nil {
		return false
	}

	// We intentionally do NOT check response.AuthenticatedData here.
	// The AD flag from upstreams cannot be trusted without full cryptographic
	// chain-of-trust verification. Relying on it creates a false sense of
	// security against MITM attackers who can forge the AD bit.

	if v.hasDNSSECRecords(response) {
		log.Debugf("SECURITY: DNSSEC record-presence check passed")
		return true
	}
	log.Debugf("SECURITY: no DNSSEC records found in response")
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
