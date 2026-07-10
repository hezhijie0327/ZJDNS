package security

import (
	"zjdns/cache"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
)

// Guard aggregates DNSSEC crypto validation and hijack detection into a single
// configuration unit.
type Guard struct {
	Crypto   *CryptoValidator // Full cryptographic DNSSEC validation
	Detector *Detector        // Hijack detection
}

// New creates a new Guard. DNSSEC cryptographic validation is always enabled;
// the CryptoValidator always loads IANA root trust anchors and performs
// chain-of-trust verification.
func New(c cache.Store, hijackEnabled bool) *Guard {
	g := &Guard{
		Crypto:   NewCryptoValidator(c),
		Detector: &Detector{},
	}
	g.Detector.Enable(hijackEnabled)
	return g
}

// IsResponseValid checks whether a DNS response appears DNSSEC-validated.
// It trusts the AuthenticatedData (AD) flag ONLY when accompanied by DNSSEC
// records — the upstream resolver set AD, meaning it cryptographically validated
// the response. Without the AD flag, the upstream either did not validate or
// validation failed (e.g. bogus delegation like dnssec-failed.org); we must NOT
// treat those as validated.
//
// The full CryptoValidator provides stronger guarantees for recursive queries;
// this function serves as the lightweight check for upstream mode where we
// rely on the upstream resolver's validation.
func IsResponseValid(response *dns.Msg, dnssecOK bool) bool {
	if !dnssecOK || response == nil {
		return false
	}

	// Trust the AD flag when DNSSEC records are present. In upstream forwarding
	// mode, the upstream resolver performed the validation. In recursive mode,
	// CryptoValidator provides the definitive answer; this is the fallback.
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
