// Package security provides DNSSEC validation and DNS hijacking detection for
// recursive resolution responses.
package security

import "zjdns/cache"

// Guard aggregates DNSSEC crypto validation and hijack detection into a single
// configuration unit. Lightweight record-presence checking is provided by the
// package-level ValidateResponse function.
type Guard struct {
	Crypto   *CryptoValidator // Full cryptographic DNSSEC validation
	Detector *Detector        // Hijack detection
}

// New creates a new Guard. DNSSEC cryptographic validation is always enabled;
// the CryptoValidator always loads IANA root trust anchors and performs
// chain-of-trust verification. The dnssec_enforce config option (not here)
// controls whether bogus responses are rejected or passed through.
func New(c cache.Store, hijackEnabled bool) *Guard {
	g := &Guard{
		Crypto:   NewCryptoValidator(c),
		Detector: &Detector{},
	}
	g.Detector.Enable(hijackEnabled)
	return g
}
