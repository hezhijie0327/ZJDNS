// Package security provides DNSSEC validation and DNS hijacking detection for
// recursive resolution responses.
package security

// Guard aggregates the DNSSEC validators and hijack detector into a single
// configuration unit.
type Guard struct {
	RecordPresence *Validator       // Lightweight record-presence check
	Crypto         *CryptoValidator // Full cryptographic DNSSEC validation
	Detector       *Detector        // Hijack detection
}

// New creates a new Guard. DNSSEC cryptographic validation is always enabled;
// the CryptoValidator always loads IANA root trust anchors and performs
// chain-of-trust verification. The dnssec_enforce config option (not here)
// controls whether bogus responses are rejected or passed through.
func New(hijackEnabled bool) *Guard {
	g := &Guard{
		RecordPresence: &Validator{},
		Crypto:         NewCryptoValidator(),
		Detector:       &Detector{},
	}
	g.Detector.Enable(hijackEnabled)
	return g
}
