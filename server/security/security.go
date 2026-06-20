// Package security provides DNSSEC validation and DNS hijacking detection for
// recursive resolution responses.
package security

// Guard aggregates the DNSSEC validator and hijack detector into a single
// configuration unit.
type Guard struct {
	Validator *Validator
	Detector  *Detector
}

// New creates a new Guard with optional hijack detection enabled.
func New(hijackEnabled bool) *Guard {
	g := &Guard{
		Validator: &Validator{},
		Detector:  &Detector{},
	}
	g.Detector.Enable(hijackEnabled)
	return g
}
