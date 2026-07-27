package defense

import "zjdns/internal/lrumap"

// HopGuard detects DNS pollution by validating the IP-layer TTL (IPv4) or
// Hop Limit (IPv6) of received response packets. A GFW-injected response
// comes from a different network location than the real server, so its TTL
// will differ. TTL baselines are stored per upstream server IP in an LRU
// cache, converging to the correct value as clean-domain queries accumulate.
//
// Enablement is gated at the call site via UpstreamServer.HopGuard.
type HopGuard struct {
	cache *lrumap.Map[string, uint8] // server IP → expected TTL
}

const (
	hopGuardFluctuation   = 2   // ±TTL tolerance
	hopGuardCacheCapacity = 256 // LRU cache capacity for TTL fingerprints
)

// NewHopGuard creates a HopGuard with LRU cache.
func NewHopGuard() *HopGuard {
	return &HopGuard{
		cache: lrumap.New[string, uint8](hopGuardCacheCapacity),
	}
}

// Validate checks whether the observed TTL is within the expected range
// for the given server. On the first query to a server (cache miss),
// auto-learns the baseline. Subsequent queries are checked against the
// cached baseline ± hopGuardFluctuation.
func (h *HopGuard) Validate(serverIP string, observed uint8) bool {
	if h == nil || observed == 0 {
		return true
	}

	expected, ok := h.cache.Get(serverIP)
	if !ok {
		// First query to this server — learn baseline.
		h.cache.Set(serverIP, observed)
		return true
	}

	lo := int(expected) - hopGuardFluctuation
	hi := int(expected) + hopGuardFluctuation
	if lo < 1 {
		lo = 1
	}
	if hi > 255 {
		hi = 255
	}
	return int(observed) >= lo && int(observed) <= hi
}

// Expected returns the cached expected TTL for the server (0 if not learned).
func (h *HopGuard) Expected(serverIP string) uint8 {
	if h == nil {
		return 0
	}
	expected, ok := h.cache.Get(serverIP)
	if !ok {
		return 0
	}
	return expected
}
