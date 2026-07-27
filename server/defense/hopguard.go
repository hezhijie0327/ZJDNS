package defense

import (
	"slices"
	"strconv"
	"strings"
	"sync"
	"zjdns/internal/log"
	"zjdns/internal/lrumap"
)

// HopGuard detects DNS pollution by validating the IP-layer TTL (IPv4) or
// Hop Limit (IPv6) of received response packets. A GFW-injected response
// comes from a different network location than the real server, so its TTL
// will differ.
//
// HopGuard builds a TTL histogram per upstream server during a learning
// phase. After collecting enough samples, it computes an adaptive trust
// threshold from the mode frequency: threshold = max(4, modeCount/4). Only
// TTLs meeting this threshold become trusted baselines. This prevents GFW
// TTLs (which scatter randomly with low repeat counts) from becoming trusted
// while allowing real server TTLs (which cluster tightly with high counts)
// to naturally dominate the trusted set.
//
// Enablement is gated at the call site via UpstreamServer.HopGuard.
type HopGuard struct {
	states *lrumap.Map[string, *serverState] // server IP → learning state
}

// serverState tracks TTL observation history for one upstream server.
// The mutex protects all fields; Validate is called concurrently from
// multiple goroutines sharing the same Client-level HopGuard instance.
type serverState struct {
	mu        sync.Mutex
	histogram map[uint8]int // TTL → occurrence count
	trusted   map[uint8]int // trusted TTLs → count snapshot
	samples   int           // total responses observed
	armed     bool          // true once minimum samples reached
}

const (
	hopGuardFluctuation   = 2   // ±TTL tolerance
	hopGuardCacheCapacity = 256 // LRU cache capacity for server states
	hopGuardMinSamples    = 32  // samples needed before arming
)

// NewHopGuard creates a HopGuard with LRU cache.
func NewHopGuard() *HopGuard {
	return &HopGuard{
		states: lrumap.New[string, *serverState](hopGuardCacheCapacity),
	}
}

// Validate checks whether the observed TTL is acceptable for the given server.
// It does NOT record TTLs — learning is handled separately by Feed, which is
// called only after spoofguard confirms the response is clean.
//
// Learning phase: all TTLs pass (insufficient data to judge).
// Enforcement phase: TTL must be within ±fluctuation of any trusted baseline.
func (h *HopGuard) Validate(serverIP string, observed uint8) bool {
	if h == nil || observed == 0 {
		return true
	}

	st, ok := h.states.Get(serverIP)
	if !ok {
		// No state yet — first contact with this server.  Feed will
		// create the state when spoofguard accepts the response.
		return true
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	// Learning phase: accept all.
	if !st.armed {
		return true
	}

	// Enforcement phase: check against trusted baselines.
	if passTrusted(st, observed) {
		return true
	}

	log.Debugf("UPSTREAM: hopguard reject TTL=%d for %s (trusted: %s)", observed, serverIP, trustedKeys(st))
	return false
}

// Feed records a TTL observation from a response that spoofguard has
// confirmed clean.  Only trusted DNS content is used for TTL learning,
// preventing GFW-injected responses from poisoning the histogram.
func (h *HopGuard) Feed(serverIP string, observed uint8) {
	if h == nil || observed == 0 {
		return
	}

	st, ok := h.states.Get(serverIP)
	if !ok {
		st = &serverState{
			histogram: make(map[uint8]int, 16),
			trusted:   make(map[uint8]int, 4),
		}
		actual, loaded := h.states.LoadOrStore(serverIP, st)
		if loaded {
			st = actual
		}
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	// Already armed — keep histogram updated for periodic rebuild.
	if st.armed {
		st.histogram[observed]++
		st.samples++
		if st.samples%hopGuardMinSamples == 0 {
			rebuildTrusted(st)
			log.Debugf("UPSTREAM: hopguard rebuild (%d trusted, threshold=%d) for %s", len(st.trusted), trustThreshold(st), serverIP)
		}
		return
	}

	// Learning phase: record and check arming.
	st.histogram[observed]++
	st.samples++
	if st.samples%8 == 0 {
		log.Debugf("UPSTREAM: hopguard learning (%d samples, %d TTLs) for %s",
			st.samples, len(st.histogram), serverIP)
	}
	if st.samples >= hopGuardMinSamples && st.samples%hopGuardMinSamples == 0 {
		rebuildTrusted(st)
		if len(st.trusted) > 0 {
			st.armed = true
			log.Debugf("UPSTREAM: hopguard armed (%d trusted, threshold=%d) for %s",
				len(st.trusted), trustThreshold(st), serverIP)
		}
	}
}

// Confident reports whether hopguard is fully armed for serverIP — the TTL
// baseline is trusted and can be used for rejection decisions.
func (h *HopGuard) Confident(serverIP string) bool {
	if h == nil {
		return true
	}
	st, ok := h.states.Get(serverIP)
	if !ok {
		return false
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.armed
}

// Expected returns the most frequent trusted TTL for the server (0 if not armed).
func (h *HopGuard) Expected(serverIP string) uint8 {
	if h == nil {
		return 0
	}
	st, ok := h.states.Get(serverIP)
	if !ok {
		return 0
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if !st.armed {
		return 0
	}
	var mode uint8
	maxCount := 0
	for ttl, count := range st.trusted {
		if count > maxCount || (count == maxCount && ttl < mode) {
			mode = ttl
			maxCount = count
		}
	}
	return mode
}

// trustThreshold computes the adaptive min-trust threshold: max(4, modeCount/4).
// This binds the trust bar to the dominant TTL's frequency, preventing
// low-repeat GFW TTLs from becoming trusted while the mode (the real server's
// most common TTL) always passes.
func trustThreshold(st *serverState) int {
	maxCount := 0
	for _, count := range st.histogram {
		if count > maxCount {
			maxCount = count
		}
	}
	// Integer division: mode/4 (floor), clamped to at least 4.
	// Floor=4 blocks GFW TTLs that repeat 2-3 times (observed on all
	// four tested international upstreams).
	threshold := max(maxCount/4, 4)
	return threshold
}

// passTrusted returns true if observed is within ±fluctuation of any trusted TTL.
func passTrusted(st *serverState, observed uint8) bool {
	for ttl := range st.trusted {
		lo := int(ttl) - hopGuardFluctuation
		hi := int(ttl) + hopGuardFluctuation
		if lo < 1 {
			lo = 1
		}
		if hi > 255 {
			hi = 255
		}
		if int(observed) >= lo && int(observed) <= hi {
			return true
		}
	}
	return false
}

// trustedKeys returns a sorted comma-separated list of trusted TTL values
// for debug logging (e.g. "100,95").
func trustedKeys(st *serverState) string {
	if len(st.trusted) == 0 {
		return "none"
	}
	keys := make([]int, 0, len(st.trusted))
	for ttl := range st.trusted {
		keys = append(keys, int(ttl))
	}
	slices.Sort(keys)
	var b strings.Builder
	for i, ttl := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.Itoa(ttl))
	}
	return b.String()
}

// rebuildTrusted promotes TTLs meeting the adaptive threshold to the trusted set.
func rebuildTrusted(st *serverState) {
	threshold := trustThreshold(st)
	clear(st.trusted)
	for ttl, count := range st.histogram {
		if count >= threshold {
			st.trusted[ttl] = count
		}
	}
}
