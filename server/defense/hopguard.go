package defense

import (
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
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
	mu          sync.Mutex
	histogram   map[uint8]int // TTL → occurrence count
	trusted     map[uint8]int // trusted TTLs → count snapshot
	samples     int           // total responses observed
	armed       bool          // true once minimum samples reached
	lastRebuild int64         // time-based rebuild fallback (log.NowUnixNano())
	rejected    int           // rejection sampling counter (1-in-16 feed of Validate-rejected TTLs)
}

const (
	hopGuardFluctuation = 2 // ±TTL tolerance.  Empirically determined from four tested
	// international upstreams — stable single-path connections exhibit ≤±1 variation.
	// Anycast PoPs or load-balanced servers that rewrite TTL may need a wider window;
	// make this configurable per-upstream if false rejections occur in practice.
	hopGuardCacheCapacity = 256 // LRU cache capacity for server states
	hopGuardMinSamples    = 32  // samples needed before arming

	// hopGuardLearnLogEvery throttles the baseline-learning debug log.
	hopGuardLearnLogEvery = 8

	// hopGuardRebuildIntervalNanos is the time-based rebuild fallback in
	// log.NowUnixNano() granularity — precomputed so the per-Feed check does
	// no Duration conversion.
	hopGuardRebuildIntervalNanos = int64(5 * time.Minute)
	// hopGuardRejectionSample: 1-in-16 uniform sampling of Validate-rejected
	// TTLs into the histogram — recovery path for legitimate TTL drift
	// (anycast reroutes) without meaningfully weakening the guard.
	hopGuardRejectionSample = 16
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
		// TTL=0 is invalid at the network layer; passing here avoids
		// rejecting responses due to a locally-misconfigured client.
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

	// Evaluate trustedKeys only when debug is on — it sorts and joins the
	// baseline keys on every rejection (R3-M20).
	if log.IsDebug() {
		log.Debugf("UPSTREAM: hopguard reject TTL=%d for %s (trusted: %s)", observed, serverIP, trustedKeys(st))
	}
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
			histogram:   make(map[uint8]int, 16),
			trusted:     make(map[uint8]int, 4),
			lastRebuild: log.NowUnixNano(),
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
		// Rebuild at most once per Feed: the time-based fallback (for
		// low-traffic upstreams where the sample-based rebuild never fires)
		// and the sample-based rebuild are mutually exclusive — firing
		// both in one call would apply the 3/4 decay twice (M-low).
		rebuild := false
		if log.NowUnixNano()-st.lastRebuild > hopGuardRebuildIntervalNanos {
			st.lastRebuild = log.NowUnixNano()
			rebuild = true
		} else if st.samples%hopGuardMinSamples == 0 {
			rebuild = true
		}
		if rebuild {
			rebuildTrusted(st)
			if len(st.trusted) == 0 {
				st.armed = false
				st.samples = 0
				log.Debugf("UPSTREAM: hopguard disarmed — all TTLs decayed, re-entering learning for %s", serverIP)
			} else {
				log.Debugf("UPSTREAM: hopguard rebuild (%d trusted, threshold=%d) for %s", len(st.trusted), trustThreshold(st), serverIP)
			}
		}
		return
	}

	// Learning phase: record and check arming.
	st.histogram[observed]++
	st.samples++
	if st.samples%hopGuardLearnLogEvery == 0 {
		log.Debugf("UPSTREAM: hopguard learning (%d samples, %d TTLs) for %s",
			st.samples, len(st.histogram), serverIP)
	}
	if st.samples%hopGuardMinSamples == 0 { // ≥1 guaranteed — the samples counter starts at 1 (S9)
		rebuildTrusted(st)
		if len(st.trusted) > 0 {
			st.armed = true
			log.Debugf("UPSTREAM: hopguard armed (%d trusted, threshold=%d) for %s",
				len(st.trusted), trustThreshold(st), serverIP)
		}
	}
}

// Confident reports whether hopguard is fully armed for serverIP — the TTL
// baseline is trusted and can be used for rejection decisions.  A nil receiver
// (no HopGuard configured) always returns true — all TTLs are trusted.
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

// ShouldSampleRejected counts one Validate-rejected packet and reports
// whether THIS one should be fed into the histogram anyway — uniform
// 1-in-16 sampling (the count mutation is part of the contract: the "this
// one" selection depends on it).  Legitimate TTL drift after an anycast reroute / PoP shift
// (which stays outside the ±2 window and is hard-rejected while armed)
// re-enters the histogram this way and can become trusted at the next
// rebuild, instead of locking the server into SERVFAIL with no recovery
// path; attacker-injected TTLs are diluted 16x and still cannot win the
// mode competition (M2).
func (h *HopGuard) ShouldSampleRejected(serverIP string) bool {
	if h == nil {
		return false
	}
	st, ok := h.states.Get(serverIP)
	if !ok {
		return false
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if !st.armed {
		return false // learning phase has no rejections
	}
	st.rejected++
	return st.rejected%hopGuardRejectionSample == 0
}

// modeTTL returns the histogram's most frequent TTL (0 if empty).
func modeTTL(st *serverState) uint8 {
	var mode uint8
	maxCount := 0
	for ttl, count := range st.histogram {
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
// Applies a 3/4 decay to all histogram counts before computing the threshold,
// so stale TTLs naturally lose influence and new TTLs can become trusted after
// routing changes (anycast reroute, PoP change).
func rebuildTrusted(st *serverState) {
	// Decay: multiply all counts by 3/4 so stale TTLs fade out.
	// Capped at 1 — entries with count=1 are removed entirely.
	for ttl, count := range st.histogram {
		newCount := count * 3 / 4
		if newCount <= 0 {
			delete(st.histogram, ttl)
		} else {
			st.histogram[ttl] = newCount
		}
	}
	// Recompute threshold from the decayed histogram. Only the MODE itself
	// is promoted: an attacker that consistently repeats one injected TTL
	// value could otherwise reach count >= mode/4 after decay and enter the
	// trusted set, weakening hopguard's discrimination.
	threshold := trustThreshold(st)
	mode := modeTTL(st)
	clear(st.trusted)
	if mode > 0 {
		st.trusted[mode] = st.histogram[mode]
	}
	for ttl, count := range st.histogram {
		if ttl != mode && count >= threshold && count >= st.histogram[mode]/2 {
			st.trusted[ttl] = count
		}
	}
}
