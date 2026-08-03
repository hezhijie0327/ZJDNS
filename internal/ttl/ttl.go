// Package ttl provides stateless TTL calculation functions for DNS cache
// entries and zone responses. Scalar helpers are zero-allocation;
// DeductElapsedCyclical allocates (it deep-copies each RR).
package ttl

import (
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
)

// NowUnix returns the current Unix timestamp. Override in tests for
// deterministic results.  This is an exported var so that test packages can
// swap it without touching the hot path.
var NowUnix = log.NowUnix //nolint:gocritic // variable allows test override

// IsExpired reports whether the TTL has elapsed relative to timestamp.
func IsExpired(timestamp int64, ttlSeconds int) bool {
	return NowUnix()-timestamp > int64(ttlSeconds)
}

// RemainingTTL returns the remaining TTL if fresh, or a constant stale TTL
// when expired (RFC 8767 §4 RECOMMENDED: 30s prevents thundering-herd
// re-queries during outages). At the exact expiry instant (remaining == 0)
// the entry is still fresh and 0 is returned, consistent with IsExpired.
func RemainingTTL(timestamp int64, ttlSeconds int, staleTTL uint32) uint32 {
	remaining := int64(ttlSeconds) - (NowUnix() - timestamp)
	if remaining >= 0 {
		return uint32(remaining) //nolint:gosec // G115: DNS TTL — protocol-bounded uint32
	}
	if staleTTL == 0 {
		return 30
	}
	return staleTTL
}

// CanServeExpired reports whether the expired entry is within the maxAge
// window past its TTL.
func CanServeExpired(timestamp int64, ttlSeconds, maxAge int) bool {
	return NowUnix()-timestamp-int64(ttlSeconds) <= int64(maxAge)
}

// ShouldPrefetch reports whether the entry is due for a background refresh
// based on the percentage threshold of its TTL remaining.
func ShouldPrefetch(timestamp int64, ttlSeconds, thresholdPercent int) bool {
	if thresholdPercent <= 0 || IsExpired(timestamp, ttlSeconds) {
		return false
	}
	if thresholdPercent > 100 {
		thresholdPercent = 100
	}
	if ttlSeconds <= 0 {
		return false
	}
	remaining := int64(ttlSeconds) - (NowUnix() - timestamp)
	if remaining <= 0 {
		return false
	}
	return remaining <= (int64(ttlSeconds)*int64(thresholdPercent)+99)/100
}

// Elapsed returns the number of seconds since timestamp.
func Elapsed(timestamp int64) int64 {
	e := NowUnix() - timestamp
	if e < 0 {
		return 0
	}
	return e
}

// DeductElapsedCyclical returns a new slice with each RR's TTL reduced by
// elapsed, decreasing monotonically and clamping at 0 — an expired record
// must never be re-served with a full TTL (the old modular wrap reset it to
// origTTL at exact multiples, keeping expired zone data valid indefinitely).
// Each RR is deep-copied and adjusted independently.
func DeductElapsedCyclical(rrs []dns.RR, elapsed int64) []dns.RR {
	if len(rrs) == 0 {
		return nil
	}
	result := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		if rr == nil {
			continue
		}
		copied := rr.Clone()
		origTTL := int64(copied.Header().TTL)
		if origTTL <= 0 {
			result = append(result, copied)
			continue
		}
		remaining := max(origTTL-elapsed, 0)
		copied.Header().TTL = uint32(remaining) //nolint:gosec // G115: DNS TTL — protocol-bounded uint32
		result = append(result, copied)
	}
	return result
}
