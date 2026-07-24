// Package ttl provides stateless TTL calculation functions for DNS cache
// entries and zone responses. All functions are zero-allocation and
// operate on scalar values.
package ttl

import (
	"time"

	"codeberg.org/miekg/dns"
)

// NowUnix returns the current Unix timestamp via the cached time source.
// Override in tests for deterministic results.
var NowUnix = time.Now().Unix

// IsExpired reports whether the TTL has elapsed relative to timestamp.
func IsExpired(timestamp int64, ttlSeconds int) bool {
	return NowUnix()-timestamp > int64(ttlSeconds)
}

// RemainingTTL returns the remaining TTL if fresh, or a cyclical stale TTL
// when expired. Each staleTTL-second window, the TTL decrements from
// staleTTL→1, then resets for the next window.
func RemainingTTL(timestamp int64, ttlSeconds int, staleTTL uint32) uint32 {
	remaining := int64(ttlSeconds) - (NowUnix() - timestamp)
	if remaining > 0 {
		return uint32(remaining) //nolint:gosec // G115: DNS TTL — protocol-bounded uint32
	}
	// Cyclical stale countdown: staleTTL - (timeSinceExpiry % staleTTL).
	timeSinceExpiry := -remaining
	cycleRemaining := max(int64(staleTTL)-(timeSinceExpiry%int64(staleTTL)), 1)
	return uint32(cycleRemaining) //nolint:gosec // G115: DNS TTL — protocol-bounded uint32
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
// elapsed modulo its original TTL, producing a cyclical countdown that wraps
// back to origTTL when elapsed reaches a multiple of origTTL. Each RR is
// deep-copied and cycles independently.
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
		copied.Header().TTL = uint32(origTTL - (elapsed % origTTL)) //nolint:gosec // G115: DNS TTL — protocol-bounded uint32
		result = append(result, copied)
	}
	return result
}
