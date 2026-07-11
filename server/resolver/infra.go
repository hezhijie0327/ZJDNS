package resolver

import (
	"time"
	"zjdns/cache"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
)

// infraBackoff returns the backoff duration for a given timeout count.
// Exponential: 1s, 2s, 4s, 8s, 16s, 32s, 64s, capped at 120s.
func infraBackoff(count int) time.Duration {
	if count <= 0 {
		return 0
	}
	if count > 7 {
		return 120 * time.Second
	}
	return time.Duration(1<<uint(count-1)) * time.Second
}

// checkInfraCache looks up the nameserver address in the infra_cache.
// Returns (skip bool, noEDNS bool).
func (r *Recursive) checkInfraCache(addr string) (skip, noEDNS bool) {
	store, ok := r.cache.(*cache.SQLiteCache)
	if !ok {
		return false, false
	}

	row := store.InfraGet(addr)
	if row == nil {
		return false, false
	}

	now := log.NowUnix()
	if row.TimeoutCount > 0 {
		backoff := int64(infraBackoff(row.TimeoutCount).Seconds())
		if now-row.LastTimeout < backoff {
			return true, false
		}
	}

	if row.EDNSVersion == -1 {
		return false, true
	}
	return false, false
}

// updateInfraCache updates the infra_cache after a query result.
func (r *Recursive) updateInfraCache(addr string, resultErr error, rcode int, duration time.Duration) {
	store, ok := r.cache.(*cache.SQLiteCache)
	if !ok {
		return
	}

	now := log.NowUnix()
	rttMs := int(duration.Milliseconds())

	existing := store.InfraGet(addr)

	ednsVersion := 0
	timeoutCount := 0
	lastTimeout := int64(0)
	lastSuccess := int64(0)

	if existing != nil {
		ednsVersion = existing.EDNSVersion
		timeoutCount = existing.TimeoutCount
		lastTimeout = existing.LastTimeout
		lastSuccess = existing.LastSuccess
	}

	if resultErr != nil {
		timeoutCount++
		lastTimeout = now
	} else {
		timeoutCount = 0
		lastSuccess = now
		rttMs = max(rttMs, 1)

		if rcode == dns.RcodeFormatError {
			ednsVersion = -1
		}
	}

	if err := store.InfraUpsert(addr, rttMs, ednsVersion, timeoutCount, lastTimeout, lastSuccess); err != nil {
		log.Debugf("INFRA: upsert failed for %s: %v", addr, err)
	}
}
