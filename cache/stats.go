package cache

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"zjdns/config"
	"zjdns/database"
	"zjdns/internal/log"
	"zjdns/internal/lrumap"
	"zjdns/internal/ttl"

	"github.com/dgraph-io/badger/v4"
)

// statsEntry holds in-memory query_stats counters for a single composite key.
type statsEntry struct {
	count   int64
	totalMS int64
}

const statsMapCapacity = 5000 // ~7 days of stats at ~500 unique keys/day

var errCacheClosed = errors.New("cache closed")

// statsKey builds the in-memory aggregation key for query_stats.
func statsKey(statDay int64, result, protocol string, rcode int, dnssecStatus string, poisoned bool) string {
	// Compact format: "{day}|{result}|{protocol}|{rcode}|{dnssec}|{poisoned}"
	poisonedByte := '0'
	if poisoned {
		poisonedByte = '1'
	}
	return fmt.Sprintf("%d|%s|%s|%d|%s|%c", statDay, result, protocol, rcode, dnssecStatus, poisonedByte)
}

// parseStatsKey reverses statsKey back into its components.
// Key format: "{statDay}|{result}|{protocol}|{rcode}|{dnssec}|{poisoned}"
func parseStatsKey(key string) (result, protocol string, rcode int, dnssec string, poisoned bool) {
	parts := strings.SplitN(key, "|", 6)
	if len(parts) < 6 {
		return "", "", 0, "", false
	}
	result = parts[1]
	protocol = parts[2]
	rcode, _ = strconv.Atoi(parts[3])
	dnssec = parts[4]
	poisoned = parts[5] == "1"
	return result, protocol, rcode, dnssec, poisoned
}

// RecordRequest upserts per-day aggregated stats counters into an in-memory
// LRU map. Stats are best-effort — the LRU evicts old entries under memory
// pressure, and concurrent updates to the same key may drop a rare increment.
func (c *Cache) RecordRequest(r *RequestRecord) {
	if r == nil || c.statsMap == nil {
		return
	}
	now := log.NowUnix()
	key := statsKey(now/86400, r.Result, r.Protocol, r.Rcode, r.DNSSECStatus, r.Poisoned)

	entry, _ := c.statsMap.Get(key)
	if entry == nil {
		entry = &statsEntry{}
	}
	entry.count++
	entry.totalMS += r.ResponseTime
	c.statsMap.Set(key, entry)
}

// ReverseLookup returns all cached domain names mapped to the given IP address.
func (c *Cache) ReverseLookup(ip string) []LookupResult {
	if ip == "" || c.db.IsClosed() {
		return nil
	}

	var results []LookupResult

	_ = c.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = database.EIPReversePrefix(ip)
		opts.PrefetchValues = true
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			if item.IsDeletedOrExpired() {
				continue
			}
			var ttlVal int32
			_ = item.Value(func(v []byte) error {
				ttlVal = database.DecodePtrMapValue(v)
				return nil //nolint:nilerr // key not found is not a View-level error — report via found=false
			})
			k := string(item.Key())
			nameOff := 0
			for nameOff < len(k) && k[nameOff] != 0 {
				nameOff++
			}
			nameOff += 1 + 8 + 1 // skip NUL + entryID(8) + NUL
			if nameOff < len(k) {
				name := k[nameOff:]
				results = append(results, LookupResult{
					Name: name,
					TTL:  ttl.RemainingTTL(0, int(ttlVal), uint32(config.DefaultStaleTTL)),
				})
			}
		}
		return nil
	})
	return results
}

// FlushDB truncates a single table: "cache" (entries), "zone" (zone_entries),
// or "ruleset" (ruleset_entries). "stats" is no longer persisted — it's a no-op.
func (c *Cache) FlushDB(target string) (int64, error) {
	if c.db.IsClosed() {
		return 0, errCacheClosed
	}
	switch target {
	case "stats":
		// Stats are in-memory only; just log and return.
		log.Infof("CACHE: flushDB stats: in-memory LRU, no persistence to clear")
		return 0, nil
	case "cache":
		if err := c.db.DropPrefix(database.EntryKeyPrefix()); err != nil {
			return 0, fmt.Errorf("flushDB cache: %w", err)
		}
	case "zone":
		if err := c.db.DropPrefix([]byte("z:")); err != nil {
			return 0, fmt.Errorf("flushDB zone: %w", err)
		}
	case "ruleset":
		if err := c.db.DropPrefix([]byte("r:")); err != nil {
			return 0, fmt.Errorf("flushDB ruleset: %w", err)
		}
	default:
		return 0, fmt.Errorf("flushDB: unknown target %q", target)
	}
	log.Infof("CACHE: flushDB %s: done", target)
	return 0, nil
}

// Clear truncates cache entries and resets in-memory stats.
func (c *Cache) Clear() (int64, error) {
	if _, err := c.FlushDB("cache"); err != nil {
		return 0, err
	}
	// Reset in-memory stats by creating a fresh map.
	if c.statsMap != nil {
		c.statsMap = lrumap.New[string, *statsEntry](statsMapCapacity)
	}
	return 0, nil
}

// Stats returns aggregated cache statistics from the in-memory LRU map.
func (c *Cache) Stats() []string {
	if c.statsMap == nil {
		return nil
	}

	var total, hits, misses, stales, zones, errCount, blockedCount, badcookieCount int64
	var udp, tcp, tls, quic, https, http3, dtls, dnscrypt, dnscryptTCP, tlcp, httpTLCP, dtlcp int64
	var noerr, formerr, servfail, nxdomain, notimp, refused, other int64
	var secureCount, insecureCount, bogusCount, poisoned int64
	var totalMS int64

	c.statsMap.Range(func(key string, e *statsEntry) bool {
		total += e.count
		totalMS += e.totalMS

		result, protocol, rcode, dnssec, isPoisoned := parseStatsKey(key)
		if result == "" {
			return true
		}

		switch result {
		case "hit":
			hits += e.count
		case "miss":
			misses += e.count
		case "stale":
			stales += e.count
		case "zone":
			zones += e.count
		case "error":
			errCount += e.count
		case "blocked":
			blockedCount += e.count
		case "badcookie":
			badcookieCount += e.count
		}

		switch protocol {
		case "udp":
			udp += e.count
		case "tcp":
			tcp += e.count
		case "tls":
			tls += e.count
		case "quic":
			quic += e.count
		case "https":
			https += e.count
		case "http3":
			http3 += e.count
		case "dtls":
			dtls += e.count
		case "dnscrypt":
			dnscrypt += e.count
		case "dnscrypt-tcp":
			dnscryptTCP += e.count
		case "tlcp":
			tlcp += e.count
		case "http-tlcp":
			httpTLCP += e.count
		case "dtlcp":
			dtlcp += e.count
		}

		switch rcode {
		case 0:
			noerr += e.count
		case 1:
			formerr += e.count
		case 2:
			servfail += e.count
		case 3:
			nxdomain += e.count
		case 4:
			notimp += e.count
		case 5:
			refused += e.count
		default:
			other += e.count
		}

		switch dnssec {
		case "secure":
			secureCount += e.count
		case "insecure":
			insecureCount += e.count
		case "bogus":
			bogusCount += e.count
		}

		if isPoisoned {
			poisoned += e.count
		}
		return true
	})

	var avgMs float64
	if total > 0 {
		avgMs = float64(totalMS) / float64(total)
	}

	return []string{
		fmt.Sprintf("total=%d avg=%.1fms", total, avgMs),
		fmt.Sprintf("hits=%d misses=%d stales=%d zones=%d", hits, misses, stales, zones),
		fmt.Sprintf("errors=%d blocked=%d badcookie=%d", errCount, blockedCount, badcookieCount),
		fmt.Sprintf("noerr=%d formerr=%d servfail=%d nx=%d nimp=%d ref=%d other=%d",
			noerr, formerr, servfail, nxdomain, notimp, refused, other),
		fmt.Sprintf("udp=%d tcp=%d", udp, tcp),
		fmt.Sprintf("tls=%d quic=%d https=%d http3=%d dtls=%d", tls, quic, https, http3, dtls),
		fmt.Sprintf("dnscrypt=%d dnscrypt-tcp=%d", dnscrypt, dnscryptTCP),
		fmt.Sprintf("tlcp=%d http-tlcp=%d dtlcp=%d", tlcp, httpTLCP, dtlcp),
		fmt.Sprintf("secure=%d insecure=%d bogus=%d poisoned=%d", secureCount, insecureCount, bogusCount, poisoned),
	}
}

// UpdateLatency stores a latency measurement keyed by IP only.
func (c *Cache) UpdateLatency(ip string, latencyMS int) {
	if latencyMS < 0 {
		latencyMS = 0
	}
	if c.db.IsClosed() {
		return
	}
	_ = c.db.Update(func(txn *badger.Txn) error {
		entry := badger.NewEntry(
			database.EIPLatencyKey(ip),
			database.EncodeLatencyValue(latencyMS),
		).WithTTL(time.Duration(config.DefaultLatencyProbeMinInterval*2) * time.Second)
		return txn.SetEntry(entry)
	})
}

// LatencyLastProbe returns the last probe time for an IP.
func (c *Cache) LatencyLastProbe(ip string) (int64, bool) {
	if c.db.IsClosed() {
		return 0, false
	}
	var found bool
	_ = c.db.View(func(txn *badger.Txn) error {
		_, err := txn.Get(database.EIPLatencyKey(ip))
		if err != nil {
			return nil //nolint:nilerr // key not found is not a View-level error — report via found=false
		}
		found = true
		return nil
	})
	if !found {
		return 0, false
	}
	return log.NowUnix(), true
}
