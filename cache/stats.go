package cache

import (
	"encoding/binary"
	"errors"
	"fmt"
	"zjdns/config"
	"zjdns/database"
	"zjdns/internal/log"
	"zjdns/internal/ttl"

	"codeberg.org/miekg/dns/dnsutil"
	"github.com/dgraph-io/badger/v4"
)

var errCacheClosed = errors.New("cache closed")

// RecordRequest logs a request outcome asynchronously. The record is queued
// into a background writer goroutine that upserts into query_stats (per-day
// aggregated counters) and, for non-hit results, inserts a row into query_log
// for the audit trail. Hits are only in query_stats.
//
// When the async writer's channel is full the record is silently dropped —
// stats are best-effort and must never block the query hot path.
//
// When the async writer is nil (e.g., in tests), RecordRequest falls back to
// synchronous writes so callers can observe results immediately.
func (c *Cache) RecordRequest(r *RequestRecord) {
	if r == nil {
		return
	}
	qname := dnsutil.Canonical(r.Qname)
	if c.asyncWriter != nil {
		rec := *r
		rec.Qname = qname
		c.asyncWriter.Record(&rec)
		return
	}

	// Synchronous fallback when no async writer is configured.
	if c.db.IsClosed() {
		return
	}
	_ = c.db.Badger.Update(func(txn *badger.Txn) error {
		upsertQueryStats(txn, r.Result, r.Protocol, r.Rcode, r.DNSSECStatus, r.Poisoned, r.ResponseTime)

		return nil
	})
}

// ReverseLookup returns all cached domain names mapped to the given IP address.
func (c *Cache) ReverseLookup(ip string) []LookupResult {
	if ip == "" || c.db.IsClosed() {
		return nil
	}

	var results []LookupResult

	_ = c.db.Badger.View(func(txn *badger.Txn) error {
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
				return nil
			})
			// Extract name from key: p:{ip}\x00{entry_id:8B BE}\x00{name}
			k := string(item.Key())
			// Find first NUL after ip, then skip entryID (8B) + NUL (1B) = 9.
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

// upsertQueryStats does a read-modify-write on a query_stats key within a
// transaction. Called from both the async writer path and the sync fallback.
func upsertQueryStats(txn *badger.Txn, result, protocol string, rcode int, dnssecStatus string, poisoned bool, responseTime int64) {
	statDay := log.NowUnix() / 86400
	key := database.QueryStatsKey(statDay, result, protocol, rcode, dnssecStatus, poisoned)

	var queryCount, totalMS int64
	item, err := txn.Get(key)
	if err == nil {
		_ = item.Value(func(v []byte) error {
			queryCount, totalMS = database.DecodeQueryStatsValue(v)
			return nil
		})
	}
	queryCount++
	totalMS += responseTime
	_ = txn.Set(key, database.EncodeQueryStatsValue(queryCount, totalMS))
}

// FlushDB truncates a single table: "stats" (query_stats), "cache" (entries),
// "zone" (zone_entries), or "ruleset" (ruleset_entries).
// Uses db.DropPrefix — NOTE: this stops all writes during the operation.
func (c *Cache) FlushDB(target string) (int64, error) {
	if c.db.IsClosed() {
		return 0, errCacheClosed
	}
	var prefix []byte
	switch target {
	case "stats":
		prefix = database.QueryStatsPrefix()
	case "cache":
		prefix = database.EntryKeyPrefix()
	case "zone":
		prefix = []byte("z:")
	case "ruleset":
		prefix = []byte("r:")
	default:
		return 0, fmt.Errorf("flushDB: unknown target %q", target)
	}
	if err := c.db.Badger.DropPrefix(prefix); err != nil {
		return 0, fmt.Errorf("flushDB %s: %w", target, err)
	}
	log.Infof("CACHE: flushDB %s: done", target)
	return 0, nil // DropPrefix doesn't return count
}

// Clear truncates cache entries and query_stats.
func (c *Cache) Clear() (int64, error) {
	for _, target := range []string{"cache", "stats"} {
		if _, err := c.FlushDB(target); err != nil {
			return 0, err
		}
	}
	return 0, nil
}

// Stats returns aggregated cache statistics as formatted TXT records.
// Uses a single prefix scan over query_stats (~500 rows).
func (c *Cache) Stats() []string {
	if c.db.IsClosed() {
		return nil
	}

	// Count cache entries via prefix scan — TTL makes atomic tracking unreliable.
	var entries int64
	_ = c.db.Badger.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = database.EntryKeyPrefix()
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			if !it.Item().IsDeletedOrExpired() {
				entries++
			}
		}
		return nil
	})

	var total, hits, misses, stales, zones, errCount, blockedCount, badcookieCount int64
	var udp, tcp, tls, quic, https, http3, dtls, dnscrypt, dnscryptTCP, tlcp, httpTLCP, dtlcp int64
	var noerr, formerr, servfail, nxdomain, notimp, refused, other int64
	var secureCount, insecureCount, bogusCount, poisoned int64
	var totalMS int64

	_ = c.db.Badger.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = database.QueryStatsPrefix()
		opts.PrefetchValues = true
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			_ = it.Item().Value(func(v []byte) error {
				qc, tms := database.DecodeQueryStatsValue(v)
				total += qc
				totalMS += tms

				k := string(it.Item().Key())
				result, protocol, rcode, dnssec, isPoisoned := parseStatsKey(k)
				if result == "" {
					return nil
				}

				switch result {
				case "hit":
					hits += qc
				case "miss":
					misses += qc
				case "stale":
					stales += qc
				case "zone":
					zones += qc
				case "error":
					errCount += qc
				case "blocked":
					blockedCount += qc
				case "badcookie":
					badcookieCount += qc
				}

				switch protocol {
				case "udp":
					udp += qc
				case "tcp":
					tcp += qc
				case "tls":
					tls += qc
				case "quic":
					quic += qc
				case "https":
					https += qc
				case "http3":
					http3 += qc
				case "dtls":
					dtls += qc
				case "dnscrypt":
					dnscrypt += qc
				case "dnscrypt-tcp":
					dnscryptTCP += qc
				case "tlcp":
					tlcp += qc
				case "http-tlcp":
					httpTLCP += qc
				case "dtlcp":
					dtlcp += qc
				}

				switch rcode {
				case 0:
					noerr += qc
				case 1:
					formerr += qc
				case 2:
					servfail += qc
				case 3:
					nxdomain += qc
				case 4:
					notimp += qc
				case 5:
					refused += qc
				default:
					other += qc
				}

				switch dnssec {
				case "secure":
					secureCount += qc
				case "insecure":
					insecureCount += qc
				case "bogus":
					bogusCount += qc
				}

				if isPoisoned {
					poisoned += qc
				}
				return nil
			})
		}
		return nil
	})

	var avgMs float64
	if total > 0 {
		avgMs = float64(totalMS) / float64(total)
	}

	return []string{
		fmt.Sprintf("entries=%d total=%d avg=%.1fms", entries, total, avgMs),
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

// parseStatsKey extracts fields from a query_stats key.
// Format: s:{stat_day:8B BE}\x00{result}\x00{protocol}\x00{rcode:2B BE}\x00{dnssec}\x00{poisoned:1B}
// Uses offset-based parsing to avoid ambiguity from 0x00 bytes inside binary rcode.
func parseStatsKey(key string) (result, protocol string, rcode int, dnssec string, poisoned bool) {
	// Skip "s:" (2) + stat_day (8) + NUL (1) = 11 bytes.
	off := 11
	if len(key) < off {
		return "", "", 0, "", false
	}
	// Read result string until NUL.
	result, off = readNulString(key, off)
	// Read protocol string until NUL.
	protocol, off = readNulString(key, off)
	// Read rcode as 2 bytes BE.
	if off+2 <= len(key) {
		rcode = int(binary.BigEndian.Uint16([]byte(key[off : off+2])))
		off += 2 + 1 // skip rcode + NUL
	}
	// Read dnssec string until NUL.
	dnssec, off = readNulString(key, off)
	// Read poisoned as 1 byte.
	if off < len(key) {
		poisoned = key[off] == '1'
	}
	return result, protocol, rcode, dnssec, poisoned
}

// readNulString reads a NUL-terminated string from key starting at off.
// Returns the string (without NUL) and the next offset (after the NUL).
func readNulString(key string, off int) (s string, nextOff int) {
	if off >= len(key) {
		return "", off
	}
	end := off
	for end < len(key) && key[end] != 0 {
		end++
	}
	s = key[off:end]
	if end < len(key) {
		end++ // skip NUL
	}
	nextOff = end
	return s, nextOff
}

// UpdateLatency stores a latency measurement keyed by IP only.
func (c *Cache) UpdateLatency(ip string, latencyMS int) {
	if latencyMS < 0 {
		latencyMS = 0
	}
	if c.db.IsClosed() {
		return
	}
	_ = c.db.Badger.Update(func(txn *badger.Txn) error {
		return txn.Set(database.EIPLatencyKey(ip), database.EncodeLatencyValue(latencyMS))
	})
}

// LatencyLastProbe returns the last probe time for an IP.
func (c *Cache) LatencyLastProbe(ip string) (int64, bool) {
	if c.db.IsClosed() {
		return 0, false
	}
	_ = c.db.Badger.View(func(txn *badger.Txn) error {
		_, err := txn.Get(database.EIPLatencyKey(ip))
		return err
	})
	// Item exists → return current time as "last probe"
	return log.NowUnix(), true
}
