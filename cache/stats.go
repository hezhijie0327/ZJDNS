package cache

import (
	"errors"
	"fmt"
	"net"
	"zjdns/config"
	"zjdns/database"
	"zjdns/internal/log"
	"zjdns/internal/ttl"

	"codeberg.org/miekg/dns"
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
		upsertQueryStats(txn, r.Result, r.Protocol, r.Rcode, r.DNSSECStatus, database.BoolToInt(r.Poisoned), r.ResponseTime)
		if r.Result != "hit" {
			_ = insertQueryLog(txn, c.db, qname, int(r.Qtype), int(r.Qclass), r.Protocol, r.Result,
				r.Rcode, r.ResponseTime, r.Server, database.BoolToInt(r.Poisoned), r.DNSSECStatus)
		}
		return nil
	})
}

// ReverseLookup returns all cached domain names mapped to the given IP address.
func (c *Cache) ReverseLookup(ip string) []LookupResult {
	if ip == "" || c.db.IsClosed() {
		return nil
	}

	staleCutoff := log.NowUnix() - defaultStaleMaxAge
	var results []LookupResult

	_ = c.db.Badger.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = database.PtrMapIPPrefix(ip)
		opts.PrefetchValues = true
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			var ttlVal int32
			var expiresAt int64
			_ = item.Value(func(v []byte) error {
				ttlVal, expiresAt = database.DecodePtrMapValue(v)
				return nil
			})
			if expiresAt < staleCutoff {
				continue
			}
			// Extract name from key: p:{ip}\x00{entry_id:016x}\x00{name}
			k := string(item.Key())
			// Find the second \x00 separator (after entry_id)
			sep1 := 0
			for i, c := range k {
				if c == 0 {
					if sep1 == 0 {
						sep1 = i
					} else {
						name := k[i+1:]
						results = append(results, LookupResult{
							Name: name,
							TTL:  ttl.RemainingTTL(0, int(ttlVal), uint32(config.DefaultStaleTTL)),
						})
						break
					}
				}
			}
		}
		return nil
	})
	return results
}

// upsertQueryStats does a read-modify-write on a query_stats key within a
// transaction. Called from both the async writer path and the sync fallback.
func upsertQueryStats(txn *badger.Txn, result, protocol string, rcode int, dnssecStatus string, poisoned int, responseTime int64) {
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

// insertQueryLog writes a single query_log entry within a transaction.
// Errors are silently discarded — audit logging is best-effort.
func insertQueryLog(txn *badger.Txn, db *database.DB, qname string, qtype, qclass int, protocol, result string,
	rcode int, responseMS int64, server string, poisoned int, dnssecStatus string,
) error {
	seq, err := db.NextQLogID()
	if err != nil {
		return err
	}
	key := database.QueryLogKey(log.NowUnix(), seq)
	val := database.EncodeQueryLogValue(log.NowUnix(), qname, uint16(qtype), uint16(qclass), //nolint:gosec // G115: DNS type/class fits uint16
		protocol, result, rcode, responseMS, server, poisoned, dnssecStatus)
	return txn.Set(key, val)
}

// FlushDB truncates a single table: "stats" (query_stats), "querylog" (query_log),
// "cache" (entries), "latency" (ip_latency), "zone" (zone_entries), or
// "ruleset" (ruleset_entries). Uses db.DropPrefix — NOTE: this stops all
// writes during the operation (admin tool, not hot-path).
func (c *Cache) FlushDB(target string) (int64, error) {
	if c.db.IsClosed() {
		return 0, errCacheClosed
	}
	var prefix []byte
	switch target {
	case "stats":
		prefix = database.QueryStatsPrefix()
	case "querylog":
		prefix = database.QueryLogPrefix()
	case "cache":
		prefix = database.EntryKeyPrefix()
	case "latency":
		prefix = []byte("l:")
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
	if target == "cache" {
		c.db.SetEntryCount(0)
	}
	log.Infof("CACHE: flushDB %s: done", target)
	return 0, nil // DropPrefix doesn't return count
}

// Clear truncates all tables: entries, query_stats, query_log, ip_latency.
func (c *Cache) Clear() (int64, error) {
	for _, target := range []string{"cache", "stats", "querylog", "latency"} {
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

	entries := c.db.EntryCount()

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
// Format: s:{stat_day:08x}\x00{result}\x00{protocol}\x00{rcode:04x}\x00{dnssec}\x00{poisoned}
func parseStatsKey(key string) (result, protocol string, rcode int, dnssec string, poisoned bool) {
	// Skip the "s:" prefix + 8 hex chars + \x00.
	if len(key) < 12 {
		return "", "", 0, "", false
	}
	// Find the separators.
	parts := splitByNul(key[11:]) // skip "s:" + 8 hex + NUL
	// parts[0] = result, parts[1] = protocol, parts[2] = rcode(hex4), parts[3] = dnssec, parts[4] = poisoned
	if len(parts) < 5 {
		return "", "", 0, "", false
	}
	result = parts[0]
	protocol = parts[1]
	rcode = parseHexInt(parts[2])
	dnssec = parts[3]
	poisoned = parts[4] == "1"
	return result, protocol, rcode, dnssec, poisoned
}

// splitByNul splits a string by \x00 bytes.
func splitByNul(s string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == 0 {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

// parseHexInt parses a 4-digit hex string to int.
func parseHexInt(s string) int {
	var n int
	for _, c := range s {
		n *= 16
		switch {
		case c >= '0' && c <= '9':
			n += int(c - '0')
		case c >= 'a' && c <= 'f':
			n += int(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			n += int(c - 'A' + 10)
		}
	}
	return n
}

// UpdateLatency stores a latency measurement keyed by IP only.
func (c *Cache) UpdateLatency(ip string, latencyMS int) {
	if latencyMS < 0 {
		latencyMS = 0
	}
	if c.db.IsClosed() {
		return
	}
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return
	}
	qtype := dns.TypeAAAA
	if parsedIP.To4() != nil {
		qtype = dns.TypeA
	}
	_ = c.db.Badger.Update(func(txn *badger.Txn) error {
		return txn.Set(database.LatencyKey(ip), database.EncodeLatencyValue(qtype, latencyMS, log.NowUnix()))
	})
}

// LatencyLastProbe returns the last probe time for an IP.
func (c *Cache) LatencyLastProbe(ip string) (int64, bool) {
	if c.db.IsClosed() {
		return 0, false
	}
	var ts int64
	_ = c.db.Badger.View(func(txn *badger.Txn) error {
		item, err := txn.Get(database.LatencyKey(ip))
		if err != nil {
			return err
		}
		return item.Value(func(v []byte) error {
			_, _, ts = database.DecodeLatencyValue(v)
			return nil
		})
	})
	if ts == 0 {
		return 0, false
	}
	return ts, true
}
