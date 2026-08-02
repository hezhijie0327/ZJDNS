package cache

import (
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

// ReverseLookup returns all cached domain names mapped to the given IP address.
func (c *Cache) ReverseLookup(ip string) []LookupResult {
	if ip == "" || c.db.IsClosed() {
		return nil //nolint:nilerr // key not found
	}
	var results []LookupResult
	if err := c.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = database.EIPReversePrefix(ip)
		opts.PrefetchValues = true
		it := txn.NewIterator(opts)
		defer it.Close()
		var buf []byte
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			if item.IsDeletedOrExpired() {
				continue
			}
			buf, err := item.ValueCopy(buf)
			if err != nil {
				// A transient BadgerDB failure must not look like an empty
				// result (the PTR middleware would then delegate upstream).
				log.Warnf("CACHE: reverse lookup ValueCopy failed for %s: %v", ip, err)
				continue
			}
			ttlVal := database.DecodePtrMapValue(buf)
			k := string(item.Key())
			nameOff := 0
			for nameOff < len(k) && k[nameOff] != 0 {
				nameOff++
			}
			nameOff += 1 + 8 + 1
			if nameOff < len(k) {
				name := k[nameOff:]
				// Exclude non-ptr keys that share the e:ip:{ip}\x00 prefix
				// (e.g. an entry key whose qname starts with "ip:{ip}"):
				// their "name" field is not an FQDN (it would contain the
				// ECS address / binary key columns, which never end in ".").
				if !dnsutil.IsFqdn(name) {
					continue
				}
				ts := database.DecodePtrMapTimestamp(buf)
				if ts == 0 {
					// Legacy 4-byte value: fall back to the entry's expiry.
					ts = int64(item.ExpiresAt()) - int64(ttlVal) //nolint:gosec // G115: unix timestamps — protocol-bounded int64
				}
				results = append(results, LookupResult{Name: name, TTL: ttl.RemainingTTL(ts, int(ttlVal), uint32(config.DefaultStaleTTL))})
			}
		}
		return nil //nolint:nilerr // key not found
	}); err != nil {
		// Surface the failure instead of silently returning an empty result.
		log.Warnf("CACHE: reverse lookup failed for %s: %v", ip, err)
	}
	return results
}

// FlushDB truncates a table: "cache", "zone", or "ruleset".
func (c *Cache) FlushDB(target string) (int64, error) {
	if c.db.IsClosed() {
		return 0, errCacheClosed
	}
	switch target {
	case "cache":
		if err := c.db.DropPrefix(database.EntryKeyPrefix()); err != nil {
			return 0, fmt.Errorf("flushDB cache: %w", err)
		}
		c.latencyCache.Clear()
		if c.frontCache != nil {
			c.frontCache.Clear()
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

// Clear truncates cache entries.
func (c *Cache) Clear() (int64, error) { return c.FlushDB("cache") }

// UpdateLatency stores a latency measurement keyed by IP.
func (c *Cache) UpdateLatency(ip string, latencyMS int) {
	if latencyMS < 0 {
		latencyMS = 0
	}
	if c.db.IsClosed() {
		return
	}
	expiresAt := uint64(log.NowUnix() + config.DefaultLatencyProbeMinInterval*2) //nolint:gosec // G115: protocol-bounded value fits target type

	if err := c.db.Update(func(txn *badger.Txn) error {
		e := badger.NewEntry(database.EIPLatencyKey(ip), database.EncodeLatencyValue(latencyMS))
		e.ExpiresAt = expiresAt
		return txn.SetEntry(e)
	}); err != nil {
		log.Warnf("CACHE: latency write failed for %s: %v", ip, err)
		return // don't populate LRU on failure — the DB is the source of truth
	}
	// Populate the in-memory LRU after a successful write, with the same
	// expiry so the LRU naturally mirrors the BadgerDB TTL.
	c.latencyCache.Set(ip, latencyEntry{
		value:     latencyMS,
		expiresAt: int64(expiresAt), //nolint:gosec // G115: unix timestamp — protocol-bounded int64
	})
}

// DBSize returns the BadgerDB LSM and value log sizes in bytes.
func (c *Cache) DBSize() (lsm, vlog int64) {
	if c.db.IsClosed() {
		return 0, 0
	}
	return c.db.Badger.Size()
}

// DBEstimateSize returns the estimated on-disk size for a key prefix.
func (c *Cache) DBEstimateSize(prefix []byte) (lsm, vlog uint64) {
	if c.db.IsClosed() {
		return 0, 0
	}
	return c.db.Badger.EstimateSize(prefix)
}

// LatencyLastProbe returns the last probe time for an IP.
func (c *Cache) LatencyLastProbe(ip string) (int64, bool) {
	if c.db.IsClosed() {
		return 0, false
	}
	var lastProbe int64
	found := false
	_ = c.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(database.EIPLatencyKey(ip))
		if err != nil {
			return nil //nolint:nilerr // key not found
		}
		// UpdateLatency stores the key with ExpiresAt = probeTime + 2*interval;
		// recover the probe time so callers can compute the elapsed interval.
		lastProbe = int64(item.ExpiresAt()) - int64(config.DefaultLatencyProbeMinInterval)*2 //nolint:gosec // G115: unix timestamps — protocol-bounded int64
		found = true
		return nil //nolint:nilerr // key not found
	})
	if !found {
		return 0, false
	}
	return lastProbe, true
}
