package cache

import (
	"fmt"
	"zjdns/internal/log"
	"zjdns/internal/pool"

	zdnsutil "zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// FlushDB truncates a table: "cache" clears all cached responses and derived
// state. "zone" and "ruleset" are no-ops — they never used the persist store.
func (c *Cache) FlushDB(target string) (int64, error) {
	switch target {
	case "cache":
		c.mu.Lock()
		c.store = make(map[entryKey]*listEntry)
		c.head.next = c.tail
		c.tail.prev = c.head
		c.totalSize = 0
		c.len = 0
		c.ptrIndex = make(map[string][]*ptrRecord)
		c.mu.Unlock()
		c.latency.Clear()
		log.Infof("CACHE: flushDB %s: done", target)
		return 0, nil
	case "zone", "ruleset":
		log.Infof("CACHE: flushDB %s: done", target)
		return 0, nil
	default:
		return 0, fmt.Errorf("flushDB: unknown target %q", target)
	}
}

// Clear truncates cache entries.
func (c *Cache) Clear() (int64, error) { return c.FlushDB("cache") }

// Save dumps non-expired entries plus the current DNSCrypt state to the
// persist file. Called on Close and on DNSCrypt key rotation.
func (c *Cache) Save() error {
	if c.file == "" {
		return nil
	}
	f := &PersistFile{Version: 1}
	now := log.NowUnix()

	c.mu.Lock()
	for e := c.head.next; e != c.tail; e = e.next {
		if e.expiresAt > 0 && e.expiresAt < now {
			continue
		}
		f.Entries = append(f.Entries, PersistEntry{
			Qname:     e.key.qname,
			ECSAddr:   e.key.ecsAddr,
			ECSPrefix: e.key.ecsPrefix,
			DNSsecOK:  e.key.dnssecOK,
			Qtype:     e.key.qtype,
			Qclass:    e.key.qclass,
			Value:     e.value,
			ExpiresAt: e.expiresAt,
			Validated: e.validated,
		})
	}
	c.mu.Unlock()

	if ds := c.dnscrypt.Load(); ds != nil {
		f.DNSCrypt = &DNSCrypt{Identity: ds.identity, Windows: ds.windows}
	}
	return f.Save(c.file)
}

// Close persists the cache and clears it.
func (c *Cache) Close() error {
	if err := c.Save(); err != nil {
		return err
	}
	_, _ = c.Clear()
	return nil
}

// loadFromDisk populates the cache from the persist file (cold start when the
// file is missing or corrupt — a corrupt file is logged, not fatal).
func (c *Cache) loadFromDisk() {
	if c.file == "" {
		return
	}
	f, err := Load(c.file)
	if err != nil {
		log.Warnf("CACHE: persist load failed (starting cold): %v", err)
		return
	}
	if f == nil {
		return
	}

	now := log.NowUnix()
	for _, pe := range f.Entries {
		if pe.ExpiresAt > 0 && pe.ExpiresAt < now {
			continue
		}
		key := entryKey{
			qname:     pe.Qname,
			ecsAddr:   pe.ECSAddr,
			ecsPrefix: pe.ECSPrefix,
			dnssecOK:  pe.DNSsecOK,
			qtype:     pe.Qtype,
			qclass:    pe.Qclass,
		}
		// Recover the write timestamp: expiresAt = ts + entryTTL + staleMaxAge.
		msg := pool.DefaultMessage.Get()
		msg.Data = pe.Value
		if err := msg.Unpack(); err != nil {
			pool.DefaultMessage.Put(msg)
			log.Debugf("CACHE: skip unparseable persisted entry for %s (type=%d)", pe.Qname, pe.Qtype)
			continue
		}
		entryTTL := minTTL(msg.Answer, msg.Ns, msg.Extra)
		pool.DefaultMessage.Put(msg)
		if entryTTL <= 0 {
			continue
		}
		ts := pe.ExpiresAt - int64(entryTTL) - defaultStaleMaxAge
		c.insert(key, pe.Value, ts, pe.ExpiresAt, pe.Validated)
	}
	c.rebuildPtrIndex()

	if f.DNSCrypt != nil {
		c.dnscrypt.Store(&dnscryptState{identity: f.DNSCrypt.Identity, windows: f.DNSCrypt.Windows})
	}
	log.Infof("CACHE: loaded %d entries from %s", c.Len(), c.file)
}

// rebuildPtrIndex re-derives the PTR index from stored entries after loading
// from disk (the index is derived data, never persisted itself).
func (c *Cache) rebuildPtrIndex() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for e := c.head.next; e != c.tail; e = e.next {
		msg := pool.DefaultMessage.Get()
		msg.Data = e.value
		if err := msg.Unpack(); err != nil {
			pool.DefaultMessage.Put(msg)
			continue
		}
		c.ptrIndexFromWireLocked(e.key, e.ts, e.expiresAt, msg.Answer, msg.Ns, msg.Extra)
		pool.DefaultMessage.Put(msg)
	}
}

// ptrIndexFromWireLocked inserts PTR records for a loaded entry. Must hold
// c.mu. Dedup by (ip, name) within the entry, same as updatePtrIndex.
func (c *Cache) ptrIndexFromWireLocked(owner entryKey, ts, expiresAt int64, sections ...[]dns.RR) {
	seen := make(map[string]bool)
	for _, rrs := range sections {
		for _, rr := range rrs {
			if rr == nil || dns.RRToType(rr) == dns.TypeOPT {
				continue
			}
			ip, ok := zdnsutil.ExtractIPString(rr)
			if !ok {
				continue
			}
			name := dnsutil.Canonical(rr.Header().Name)
			if seen[ip+"\x00"+name] {
				continue
			}
			seen[ip+"\x00"+name] = true
			c.ptrIndex[ip] = append(c.ptrIndex[ip], &ptrRecord{
				name: name, ttl: int32(rr.Header().TTL), //nolint:gosec // G115: protocol-bounded value fits target type
				ts:        ts,
				expiresAt: expiresAt,
				ownerKey:  owner,
			})
		}
	}
}

// SetDNSCrypt records the DNSCrypt server state and persists it immediately
// (key rotation must survive a restart). The DNSCrypt server owns the data.
func (c *Cache) SetDNSCrypt(identity []byte, windows []Window) {
	c.dnscrypt.Store(&dnscryptState{identity: identity, windows: windows})
	if err := c.Save(); err != nil {
		log.Warnf("CACHE: persist dnscrypt state failed: %v", err)
	}
}

// DNSCryptState returns the persisted DNSCrypt state (nil on first run).
func (c *Cache) DNSCryptState() (*DNSCrypt, bool) {
	ds := c.dnscrypt.Load()
	if ds == nil {
		return nil, false
	}
	return &DNSCrypt{Identity: ds.identity, Windows: ds.windows}, true
}
