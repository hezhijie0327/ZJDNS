// The statsjournal provides an in-memory replacement for the SQLite
// query_stats and query_log tables: atomic counters for aggregated query
// metrics and a per-RCODE top-N domain journal for debugging.
//
// Record is a nanosecond-scale pure-memory operation (no SQL, no disk, no
// locks on the counter path); Snapshot reads are equally lock-free apart from
// the per-RCODE journal. Data is intentionally not persisted — counters reset
// on restart.
package cache

import (
	"sync/atomic"
	"zjdns/internal/topk"
)

// Record captures per-query metadata. Every query updates the counters; only
// non-hit results enter the per-RCODE domain journal.
type Record struct {
	Qname        string // normalized FQDN
	Result       string // 'hit','miss','stale','zone','error','blocked','badcookie'
	Protocol     string // 'udp','tcp','tls','quic','https','http3','dtls','dnscrypt','dnscrypt-tcp','tlcp','http-tlcp','dtlcp'
	Rcode        int
	ResponseTime int64  // milliseconds
	DNSSECStatus string // 'secure','insecure','bogus', or ''
	Poisoned     bool
}

// StatsResult is a point-in-time snapshot of all counters and the per-RCODE
// top-N journal.
type StatsResult struct {
	Entries int64

	Total, Hits, Misses, Stales, Zones, Errors, Blocked, Badcookie                        int64
	UDP, TCP, TLS, QUIC, HTTPS, HTTP3, DTLS, DNSCrypt, DNSCryptTCP, TLCP, HTTPTLCP, DTLCP int64
	Noerr, Formerr, Servfail, NXDomain, Notimp, Refused, Other                            int64
	Secure, Insecure, Bogus, Poisoned                                                     int64
	TotalMS                                                                               int64

	// TopByRcode lists the highest-count domain names per RCODE, ordered by
	// count descending. Present only for RCODEs that saw non-hit queries.
	TopByRcode map[int][]topk.Entry[string]
}

// counters mirrors the aggregation dimensions of the former query_stats table.
// All fields are atomic.Int64 so the hot-path Record needs no locks.
type counters struct {
	total, hits, misses, stales, zones, errors, blocked, badcookie                        atomic.Int64
	udp, tcp, tls, quic, https, http3, dtls, dnscrypt, dnscryptTCP, tlcp, httpTLCP, dtlcp atomic.Int64
	noerr, formerr, servfail, nxdomain, notimp, refused, other                            atomic.Int64
	secure, insecure, bogus, poisoned                                                     atomic.Int64
	totalMS                                                                               atomic.Int64
}

// rcodeJournal tracks per-RCODE domain counts, replacing the former
// query_log table. Each RCODE owns a bounded topk.Map so the memory footprint
// stays bounded while the highest-count domains survive eviction.
//
// All buckets are pre-created at construction and the map is never written
// again — record() is a lock-free map read plus the sharded topk.Inc (the
// per-query stats path must not serialise on a journal-wide mutex).
type rcodeJournal struct {
	byRcode  map[int]*topk.Map[string]
	capacity int
}

// Manager combines the atomic counters and the per-RCODE journal. It is the
// single entry point for the cache package's stats hot path.
type Manager struct {
	cnt     counters
	journal *rcodeJournal
}

// maxRcodeBucket is the fold-in bucket for all extended RCODEs (24..4095,
// e.g. bits carried by the OPT record).  Bounding the bucket space keeps the
// journal immune to attacker-influenced RCODE diversity (M2).
const maxRcodeBucket = 24

// rcodeBucket folds an extended RCODE into the bounded bucket space: the
// standard RCODEs 0-23 keep their own journal, everything else shares one
// bucket so the map can never grow with RCODE diversity (M2).
func rcodeBucket(rcode int) int {
	if rcode > maxRcodeBucket {
		return maxRcodeBucket
	}
	return rcode
}

func (j *rcodeJournal) record(rcode int, qname string) {
	j.byRcode[rcodeBucket(rcode)].Inc(qname)
}

// topAll returns the top-n domains per RCODE. The bucket map is immutable
// after construction, so no lock is needed; empty buckets are omitted,
// mirroring the lazily-created layout this journal had before buckets were
// pre-created.
func (j *rcodeJournal) topAll(n int) map[int][]topk.Entry[string] {
	out := make(map[int][]topk.Entry[string], len(j.byRcode))
	for rc, m := range j.byRcode {
		if entries := m.TopN(n); len(entries) > 0 {
			out[rc] = entries
		}
	}
	return out
}

// newStatsJournal creates a Manager. journalCapacity bounds the per-RCODE
// domain journal (capacity <= 0 applies the topk package default).
func newStatsJournal(journalCapacity int) *Manager {
	byRcode := make(map[int]*topk.Map[string], maxRcodeBucket+1)
	for rc := range maxRcodeBucket + 1 {
		byRcode[rc] = topk.New[string](journalCapacity)
	}
	return &Manager{
		journal: &rcodeJournal{
			byRcode:  byRcode,
			capacity: journalCapacity,
		},
	}
}

// Record updates the aggregated counters and, for non-hit results, the
// per-RCODE domain journal. Pure memory: atomic adds + one short critical
// section. Must not be called after Close (there is none — the Manager is
// owned by the cache and dies with it).
func (m *Manager) Record(r *Record) {
	c := &m.cnt
	c.total.Add(1)
	c.totalMS.Add(r.ResponseTime)
	switch r.Result {
	case "hit":
		c.hits.Add(1)
	case "miss":
		c.misses.Add(1)
	case "stale":
		c.stales.Add(1)
	case "zone":
		c.zones.Add(1)
	case "error":
		c.errors.Add(1)
	case "blocked":
		c.blocked.Add(1)
	case "badcookie":
		c.badcookie.Add(1)
	}
	switch r.Protocol {
	case "udp":
		c.udp.Add(1)
	case "tcp":
		c.tcp.Add(1)
	case "tls":
		c.tls.Add(1)
	case "quic":
		c.quic.Add(1)
	case "https":
		c.https.Add(1)
	case "http3":
		c.http3.Add(1)
	case "dtls":
		c.dtls.Add(1)
	case "dnscrypt":
		c.dnscrypt.Add(1)
	case "dnscrypt-tcp":
		c.dnscryptTCP.Add(1)
	case "tlcp":
		c.tlcp.Add(1)
	case "http-tlcp":
		c.httpTLCP.Add(1)
	case "dtlcp":
		c.dtlcp.Add(1)
	}
	switch r.Rcode {
	case 0:
		c.noerr.Add(1)
	case 1:
		c.formerr.Add(1)
	case 2:
		c.servfail.Add(1)
	case 3:
		c.nxdomain.Add(1)
	case 4:
		c.notimp.Add(1)
	case 5:
		c.refused.Add(1)
	default:
		c.other.Add(1)
	}
	switch r.DNSSECStatus {
	case "secure":
		c.secure.Add(1)
	case "insecure":
		c.insecure.Add(1)
	case "bogus":
		c.bogus.Add(1)
	}
	if r.Poisoned {
		c.poisoned.Add(1)
	}

	if r.Result != "hit" {
		m.journal.record(r.Rcode, r.Qname)
	}
}

// ResetCounters zeroes all atomic counters. Used by the .stats.clear CHAOS
// control endpoint.
func (m *Manager) ResetCounters() {
	c := &m.cnt
	c.total.Store(0)
	c.hits.Store(0)
	c.misses.Store(0)
	c.stales.Store(0)
	c.zones.Store(0)
	c.errors.Store(0)
	c.blocked.Store(0)
	c.badcookie.Store(0)
	c.udp.Store(0)
	c.tcp.Store(0)
	c.tls.Store(0)
	c.quic.Store(0)
	c.https.Store(0)
	c.http3.Store(0)
	c.dtls.Store(0)
	c.dnscrypt.Store(0)
	c.dnscryptTCP.Store(0)
	c.tlcp.Store(0)
	c.httpTLCP.Store(0)
	c.dtlcp.Store(0)
	c.noerr.Store(0)
	c.formerr.Store(0)
	c.servfail.Store(0)
	c.nxdomain.Store(0)
	c.notimp.Store(0)
	c.refused.Store(0)
	c.other.Store(0)
	c.secure.Store(0)
	c.insecure.Store(0)
	c.bogus.Store(0)
	c.poisoned.Store(0)
	c.totalMS.Store(0)
}

// ResetJournal clears the per-RCODE domain journal. Used by the
// .querylog.clear CHAOS control endpoint.
func (m *Manager) ResetJournal() {
	for _, mm := range m.journal.byRcode {
		mm.Clear()
	}
}

// Snapshot returns a consistent point-in-time view of all counters and the
// per-RCODE top-N journal (top 10 per RCODE). entryCount is the cache's entry
// count, passed through from the caller.
func (m *Manager) Snapshot(entryCount int64) *StatsResult {
	c := &m.cnt
	return &StatsResult{
		Entries:     entryCount,
		Total:       c.total.Load(),
		Hits:        c.hits.Load(),
		Misses:      c.misses.Load(),
		Stales:      c.stales.Load(),
		Zones:       c.zones.Load(),
		Errors:      c.errors.Load(),
		Blocked:     c.blocked.Load(),
		Badcookie:   c.badcookie.Load(),
		UDP:         c.udp.Load(),
		TCP:         c.tcp.Load(),
		TLS:         c.tls.Load(),
		QUIC:        c.quic.Load(),
		HTTPS:       c.https.Load(),
		HTTP3:       c.http3.Load(),
		DTLS:        c.dtls.Load(),
		DNSCrypt:    c.dnscrypt.Load(),
		DNSCryptTCP: c.dnscryptTCP.Load(),
		TLCP:        c.tlcp.Load(),
		HTTPTLCP:    c.httpTLCP.Load(),
		DTLCP:       c.dtlcp.Load(),
		Noerr:       c.noerr.Load(),
		Formerr:     c.formerr.Load(),
		Servfail:    c.servfail.Load(),
		NXDomain:    c.nxdomain.Load(),
		Notimp:      c.notimp.Load(),
		Refused:     c.refused.Load(),
		Other:       c.other.Load(),
		Secure:      c.secure.Load(),
		Insecure:    c.insecure.Load(),
		Bogus:       c.bogus.Load(),
		Poisoned:    c.poisoned.Load(),
		TotalMS:     c.totalMS.Load(),
		TopByRcode:  m.journal.topAll(10),
	}
}
