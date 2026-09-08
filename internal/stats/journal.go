// Package stats provides the in-memory query statistics: pooled request
// records, atomic counters for aggregated query metrics, and a per-RCODE
// top-N domain journal for debugging.
//
// Record is a nanosecond-scale pure-memory operation (no disk, no locks on
// the counter path); Snapshot reads are equally lock-free apart from the
// per-RCODE journal. Data is intentionally not persisted — counters reset on
// restart.
package stats

import (
	"sync/atomic"
	"zjdns/internal/topk"
)

// StatsResult is a point-in-time snapshot of all counters and the per-RCODE
// top-N journal.
type StatsResult struct {
	Entries int64

	Total, Hits, Misses, Stales, Zones, Errors, Blocked, Badcookie                        int64
	Any, ACL                                                                              int64
	UDP, TCP, TLS, QUIC, HTTPS, HTTP3, DTLS, DNSCrypt, DNSCryptTCP, TLCP, HTTPTLCP, DTLCP int64
	Noerr, Formerr, Servfail, NXDomain, Notimp, Refused, Other                            int64
	Secure, Insecure, Bogus, Poisoned                                                     int64
	TotalMS                                                                               int64

	// TopByRcode lists the highest-count domain names per RCODE, ordered by
	// count descending. Present only for RCODEs that saw non-hit queries.
	TopByRcode map[int][]topk.Entry[string]
}

// counters holds every aggregation dimension of the query stats.
//
// Dimensions are packed into two combo-indexed counter arrays instead of one
// atomic.Int64 per metric: Record adds once per combo array, so a query pays
// three atomic adds (totalMS + result×protocol + rcode×dnssec×poisoned)
// instead of five — total was the single most contended line under load —
// and concurrent protocols land on different cache lines instead of
// false-sharing adjacent fields.  Snapshot decodes each nonzero combo slot
// back into its per-dimension metrics, so the public StatsResult shape is
// unchanged.  A single packed 64-bit word per query is NOT possible: counts
// accumulated in bit-fields carry across dimension boundaries, corrupting
// the per-dimension totals.
type counters struct {
	resultProto       [resultCount * protoCount]atomic.Int64
	rcodeDnssecPoison [rcodeCount * dnssecCount * poisonCount]atomic.Int64
	totalMS           atomic.Int64
}

// rcodeJournal tracks per-RCODE domain counts. Each RCODE owns a bounded
// topk.Map so the memory footprint stays bounded while the highest-count
// domains survive eviction.
//
// All buckets are pre-created at construction and the map is never written
// again — record() is a lock-free map read plus the sharded topk.Inc (the
// per-query stats path must not serialise on a journal-wide mutex).
type rcodeJournal struct {
	byRcode  map[int]*topk.Map[string]
	capacity int
}

// Journal combines the atomic counters and the per-RCODE journal. It is the
// single entry point for the cache package's stats hot path.
type Journal struct {
	cnt     counters
	journal *rcodeJournal
}

// maxRcodeBucket is the fold-in bucket for all extended RCODEs (24..4095,
// e.g. bits carried by the OPT record).  Bounding the bucket space keeps the
// journal immune to attacker-influenced RCODE diversity.
const maxRcodeBucket = 24

// Result dimension indices.  "any" (RFC 8482) and "acl" (REFUSED by access
// control) are explicit slots so every query is counted in exactly one
// result bucket.
const (
	idxResultHit = iota
	idxResultMiss
	idxResultStale
	idxResultZone
	idxResultAny
	idxResultACL
	idxResultError
	idxResultBlocked
	idxResultBadcookie
	idxResultOther
)

const (
	idxProtoUDP = iota
	idxProtoTCP
	idxProtoTLS
	idxProtoQUIC
	idxProtoHTTPS
	idxProtoHTTP3
	idxProtoDTLS
	idxProtoDNSCrypt
	idxProtoDNSCryptTCP
	idxProtoTLCP
	idxProtoHTTPTLCP
	idxProtoDTLCP
	idxProtoOther
)

// Rcode dimension: standard RCODEs 0-5 keep their own slots (mirroring the
// former rcodeJournal bucketing), everything else shares one.
const (
	idxRcodeOther = 6
	rcodeCount    = idxRcodeOther + 1
)

const (
	idxDNSSECNone = iota
	idxDNSSECSecure
	idxDNSSECInsecure
	idxDNSSECBogus
)

const (
	resultCount = idxResultOther + 1
	protoCount  = idxProtoOther + 1
	dnssecCount = idxDNSSECBogus + 1
	poisonCount = 2
)

// rcodeBucket folds an extended RCODE into the bounded bucket space: the
// standard RCODEs 0-23 keep their own journal, everything else shares one
// bucket so the map can never grow with RCODE diversity.
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
// after construction, so no lock is needed; empty buckets are omitted.
func (j *rcodeJournal) topAll(n int) map[int][]topk.Entry[string] {
	out := make(map[int][]topk.Entry[string], len(j.byRcode))
	for rc, m := range j.byRcode {
		if entries := m.TopN(n); len(entries) > 0 {
			out[rc] = entries
		}
	}
	return out
}

// NewJournal creates a Journal. journalCapacity bounds the per-RCODE domain
// journal (capacity <= 0 applies the topk package default).
func NewJournal(journalCapacity int) *Journal {
	byRcode := make(map[int]*topk.Map[string], maxRcodeBucket+1)
	for rc := range maxRcodeBucket + 1 {
		byRcode[rc] = topk.New[string](journalCapacity)
	}
	return &Journal{
		journal: &rcodeJournal{
			byRcode:  byRcode,
			capacity: journalCapacity,
		},
	}
}

// Record updates the aggregated counters and, for non-hit results, the
// per-RCODE domain journal. Pure memory: three atomic adds + two combo-index
// switches. Must not be called after Close (there is none — the Journal is
// owned by the cache and dies with it).
func (m *Journal) Record(r *RequestRecord) {
	c := &m.cnt
	c.totalMS.Add(r.ResponseTime)
	c.resultProto[resultIndex(r.Result)*protoCount+protocolIndex(r.Protocol)].Add(1)
	c.rcodeDnssecPoison[rcodeIndex(r.Rcode)*(dnssecCount*poisonCount)+
		dnssecIndex(r.DNSSECStatus)*poisonCount+boolIndex(r.Poisoned)].Add(1)

	if r.Result != "hit" {
		m.journal.record(r.Rcode, r.Qname)
	}
}

// resultIndex maps a Result classification to its combo-slot index.
func resultIndex(result string) int {
	switch result {
	case "hit":
		return idxResultHit
	case "miss":
		return idxResultMiss
	case "stale":
		return idxResultStale
	case "zone":
		return idxResultZone
	case "any":
		return idxResultAny
	case "acl":
		return idxResultACL
	case "error":
		return idxResultError
	case "blocked":
		return idxResultBlocked
	case "badcookie":
		return idxResultBadcookie
	default:
		return idxResultOther
	}
}

// protocolIndex maps a transport label to its combo-slot index.
func protocolIndex(protocol string) int {
	switch protocol {
	case "udp":
		return idxProtoUDP
	case "tcp":
		return idxProtoTCP
	case "tls":
		return idxProtoTLS
	case "quic":
		return idxProtoQUIC
	case "https":
		return idxProtoHTTPS
	case "http3":
		return idxProtoHTTP3
	case "dtls":
		return idxProtoDTLS
	case "dnscrypt":
		return idxProtoDNSCrypt
	case "dnscrypt-tcp":
		return idxProtoDNSCryptTCP
	case "tlcp":
		return idxProtoTLCP
	case "http-tlcp":
		return idxProtoHTTPTLCP
	case "dtlcp":
		return idxProtoDTLCP
	default:
		return idxProtoOther
	}
}

// rcodeIndex folds an extended RCODE (24..4095, e.g. bits carried by the OPT
// record) into the bounded slot space, mirroring the journal's bucketing.
func rcodeIndex(rcode int) int {
	if rcode < 0 || rcode > idxRcodeOther-1 {
		return idxRcodeOther
	}
	return rcode
}

// dnssecIndex maps a DNSSEC validation status to its combo-slot index.
func dnssecIndex(status string) int {
	switch status {
	case "secure":
		return idxDNSSECSecure
	case "insecure":
		return idxDNSSECInsecure
	case "bogus":
		return idxDNSSECBogus
	default:
		return idxDNSSECNone
	}
}

// boolIndex maps a bool to its combo-slot half (poisoned).
func boolIndex(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ResetCounters zeroes all atomic counters. Used by the .stats.clear CHAOS
// control endpoint.
func (m *Journal) ResetCounters() {
	c := &m.cnt
	for i := range c.resultProto {
		c.resultProto[i].Store(0)
	}
	for i := range c.rcodeDnssecPoison {
		c.rcodeDnssecPoison[i].Store(0)
	}
	c.totalMS.Store(0)
}

// ResetJournal clears the per-RCODE domain journal. Used by the
// .querylog.clear CHAOS control endpoint.
func (m *Journal) ResetJournal() {
	for _, mm := range m.journal.byRcode {
		mm.Clear()
	}
}

// Snapshot returns a consistent point-in-time view of all counters and the
// per-RCODE top-N journal (top 10 per RCODE). entryCount is the cache's entry
// count, passed through from the caller.  Total is derived as the sum of the
// result buckets — every Record adds to exactly one, so the sum is exact.
func (m *Journal) Snapshot(entryCount int64) *StatsResult {
	s := &StatsResult{
		Entries:    entryCount,
		TopByRcode: m.journal.topAll(10),
	}
	c := &m.cnt
	for i := range c.resultProto {
		v := c.resultProto[i].Load()
		if v == 0 {
			continue
		}
		result, proto := i/protoCount, i%protoCount
		s.Total += v
		switch result {
		case idxResultHit:
			s.Hits += v
		case idxResultMiss:
			s.Misses += v
		case idxResultStale:
			s.Stales += v
		case idxResultZone:
			s.Zones += v
		case idxResultAny:
			s.Any += v
		case idxResultACL:
			s.ACL += v
		case idxResultError:
			s.Errors += v
		case idxResultBlocked:
			s.Blocked += v
		case idxResultBadcookie:
			s.Badcookie += v
		}
		switch proto {
		case idxProtoUDP:
			s.UDP += v
		case idxProtoTCP:
			s.TCP += v
		case idxProtoTLS:
			s.TLS += v
		case idxProtoQUIC:
			s.QUIC += v
		case idxProtoHTTPS:
			s.HTTPS += v
		case idxProtoHTTP3:
			s.HTTP3 += v
		case idxProtoDTLS:
			s.DTLS += v
		case idxProtoDNSCrypt:
			s.DNSCrypt += v
		case idxProtoDNSCryptTCP:
			s.DNSCryptTCP += v
		case idxProtoTLCP:
			s.TLCP += v
		case idxProtoHTTPTLCP:
			s.HTTPTLCP += v
		case idxProtoDTLCP:
			s.DTLCP += v
		}
	}
	for i := range c.rcodeDnssecPoison {
		v := c.rcodeDnssecPoison[i].Load()
		if v == 0 {
			continue
		}
		rc, rem := i/(dnssecCount*poisonCount), i%(dnssecCount*poisonCount)
		dnssec, poison := rem/poisonCount, rem%poisonCount
		switch rc {
		case 0:
			s.Noerr += v
		case 1:
			s.Formerr += v
		case 2:
			s.Servfail += v
		case 3:
			s.NXDomain += v
		case 4:
			s.Notimp += v
		case 5:
			s.Refused += v
		default:
			s.Other += v
		}
		switch dnssec {
		case idxDNSSECSecure:
			s.Secure += v
		case idxDNSSECInsecure:
			s.Insecure += v
		case idxDNSSECBogus:
			s.Bogus += v
		}
		if poison == 1 {
			s.Poisoned += v
		}
	}
	s.TotalMS = c.totalMS.Load()
	return s
}
