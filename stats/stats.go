// Package stats provides a lock-free atomic statistics collector for DNS server
// metrics.
package stats

import (
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"zjdns/cache"
	"zjdns/config"
	"zjdns/internal/log"
)

const persistKey = config.StatsPersistKey

// Snapshot contains a point-in-time copy of all DNS request counters.
type Snapshot struct {
	TotalRequests       uint64 `json:"total_requests"`
	CacheHits           uint64 `json:"cache_hits"`
	CacheMisses         uint64 `json:"cache_misses"`
	PrefetchRequests    uint64 `json:"prefetch_requests"`
	ErrorResponses      uint64 `json:"error_responses"`
	StaleResponses      uint64 `json:"stale_responses"`
	FallbackRequests    uint64 `json:"fallback_requests"`
	TotalResponseTimeMs uint64 `json:"total_response_time_ms"`
	LastResponseTimeMs  uint64 `json:"last_response_time_ms"`
	UDPRequests         uint64 `json:"udp_requests"`
	TCPRequests         uint64 `json:"tcp_requests"`
	DOTRequests         uint64 `json:"dot_requests"`
	DOQRequests         uint64 `json:"doq_requests"`
	DOHRequests         uint64 `json:"doh_requests"`
	DOH3Requests        uint64 `json:"doh3_requests"`
	RewriteRequests     uint64 `json:"rewrite_requests"`
	HijackDetections    uint64 `json:"hijack_detections"`
	DNSSECSecure        uint64 `json:"dnssec_secure"`
	DNSSECBogus         uint64 `json:"dnssec_bogus"`
	DNSSECInsecure      uint64 `json:"dnssec_insecure"`
	RCODENoError        uint64 `json:"rcode_noerror"`
	RCODEFormErr        uint64 `json:"rcode_formerr"`
	RCODEServFail       uint64 `json:"rcode_servfail"`
	RCODENXDomain       uint64 `json:"rcode_nxdomain"`
	RCODENotImp         uint64 `json:"rcode_notimp"`
	RCODERefused        uint64 `json:"rcode_refused"`
	RCODEOther          uint64 `json:"rcode_other"`
	UpdatedAt           int64  `json:"updated_at"`
}

type logTotals struct {
	TotalRequests         uint64  `json:"total_requests"`
	TotalResponseTimeMs   uint64  `json:"total_response_time_ms"`
	LastResponseTimeMs    uint64  `json:"last_response_time_ms"`
	AverageResponseTimeMs float64 `json:"average_response_time_ms,omitempty"`
	CacheHits             uint64  `json:"cache_hits"`
	CacheMisses           uint64  `json:"cache_misses"`
	StaleResponses        uint64  `json:"stale_responses,omitempty"`
	ErrorResponses        uint64  `json:"error_responses,omitempty"`
}

type logProtocolCounts struct {
	UDPRequests  uint64 `json:"udp_requests,omitempty"`
	TCPRequests  uint64 `json:"tcp_requests,omitempty"`
	DOTRequests  uint64 `json:"dot_requests,omitempty"`
	DOQRequests  uint64 `json:"doq_requests,omitempty"`
	DOHRequests  uint64 `json:"doh_requests,omitempty"`
	DOH3Requests uint64 `json:"doh3_requests,omitempty"`
}

type logEvents struct {
	RewriteRequests  uint64 `json:"rewrite_requests,omitempty"`
	HijackDetections uint64 `json:"hijack_detections,omitempty"`
	PrefetchRequests uint64 `json:"prefetch_requests,omitempty"`
	FallbackRequests uint64 `json:"fallback_requests,omitempty"`
}

type logDNSSEC struct {
	Secure   uint64 `json:"secure,omitempty"`
	Bogus    uint64 `json:"bogus,omitempty"`
	Insecure uint64 `json:"insecure,omitempty"`
}

type logErrorCodes struct {
	NoError  uint64 `json:"noerror,omitempty"`
	FormErr  uint64 `json:"formerr,omitempty"`
	ServFail uint64 `json:"servfail,omitempty"`
	NXDomain uint64 `json:"nxdomain,omitempty"`
	NotImp   uint64 `json:"notimp,omitempty"`
	Refused  uint64 `json:"refused,omitempty"`
	Other    uint64 `json:"other,omitempty"`
}

type logRates struct {
	CacheRate        float64 `json:"cache_rate,omitempty"`
	PrefetchRate     float64 `json:"prefetch_rate,omitempty"`
	FailureRate      float64 `json:"failure_rate,omitempty"`
	StaleRate        float64 `json:"stale_rate,omitempty"`
	FallbackRate     float64 `json:"fallback_rate,omitempty"`
	RewriteRate      float64 `json:"rewrite_rate,omitempty"`
	HijackRate       float64 `json:"hijack_rate,omitempty"`
	DNSSECSecureRate float64 `json:"dnssec_secure_rate,omitempty"`
	DNSSECBogusRate  float64 `json:"dnssec_bogus_rate,omitempty"`
}

type logEntry struct {
	Totals     logTotals         `json:"totals"`
	Protocols  logProtocolCounts `json:"protocols,omitempty"`
	Events     logEvents         `json:"events,omitempty"`
	DNSSEC     logDNSSEC         `json:"dnssec,omitempty"`
	ErrorCodes logErrorCodes     `json:"error_codes,omitempty"`
	Rates      logRates          `json:"rates,omitempty"`
}

// Collector manages DNS server statistics using lock-free atomic counters.
type Collector struct {
	enabled bool

	totalRequests       atomic.Uint64
	cacheHits           atomic.Uint64
	cacheMisses         atomic.Uint64
	prefetchRequests    atomic.Uint64
	errorResponses      atomic.Uint64
	staleResponses      atomic.Uint64
	fallbackRequests    atomic.Uint64
	totalResponseTimeMs atomic.Uint64
	lastResponseTimeMs  atomic.Uint64
	udpRequests         atomic.Uint64
	tcpRequests         atomic.Uint64
	dotRequests         atomic.Uint64
	doqRequests         atomic.Uint64
	dohRequests         atomic.Uint64
	doh3Requests        atomic.Uint64
	rewriteRequests     atomic.Uint64
	hijackDetections    atomic.Uint64
	dnssecSecure        atomic.Uint64
	dnssecBogus         atomic.Uint64
	dnssecInsecure      atomic.Uint64
	rcodeNoError        atomic.Uint64
	rcodeFormErr        atomic.Uint64
	rcodeServFail       atomic.Uint64
	rcodeNXDomain       atomic.Uint64
	rcodeNotImp         atomic.Uint64
	rcodeRefused        atomic.Uint64
	rcodeOther          atomic.Uint64

	persistTTL int
}

// AverageResponseTimeMs computes the mean response time in milliseconds.
func (s Snapshot) AverageResponseTimeMs() float64 {
	if s.TotalRequests == 0 {
		return 0
	}
	return float64(s.TotalResponseTimeMs) / float64(s.TotalRequests)
}

// BuildStatsLogJSON serializes a snapshot into JSON-formatted log entry bytes.
func BuildStatsLogJSON(snapshot *Snapshot) ([]byte, error) {
	if snapshot == nil {
		return nil, fmt.Errorf("nil snapshot")
	}
	entry := logEntry{
		Totals: logTotals{
			TotalRequests:       snapshot.TotalRequests,
			TotalResponseTimeMs: snapshot.TotalResponseTimeMs,
			CacheHits:           snapshot.CacheHits,
			CacheMisses:         snapshot.CacheMisses,
			StaleResponses:      snapshot.StaleResponses,
			ErrorResponses:      snapshot.ErrorResponses,
			LastResponseTimeMs:  snapshot.LastResponseTimeMs,
		},
		Protocols: logProtocolCounts{
			UDPRequests:  snapshot.UDPRequests,
			TCPRequests:  snapshot.TCPRequests,
			DOTRequests:  snapshot.DOTRequests,
			DOQRequests:  snapshot.DOQRequests,
			DOHRequests:  snapshot.DOHRequests,
			DOH3Requests: snapshot.DOH3Requests,
		},
		Events: logEvents{
			HijackDetections: snapshot.HijackDetections,
			PrefetchRequests: snapshot.PrefetchRequests,
			RewriteRequests:  snapshot.RewriteRequests,
			FallbackRequests: snapshot.FallbackRequests,
		},
		DNSSEC: logDNSSEC{
			Secure:   snapshot.DNSSECSecure,
			Bogus:    snapshot.DNSSECBogus,
			Insecure: snapshot.DNSSECInsecure,
		},
		ErrorCodes: logErrorCodes{
			NoError:  snapshot.RCODENoError,
			FormErr:  snapshot.RCODEFormErr,
			ServFail: snapshot.RCODEServFail,
			NXDomain: snapshot.RCODENXDomain,
			NotImp:   snapshot.RCODENotImp,
			Refused:  snapshot.RCODERefused,
			Other:    snapshot.RCODEOther,
		},
	}
	if snapshot.TotalRequests > 0 {
		entry.Totals.AverageResponseTimeMs = snapshot.AverageResponseTimeMs()
		entry.Rates = logRates{
			CacheRate:        float64(snapshot.CacheHits) / float64(snapshot.TotalRequests),
			StaleRate:        float64(snapshot.StaleResponses) / float64(snapshot.TotalRequests),
			FailureRate:      float64(snapshot.ErrorResponses) / float64(snapshot.TotalRequests),
			HijackRate:       float64(snapshot.HijackDetections) / float64(snapshot.TotalRequests),
			PrefetchRate:     float64(snapshot.PrefetchRequests) / float64(snapshot.TotalRequests),
			RewriteRate:      float64(snapshot.RewriteRequests) / float64(snapshot.TotalRequests),
			FallbackRate:     float64(snapshot.FallbackRequests) / float64(snapshot.TotalRequests),
			DNSSECSecureRate: float64(snapshot.DNSSECSecure) / float64(snapshot.TotalRequests),
			DNSSECBogusRate:  float64(snapshot.DNSSECBogus) / float64(snapshot.TotalRequests),
		}
	}
	return json.Marshal(entry)
}

// New creates a Collector from the server config and optionally restores a
// cached stats snapshot.
func New(cfg *config.ServerConfig, store cache.Store) *Collector {
	if cfg == nil {
		return nil
	}
	coll := &Collector{
		enabled:    true,
		persistTTL: cfg.Server.StatsPersistInterval(),
	}
	if store != nil {
		if entry, found, expired := store.Get(persistKey); found && entry != nil {
			if expired {
				log.Debugf("STATS: cached stats snapshot is expired, starting fresh")
			} else if err := coll.LoadFromCacheEntry(entry); err != nil {
				log.Warnf("STATS: failed to restore stats from cache: %v", err)
			} else {
				log.Infof("STATS: restored stats from cache snapshot")
			}
		}
	}
	return coll
}

// RecordRequest atomically increments counters for a single DNS query event.
func (c *Collector) RecordRequest(duration time.Duration, cacheHit bool, hadError bool,
	protocol string, rewrote bool, hijackDetected bool, staleServed bool,
	fallbackUsed bool, prefetchTriggered bool, dnssecStatus string, rcode int) {

	if c == nil || !c.enabled {
		return
	}

	durationMs := uint64(duration.Milliseconds())
	if durationMs == 0 {
		durationMs = 1
	}
	// Fast protocol normalization without allocation: all protocol strings
	// are well-known constants; switch on first byte avoids ToUpper+TrimSpace.
	switch {
	case len(protocol) >= 3 && (protocol[0] == 'u' || protocol[0] == 'U') && (protocol[1] == 'd' || protocol[1] == 'D') && (protocol[2] == 'p' || protocol[2] == 'P'):
		protocol = "UDP"
	case len(protocol) >= 3 && (protocol[0] == 't' || protocol[0] == 'T') && (protocol[1] == 'c' || protocol[1] == 'C') && (protocol[2] == 'p' || protocol[2] == 'P'):
		protocol = "TCP"
	case len(protocol) >= 3 && (protocol[0] == 'd' || protocol[0] == 'D') && (protocol[1] == 'o' || protocol[1] == 'O') && (protocol[2] == 't' || protocol[2] == 'T'):
		protocol = "DOT"
	case len(protocol) >= 3 && (protocol[0] == 'd' || protocol[0] == 'D') && (protocol[1] == 'o' || protocol[1] == 'O') && (protocol[2] == 'q' || protocol[2] == 'Q'):
		protocol = "DOQ"
	case len(protocol) >= 3 && (protocol[0] == 'd' || protocol[0] == 'D') && (protocol[1] == 'o' || protocol[1] == 'O') && (protocol[2] == 'h' || protocol[2] == 'H'):
		if len(protocol) >= 4 && (protocol[3] == '3') {
			protocol = "DOH3"
		} else {
			protocol = "DOH"
		}
	default:
		protocol = "UDP"
	}

	c.totalRequests.Add(1)
	if cacheHit {
		c.cacheHits.Add(1)
	} else {
		c.cacheMisses.Add(1)
	}
	if hadError {
		c.errorResponses.Add(1)
	}
	c.totalResponseTimeMs.Add(durationMs)
	c.lastResponseTimeMs.Store(durationMs)

	switch protocol {
	case "UDP":
		c.udpRequests.Add(1)
	case "TCP":
		c.tcpRequests.Add(1)
	case "DOT":
		c.dotRequests.Add(1)
	case "DOQ":
		c.doqRequests.Add(1)
	case "DOH":
		c.dohRequests.Add(1)
	case "DOH3":
		c.doh3Requests.Add(1)
	default:
		c.udpRequests.Add(1)
	}

	if rewrote {
		c.rewriteRequests.Add(1)
	}
	if hijackDetected {
		c.hijackDetections.Add(1)
	}
	if staleServed {
		c.staleResponses.Add(1)
	}
	if fallbackUsed {
		c.fallbackRequests.Add(1)
	}
	if prefetchTriggered {
		c.prefetchRequests.Add(1)
	}

	switch dnssecStatus {
	case config.DNSSECStatusSecure:
		c.dnssecSecure.Add(1)
	case config.DNSSECStatusBogus:
		c.dnssecBogus.Add(1)
	case config.DNSSECStatusInsecure:
		c.dnssecInsecure.Add(1)
	}

	switch rcode {
	case dns.RcodeSuccess:
		c.rcodeNoError.Add(1)
	case dns.RcodeFormatError:
		c.rcodeFormErr.Add(1)
	case dns.RcodeServerFailure:
		c.rcodeServFail.Add(1)
	case dns.RcodeNameError:
		c.rcodeNXDomain.Add(1)
	case dns.RcodeNotImplemented:
		c.rcodeNotImp.Add(1)
	case dns.RcodeRefused:
		c.rcodeRefused.Add(1)
	default:
		c.rcodeOther.Add(1)
	}
}

// Snapshot returns a point-in-time copy of all accumulated counters.
func (c *Collector) Snapshot() Snapshot {
	if c == nil || !c.enabled {
		return Snapshot{}
	}
	return Snapshot{
		TotalRequests:       c.totalRequests.Load(),
		CacheHits:           c.cacheHits.Load(),
		CacheMisses:         c.cacheMisses.Load(),
		PrefetchRequests:    c.prefetchRequests.Load(),
		ErrorResponses:      c.errorResponses.Load(),
		StaleResponses:      c.staleResponses.Load(),
		FallbackRequests:    c.fallbackRequests.Load(),
		TotalResponseTimeMs: c.totalResponseTimeMs.Load(),
		LastResponseTimeMs:  c.lastResponseTimeMs.Load(),
		UDPRequests:         c.udpRequests.Load(),
		TCPRequests:         c.tcpRequests.Load(),
		DOTRequests:         c.dotRequests.Load(),
		DOQRequests:         c.doqRequests.Load(),
		DOHRequests:         c.dohRequests.Load(),
		DOH3Requests:        c.doh3Requests.Load(),
		RewriteRequests:     c.rewriteRequests.Load(),
		HijackDetections:    c.hijackDetections.Load(),
		DNSSECSecure:        c.dnssecSecure.Load(),
		DNSSECBogus:         c.dnssecBogus.Load(),
		DNSSECInsecure:      c.dnssecInsecure.Load(),
		RCODENoError:        c.rcodeNoError.Load(),
		RCODEFormErr:        c.rcodeFormErr.Load(),
		RCODEServFail:       c.rcodeServFail.Load(),
		RCODENXDomain:       c.rcodeNXDomain.Load(),
		RCODENotImp:         c.rcodeNotImp.Load(),
		RCODERefused:        c.rcodeRefused.Load(),
		RCODEOther:          c.rcodeOther.Load(),
		UpdatedAt:           time.Now().Unix(),
	}
}

// Reset zeroes all counters in the collector.
func (c *Collector) Reset() {
	if c == nil || !c.enabled {
		return
	}
	c.totalRequests.Store(0)
	c.cacheHits.Store(0)
	c.cacheMisses.Store(0)
	c.prefetchRequests.Store(0)
	c.errorResponses.Store(0)
	c.staleResponses.Store(0)
	c.fallbackRequests.Store(0)
	c.totalResponseTimeMs.Store(0)
	c.lastResponseTimeMs.Store(0)
	c.udpRequests.Store(0)
	c.tcpRequests.Store(0)
	c.dotRequests.Store(0)
	c.doqRequests.Store(0)
	c.dohRequests.Store(0)
	c.doh3Requests.Store(0)
	c.rewriteRequests.Store(0)
	c.hijackDetections.Store(0)
	c.dnssecSecure.Store(0)
	c.dnssecBogus.Store(0)
	c.dnssecInsecure.Store(0)
	c.rcodeNoError.Store(0)
	c.rcodeFormErr.Store(0)
	c.rcodeServFail.Store(0)
	c.rcodeNXDomain.Store(0)
	c.rcodeNotImp.Store(0)
	c.rcodeRefused.Store(0)
	c.rcodeOther.Store(0)
}

// FetchStats returns a Snapshot pointer suitable for external consumption.
func (c *Collector) FetchStats() (*Snapshot, error) {
	if c == nil || !c.enabled {
		return nil, fmt.Errorf("stats disabled")
	}
	s := c.Snapshot()
	return &s, nil
}

// ToCacheEntry serializes the current snapshot into a cache.CacheEntry for
// persistence.
func (c *Collector) ToCacheEntry() (*cache.CacheEntry, error) {
	if c == nil || !c.enabled {
		return nil, fmt.Errorf("stats disabled")
	}
	snap := c.Snapshot()
	data, err := json.Marshal(snap)
	if err != nil {
		return nil, fmt.Errorf("marshal stats snapshot: %w", err)
	}
	now := time.Now().Unix()
	ttl := c.persistTTL
	if ttl <= 0 {
		ttl = config.DefaultStatsPersistInterval
	}
	return &cache.CacheEntry{
		Timestamp:   now,
		AccessTime:  now,
		TTL:         ttl,
		OriginalTTL: ttl,
		Payload:     data,
	}, nil
}

// LoadFromCacheEntry restores collector state from a previously persisted
// cache entry.
func (c *Collector) LoadFromCacheEntry(entry *cache.CacheEntry) error {
	if c == nil {
		return fmt.Errorf("stats Collector nil")
	}
	if entry == nil || len(entry.Payload) == 0 {
		return fmt.Errorf("empty cache entry")
	}
	var snap Snapshot
	if err := json.Unmarshal(entry.Payload, &snap); err != nil {
		return fmt.Errorf("unmarshal stats snapshot: %w", err)
	}
	c.totalRequests.Store(snap.TotalRequests)
	c.cacheHits.Store(snap.CacheHits)
	c.cacheMisses.Store(snap.CacheMisses)
	c.prefetchRequests.Store(snap.PrefetchRequests)
	c.errorResponses.Store(snap.ErrorResponses)
	c.staleResponses.Store(snap.StaleResponses)
	c.fallbackRequests.Store(snap.FallbackRequests)
	c.totalResponseTimeMs.Store(snap.TotalResponseTimeMs)
	c.lastResponseTimeMs.Store(snap.LastResponseTimeMs)
	c.udpRequests.Store(snap.UDPRequests)
	c.tcpRequests.Store(snap.TCPRequests)
	c.dotRequests.Store(snap.DOTRequests)
	c.doqRequests.Store(snap.DOQRequests)
	c.dohRequests.Store(snap.DOHRequests)
	c.doh3Requests.Store(snap.DOH3Requests)
	c.rewriteRequests.Store(snap.RewriteRequests)
	c.hijackDetections.Store(snap.HijackDetections)
	c.dnssecSecure.Store(snap.DNSSECSecure)
	c.dnssecBogus.Store(snap.DNSSECBogus)
	c.dnssecInsecure.Store(snap.DNSSECInsecure)
	c.rcodeNoError.Store(snap.RCODENoError)
	c.rcodeFormErr.Store(snap.RCODEFormErr)
	c.rcodeServFail.Store(snap.RCODEServFail)
	c.rcodeNXDomain.Store(snap.RCODENXDomain)
	c.rcodeNotImp.Store(snap.RCODENotImp)
	c.rcodeRefused.Store(snap.RCODERefused)
	c.rcodeOther.Store(snap.RCODEOther)
	return nil
}

// Persist writes the current stats snapshot to the given cache store.
func (c *Collector) Persist(store cache.Store) {
	if c == nil || !c.enabled || store == nil {
		return
	}
	entry, err := c.ToCacheEntry()
	if err != nil {
		log.Debugf("STATS: failed to serialize stats for cache persistence: %v", err)
		return
	}
	store.SetEntry(persistKey, entry)
}
