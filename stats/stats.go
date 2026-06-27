// Package stats provides a lock-free atomic statistics collector for DNS server
// metrics.
package stats

import (
	"encoding/json"
	"fmt"
	"strings"
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
	DoTRequests         uint64 `json:"dot_requests"`
	DoQRequests         uint64 `json:"doq_requests"`
	DoHRequests         uint64 `json:"doh_requests"`
	DoH3Requests        uint64 `json:"doh3_requests"`
	RewriteRequests     uint64 `json:"rewrite_requests"`
	HijackDetections    uint64 `json:"hijack_detections"`
	DNSSECSecure        uint64 `json:"dnssec_secure"`
	DNSSECBogus         uint64 `json:"dnssec_bogus"`
	DNSSECInsecure      uint64 `json:"dnssec_insecure"`
	RcodeNoError        uint64 `json:"rcode_noerror"`
	RcodeFormErr        uint64 `json:"rcode_formerr"`
	RcodeServFail       uint64 `json:"rcode_servfail"`
	RcodeNXDomain       uint64 `json:"rcode_nxdomain"`
	RcodeNotImp         uint64 `json:"rcode_notimp"`
	RcodeRefused        uint64 `json:"rcode_refused"`
	RcodeOther          uint64 `json:"rcode_other"`
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
	DoTRequests  uint64 `json:"dot_requests,omitempty"`
	DoQRequests  uint64 `json:"doq_requests,omitempty"`
	DoHRequests  uint64 `json:"doh_requests,omitempty"`
	DoH3Requests uint64 `json:"doh3_requests,omitempty"`
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

	resetInterval time.Duration
	persistTTL    int
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
			DoTRequests:  snapshot.DoTRequests,
			DoQRequests:  snapshot.DoQRequests,
			DoHRequests:  snapshot.DoHRequests,
			DoH3Requests: snapshot.DoH3Requests,
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
			NoError:  snapshot.RcodeNoError,
			FormErr:  snapshot.RcodeFormErr,
			ServFail: snapshot.RcodeServFail,
			NXDomain: snapshot.RcodeNXDomain,
			NotImp:   snapshot.RcodeNotImp,
			Refused:  snapshot.RcodeRefused,
			Other:    snapshot.RcodeOther,
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
func New(cfg *config.ServerConfig, c cache.Store) *Collector {
	if cfg == nil {
		return nil
	}
	sc := &Collector{
		enabled:    true,
		persistTTL: cfg.Server.StatsPersistInterval(),
	}
	if ri := cfg.Server.StatsResetInterval(); ri > 0 {
		sc.resetInterval = time.Duration(ri) * time.Second
	}
	if c != nil {
		if entry, found, expired := c.Get(persistKey); found && entry != nil {
			if expired {
				log.Debugf("STATS: cached stats snapshot is expired, starting fresh")
			} else if err := sc.LoadFromCacheEntry(entry); err != nil {
				log.Warnf("STATS: failed to restore stats from cache: %v", err)
			} else {
				log.Infof("STATS: restored stats from cache snapshot")
			}
		}
	}
	return sc
}

// RecordRequest atomically increments counters for a single DNS query event.
func (sc *Collector) RecordRequest(duration time.Duration, cacheHit bool, hadError bool,
	protocol string, rewrote bool, hijackDetected bool, staleServed bool,
	fallbackUsed bool, prefetchTriggered bool, dnssecStatus string, rcode int) {

	if sc == nil || !sc.enabled {
		return
	}

	durationMs := uint64(duration.Milliseconds())
	if durationMs == 0 {
		durationMs = 1
	}
	protocol = strings.ToUpper(strings.TrimSpace(protocol))
	if protocol == "" {
		protocol = "UDP"
	}

	sc.totalRequests.Add(1)
	if cacheHit {
		sc.cacheHits.Add(1)
	} else {
		sc.cacheMisses.Add(1)
	}
	if hadError {
		sc.errorResponses.Add(1)
	}
	sc.totalResponseTimeMs.Add(durationMs)
	sc.lastResponseTimeMs.Store(durationMs)

	switch protocol {
	case "UDP":
		sc.udpRequests.Add(1)
	case "TCP":
		sc.tcpRequests.Add(1)
	case "DOT":
		sc.dotRequests.Add(1)
	case "DOQ":
		sc.doqRequests.Add(1)
	case "DOH":
		sc.dohRequests.Add(1)
	case "DOH3":
		sc.doh3Requests.Add(1)
	default:
		sc.udpRequests.Add(1)
	}

	if rewrote {
		sc.rewriteRequests.Add(1)
	}
	if hijackDetected {
		sc.hijackDetections.Add(1)
	}
	if staleServed {
		sc.staleResponses.Add(1)
	}
	if fallbackUsed {
		sc.fallbackRequests.Add(1)
	}
	if prefetchTriggered {
		sc.prefetchRequests.Add(1)
	}

	switch dnssecStatus {
	case config.DNSSECStatusSecure:
		sc.dnssecSecure.Add(1)
	case config.DNSSECStatusBogus:
		sc.dnssecBogus.Add(1)
	case config.DNSSECStatusInsecure:
		sc.dnssecInsecure.Add(1)
	}

	switch rcode {
	case dns.RcodeSuccess:
		sc.rcodeNoError.Add(1)
	case dns.RcodeFormatError:
		sc.rcodeFormErr.Add(1)
	case dns.RcodeServerFailure:
		sc.rcodeServFail.Add(1)
	case dns.RcodeNameError:
		sc.rcodeNXDomain.Add(1)
	case dns.RcodeNotImplemented:
		sc.rcodeNotImp.Add(1)
	case dns.RcodeRefused:
		sc.rcodeRefused.Add(1)
	default:
		sc.rcodeOther.Add(1)
	}
}

// Snapshot returns a point-in-time copy of all accumulated counters.
func (sc *Collector) Snapshot() Snapshot {
	if sc == nil || !sc.enabled {
		return Snapshot{}
	}
	return Snapshot{
		TotalRequests:       sc.totalRequests.Load(),
		CacheHits:           sc.cacheHits.Load(),
		CacheMisses:         sc.cacheMisses.Load(),
		PrefetchRequests:    sc.prefetchRequests.Load(),
		ErrorResponses:      sc.errorResponses.Load(),
		StaleResponses:      sc.staleResponses.Load(),
		FallbackRequests:    sc.fallbackRequests.Load(),
		TotalResponseTimeMs: sc.totalResponseTimeMs.Load(),
		LastResponseTimeMs:  sc.lastResponseTimeMs.Load(),
		UDPRequests:         sc.udpRequests.Load(),
		TCPRequests:         sc.tcpRequests.Load(),
		DoTRequests:         sc.dotRequests.Load(),
		DoQRequests:         sc.doqRequests.Load(),
		DoHRequests:         sc.dohRequests.Load(),
		DoH3Requests:        sc.doh3Requests.Load(),
		RewriteRequests:     sc.rewriteRequests.Load(),
		HijackDetections:    sc.hijackDetections.Load(),
		DNSSECSecure:        sc.dnssecSecure.Load(),
		DNSSECBogus:         sc.dnssecBogus.Load(),
		DNSSECInsecure:      sc.dnssecInsecure.Load(),
		RcodeNoError:        sc.rcodeNoError.Load(),
		RcodeFormErr:        sc.rcodeFormErr.Load(),
		RcodeServFail:       sc.rcodeServFail.Load(),
		RcodeNXDomain:       sc.rcodeNXDomain.Load(),
		RcodeNotImp:         sc.rcodeNotImp.Load(),
		RcodeRefused:        sc.rcodeRefused.Load(),
		RcodeOther:          sc.rcodeOther.Load(),
		UpdatedAt:           time.Now().Unix(),
	}
}

// Reset zeroes all counters in the collector.
func (sc *Collector) Reset() {
	if sc == nil || !sc.enabled {
		return
	}
	sc.totalRequests.Store(0)
	sc.cacheHits.Store(0)
	sc.cacheMisses.Store(0)
	sc.prefetchRequests.Store(0)
	sc.errorResponses.Store(0)
	sc.staleResponses.Store(0)
	sc.fallbackRequests.Store(0)
	sc.totalResponseTimeMs.Store(0)
	sc.lastResponseTimeMs.Store(0)
	sc.udpRequests.Store(0)
	sc.tcpRequests.Store(0)
	sc.dotRequests.Store(0)
	sc.doqRequests.Store(0)
	sc.dohRequests.Store(0)
	sc.doh3Requests.Store(0)
	sc.rewriteRequests.Store(0)
	sc.hijackDetections.Store(0)
	sc.dnssecSecure.Store(0)
	sc.dnssecBogus.Store(0)
	sc.dnssecInsecure.Store(0)
	sc.rcodeNoError.Store(0)
	sc.rcodeFormErr.Store(0)
	sc.rcodeServFail.Store(0)
	sc.rcodeNXDomain.Store(0)
	sc.rcodeNotImp.Store(0)
	sc.rcodeRefused.Store(0)
	sc.rcodeOther.Store(0)
}

// FetchStats returns a Snapshot pointer suitable for external consumption.
func (sc *Collector) FetchStats() (*Snapshot, error) {
	if sc == nil || !sc.enabled {
		return nil, fmt.Errorf("stats disabled")
	}
	s := sc.Snapshot()
	return &s, nil
}

// ToCacheEntry serializes the current snapshot into a cache.CacheEntry for
// persistence.
func (sc *Collector) ToCacheEntry() (*cache.CacheEntry, error) {
	if sc == nil || !sc.enabled {
		return nil, fmt.Errorf("stats disabled")
	}
	snap := sc.Snapshot()
	data, err := json.Marshal(snap)
	if err != nil {
		return nil, fmt.Errorf("marshal stats snapshot: %w", err)
	}
	now := time.Now().Unix()
	ttl := sc.persistTTL
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
func (sc *Collector) LoadFromCacheEntry(entry *cache.CacheEntry) error {
	if sc == nil {
		return fmt.Errorf("stats Collector nil")
	}
	if entry == nil || len(entry.Payload) == 0 {
		return fmt.Errorf("empty cache entry")
	}
	var snap Snapshot
	if err := json.Unmarshal(entry.Payload, &snap); err != nil {
		return fmt.Errorf("unmarshal stats snapshot: %w", err)
	}
	sc.totalRequests.Store(snap.TotalRequests)
	sc.cacheHits.Store(snap.CacheHits)
	sc.cacheMisses.Store(snap.CacheMisses)
	sc.prefetchRequests.Store(snap.PrefetchRequests)
	sc.errorResponses.Store(snap.ErrorResponses)
	sc.staleResponses.Store(snap.StaleResponses)
	sc.fallbackRequests.Store(snap.FallbackRequests)
	sc.totalResponseTimeMs.Store(snap.TotalResponseTimeMs)
	sc.lastResponseTimeMs.Store(snap.LastResponseTimeMs)
	sc.udpRequests.Store(snap.UDPRequests)
	sc.tcpRequests.Store(snap.TCPRequests)
	sc.dotRequests.Store(snap.DoTRequests)
	sc.doqRequests.Store(snap.DoQRequests)
	sc.dohRequests.Store(snap.DoHRequests)
	sc.doh3Requests.Store(snap.DoH3Requests)
	sc.rewriteRequests.Store(snap.RewriteRequests)
	sc.hijackDetections.Store(snap.HijackDetections)
	sc.dnssecSecure.Store(snap.DNSSECSecure)
	sc.dnssecBogus.Store(snap.DNSSECBogus)
	sc.dnssecInsecure.Store(snap.DNSSECInsecure)
	sc.rcodeNoError.Store(snap.RcodeNoError)
	sc.rcodeFormErr.Store(snap.RcodeFormErr)
	sc.rcodeServFail.Store(snap.RcodeServFail)
	sc.rcodeNXDomain.Store(snap.RcodeNXDomain)
	sc.rcodeNotImp.Store(snap.RcodeNotImp)
	sc.rcodeRefused.Store(snap.RcodeRefused)
	sc.rcodeOther.Store(snap.RcodeOther)
	return nil
}

// Persist writes the current stats snapshot to the given cache store.
func (sc *Collector) Persist(c cache.Store) {
	if sc == nil || !sc.enabled || c == nil {
		return
	}
	entry, err := sc.ToCacheEntry()
	if err != nil {
		log.Debugf("STATS: failed to serialize stats for cache persistence: %v", err)
		return
	}
	c.SetEntry(persistKey, entry)
}
