// Package stats provides lock-free DNS server metrics collection.
package stats

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"zjdns/cache"
	"zjdns/config"
	"zjdns/internal/log"
)

const persistKey = "__stats__"

// Snapshot contains the raw collected counters.
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

type logRates struct {
	CacheRate    float64 `json:"cache_rate,omitempty"`
	PrefetchRate float64 `json:"prefetch_rate,omitempty"`
	FailureRate  float64 `json:"failure_rate,omitempty"`
	StaleRate    float64 `json:"stale_rate,omitempty"`
	FallbackRate float64 `json:"fallback_rate,omitempty"`
	RewriteRate  float64 `json:"rewrite_rate,omitempty"`
	HijackRate   float64 `json:"hijack_rate,omitempty"`
}

type logEntry struct {
	Totals    logTotals         `json:"totals"`
	Protocols logProtocolCounts `json:"protocols,omitempty"`
	Events    logEvents         `json:"events,omitempty"`
	Rates     logRates          `json:"rates,omitempty"`
}

// Manager manages lock-free metrics collection with periodic reset.
type Manager struct {
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

	resetInterval time.Duration
	persistTTL    int
}

// AverageResponseTimeMs calculates average response time in milliseconds.
func (s Snapshot) AverageResponseTimeMs() float64 {
	if s.TotalRequests == 0 {
		return 0
	}
	return float64(s.TotalResponseTimeMs) / float64(s.TotalRequests)
}

// BuildStatsLogJSON converts a metrics snapshot into JSON for export.
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
	}
	if snapshot.TotalRequests > 0 {
		entry.Totals.AverageResponseTimeMs = snapshot.AverageResponseTimeMs()
		entry.Rates = logRates{
			CacheRate:    float64(snapshot.CacheHits) / float64(snapshot.TotalRequests),
			StaleRate:    float64(snapshot.StaleResponses) / float64(snapshot.TotalRequests),
			FailureRate:  float64(snapshot.ErrorResponses) / float64(snapshot.TotalRequests),
			HijackRate:   float64(snapshot.HijackDetections) / float64(snapshot.TotalRequests),
			PrefetchRate: float64(snapshot.PrefetchRequests) / float64(snapshot.TotalRequests),
			RewriteRate:  float64(snapshot.RewriteRequests) / float64(snapshot.TotalRequests),
			FallbackRate: float64(snapshot.FallbackRequests) / float64(snapshot.TotalRequests),
		}
	}
	return json.Marshal(entry)
}

// New creates a lock-free stats Manager.
func New(cfg *config.ServerConfig, c cache.Manager) *Manager {
	if cfg == nil {
		return nil
	}
	mgr := &Manager{
		enabled:    true,
		persistTTL: cfg.Server.StatsPersistTTL(),
	}
	if ri := cfg.Server.StatsResetInterval(); ri > 0 {
		mgr.resetInterval = time.Duration(ri) * time.Second
	}
	if c != nil {
		if entry, found, expired := c.Get(persistKey); found && entry != nil {
			if expired {
				log.Debugf("STATS: cached stats snapshot is expired, starting fresh")
			} else if err := mgr.LoadFromCacheEntry(entry); err != nil {
				log.Warnf("STATS: failed to restore stats from cache: %v", err)
			} else {
				log.Infof("STATS: restored stats from cache snapshot")
			}
		}
	}
	return mgr
}

// RecordRequest updates counters (lock-free hot path).
func (sm *Manager) RecordRequest(duration time.Duration, cacheHit bool, hadError bool,
	protocol string, rewrote bool, hijackDetected bool, staleServed bool,
	fallbackUsed bool, prefetchTriggered bool) {

	if sm == nil || !sm.enabled {
		return
	}
	// Note: sub-millisecond response times are rounded up to 1ms.
	// This inflates average response times slightly for ultra-fast responses.
	durationMs := uint64(duration.Milliseconds())
	if durationMs == 0 {
		durationMs = 1
	}
	protocol = strings.ToUpper(strings.TrimSpace(protocol))
	if protocol == "" {
		protocol = "UDP"
	}

	sm.totalRequests.Add(1)
	if cacheHit {
		sm.cacheHits.Add(1)
	} else {
		sm.cacheMisses.Add(1)
	}
	if hadError {
		sm.errorResponses.Add(1)
	}
	sm.totalResponseTimeMs.Add(durationMs)
	sm.lastResponseTimeMs.Store(durationMs)

	switch protocol {
	case "UDP":
		sm.udpRequests.Add(1)
	case "TCP":
		sm.tcpRequests.Add(1)
	case "DOT":
		sm.dotRequests.Add(1)
	case "DOQ":
		sm.doqRequests.Add(1)
	case "DOH":
		sm.dohRequests.Add(1)
	case "DOH3":
		sm.doh3Requests.Add(1)
	default:
		sm.udpRequests.Add(1)
	}

	if rewrote {
		sm.rewriteRequests.Add(1)
	}
	if hijackDetected {
		sm.hijackDetections.Add(1)
	}
	if staleServed {
		sm.staleResponses.Add(1)
	}
	if fallbackUsed {
		sm.fallbackRequests.Add(1)
	}
	if prefetchTriggered {
		sm.prefetchRequests.Add(1)
	}
}

// Snapshot returns a copy of the current counters.
func (sm *Manager) Snapshot() Snapshot {
	if sm == nil || !sm.enabled {
		return Snapshot{}
	}
	return Snapshot{
		TotalRequests:       sm.totalRequests.Load(),
		CacheHits:           sm.cacheHits.Load(),
		CacheMisses:         sm.cacheMisses.Load(),
		PrefetchRequests:    sm.prefetchRequests.Load(),
		ErrorResponses:      sm.errorResponses.Load(),
		StaleResponses:      sm.staleResponses.Load(),
		FallbackRequests:    sm.fallbackRequests.Load(),
		TotalResponseTimeMs: sm.totalResponseTimeMs.Load(),
		LastResponseTimeMs:  sm.lastResponseTimeMs.Load(),
		UDPRequests:         sm.udpRequests.Load(),
		TCPRequests:         sm.tcpRequests.Load(),
		DoTRequests:         sm.dotRequests.Load(),
		DoQRequests:         sm.doqRequests.Load(),
		DoHRequests:         sm.dohRequests.Load(),
		DoH3Requests:        sm.doh3Requests.Load(),
		RewriteRequests:     sm.rewriteRequests.Load(),
		HijackDetections:    sm.hijackDetections.Load(),
		UpdatedAt:           time.Now().Unix(),
	}
}

// Reset clears all counters.
func (sm *Manager) Reset() {
	if sm == nil || !sm.enabled {
		return
	}
	sm.totalRequests.Store(0)
	sm.cacheHits.Store(0)
	sm.cacheMisses.Store(0)
	sm.prefetchRequests.Store(0)
	sm.errorResponses.Store(0)
	sm.staleResponses.Store(0)
	sm.fallbackRequests.Store(0)
	sm.totalResponseTimeMs.Store(0)
	sm.lastResponseTimeMs.Store(0)
	sm.udpRequests.Store(0)
	sm.tcpRequests.Store(0)
	sm.dotRequests.Store(0)
	sm.doqRequests.Store(0)
	sm.dohRequests.Store(0)
	sm.doh3Requests.Store(0)
	sm.rewriteRequests.Store(0)
	sm.hijackDetections.Store(0)
}

// FetchStats returns a snapshot for logging.
func (sm *Manager) FetchStats(ctx context.Context) (*Snapshot, error) {
	if sm == nil || !sm.enabled {
		return nil, fmt.Errorf("stats disabled")
	}
	s := sm.Snapshot()
	return &s, nil
}

// ToCacheEntry serializes the snapshot for cache persistence.
func (sm *Manager) ToCacheEntry() (*cache.CacheEntry, error) {
	if sm == nil || !sm.enabled {
		return nil, fmt.Errorf("stats disabled")
	}
	snap := sm.Snapshot()
	data, err := json.Marshal(snap)
	if err != nil {
		return nil, fmt.Errorf("marshal stats snapshot: %w", err)
	}
	now := time.Now().Unix()
	ttl := sm.persistTTL
	if ttl <= 0 {
		ttl = config.DefaultStatsPersistTTL
	}
	return &cache.CacheEntry{
		Timestamp:   now,
		AccessTime:  now,
		TTL:         ttl,
		OriginalTTL: ttl,
		Payload:     data,
	}, nil
}

// LoadFromCacheEntry restores counters from a persisted snapshot.
func (sm *Manager) LoadFromCacheEntry(entry *cache.CacheEntry) error {
	if sm == nil {
		return fmt.Errorf("stats manager nil")
	}
	if entry == nil || len(entry.Payload) == 0 {
		return fmt.Errorf("empty cache entry")
	}
	var snap Snapshot
	if err := json.Unmarshal(entry.Payload, &snap); err != nil {
		return fmt.Errorf("unmarshal stats snapshot: %w", err)
	}
	sm.totalRequests.Store(snap.TotalRequests)
	sm.cacheHits.Store(snap.CacheHits)
	sm.cacheMisses.Store(snap.CacheMisses)
	sm.prefetchRequests.Store(snap.PrefetchRequests)
	sm.errorResponses.Store(snap.ErrorResponses)
	sm.staleResponses.Store(snap.StaleResponses)
	sm.fallbackRequests.Store(snap.FallbackRequests)
	sm.totalResponseTimeMs.Store(snap.TotalResponseTimeMs)
	sm.lastResponseTimeMs.Store(snap.LastResponseTimeMs)
	sm.udpRequests.Store(snap.UDPRequests)
	sm.tcpRequests.Store(snap.TCPRequests)
	sm.dotRequests.Store(snap.DoTRequests)
	sm.doqRequests.Store(snap.DoQRequests)
	sm.dohRequests.Store(snap.DoHRequests)
	sm.doh3Requests.Store(snap.DoH3Requests)
	sm.rewriteRequests.Store(snap.RewriteRequests)
	sm.hijackDetections.Store(snap.HijackDetections)
	return nil
}

// Persist saves the current snapshot into the cache.
func (sm *Manager) Persist(c cache.Manager) {
	if sm == nil || !sm.enabled || c == nil {
		return
	}
	entry, err := sm.ToCacheEntry()
	if err != nil {
		log.Debugf("STATS: failed to serialize stats for cache persistence: %v", err)
		return
	}
	c.SetEntry(persistKey, entry)
}
