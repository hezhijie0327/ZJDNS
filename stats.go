// Package main implements ZJDNS, a high-performance DNS server with in-memory metrics.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	DefaultStatsPersistTTL = 86400 // Default TTL for persisted stats snapshots in seconds

	StatsPersistKey = "__stats__" // Key used for storing stats snapshot in cache for persistence across restarts
)

// StatsSnapshot contains the raw collected counters for server metrics.
type StatsSnapshot struct {
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

// StatsLogTotals contains aggregated totals for metrics export.
type StatsLogTotals struct {
	TotalRequests         uint64  `json:"total_requests"`
	TotalResponseTimeMs   uint64  `json:"total_response_time_ms"`
	LastResponseTimeMs    uint64  `json:"last_response_time_ms"`
	AverageResponseTimeMs float64 `json:"average_response_time_ms,omitempty"`
	CacheHits             uint64  `json:"cache_hits"`
	CacheMisses           uint64  `json:"cache_misses"`
	StaleResponses        uint64  `json:"stale_responses,omitempty"`
	ErrorResponses        uint64  `json:"error_responses,omitempty"`
}

// StatsLogProtocolCounts contains request counts by DNS protocol.
type StatsLogProtocolCounts struct {
	UDPRequests  uint64 `json:"udp_requests,omitempty"`
	TCPRequests  uint64 `json:"tcp_requests,omitempty"`
	DoTRequests  uint64 `json:"dot_requests,omitempty"`
	DoQRequests  uint64 `json:"doq_requests,omitempty"`
	DoHRequests  uint64 `json:"doh_requests,omitempty"`
	DoH3Requests uint64 `json:"doh3_requests,omitempty"`
}

// StatsLogEvents contains event counters such as rewrite and hijack detections.
type StatsLogEvents struct {
	RewriteRequests  uint64 `json:"rewrite_requests,omitempty"`
	HijackDetections uint64 `json:"hijack_detections,omitempty"`
	PrefetchRequests uint64 `json:"prefetch_requests,omitempty"`
	FallbackRequests uint64 `json:"fallback_requests,omitempty"`
}

// StatsLogRates contains derived rates computed from raw metrics.
type StatsLogRates struct {
	CacheRate    float64 `json:"cache_rate,omitempty"`
	PrefetchRate float64 `json:"prefetch_rate,omitempty"`
	FailureRate  float64 `json:"failure_rate,omitempty"`
	StaleRate    float64 `json:"stale_rate,omitempty"`
	FallbackRate float64 `json:"fallback_rate,omitempty"`
	RewriteRate  float64 `json:"rewrite_rate,omitempty"`
	HijackRate   float64 `json:"hijack_rate,omitempty"`
}

// StatsLog is the serialized log format for server metrics.
type StatsLog struct {
	Totals    StatsLogTotals         `json:"totals"`
	Protocols StatsLogProtocolCounts `json:"protocols,omitempty"`
	Events    StatsLogEvents         `json:"events,omitempty"`
	Rates     StatsLogRates          `json:"rates,omitempty"`
}

// StatsManager manages collection and reset schedule for metrics.
type StatsManager struct {
	enabled       bool
	mu            sync.RWMutex
	snapshot      StatsSnapshot
	resetInterval time.Duration
	persistTTL    int
	nextResetAt   int64
}

// AverageResponseTimeMs calculates the average response time in milliseconds based on total response time and total requests.
func (s StatsSnapshot) AverageResponseTimeMs() float64 {
	if s.TotalRequests == 0 {
		return 0
	}
	return float64(s.TotalResponseTimeMs) / float64(s.TotalRequests)
}

// BuildStatsLogJSON converts a metrics snapshot into JSON suitable for export.
func BuildStatsLogJSON(snapshot *StatsSnapshot) ([]byte, error) {
	statsLog := StatsLog{
		Totals: StatsLogTotals{
			TotalRequests:      snapshot.TotalRequests,
			CacheHits:          snapshot.CacheHits,
			CacheMisses:        snapshot.CacheMisses,
			StaleResponses:     snapshot.StaleResponses,
			ErrorResponses:     snapshot.ErrorResponses,
			LastResponseTimeMs: snapshot.LastResponseTimeMs,
		},
		Protocols: StatsLogProtocolCounts{
			UDPRequests:  snapshot.UDPRequests,
			TCPRequests:  snapshot.TCPRequests,
			DoTRequests:  snapshot.DoTRequests,
			DoQRequests:  snapshot.DoQRequests,
			DoHRequests:  snapshot.DoHRequests,
			DoH3Requests: snapshot.DoH3Requests,
		},
		Events: StatsLogEvents{
			HijackDetections: snapshot.HijackDetections,
			PrefetchRequests: snapshot.PrefetchRequests,
			RewriteRequests:  snapshot.RewriteRequests,

			FallbackRequests: snapshot.FallbackRequests,
		},
	}

	if snapshot.TotalRequests > 0 {
		statsLog.Totals.AverageResponseTimeMs = snapshot.AverageResponseTimeMs()
		statsLog.Rates = StatsLogRates{
			CacheRate:    float64(snapshot.CacheHits) / float64(snapshot.TotalRequests),
			StaleRate:    float64(snapshot.StaleResponses) / float64(snapshot.TotalRequests),
			FailureRate:  float64(snapshot.ErrorResponses) / float64(snapshot.TotalRequests),
			HijackRate:   float64(snapshot.HijackDetections) / float64(snapshot.TotalRequests),
			PrefetchRate: float64(snapshot.PrefetchRequests) / float64(snapshot.TotalRequests),
			RewriteRate:  float64(snapshot.RewriteRequests) / float64(snapshot.TotalRequests),
			FallbackRate: float64(snapshot.FallbackRequests) / float64(snapshot.TotalRequests),
		}
	}

	return json.Marshal(statsLog)
}

// NewStatsManager creates a new in-memory StatsManager.
func NewStatsManager(config *ServerConfig, cache CacheManager) *StatsManager {
	if config == nil {
		return nil
	}

	statsMgr := &StatsManager{
		enabled:    true,
		persistTTL: config.Server.GetStatsPersistTTL(),
	}

	resetInterval := config.Server.GetStatsResetInterval()
	if resetInterval > 0 {
		statsMgr.resetInterval = time.Duration(resetInterval) * time.Second
		statsMgr.nextResetAt = time.Now().Unix() + int64(statsMgr.resetInterval/time.Second)
	}

	// If cache is available, attempt to restore stats from cache snapshot
	if cache != nil {
		if entry, found, _ := cache.Get(StatsPersistKey); found && entry != nil {
			if err := statsMgr.LoadFromCacheEntry(entry); err != nil {
				LogWarn("STATS: failed to restore stats from cache: %v", err)
			} else {
				LogInfo("STATS: restored stats from cache snapshot")
			}
		}
	}

	return statsMgr
}

// RecordRequest updates the in-memory snapshot with details of a processed request.
func (sm *StatsManager) RecordRequest(duration time.Duration, cacheHit bool, hadError bool, protocol string, rewrote bool, hijackDetected bool, staleServed bool, fallbackUsed bool, prefetchTriggered bool) {
	if sm == nil || !sm.enabled {
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

	sm.mu.Lock()
	sm.snapshot.TotalRequests++
	if cacheHit {
		sm.snapshot.CacheHits++
	} else {
		sm.snapshot.CacheMisses++
	}
	if hadError {
		sm.snapshot.ErrorResponses++
	}
	sm.snapshot.TotalResponseTimeMs += durationMs
	sm.snapshot.LastResponseTimeMs = durationMs
	sm.snapshot.UpdatedAt = time.Now().Unix()

	switch protocol {
	case "UDP":
		sm.snapshot.UDPRequests++
	case "TCP":
		sm.snapshot.TCPRequests++
	case "DOT":
		sm.snapshot.DoTRequests++
	case "DOQ":
		sm.snapshot.DoQRequests++
	case "DOH":
		sm.snapshot.DoHRequests++
	case "DOH3":
		sm.snapshot.DoH3Requests++
	default:
		sm.snapshot.UDPRequests++
	}

	if rewrote {
		sm.snapshot.RewriteRequests++
	}
	if hijackDetected {
		sm.snapshot.HijackDetections++
	}
	if staleServed {
		sm.snapshot.StaleResponses++
	}
	if fallbackUsed {
		sm.snapshot.FallbackRequests++
	}
	if prefetchTriggered {
		sm.snapshot.PrefetchRequests++
	}

	sm.mu.Unlock()
}

// Snapshot returns a copy of the current in-memory metrics snapshot. This allows callers to retrieve the latest metrics without modifying the internal state of the StatsManager.
func (sm *StatsManager) Snapshot() StatsSnapshot {
	sm.mu.RLock()
	snapshot := sm.snapshot
	sm.mu.RUnlock()
	return snapshot
}

// Reset clears all metrics counters and schedules the next reset time if configured.
func (sm *StatsManager) Reset() {
	if sm == nil || !sm.enabled {
		return
	}

	now := time.Now().Unix()
	sm.mu.Lock()
	sm.snapshot = StatsSnapshot{UpdatedAt: now}
	sm.nextResetAt = 0
	if sm.resetInterval > 0 {
		sm.nextResetAt = now + int64(sm.resetInterval/time.Second)
	}
	sm.mu.Unlock()
}

// FetchStats retrieves the current in-memory metrics snapshot.
func (sm *StatsManager) FetchStats(ctx context.Context) (*StatsSnapshot, error) {
	if sm == nil || !sm.enabled {
		return nil, fmt.Errorf("stats disabled")
	}
	snapshot := sm.Snapshot()
	return &snapshot, nil
}

// ToCacheEntry serializes the current stats snapshot into a CacheEntry for persistence via the cache system.
func (sm *StatsManager) ToCacheEntry() (*CacheEntry, error) {
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
		ttl = DefaultStatsPersistTTL
	}
	return &CacheEntry{
		Timestamp:   now,
		AccessTime:  now,
		TTL:         ttl,
		OriginalTTL: ttl,
		Payload:     data,
	}, nil
}

// LoadFromCacheEntry restores stats from a CacheEntry previously created by ToCacheEntry.
func (sm *StatsManager) LoadFromCacheEntry(entry *CacheEntry) error {
	if sm == nil {
		return fmt.Errorf("stats manager nil")
	}
	if entry == nil || len(entry.Payload) == 0 {
		return fmt.Errorf("empty cache entry")
	}

	var snap StatsSnapshot
	if err := json.Unmarshal(entry.Payload, &snap); err != nil {
		return fmt.Errorf("unmarshal stats snapshot: %w", err)
	}

	sm.mu.Lock()
	sm.snapshot = snap
	sm.mu.Unlock()
	return nil
}

// Persist saves the current stats snapshot into the provided cache manager.
func (sm *StatsManager) Persist(cache CacheManager) {
	if sm == nil || !sm.enabled || cache == nil {
		return
	}

	entry, err := sm.ToCacheEntry()
	if err != nil {
		LogDebug("STATS: failed to serialize stats for cache persistence: %v", err)
		return
	}

	cache.SetEntry(StatsPersistKey, entry)
}
