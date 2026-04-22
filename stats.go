package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

func (s StatsSnapshot) AverageResponseTimeMs() float64 {
	if s.TotalRequests == 0 {
		return 0
	}
	return float64(s.TotalResponseTimeMs) / float64(s.TotalRequests)
}

func BuildStatsLogJSON(snapshot *StatsSnapshot) ([]byte, error) {
	statsLog := StatsLog{
		Totals: StatsLogTotals{
			TotalRequests:      snapshot.TotalRequests,
			CacheHits:          snapshot.CacheHits,
			CacheMisses:        snapshot.CacheMisses,
			ErrorResponses:     snapshot.ErrorResponses,
			StaleResponses:     snapshot.StaleResponses,
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
			RewriteRequests:  snapshot.RewriteRequests,
			HijackDetections: snapshot.HijackDetections,
		},
	}

	if snapshot.TotalRequests > 0 {
		statsLog.Totals.AverageResponseTimeMs = snapshot.AverageResponseTimeMs()
		statsLog.Rates = StatsLogRates{
			FailureRate: float64(snapshot.ErrorResponses) / float64(snapshot.TotalRequests),
			StaleRate:   float64(snapshot.StaleResponses) / float64(snapshot.TotalRequests),
			CacheRate:   float64(snapshot.CacheHits) / float64(snapshot.TotalRequests),
			RewriteRate: float64(snapshot.RewriteRequests) / float64(snapshot.TotalRequests),
			HijackRate:  float64(snapshot.HijackDetections) / float64(snapshot.TotalRequests),
		}
	}

	return json.Marshal(statsLog)
}

func NewStatsManager(config *ServerConfig, redisClient *redis.Client) *StatsManager {
	if config == nil {
		return nil
	}

	redisKey := config.Redis.KeyPrefix + RedisPrefixStats + "global"
	statsMgr := &StatsManager{
		enabled:  true,
		redisKey: redisKey,
		client:   redisClient,
	}

	resetInterval := config.Server.GetStatsResetInterval()
	if statsMgr.client != nil && resetInterval > 0 {
		statsMgr.resetInterval = time.Duration(resetInterval) * time.Second
		statsMgr.loadResetSchedule()
	}

	return statsMgr
}

func (sm *StatsManager) loadResetSchedule() {
	if sm == nil || sm.client == nil || sm.resetInterval <= 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), OperationTimeout)
	defer cancel()

	resetAtStr, err := sm.client.HGet(ctx, sm.redisKey, "reset_at").Result()
	if err != nil && err != redis.Nil {
		LogError("STATS: failed to fetch reset_at from redis: %v", err)
		return
	}

	now := time.Now().Unix()
	resetAt := parseInt64OrZero(resetAtStr)
	if resetAt == 0 {
		sm.setNextResetAt(ctx, now+int64(sm.resetInterval/time.Second))
		return
	}

	if now >= resetAt {
		sm.Reset()
		return
	}

	sm.mu.Lock()
	sm.nextResetAt = resetAt
	sm.mu.Unlock()
}

func (sm *StatsManager) setNextResetAt(ctx context.Context, nextResetAt int64) {
	if sm == nil || sm.client == nil || nextResetAt <= 0 {
		return
	}

	if _, err := sm.client.HSet(ctx, sm.redisKey, "reset_at", nextResetAt).Result(); err != nil {
		LogError("STATS: failed to persist reset_at to redis: %v", err)
		return
	}

	sm.mu.Lock()
	sm.nextResetAt = nextResetAt
	sm.mu.Unlock()
}

func (sm *StatsManager) RecordRequest(duration time.Duration, cacheHit bool, hadError bool, protocol string, rewrote bool, hijackDetected bool, staleServed bool) {
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

	sm.mu.Unlock()

	if sm.client == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), OperationTimeout)
	defer cancel()

	pipe := sm.client.Pipeline()
	pipe.HIncrBy(ctx, sm.redisKey, "total_requests", 1)
	if cacheHit {
		pipe.HIncrBy(ctx, sm.redisKey, "cache_hits", 1)
	} else {
		pipe.HIncrBy(ctx, sm.redisKey, "cache_misses", 1)
	}
	if hadError {
		pipe.HIncrBy(ctx, sm.redisKey, "error_responses", 1)
	}
	pipe.HIncrBy(ctx, sm.redisKey, "total_response_time_ms", int64(durationMs))
	pipe.HSet(ctx, sm.redisKey, "last_response_time_ms", int64(durationMs))
	pipe.HSet(ctx, sm.redisKey, "updated_at", time.Now().Unix())

	switch protocol {
	case "UDP":
		pipe.HIncrBy(ctx, sm.redisKey, "udp_requests", 1)
	case "TCP":
		pipe.HIncrBy(ctx, sm.redisKey, "tcp_requests", 1)
	case "DOT":
		pipe.HIncrBy(ctx, sm.redisKey, "dot_requests", 1)
	case "DOQ":
		pipe.HIncrBy(ctx, sm.redisKey, "doq_requests", 1)
	case "DOH":
		pipe.HIncrBy(ctx, sm.redisKey, "doh_requests", 1)
	case "DOH3":
		pipe.HIncrBy(ctx, sm.redisKey, "doh3_requests", 1)
	default:
		pipe.HIncrBy(ctx, sm.redisKey, "udp_requests", 1)
	}
	if rewrote {
		pipe.HIncrBy(ctx, sm.redisKey, "rewrite_requests", 1)
	}
	if hijackDetected {
		pipe.HIncrBy(ctx, sm.redisKey, "hijack_detections", 1)
	}
	if staleServed {
		pipe.HIncrBy(ctx, sm.redisKey, "stale_responses", 1)
	}
	_, _ = pipe.Exec(ctx)
}

func (sm *StatsManager) Snapshot() StatsSnapshot {
	sm.mu.RLock()
	snapshot := sm.snapshot
	sm.mu.RUnlock()
	return snapshot
}

func (sm *StatsManager) Reset() {
	if sm == nil || !sm.enabled {
		return
	}

	now := time.Now().Unix()
	sm.mu.Lock()
	sm.snapshot = StatsSnapshot{UpdatedAt: now}
	sm.mu.Unlock()

	if sm.client == nil {
		return
	}

	nextResetAt := int64(0)
	if sm.resetInterval > 0 {
		nextResetAt = now + int64(sm.resetInterval/time.Second)
	}

	ctx, cancel := context.WithTimeout(context.Background(), OperationTimeout)
	defer cancel()

	_, _ = sm.client.HSet(ctx, sm.redisKey, map[string]interface{}{
		"total_requests":         0,
		"cache_hits":             0,
		"cache_misses":           0,
		"error_responses":        0,
		"stale_responses":        0,
		"total_response_time_ms": 0,
		"last_response_time_ms":  0,
		"udp_requests":           0,
		"tcp_requests":           0,
		"dot_requests":           0,
		"doq_requests":           0,
		"doh_requests":           0,
		"doh3_requests":          0,
		"rewrite_requests":       0,
		"hijack_detections":      0,
		"updated_at":             now,
		"reset_at":               nextResetAt,
	}).Result()

	sm.mu.Lock()
	sm.nextResetAt = nextResetAt
	sm.mu.Unlock()
}

func (sm *StatsManager) FetchStats(ctx context.Context) (*StatsSnapshot, error) {
	if sm == nil || !sm.enabled {
		return nil, fmt.Errorf("stats disabled")
	}
	if sm.client == nil {
		snapshot := sm.Snapshot()
		return &snapshot, nil
	}

	if ctx == nil {
		ctx = context.Background()
	}

	data, err := sm.client.HGetAll(ctx, sm.redisKey).Result()
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return &StatsSnapshot{}, nil
	}

	snapshot := StatsSnapshot{
		TotalRequests:       parseUint64OrZero(data["total_requests"]),
		CacheHits:           parseUint64OrZero(data["cache_hits"]),
		CacheMisses:         parseUint64OrZero(data["cache_misses"]),
		ErrorResponses:      parseUint64OrZero(data["error_responses"]),
		TotalResponseTimeMs: parseUint64OrZero(data["total_response_time_ms"]),
		LastResponseTimeMs:  parseUint64OrZero(data["last_response_time_ms"]),
		UDPRequests:         parseUint64OrZero(data["udp_requests"]),
		TCPRequests:         parseUint64OrZero(data["tcp_requests"]),
		DoTRequests:         parseUint64OrZero(data["dot_requests"]),
		DoQRequests:         parseUint64OrZero(data["doq_requests"]),
		DoHRequests:         parseUint64OrZero(data["doh_requests"]),
		DoH3Requests:        parseUint64OrZero(data["doh3_requests"]),
		RewriteRequests:     parseUint64OrZero(data["rewrite_requests"]),
		HijackDetections:    parseUint64OrZero(data["hijack_detections"]),
		StaleResponses:      parseUint64OrZero(data["stale_responses"]),
		UpdatedAt:           parseInt64OrZero(data["updated_at"]),
	}
	return &snapshot, nil
}

func parseUint64OrZero(value string) uint64 {
	if value == "" {
		return 0
	}
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func parseInt64OrZero(value string) int64 {
	if value == "" {
		return 0
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0
	}
	return n
}
