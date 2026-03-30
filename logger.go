// Package main implements ZJDNS - High Performance DNS Server
package main

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// =============================================================================
// Global Variables
// =============================================================================

var (
	globalLog = NewLogManager()
	timeCache = NewTimeCache()
	globalRNG = NewRNG(time.Now().UnixNano())
)

// RNG is a simple random number generator
type RNG struct {
	mu    sync.Mutex
	seed  int64
	state uint64
}

// NewRNG creates a new RNG with the given seed
func NewRNG(seed int64) *RNG {
	return &RNG{
		seed:  seed,
		state: uint64(seed),
	}
}

// Intn returns a random integer in [0, n)
func (r *RNG) Intn(n int) int {
	if n <= 0 {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	// xorshift64* algorithm
	r.state ^= r.state >> 12
	r.state ^= r.state << 25
	r.state ^= r.state >> 27
	return int((r.state * 2685821657736338717) % uint64(n))
}

// =============================================================================
// LogManager Implementation
// =============================================================================

// NewLogManager creates a new LogManager
func NewLogManager() *LogManager {
	lm := &LogManager{
		writer: os.Stdout,
		colorMap: map[LogLevel]string{
			Error: ColorRed,
			Warn:  ColorYellow,
			Info:  ColorGreen,
			Debug: ColorCyan,
		},
	}
	lm.level.Store(int32(Info))
	return lm
}

// SetLevel sets the logging level
func (lm *LogManager) SetLevel(level LogLevel) {
	if level < Error {
		level = Error
	} else if level > Debug {
		level = Debug
	}
	lm.level.Store(int32(level))
}

// GetLevel returns the current logging level
func (lm *LogManager) GetLevel() LogLevel {
	return LogLevel(lm.level.Load())
}

// Log logs a message at the specified level
func (lm *LogManager) Log(level LogLevel, format string, args ...any) {
	if level < Error {
		level = Error
	} else if level > Debug {
		level = Debug
	}

	if level > LogLevel(lm.level.Load()) {
		return
	}

	var levelStr string
	switch level {
	case Error:
		levelStr = "ERROR"
	case Warn:
		levelStr = "WARN"
	case Info:
		levelStr = "INFO"
	case Debug:
		levelStr = "DEBUG"
	default:
		levelStr = "UNKNOWN"
	}

	color, ok := lm.colorMap[level]
	if !ok {
		color = ColorReset
	}

	timestamp := timeCache.Now().Format("2006-01-02 15:04:05")
	message := fmt.Sprintf(format, args...)

	logLine := fmt.Sprintf("%s[%s]%s %s%-5s%s %s\n",
		ColorBold, timestamp, ColorReset,
		color, levelStr, ColorReset,
		message)

	_, _ = fmt.Fprint(lm.writer, logLine)
}

// Error logs an error message
func (lm *LogManager) Error(format string, args ...any) { lm.Log(Error, format, args...) }

// Warn logs a warning message
func (lm *LogManager) Warn(format string, args ...any) { lm.Log(Warn, format, args...) }

// Info logs an info message
func (lm *LogManager) Info(format string, args ...any) { lm.Log(Info, format, args...) }

// Debug logs a debug message
func (lm *LogManager) Debug(format string, args ...any) { lm.Log(Debug, format, args...) }

// LogError logs an error message using the global logger
func LogError(format string, args ...any) { globalLog.Error(format, args...) }

// LogWarn logs a warning message using the global logger
func LogWarn(format string, args ...any) { globalLog.Warn(format, args...) }

// LogInfo logs an info message using the global logger
func LogInfo(format string, args ...any) { globalLog.Info(format, args...) }

// LogDebug logs a debug message using the global logger
func LogDebug(format string, args ...any) { globalLog.Debug(format, args...) }

// =============================================================================
// TimeCache Implementation
// =============================================================================

// NewTimeCache creates a new TimeCache
func NewTimeCache() *TimeCache {
	tc := &TimeCache{
		ticker: time.NewTicker(time.Second),
	}
	tc.currentTime.Store(time.Now())

	go func() {
		for range tc.ticker.C {
			tc.currentTime.Store(time.Now())
		}
	}()

	return tc
}

// Now returns the cached current time
func (tc *TimeCache) Now() time.Time {
	return tc.currentTime.Load().(time.Time)
}

// Stop stops the time cache ticker
func (tc *TimeCache) Stop() {
	if tc.ticker != nil {
		tc.ticker.Stop()
	}
}
