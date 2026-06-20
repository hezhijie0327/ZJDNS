// Package log provides leveled logging with color output and a cached time source.
package log

import (
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"time"
)

// Level represents the severity of a log message.
type Level int

const (
	Error Level = iota
	Warn
	Info
	Debug
)

const (
	DefaultLevel = "info" // Default logging level name.
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorGreen  = "\033[32m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
)

// Manager handles leveled, color-coded logging.
type Manager struct {
	level    atomic.Int32
	writer   io.Writer
	colorMap map[Level]string
}

// TimeCache provides a low-cost cached current time, updated once per second.
type TimeCache struct {
	currentTime atomic.Value
	ticker      *time.Ticker
}

// Default is the package-level logger instance. Call SetLevel on it during
// startup to configure verbosity.
var Default = NewManager()

// DefaultTimeCache is the package-level time cache. Stop it during shutdown.
var DefaultTimeCache = NewTimeCache()

// NewManager creates a new Manager writing to stdout with Info level.
func NewManager() *Manager {
	m := &Manager{
		writer: os.Stdout,
		colorMap: map[Level]string{
			Error: colorRed,
			Warn:  colorYellow,
			Info:  colorGreen,
			Debug: colorCyan,
		},
	}
	m.level.Store(int32(Info))
	return m
}

// SetLevel sets the logging level.
func (m *Manager) SetLevel(lvl Level) {
	if lvl < Error {
		lvl = Error
	} else if lvl > Debug {
		lvl = Debug
	}
	m.level.Store(int32(lvl))
}

// Level returns the current logging level.
func (m *Manager) Level() Level {
	return Level(m.level.Load())
}

// Log emits a message at the given level. Messages below the configured level
// are suppressed.
func (m *Manager) Log(lvl Level, format string, args ...any) {
	if lvl < Error {
		lvl = Error
	} else if lvl > Debug {
		lvl = Debug
	}
	if lvl > Level(m.level.Load()) {
		return
	}

	levelStr := [...]string{"ERROR", "WARN", "INFO", "DEBUG"}[lvl]

	color, ok := m.colorMap[lvl]
	if !ok {
		color = colorReset
	}

	timestamp := DefaultTimeCache.Now().Format("2006-01-02 15:04:05")
	message := fmt.Sprintf(format, args...)

	logLine := fmt.Sprintf("%s[%s]%s %s%-5s%s %s\n",
		colorBold, timestamp, colorReset,
		color, levelStr, colorReset,
		message)

	_, _ = fmt.Fprint(m.writer, logLine)
}

// Error logs at ERROR level.
func (m *Manager) Error(format string, args ...any) { m.Log(Error, format, args...) }

// Warn logs at WARN level.
func (m *Manager) Warn(format string, args ...any) { m.Log(Warn, format, args...) }

// Info logs at INFO level.
func (m *Manager) Info(format string, args ...any) { m.Log(Info, format, args...) }

// Debug logs at DEBUG level.
func (m *Manager) Debug(format string, args ...any) { m.Log(Debug, format, args...) }

// Package-level convenience functions that operate on Default.

// Error logs at ERROR level on the default logger.
func Errorf(format string, args ...any) { Default.Error(format, args...) }

// Warnf logs at WARN level on the default logger.
func Warnf(format string, args ...any) { Default.Warn(format, args...) }

// Infof logs at INFO level on the default logger.
func Infof(format string, args ...any) { Default.Info(format, args...) }

// Debugf logs at DEBUG level on the default logger.
func Debugf(format string, args ...any) { Default.Debug(format, args...) }

// SetLevel configures the default logger's verbosity.
func SetLevel(lvl Level) { Default.SetLevel(lvl) }

// NewTimeCache creates a TimeCache that updates once per second.
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

// Now returns the cached current time with 1-second granularity.
func (tc *TimeCache) Now() time.Time {
	return tc.currentTime.Load().(time.Time)
}

// Stop stops the time cache ticker.
func (tc *TimeCache) Stop() {
	if tc != nil && tc.ticker != nil {
		tc.ticker.Stop()
	}
}
