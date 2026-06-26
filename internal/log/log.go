// Package log provides a leveled logging manager with colored output.
package log

import (
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Error level indicates a component failure or data loss risk.
// Warn level indicates a rare boundary condition or background task failure.
// Info level indicates a startup/shutdown lifecycle event or configuration
// summary.
// Debug level provides detailed hot-path information for debugging.
const (
	Error Level = iota
	Warn
	Info
	Debug
)

// DefaultLevel is the default logging level string.
const (
	DefaultLevel = "info"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorGreen  = "\033[32m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
)

const logTimeFormat = "2006-01-02 15:04:05"

// Default is the package-level default Manager instance.
var Default = NewManager()

// DefaultTimeCache is the package-level default TimeCache.
var DefaultTimeCache = NewTimeCache()

// Level represents a logging severity level.
type Level int

// Manager manages leveled logging with configurable output.
type Manager struct {
	level    atomic.Int32
	writer   io.Writer
	colorMap map[Level]string
}

// TimeCache caches the current time with periodic one-second updates.
type TimeCache struct {
	currentTime atomic.Value
	ticker      *time.Ticker
	done        chan struct{}
	closeOnce   sync.Once
}

// NewManager creates a new Manager with default settings.
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

// SetLevel sets the logging level, clamped to the valid range.
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

// String returns the string representation of the Level.
func (l Level) String() string {
	switch l {
	case Error:
		return "error"
	case Warn:
		return "warn"
	case Info:
		return "info"
	case Debug:
		return "debug"
	default:
		return "unknown"
	}
}

// Log logs a message at the specified level.
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

	timestamp := DefaultTimeCache.Now().Format(logTimeFormat)
	message := sanitizeLogMessage(fmt.Sprintf(format, args...))

	logLine := fmt.Sprintf("%s[%s]%s %s%-5s%s %s\n",
		colorBold, timestamp, colorReset,
		color, levelStr, colorReset,
		message)

	_, _ = fmt.Fprint(m.writer, logLine)
}

// Error logs an error-level message.
func (m *Manager) Error(format string, args ...any) { m.Log(Error, format, args...) }

// Warn logs a warning-level message.
func (m *Manager) Warn(format string, args ...any) { m.Log(Warn, format, args...) }

// Info logs an info-level message.
func (m *Manager) Info(format string, args ...any) { m.Log(Info, format, args...) }

// Debug logs a debug-level message.
func (m *Manager) Debug(format string, args ...any) { m.Log(Debug, format, args...) }

// Errorf logs an error-level message via the default manager.
func Errorf(format string, args ...any) { Default.Error(format, args...) }

// Warnf logs a warning-level message via the default manager.
func Warnf(format string, args ...any) { Default.Warn(format, args...) }

// Infof logs an info-level message via the default manager.
func Infof(format string, args ...any) { Default.Info(format, args...) }

// Debugf logs a debug-level message via the default manager.
func Debugf(format string, args ...any) { Default.Debug(format, args...) }

// SetLevel sets the logging level on the default manager.
func SetLevel(lvl Level) { Default.SetLevel(lvl) }

func sanitizeLogMessage(msg string) string {
	if len(msg) == 0 {
		return msg
	}
	b := make([]byte, 0, len(msg))
	for i := 0; i < len(msg); i++ {
		c := msg[i]
		if c == 0x0a || c == 0x0d || c == 0x09 || c == 0x7f || (c < 32 && c != 0) {
			b = append(b, ' ')
		} else {
			b = append(b, c)
		}
	}
	return string(b)
}

// NewTimeCache creates and starts a new TimeCache.
func NewTimeCache() *TimeCache {
	tc := &TimeCache{
		ticker: time.NewTicker(time.Second),
		done:   make(chan struct{}),
	}
	tc.currentTime.Store(time.Now())

	go func() {
		for {
			select {
			case <-tc.ticker.C:
				tc.currentTime.Store(time.Now())
			case <-tc.done:
				return
			}
		}
	}()

	return tc
}

// Now returns the current cached time.
func (tc *TimeCache) Now() time.Time {
	return tc.currentTime.Load().(time.Time)
}

// Stop stops the time cache ticker and goroutine. It is safe to call multiple
// times.
func (tc *TimeCache) Stop() {
	if tc == nil {
		return
	}
	tc.closeOnce.Do(func() {
		if tc.done != nil {
			close(tc.done)
		}
		if tc.ticker != nil {
			tc.ticker.Stop()
		}
	})
}
