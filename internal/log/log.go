// Package log provides a leveled logging manager with colored output and
// component-based filtering.
//
// Log Level Format:
//
//	error | warn | info | debug
//
// Component Filtering:
//
//	debug:UPSTREAM,RECURSION  → Debug level, only UPSTREAM + RECURSION components
//	info                       → Info level, all components
//
// Messages with a "PREFIX: " prefix are filtered by component; messages
// without a recognized prefix always pass through.
package log

import (
	"fmt"
	"io"
	"os"
	"strings"
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
const DefaultLevel = "info"

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorGreen  = "\033[32m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
)

const logTimeFormat = "2006-01-02 15:04:05"

var levelNames = [...]string{"ERROR", "WARN", "INFO", "DEBUG"}

// Default is the package-level default Manager instance.
var Default = NewManager()

// DefaultTimeCache is the package-level default TimeCache.
var DefaultTimeCache = NewTimeCache()

// Level represents a logging severity level.
type Level int

// Manager manages leveled logging with configurable output and optional
// component-based filtering.
type Manager struct {
	level           atomic.Int32
	writer          io.Writer
	colorMap        map[Level]string
	componentFilter map[string]bool // nil = all enabled; non-nil = only listed components
	mu              sync.RWMutex    // protects componentFilter
}

// TimeCache caches the current time with periodic one-second updates.
type TimeCache struct {
	unixNano  atomic.Int64
	ticker    *time.Ticker
	done      chan struct{}
	closeOnce sync.Once
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

// SetComponentFilter sets the component filter. If components is empty, all
// components pass through (no filtering). Otherwise, only messages with a
// matching "PREFIX:" prefix are emitted. Messages without a recognized prefix
// always pass through.
func (m *Manager) SetComponentFilter(components []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(components) == 0 {
		m.componentFilter = nil
		return
	}
	filter := make(map[string]bool, len(components))
	for _, c := range components {
		c = strings.ToUpper(strings.TrimSpace(c))
		if c != "" {
			filter[c] = true
		}
	}
	if len(filter) == 0 {
		m.componentFilter = nil
	} else {
		m.componentFilter = filter
	}
}

// ParseLevelFilter parses a log level string that may include component
// filters in the format "level:comp1,comp2,...". Returns the level and a
// component list (nil components means no filtering). The defaultLevel is
// used when parsing fails.
func ParseLevelFilter(s string, defaultLevel Level) (Level, []string) {
	if s == "" {
		return defaultLevel, nil
	}

	// Split on colon: "debug:upstream,recursion" or plain "info".
	parts := strings.SplitN(s, ":", 2)
	levelStr := strings.TrimSpace(strings.ToLower(parts[0]))

	var lvl Level
	switch levelStr {
	case "error":
		lvl = Error
	case "warn":
		lvl = Warn
	case "info":
		lvl = Info
	case "debug":
		lvl = Debug
	default:
		return defaultLevel, nil
	}

	if len(parts) == 2 && parts[1] != "" {
		raw := strings.Split(parts[1], ",")
		components := make([]string, 0, len(raw))
		for _, c := range raw {
			c = strings.TrimSpace(c)
			if c != "" {
				components = append(components, c)
			}
		}
		return lvl, components
	}

	return lvl, nil
}

// extractPrefix extracts the component prefix from a log message. Messages
// are expected to start with "PREFIX: " (e.g., "UPSTREAM: querying...").
// Returns the prefix in uppercase, or empty string if no prefix found.
func extractPrefix(msg string) string {
	idx := strings.Index(msg, ":")
	if idx <= 0 || idx >= len(msg)-1 || msg[idx+1] != ' ' {
		return ""
	}
	return strings.ToUpper(msg[:idx])
}

// Log logs a message at the specified level, respecting both the level
// threshold and any component filter.
func (m *Manager) Log(lvl Level, format string, args ...any) {
	if lvl < Error {
		lvl = Error
	} else if lvl > Debug {
		lvl = Debug
	}
	if lvl > Level(m.level.Load()) {
		return
	}

	message := sanitizeLogMessage(fmt.Sprintf(format, args...))

	// Check component filter: if set, only emit messages whose prefix
	// matches. Messages without a recognizable "PREFIX: " always pass.
	m.mu.RLock()
	filter := m.componentFilter
	m.mu.RUnlock()
	if filter != nil {
		prefix := extractPrefix(message)
		if prefix != "" && !filter[prefix] {
			return
		}
	}

	levelStr := levelNames[lvl]

	color, ok := m.colorMap[lvl]
	if !ok {
		color = colorReset
	}

	timestamp := DefaultTimeCache.Now().Format(logTimeFormat)

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

// IsDebug reports whether the default manager is at Debug level or higher.
func IsDebug() bool { return Default.Level() >= Debug }

// SetLevel sets the logging level on the default manager.
func SetLevel(lvl Level) { Default.SetLevel(lvl) }

// SetLevelFilter applies both a level and optional component filter to the
// default manager. The logLevelStr is in the format "level:comp1,comp2".
func SetLevelFilter(logLevelStr string) {
	lvl, components := ParseLevelFilter(logLevelStr, Info)
	Default.SetLevel(lvl)
	Default.SetComponentFilter(components)
}

func sanitizeLogMessage(msg string) string {
	if len(msg) == 0 {
		return msg
	}
	// Fast path: scan for any byte that needs replacement.
	// Replace NUL (0x00), control chars (0x01-0x1F), DEL (0x7F).
	needsReplace := false
	for i := 0; i < len(msg); i++ {
		c := msg[i]
		if c <= 0x1f || c == 0x7f {
			needsReplace = true
			break
		}
	}
	if !needsReplace {
		return msg
	}
	b := make([]byte, 0, len(msg))
	for i := 0; i < len(msg); i++ {
		c := msg[i]
		if c <= 0x1f || c == 0x7f {
			b = append(b, ' ')
		} else {
			b = append(b, c)
		}
	}
	return string(b)
}

// NewTimeCache creates and starts a new TimeCache.
func NewTimeCache() *TimeCache {
	t := &TimeCache{
		ticker: time.NewTicker(time.Second),
		done:   make(chan struct{}),
	}
	t.unixNano.Store(time.Now().UnixNano())

	go func() {
		for {
			select {
			case <-t.ticker.C:
				t.unixNano.Store(time.Now().UnixNano())
			case <-t.done:
				return
			}
		}
	}()

	return t
}

// Now returns the current cached time.
func (t *TimeCache) Now() time.Time {
	return time.Unix(0, t.unixNano.Load())
}

// NowUnix returns the current cached Unix timestamp (seconds).
func NowUnix() int64 {
	return DefaultTimeCache.unixNano.Load() / 1e9
}

// NowUnixNano returns the current cached Unix timestamp (nanoseconds).
func NowUnixNano() int64 {
	return DefaultTimeCache.unixNano.Load()
}

// Stop stops the time cache ticker and goroutine. It is safe to call multiple
// times.
func (t *TimeCache) Stop() {
	if t == nil {
		return
	}
	t.closeOnce.Do(func() {
		if t.done != nil {
			close(t.done)
		}
		if t.ticker != nil {
			t.ticker.Stop()
		}
	})
}
