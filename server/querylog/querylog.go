// Package querylog provides a buffered JSON-lines writer for DNS query events.
package querylog

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"zjdns/internal/log"
)

// Entry represents a single DNS query event for JSON-lines logging.
type Entry struct {
	Timestamp       string `json:"timestamp"`
	Domain          string `json:"domain"`
	QType           string `json:"qtype"`
	ClientIP        string `json:"client_ip"`
	Protocol        string `json:"protocol"`
	Rcode           string `json:"rcode"`
	RcodeNum        int    `json:"rcode_num"`
	ResponseTimeMs  int64  `json:"response_time_ms"`
	CacheHit        bool   `json:"cache_hit"`
	Error           string `json:"error,omitempty"`
	EDECode         uint16 `json:"ede_code,omitempty"`
	EDEName         string `json:"ede_name,omitempty"`
	DNSSECStatus    string `json:"dnssec_status,omitempty"`
	Mode            string `json:"mode"`
	AnswerCount     int    `json:"answer_count"`
	AuthorityCount  int    `json:"authority_count"`
	AdditionalCount int    `json:"additional_count"`
	StaleServed     bool   `json:"stale_served,omitempty"`
	FallbackUsed    bool   `json:"fallback_used,omitempty"`
	HijackDetected  bool   `json:"hijack_detected,omitempty"`
}

// Logger writes DNS query events to a JSON-lines file with optional
// rcode filtering. It is safe for concurrent use.
type Logger struct {
	mu          sync.Mutex
	file        *os.File
	buf         *bufio.Writer
	enc         *json.Encoder
	rcodeFilter map[int]bool // nil means log everything
	closed      bool
}

// New opens the query log file and returns a Logger. rcodeFilter is a set of
// rcode numbers to log; nil means log all queries.
func New(filePath string, rcodeFilter map[int]bool) (*Logger, error) {
	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	buf := bufio.NewWriter(f)
	return &Logger{
		file:        f,
		buf:         buf,
		enc:         json.NewEncoder(buf),
		rcodeFilter: rcodeFilter,
	}, nil
}

// Log writes an Entry to the log file if it passes the rcode filter.
// It is a no-op if l is nil or closed.
func (l *Logger) Log(entry Entry) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.enc == nil {
		return
	}
	// Apply rcode filter: nil filter = log everything
	if l.rcodeFilter != nil && !l.rcodeFilter[entry.RcodeNum] {
		return
	}
	if err := l.enc.Encode(entry); err != nil {
		log.Debugf("QUERY_LOG: write error: %v", err)
	}
}

// Close flushes the buffer and closes the underlying file.
func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	if l.buf != nil {
		if err := l.buf.Flush(); err != nil {
			log.Debugf("QUERY_LOG: flush error on close: %v", err)
		}
	}
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// ClientIPString returns the string representation of a net.IP, or
// "<unknown>" if the IP is nil.
func ClientIPString(ip net.IP) string {
	if ip == nil {
		return "<unknown>"
	}
	return ip.String()
}

// ParseRcodeFilter parses a comma-separated list of rcode numbers into a set.
// An empty string returns nil (log everything). Invalid numbers are skipped
// with a debug log warning.
func ParseRcodeFilter(raw string) map[int]bool {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	filter := make(map[int]bool, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			log.Debugf("QUERY_LOG: invalid rcode in query_log_rcode filter: %q", p)
			continue
		}
		filter[n] = true
	}
	if len(filter) == 0 {
		return nil
	}
	return filter
}
