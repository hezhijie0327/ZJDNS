// Package dashboard provides the Unix socket server for the TUI dashboard.
package dashboard

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"zjdns/cache"
	"zjdns/internal/ringbuffer"
)

// QueryEvent is a dashboard-friendly query log entry (mirrors TUI types).
type QueryEvent struct {
	Qname        string  `json:"qname"`
	Qtype        string  `json:"qtype"`
	Result       string  `json:"result"`
	Rcode        int     `json:"rcode"`
	ResponseTime float64 `json:"resp_ms"`
	Protocol     string  `json:"protocol"`
	Poisoned     bool    `json:"poisoned"`
	DNSSECStatus string  `json:"dnssec"`
}

// StatsSnapshot holds aggregated statistics (mirrors TUI types).
type StatsSnapshot struct {
	Entries                                      int64   `json:"entries"`
	Total                                        int64   `json:"total"`
	AvgMS                                        float64 `json:"avg_ms"`
	Hits                                         int64   `json:"hits"`
	Misses                                       int64   `json:"misses"`
	Stales                                       int64   `json:"stales"`
	Zones                                        int64   `json:"zones"`
	Errors                                       int64   `json:"errors"`
	Blocked                                      int64   `json:"blocked"`
	BadCookie                                    int64   `json:"badcookie"`
	NOERR                                        int64   `json:"noerr"`
	FormErr                                      int64   `json:"formerr"`
	ServFail                                     int64   `json:"servfail"`
	NXDomain                                     int64   `json:"nxdomain"`
	NotImp                                       int64   `json:"notimp"`
	Refused                                      int64   `json:"refused"`
	UDP, TCP, TLS, QUIC, HTTPS, HTTP3, DTLS      int64
	DNSCrypt, DNSCryptTCP, TLCP, HTTPTLCP, DTLCP int64
	Secure, Insecure, Bogus, Poisoned            int64
}

// SocketServer listens on a Unix domain socket and serves dashboard data.
type SocketServer struct {
	ln      net.Listener
	store   cache.Store
	ringBuf *ringbuffer.RingBuffer[cache.RequestRecord]
}

// NewSocketServer creates a SocketServer.  socketPath is the filesystem path
// for the Unix socket.  The existing socket file is removed before binding.
func NewSocketServer(socketPath string, store cache.Store, rb *ringbuffer.RingBuffer[cache.RequestRecord]) (*SocketServer, error) {
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("dashboard socket: listen %s: %w", socketPath, err)
	}
	return &SocketServer{
		ln:      ln,
		store:   store,
		ringBuf: rb,
	}, nil
}

// Start accepts connections and handles them.  Blocks until ctx is cancelled.
func (s *SocketServer) Start() error {
	go s.acceptLoop()
	return nil
}

// Close unregisters and closes the listener, removing the socket file.
func (s *SocketServer) Close() error {
	return s.ln.Close()
}

func (s *SocketServer) acceptLoop() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *SocketServer) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	dec := json.NewDecoder(conn)
	enc := json.NewEncoder(conn)

	for {
		var req struct {
			Cmd   string `json:"cmd"`
			Limit int    `json:"limit,omitzero"`
		}
		if err := dec.Decode(&req); err != nil {
			return
		}

		switch req.Cmd {
		case "stats":
			s.writeStats(enc)
		case "log":
			if req.Limit <= 0 {
				req.Limit = 100
			}
			s.writeLog(enc, req.Limit)
		default:
			_ = enc.Encode(map[string]string{"type": "error", "message": "unknown command: " + req.Cmd})
		}
	}
}

func (s *SocketServer) writeStats(enc *json.Encoder) {
	lines := s.store.Stats()
	stats := ParseStats(lines)
	_ = enc.Encode(map[string]any{
		"type": "stats",
		"data": stats,
	})
}

func (s *SocketServer) writeLog(enc *json.Encoder, limit int) {
	records := s.ringBuf.SnapshotN(limit)
	events := make([]QueryEvent, 0, len(records))
	//nolint:gocritic // ring buffer snapshot is a slice copy, the copy is intentional
	for _, r := range records {
		events = append(events, QueryEvent{
			Qname:        r.Qname,
			Qtype:        typeToString(r.Qtype),
			Result:       r.Result,
			Rcode:        r.Rcode,
			ResponseTime: float64(r.ResponseTime),
			Protocol:     r.Protocol,
			Poisoned:     r.Poisoned,
			DNSSECStatus: r.DNSSECStatus,
		})
	}
	_ = enc.Encode(map[string]any{
		"type":    "log",
		"entries": events,
	})
}

// typeToString converts a DNS type code to its string representation.
func typeToString(qtype uint16) string {
	names := map[uint16]string{
		1: "A", 28: "AAAA", 5: "CNAME", 2: "NS", 15: "MX", 16: "TXT",
		6: "SOA", 12: "PTR", 33: "SRV", 65: "HTTPS", 64: "SVCB",
		257: "CAA", 48: "DNSKEY", 43: "DS", 46: "RRSIG", 47: "NSEC",
		252: "AXFR", 255: "ANY",
	}
	if s, ok := names[qtype]; ok {
		return s
	}
	return fmt.Sprintf("TYPE%d", qtype)
}

// ParseStats parses Stats() []string output into a structured snapshot.
func ParseStats(lines []string) StatsSnapshot {
	var s StatsSnapshot
	for _, line := range lines {
		parseLine(line, &s)
	}
	return s
}

func parseLine(line string, s *StatsSnapshot) {
	var key, val string
	for _, field := range splitFields(line) {
		for i := 0; i < len(field); i++ {
			if field[i] == '=' {
				key = field[:i]
				val = field[i+1:]
				break
			}
		}
		if key == "" {
			continue
		}
		assignField(key, val, s)
	}
}

func splitFields(s string) []string {
	var fields []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' {
			if i > start {
				fields = append(fields, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		fields = append(fields, s[start:])
	}
	return fields
}

func parseFloat(s string) float64 {
	n := len(s)
	if n > 2 && s[n-2:] == "ms" {
		s = s[:n-2]
	}
	var f float64
	_, _ = fmt.Sscanf(s, "%f", &f)
	return f
}

func assignField(key, val string, s *StatsSnapshot) {
	switch key {
	case "entries":
		_, _ = fmt.Sscanf(val, "%d", &s.Entries)
	case "total":
		_, _ = fmt.Sscanf(val, "%d", &s.Total)
	case "avg":
		s.AvgMS = parseFloat(val)
	case "hits":
		_, _ = fmt.Sscanf(val, "%d", &s.Hits)
	case "misses":
		_, _ = fmt.Sscanf(val, "%d", &s.Misses)
	case "stales":
		_, _ = fmt.Sscanf(val, "%d", &s.Stales)
	case "zones":
		_, _ = fmt.Sscanf(val, "%d", &s.Zones)
	case "errors":
		_, _ = fmt.Sscanf(val, "%d", &s.Errors)
	case "blocked":
		_, _ = fmt.Sscanf(val, "%d", &s.Blocked)
	case "badcookie":
		_, _ = fmt.Sscanf(val, "%d", &s.BadCookie)
	case "noerr":
		_, _ = fmt.Sscanf(val, "%d", &s.NOERR)
	case "formerr":
		_, _ = fmt.Sscanf(val, "%d", &s.FormErr)
	case "servfail":
		_, _ = fmt.Sscanf(val, "%d", &s.ServFail)
	case "nx":
		_, _ = fmt.Sscanf(val, "%d", &s.NXDomain)
	case "nimp":
		_, _ = fmt.Sscanf(val, "%d", &s.NotImp)
	case "ref":
		_, _ = fmt.Sscanf(val, "%d", &s.Refused)
	case "udp":
		_, _ = fmt.Sscanf(val, "%d", &s.UDP)
	case "tcp":
		_, _ = fmt.Sscanf(val, "%d", &s.TCP)
	case "tls":
		_, _ = fmt.Sscanf(val, "%d", &s.TLS)
	case "quic":
		_, _ = fmt.Sscanf(val, "%d", &s.QUIC)
	case "https":
		_, _ = fmt.Sscanf(val, "%d", &s.HTTPS)
	case "http3":
		_, _ = fmt.Sscanf(val, "%d", &s.HTTP3)
	case "dtls":
		_, _ = fmt.Sscanf(val, "%d", &s.DTLS)
	case "dnscrypt":
		_, _ = fmt.Sscanf(val, "%d", &s.DNSCrypt)
	case "dnscrypt-tcp":
		_, _ = fmt.Sscanf(val, "%d", &s.DNSCryptTCP)
	case "tlcp":
		_, _ = fmt.Sscanf(val, "%d", &s.TLCP)
	case "http-tlcp":
		_, _ = fmt.Sscanf(val, "%d", &s.HTTPTLCP)
	case "dtlcp":
		_, _ = fmt.Sscanf(val, "%d", &s.DTLCP)
	case "secure":
		_, _ = fmt.Sscanf(val, "%d", &s.Secure)
	case "insecure":
		_, _ = fmt.Sscanf(val, "%d", &s.Insecure)
	case "bogus":
		_, _ = fmt.Sscanf(val, "%d", &s.Bogus)
	case "poisoned":
		_, _ = fmt.Sscanf(val, "%d", &s.Poisoned)
	}
}
