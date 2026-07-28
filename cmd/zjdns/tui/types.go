// Package tui provides the Bubble Tea terminal dashboard for ZJDNS.
package tui

import (
	"strconv"
	"strings"
)

// QueryEvent is a TUI-friendly query log entry, matching the server wire format.
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

// StatsSnapshot holds a structured snapshot of aggregated query statistics.
// Parsed from cache.Store.Stats() output.
type StatsSnapshot struct {
	Entries   int64   `json:"entries"`
	Total     int64   `json:"total"`
	AvgMS     float64 `json:"avg_ms"`
	Hits      int64   `json:"hits"`
	Misses    int64   `json:"misses"`
	Stales    int64   `json:"stales"`
	Zones     int64   `json:"zones"`
	Errors    int64   `json:"errors"`
	Blocked   int64   `json:"blocked"`
	BadCookie int64   `json:"badcookie"`
	// RCODE distribution
	NOERR    int64 `json:"noerr"`
	FormErr  int64 `json:"formerr"`
	ServFail int64 `json:"servfail"`
	NXDomain int64 `json:"nxdomain"`
	NotImp   int64 `json:"notimp"`
	Refused  int64 `json:"refused"`
	// Protocol breakdown
	UDP, TCP, TLS, QUIC, HTTPS, HTTP3, DTLS      int64
	DNSCrypt, DNSCryptTCP, TLCP, HTTPTLCP, DTLCP int64
	// DNSSEC
	Secure, Insecure, Bogus, Poisoned int64
}

// ParseStats parses the []string returned by cache.Store.Stats() into a
// structured StatsSnapshot.  Unknown or malformed lines are silently ignored;
// the caller gets whatever was successfully parsed.
func ParseStats(lines []string) StatsSnapshot {
	var s StatsSnapshot
	for _, line := range lines {
		parseLine(line, &s)
	}
	return s
}

func parseLine(line string, s *StatsSnapshot) {
	pairs := strings.FieldsSeq(line)
	for pair := range pairs {
		key, val, ok := strings.Cut(pair, "=")
		if !ok {
			continue
		}
		switch key {
		case "entries":
			s.Entries, _ = strconv.ParseInt(val, 10, 64)
		case "total":
			s.Total, _ = strconv.ParseInt(val, 10, 64)
		case "avg":
			s.AvgMS = parseFloat(val)
		case "hits":
			s.Hits, _ = strconv.ParseInt(val, 10, 64)
		case "misses":
			s.Misses, _ = strconv.ParseInt(val, 10, 64)
		case "stales":
			s.Stales, _ = strconv.ParseInt(val, 10, 64)
		case "zones":
			s.Zones, _ = strconv.ParseInt(val, 10, 64)
		case "errors":
			s.Errors, _ = strconv.ParseInt(val, 10, 64)
		case "blocked":
			s.Blocked, _ = strconv.ParseInt(val, 10, 64)
		case "badcookie":
			s.BadCookie, _ = strconv.ParseInt(val, 10, 64)
		case "noerr":
			s.NOERR, _ = strconv.ParseInt(val, 10, 64)
		case "formerr":
			s.FormErr, _ = strconv.ParseInt(val, 10, 64)
		case "servfail":
			s.ServFail, _ = strconv.ParseInt(val, 10, 64)
		case "nx":
			s.NXDomain, _ = strconv.ParseInt(val, 10, 64)
		case "nimp":
			s.NotImp, _ = strconv.ParseInt(val, 10, 64)
		case "ref":
			s.Refused, _ = strconv.ParseInt(val, 10, 64)
		case "udp":
			s.UDP, _ = strconv.ParseInt(val, 10, 64)
		case "tcp":
			s.TCP, _ = strconv.ParseInt(val, 10, 64)
		case "tls":
			s.TLS, _ = strconv.ParseInt(val, 10, 64)
		case "quic":
			s.QUIC, _ = strconv.ParseInt(val, 10, 64)
		case "https":
			s.HTTPS, _ = strconv.ParseInt(val, 10, 64)
		case "http3":
			s.HTTP3, _ = strconv.ParseInt(val, 10, 64)
		case "dtls":
			s.DTLS, _ = strconv.ParseInt(val, 10, 64)
		case "dnscrypt":
			s.DNSCrypt, _ = strconv.ParseInt(val, 10, 64)
		case "dnscrypt-tcp":
			s.DNSCryptTCP, _ = strconv.ParseInt(val, 10, 64)
		case "tlcp":
			s.TLCP, _ = strconv.ParseInt(val, 10, 64)
		case "http-tlcp":
			s.HTTPTLCP, _ = strconv.ParseInt(val, 10, 64)
		case "dtlcp":
			s.DTLCP, _ = strconv.ParseInt(val, 10, 64)
		case "secure":
			s.Secure, _ = strconv.ParseInt(val, 10, 64)
		case "insecure":
			s.Insecure, _ = strconv.ParseInt(val, 10, 64)
		case "bogus":
			s.Bogus, _ = strconv.ParseInt(val, 10, 64)
		case "poisoned":
			s.Poisoned, _ = strconv.ParseInt(val, 10, 64)
		}
	}
}

func parseFloat(s string) float64 {
	// strip trailing "ms" suffix and parse
	s = strings.TrimSuffix(s, "ms")
	f, _ := strconv.ParseFloat(s, 64)
	return f
}
