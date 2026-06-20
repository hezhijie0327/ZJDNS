// Package dnsutil provides DNS-related utility functions used across the server.
package dnsutil

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"zjdns/internal/log"

	"github.com/miekg/dns"
)

// NormalizeDomain lowercases the domain and removes the trailing dot.
func NormalizeDomain(domain string) string {
	return strings.ToLower(strings.TrimSuffix(domain, "."))
}

// IsSecureProtocol reports whether the protocol string represents an encrypted
// DNS transport (tls, quic, https, http3).
func IsSecureProtocol(protocol string) bool {
	switch protocol {
	case "tls", "quic", "https", "http3":
		return true
	default:
		return false
	}
}

// CloseWithLog attempts to close a resource and logs a warning on failure.
func CloseWithLog(c any, name string) {
	if c == nil {
		return
	}
	if closer, ok := c.(interface{ Close() error }); ok {
		if err := closer.Close(); err != nil {
			log.Warnf("SERVER: Close %s failed: %v", name, err)
		}
	}
}

// HandlePanic recovers from a panic in a goroutine, logs the stack trace, and
// allows the goroutine to exit cleanly. Unlike the original implementation,
// this does NOT call os.Exit — a single connection panic will not crash the
// entire server.
func HandlePanic(operation string) {
	if r := recover(); r != nil {
		buf := make([]byte, 4096)
		n := runtime.Stack(buf, false)
		log.Errorf("PANIC: Panic [%s]: %v\nStack:\n%s", operation, r, buf[:n])
	}
}

// ParseReverseDNSName parses a PTR query name into an IP address.
// Supports in-addr.arpa (IPv4) and ip6.arpa (IPv6) reverse names.
func ParseReverseDNSName(name string) net.IP {
	fqdn := strings.TrimSuffix(dns.Fqdn(name), ".")
	lower := strings.ToLower(fqdn)

	if strings.HasSuffix(lower, ".in-addr.arpa") {
		octets := strings.Split(strings.TrimSuffix(strings.TrimSuffix(lower, ".in-addr.arpa"), "."), ".")
		if len(octets) != 4 {
			return nil
		}
		for i, j := 0, len(octets)-1; i < j; i, j = i+1, j-1 {
			octets[i], octets[j] = octets[j], octets[i]
		}
		return net.ParseIP(strings.Join(octets, "."))
	}

	if strings.HasSuffix(lower, ".ip6.arpa") {
		nibbles := strings.Split(strings.TrimSuffix(strings.TrimSuffix(lower, ".ip6.arpa"), "."), ".")
		if len(nibbles) != 32 {
			return nil
		}
		for i, j := 0, len(nibbles)-1; i < j; i, j = i+1, j-1 {
			nibbles[i], nibbles[j] = nibbles[j], nibbles[i]
		}
		var builder strings.Builder
		for i, nibble := range nibbles {
			builder.WriteString(nibble)
			if i%4 == 3 && i != len(nibbles)-1 {
				builder.WriteByte(':')
			}
		}
		return net.ParseIP(builder.String())
	}

	return nil
}

// BuildPTRRecord creates a PTR DNS record.
func BuildPTRRecord(name, target string, ttl uint32, qclass uint16) dns.RR {
	return &dns.PTR{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(name),
			Rrtype: dns.TypePTR,
			Class:  qclass,
			Ttl:    ttl,
		},
		Ptr: dns.Fqdn(target),
	}
}

// ClientIP extracts the client IP address from a DNS response writer.
func ClientIP(w dns.ResponseWriter) net.IP {
	if addr := w.RemoteAddr(); addr != nil {
		switch a := addr.(type) {
		case *net.UDPAddr:
			return a.IP
		case *net.TCPAddr:
			return a.IP
		}
	}
	return nil
}

// FormatRecords formats DNS record sections for debug logging.
func FormatRecords(answers, authority, additional []dns.RR) string {
	var b strings.Builder
	if len(answers) > 0 {
		b.WriteString("\n  ;; ANSWER SECTION:")
		for _, rr := range answers {
			b.WriteString("\n  " + rr.String())
		}
	}
	if len(authority) > 0 {
		b.WriteString("\n  ;; AUTHORITY SECTION:")
		for _, rr := range authority {
			b.WriteString("\n  " + rr.String())
		}
	}
	if len(additional) > 0 {
		b.WriteString("\n  ;; ADDITIONAL SECTION:")
		for _, rr := range additional {
			b.WriteString("\n  " + rr.String())
		}
	}
	return b.String()
}

// IsValidFilePath checks if a path is safe (no traversal, no dangerous prefixes,
// no symlinks) and points to a regular file.
func IsValidFilePath(path string) bool {
	// Resolve absolute path and clean traversal components.
	abs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return false
	}
	// Reject paths with parent traversal after cleaning.
	if strings.Contains(abs, "..") {
		return false
	}
	// Block dangerous system directories after resolution.
	dangerousPrefixes := []string{"/etc/", "/proc/", "/sys/", "/dev/", "/run/"}
	for _, prefix := range dangerousPrefixes {
		if strings.HasPrefix(abs, prefix) {
			return false
		}
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return false
	}
	// Reject symlinks.
	if info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	return info.Mode().IsRegular()
}
