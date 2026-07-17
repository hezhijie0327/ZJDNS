// Package dnsutil provides utility functions for DNS operations.
package dnsutil

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// DNSFramePrefixLen is the number of bytes used for the 2-byte DNS message
// length prefix in TCP, DoT, and DoQ transports (RFC 1035 §4.2.2, RFC 9250).
const (
	DNSFramePrefixLen        = 2
	defaultPanicStackBufSize = 8192
)

var dangerousPrefixes = []string{"/etc/", "/proc/", "/sys/", "/dev/", "/run/"}

// TrimTrailingDot removes a single trailing dot from a DNS name using sub-slicing
// (zero-alloc) instead of strings.TrimSuffix (which allocates when the suffix is
// present). Returns the input unchanged if it is empty or doesn't end with '.'.
func TrimTrailingDot(s string) string {
	if s != "" && s[len(s)-1] == '.' {
		return s[:len(s)-1]
	}
	return s
}

// NormalizeDomain converts a domain name to lowercase and removes the trailing
// dot. Uses sub-slicing (zero-alloc) instead of strings.TrimSuffix to avoid
// allocation on the hot path.
func NormalizeDomain(domain string) string {
	return strings.ToLower(TrimTrailingDot(domain))
}

// IsSecureProtocol reports whether the protocol is a secure DNS transport.
// Accepts both canonical names (tls, quic, https, http3) and user-facing
// aliases (dot, doq, doh, doh3).  Strings are hardcoded because this
// internal package cannot import config for the Proto* constants.
func IsSecureProtocol(protocol string) bool {
	switch protocol {
	case "tls", "quic", "https", "http3", "dtls", "tlcp", "http-tlcp", "dtlcp":
		return true
	default:
		return false
	}
}

// CloseWithLog closes a resource and logs any error that occurs.
// The prefix parameter sets the log component prefix (e.g., "SERVER", "TLS").
func CloseWithLog(c io.Closer, name, prefix string) {
	if c == nil {
		return
	}
	if err := c.Close(); err != nil {
		log.Warnf("%s: Close %s failed: %v", prefix, name, err)
	}
}

// HandlePanic recovers from a panic and logs the stack trace.
func HandlePanic(operation string) {
	if r := recover(); r != nil {
		buf := make([]byte, defaultPanicStackBufSize)
		n := runtime.Stack(buf, false)
		log.Errorf("PANIC: Panic [%s]: %v\nStack:\n%s", operation, r, buf[:n])
	}
}

// ParseReverseDNSName parses a reverse DNS name (in-addr.arpa or ip6.arpa)
// into a net.IP.  Delegates to the library's dnsutil.AddrReverse and converts
// the netip.Addr result.
func ParseReverseDNSName(name string) net.IP {
	if !dnsutil.IsFqdn(name) {
		name = dnsutil.Fqdn(name)
	}
	addr := dnsutil.AddrReverse(name)
	if !addr.IsValid() {
		return nil
	}
	return net.IP(addr.AsSlice())
}

// NewPTRRecord returns a DNS PTR record.
func NewPTRRecord(name, target string, ttl uint32, qclass uint16) dns.RR {
	return &dns.PTR{
		Hdr: dns.Header{
			Name:  dnsutil.Fqdn(name),
			Class: qclass,
			TTL:   ttl,
		},
		PTR: rdata.PTR{Ptr: dnsutil.Fqdn(target)},
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

// FormatRecords formats DNS answer, authority, and additional sections into a
// human-readable string.
func FormatRecords(answers, authority, additional []dns.RR) string {
	var b strings.Builder
	if len(answers) > 0 {
		b.WriteString("\n  ;; ANSWER SECTION:")
		for _, rr := range answers {
			b.WriteString("\n  ")
			b.WriteString(rr.String())
		}
	}
	if len(authority) > 0 {
		b.WriteString("\n  ;; AUTHORITY SECTION:")
		for _, rr := range authority {
			b.WriteString("\n  ")
			b.WriteString(rr.String())
		}
	}
	if len(additional) > 0 {
		b.WriteString("\n  ;; ADDITIONAL SECTION:")
		for _, rr := range additional {
			b.WriteString("\n  ")
			b.WriteString(rr.String())
		}
	}
	return b.String()
}

// IsValidFilePath validates a file path for security and existence.
func IsValidFilePath(path string) bool {
	abs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return false
	}

	for _, prefix := range dangerousPrefixes {
		if strings.HasPrefix(abs, prefix) {
			return false
		}
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return false
	}

	if info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	return info.Mode().IsRegular()
}

// ExtractIP returns the IP address from an A or AAAA DNS record, or nil if the
// record is neither type.
func ExtractIP(rr any) net.IP {
	switch r := rr.(type) {
	case *dns.A:
		if r.Addr.IsValid() {
			return net.IP(r.Addr.AsSlice())
		}
	case *dns.AAAA:
		if r.Addr.IsValid() {
			return net.IP(r.Addr.AsSlice())
		}
	}
	return nil
}

// ExtractIPString returns the IP address string from an A or AAAA record.
func ExtractIPString(rr dns.RR) (string, bool) {
	switch r := rr.(type) {
	case *dns.A:
		return r.A.String(), true
	case *dns.AAAA:
		return r.AAAA.String(), true
	}
	return "", false
}

// IsAOrAAAA reports whether rr is an A or AAAA record.
func IsAOrAAAA(rr dns.RR) bool {
	t := dns.RRToType(rr)
	return t == dns.TypeA || t == dns.TypeAAAA
}

// LogTLSConnectionState emits a debug-level log of the negotiated TLS version,
// key exchange group, and cipher suite. It is shared by both the upstream client
// (role="UPSTREAM", dir="negotiated for") and the server-side TLS listener
// (role="TLS", dir="handshake from").
//
// It accepts the individual fields to work with both crypto/tls.ConnectionState
// and go-extension/tls.ConnectionState without type coupling.
func LogTLSConnectionState(role, dir, addr string, version, cipherSuite uint16, curveID interface{ String() string }) {
	log.Debugf("%s: TLS %s %s — version(codepoint)=0x%04X, group(name)=%s, cipher(codepoint)=0x%04X",
		role, dir, addr, version, curveID, cipherSuite)
}

// JoinDNSPort appends the default DNS port (53) to an IP address string,
// producing an "ip:53" pair suitable for use as a nameserver address.
func JoinDNSPort(ip string) string {
	return net.JoinHostPort(ip, "53")
}

// IsTemporaryError reports whether err is a temporary network error (timeout)
// or contains "timeout"/"temporary" in its message.  Used by accept loops and
// connection handlers to distinguish transient failures from permanent ones.
func IsTemporaryError(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "temporary")
}

// CopyIP returns a deep copy of ip, allocating a new backing array.
func CopyIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	return append(net.IP(nil), ip...)
}
