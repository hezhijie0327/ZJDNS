// Package dnsutil provides utility functions for DNS operations.
package dnsutil

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"codeberg.org/miekg/dns"
	dnsutilv2 "codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"

	"zjdns/internal/log"
)

// DNSFramePrefixLen is the number of bytes used for the 2-byte DNS message
// length prefix in TCP, DoT, and DoQ transports (RFC 1035 §4.2.2, RFC 9250).
const (
	DNSFramePrefixLen        = 2
	defaultPanicStackBufSize = 8192
)

var dangerousPrefixes = []string{"/etc/", "/proc/", "/sys/", "/dev/", "/run/"}

// MaxLabelLength is the maximum length of a single DNS label per RFC 1035 §2.3.4.
const MaxLabelLength = 63

// NormalizeDomain converts a domain name to lowercase and removes the trailing
// dot. Uses sub-slicing (zero-alloc) instead of strings.TrimSuffix to avoid
// allocation on the hot path.
func NormalizeDomain(domain string) string {
	if len(domain) > 0 && domain[len(domain)-1] == '.' {
		domain = domain[:len(domain)-1]
	}
	return strings.ToLower(domain)
}

// IsValidDomainLabels checks that each label in the domain name does not exceed
// the RFC 1035 maximum of 63 bytes. Returns true if all labels are valid.
func IsValidDomainLabels(domain string) bool {
	// Strip trailing dot(s) without allocation (sub-slicing).
	if len(domain) > 0 && domain[len(domain)-1] == '.' {
		domain = domain[:len(domain)-1]
	}
	if domain == "" {
		return true // root zone
	}
	// Scan labels without allocating a string slice.
	for len(domain) > 0 {
		dot := strings.IndexByte(domain, '.')
		if dot < 0 {
			return len(domain) <= MaxLabelLength
		}
		if dot > MaxLabelLength {
			return false
		}
		domain = domain[dot+1:]
	}
	return true
}

// IsSecureProtocol reports whether the protocol is a secure DNS transport.
// Accepts both canonical names (tls, quic, https, http3) and user-facing
// aliases (dot, doq, doh, doh3).
func IsSecureProtocol(protocol string) bool {
	switch protocol {
	case "tls", "dot", "quic", "doq", "https", "doh", "http3", "doh3":
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
// into a net.IP.
func ParseReverseDNSName(name string) net.IP {
	fqdn := strings.TrimSuffix(dnsutilv2.Fqdn(name), ".")
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

// NewPTRRecord returns a DNS PTR record.
func NewPTRRecord(name, target string, ttl uint32, qclass uint16) dns.RR {
	return &dns.PTR{
		Hdr: dns.Header{
			Name:  dnsutilv2.Fqdn(name),
			Class: qclass,
			TTL:   ttl,
		},
		PTR: rdata.PTR{Ptr: dnsutilv2.Fqdn(target)},
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
func LogTLSConnectionState(role, dir, addr string, version uint16, cipherSuite uint16, curveID interface{ String() string }) {
	log.Debugf("%s: TLS %s %s — version(codepoint)=0x%04X, group(name)=%s, cipher(codepoint)=0x%04X",
		role, dir, addr, version, curveID, cipherSuite)
}

// JoinDNSPort appends the default DNS port (53) to an IP address string,
// producing an "ip:53" pair suitable for use as a nameserver address.
func JoinDNSPort(ip string) string {
	return net.JoinHostPort(ip, "53")
}
