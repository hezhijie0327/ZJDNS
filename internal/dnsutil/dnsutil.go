// Package dnsutil provides utility functions for DNS operations.
package dnsutil

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// HandshakeInfo carries the negotiated parameters from a TLS, TLCP, DTLS, or
// DTLCP handshake.  Zero-value fields are omitted from the log output.
//
// This type lives in dnsutil (a foundation package) rather than in the TLS or
// TLCP protocol packages to break the import cycle: both server/protocol/tls
// and server/protocol/tlcp (and their dtls/dtlcp counterparts) would need to
// import a shared HandshakeInfo type, but each protocol package may import
// dnsutil for other helpers.  A type in a third shared package would create
// the same cycle since neither protocol can import the other.
type HandshakeInfo struct {
	Role       string // log prefix: "TLS", "TLCP", "UPSTREAM"
	Direction  string // "handshake from" (server) or "negotiated for" (client)
	RemoteAddr string // peer address, hostname, or "client"
	Version    uint16 // protocol version codepoint (0 if unknown, e.g. DTLS)
	Cipher     string // cipher suite name (e.g. "TLS_AES_256_GCM_SHA384", "ECC_SM4_GCM_SM3")
	Group      string // key exchange group (e.g. "X25519", "SM2"; empty if N/A)
	Resumed    bool   // session resumption
	ALPN       string // negotiated ALPN protocol (empty if none)
}

// DNSFramePrefixLen is the number of bytes used for the 2-byte DNS message
// length prefix in TCP, DoT, and DoQ transports (RFC 1035 §4.2.2, RFC 9250).
const (
	DNSFramePrefixLen        = 2
	defaultPanicStackBufSize = 8192
)

var dangerousPrefixes = []string{"/etc/", "/proc/", "/sys/", "/dev/", "/run/"}

// IsSecureProtocol reports whether the protocol is an encrypted DNS transport.
// Accepts the config.Proto* constant values (e.g. "tls", "quic", "dnscrypt").
// Strings are hardcoded because this internal package cannot import the config
// package.  Keep in sync with the Proto* constants in config/defaults.go.
func IsSecureProtocol(protocol string) bool {
	switch protocol {
	case "tls", "quic", "https", "http3", "dtls", "tlcp", "http-tlcp", "dtlcp", "dnscrypt", "dnscrypt-tcp":
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
// The 8KB stack buffer allocates on every call, but panics are rare events
// so per-call allocation is acceptable.
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

// IsValidFilePath validates a file path for security and existence.
func IsValidFilePath(path string) bool {
	abs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	// Resolve symlinks BEFORE cleaning: a .. component traverses through the
	// symlink target (e.g. /tmp/link -> /etc, then /tmp/link/../passwd), so
	// resolving first prevents symlink-based traversal (e.g. /tmp/link ->
	// /etc/passwd). Clean afterwards so the prefix check sees the real path.
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = filepath.Clean(resolved)
	} else {
		abs = filepath.Clean(abs)
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
// ExtractIP accepts any to also handle *dns.A and *dns.AAAA directly;
// ExtractIPString below accepts dns.RR for type-safety at the call site.
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
		if r.Addr.IsValid() {
			return r.Addr.String(), true
		}
	case *dns.AAAA:
		if r.Addr.IsValid() {
			return r.Addr.String(), true
		}
	}
	return "", false
}

// LogHandshake emits a debug-level log of the negotiated handshake parameters.
// It is shared by server-side listeners (inbound) and upstream clients (outbound)
// across all secure transports: TLS, DTLS, TLCP, and DTLCP.
//
// Called once per handshake — path is not hot, but we pre-size the buffer and
// avoid strconv allocations to keep it cheap.
func LogHandshake(info *HandshakeInfo) {
	if info == nil {
		return
	}
	if !log.IsDebug() {
		return
	}
	var buf strings.Builder
	buf.Grow(128) // typical line ~100-140 bytes; avoid reallocation
	buf.WriteString(info.Role)
	buf.WriteString(": ")
	buf.WriteString(info.Direction)
	buf.WriteByte(' ')
	buf.WriteString(info.RemoteAddr)
	buf.WriteString(" —")
	if info.Version != 0 {
		buf.WriteString(" version=0x")
		var vbuf [8]byte
		s := strconv.AppendUint(vbuf[:0], uint64(info.Version), 16)
		buf.Write(s)
	}
	buf.WriteString(" cipher=")
	buf.WriteString(info.Cipher)
	if info.Group != "" {
		buf.WriteString(" group=")
		buf.WriteString(info.Group)
	}
	if info.Resumed {
		buf.WriteString(" resumed=true")
	}
	if info.ALPN != "" {
		buf.WriteString(" alpn=")
		buf.WriteString(info.ALPN)
	}
	log.Debugf("TLS: %s", buf.String())
}

// IsTemporaryError reports whether err is a temporary network error (timeout)
// or contains "timeout"/"temporary" in its message.  Used by accept loops and
// connection handlers to distinguish transient failures from permanent ones.
func IsTemporaryError(err error) bool {
	if err == nil {
		return false
	}
	ne, ok := errors.AsType[net.Error](err)
	if ok && ne.Timeout() {
		return true
	}
	// Some wrapped errors (e.g., from quic-go or io.Pipe) do not implement
	// net.Error or have lost the interface via wrapping, so we fall back to
	// substring matching as a best-effort heuristic.  This is deliberately
	// limited to "timeout" and "temporary" — the two canonical transient
	// failure keywords — to avoid false positives from unrelated error text.
	return strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "temporary")
}

// CloneRRs returns a deep copy of a slice of RRs. Each RR is cloned via its
// Clone method, which copies the header and record data; nil entries are
// preserved as nil.
func CloneRRs(rrs []dns.RR) []dns.RR {
	if len(rrs) == 0 {
		return nil
	}
	out := make([]dns.RR, len(rrs))
	for i, rr := range rrs {
		if rr != nil {
			out[i] = rr.Clone()
		}
	}
	return out
}
