// Package main implements ZJDNS - High Performance DNS Server
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// =============================================================================
// Protocol and Security Helpers
// =============================================================================

// IsSecureProtocol checks if the protocol is secure (TLS/QUIC/HTTPS)
func IsSecureProtocol(protocol string) bool {
	switch protocol {
	case "tls", "quic", "https", "http3":
		return true
	default:
		return false
	}
}

// =============================================================================
// File and Path Helpers
// =============================================================================

// IsValidFilePath checks if a file path is safe and exists
func IsValidFilePath(path string) bool {
	dangerousPrefixes := []string{"/etc/", "/proc/", "/sys/"}
	if strings.Contains(path, "..") || slices.ContainsFunc(dangerousPrefixes, func(prefix string) bool {
		return strings.HasPrefix(path, prefix)
	}) {
		return false
	}

	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// =============================================================================
// Domain Helpers
// =============================================================================

// NormalizeDomain normalizes a domain name to lowercase and removes trailing dot
func NormalizeDomain(domain string) string {
	return strings.ToLower(strings.TrimSuffix(domain, "."))
}

// ParseReverseDNSName parses a PTR query name into an IP address.
// It supports IPv4 reverse names under in-addr.arpa and IPv6 reverse names
// under ip6.arpa.
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

// BuildPTRRecord creates a PTR record for the given query name and target.
func BuildPTRRecord(name, target string, ttl uint32, qclass uint16) dns.RR {
	if ttl == 0 {
		ttl = DefaultTTL
	}
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

// =============================================================================
// Error Helpers
// =============================================================================

// IsTemporaryError checks if an error is temporary/recoverable
func IsTemporaryError(err error) bool {
	if err == nil {
		return false
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	return strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "temporary")
}

// =============================================================================
// Panic Handler
// =============================================================================

// HandlePanic recovers from panics and logs the stack trace
func HandlePanic(operation string) {
	if r := recover(); r != nil {
		buf := make([]byte, TCPBufferSize)
		n := runtime.Stack(buf, false)
		stackTrace := string(buf[:n])
		LogError("PANIC: Panic [%s]: %v\nStack:\n%s\nExiting due to panic", operation, r, stackTrace)
		os.Exit(1)
	}
}

// =============================================================================
// Client IP Helpers
// =============================================================================

// GetClientIP extracts client IP from DNS response writer
func GetClientIP(w dns.ResponseWriter) net.IP {
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

// GetClientIPFromMsg extracts client IP from a DNS message (for cookie validation)
func GetClientIPFromMsg(msg *dns.Msg) net.IP {
	if msg == nil {
		return nil
	}
	// Try to extract from EDNS0 ECS if available
	if opt := msg.IsEdns0(); opt != nil {
		for _, option := range opt.Option {
			if subnet, ok := option.(*dns.EDNS0_SUBNET); ok {
				return subnet.Address
			}
		}
	}
	return nil
}

// GetSecureClientIP extracts client IP from secure connection
func GetSecureClientIP(conn any) net.IP {
	switch c := conn.(type) {
	case *net.Conn:
		if addr, ok := (*c).RemoteAddr().(*net.TCPAddr); ok {
			return addr.IP
		}
	case interface{ RemoteAddr() net.Addr }:
		if addr, ok := c.RemoteAddr().(*net.TCPAddr); ok {
			return addr.IP
		}
	}
	return nil
}

// =============================================================================
// Resource Cleanup
// =============================================================================

// CloseWithLog closes a resource and logs any errors
func CloseWithLog(c any, name string) {
	if c == nil {
		return
	}
	if closer, ok := c.(interface{ Close() error }); ok {
		if err := closer.Close(); err != nil {
			LogWarn("SERVER: Close %s failed: %v", name, err)
		}
	}
}

// =============================================================================
// Record Helpers
// =============================================================================

// CreateCompactRecord creates a compact representation of a DNS record
func CreateCompactRecord(rr dns.RR) *CompactRecord {
	if rr == nil {
		return nil
	}
	return &CompactRecord{
		Text:    rr.String(),
		OrigTTL: rr.Header().Ttl,
		Type:    rr.Header().Rrtype,
	}
}

// ExpandRecord expands a compact record back to a DNS RR
func ExpandRecord(cr *CompactRecord) dns.RR {
	if cr == nil || cr.Text == "" {
		return nil
	}
	rr, _ := dns.NewRR(cr.Text)
	return rr
}

// compactRecords converts DNS RRs to compact records
func compactRecords(rrs []dns.RR) []*CompactRecord {
	if len(rrs) == 0 {
		return nil
	}

	seen := make(map[string]bool, len(rrs))
	result := make([]*CompactRecord, 0, len(rrs))

	for _, rr := range rrs {
		if rr == nil || rr.Header().Rrtype == dns.TypeOPT {
			continue
		}

		rrText := rr.String()
		if !seen[rrText] {
			seen[rrText] = true
			if cr := CreateCompactRecord(rr); cr != nil {
				result = append(result, cr)
			}
		}
	}
	return result
}

// ExpandRecords expands compact records to DNS RRs
func ExpandRecords(crs []*CompactRecord) []dns.RR {
	if len(crs) == 0 {
		return nil
	}
	result := make([]dns.RR, 0, len(crs))
	for _, cr := range crs {
		if rr := ExpandRecord(cr); rr != nil {
			result = append(result, rr)
		}
	}
	return result
}

// ProcessRecords processes DNS records for response
func ProcessRecords(rrs []dns.RR, ttl uint32, includeDNSSEC bool) []dns.RR {
	if len(rrs) == 0 {
		return nil
	}

	result := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		if rr == nil {
			continue
		}

		if !includeDNSSEC {
			switch rr.(type) {
			case *dns.RRSIG, *dns.NSEC, *dns.NSEC3, *dns.DNSKEY, *dns.DS:
				continue
			}
		}

		newRR := dns.Copy(rr)
		if newRR != nil {
			if ttl > 0 {
				newRR.Header().Ttl = ttl
			}
			result = append(result, newRR)
		}
	}
	return result
}

// =============================================================================
// Cache Key and TTL Helpers
// =============================================================================

// BuildCacheKey generates a cache key from question and options
func BuildCacheKey(question dns.Question, ecs *ECSOption, clientRequestedDNSSEC bool, globalPrefix string) string {
	var buf strings.Builder
	buf.Grow(ResultBufferCapacity)

	buf.WriteString(globalPrefix)
	buf.WriteString(RedisPrefixDNS)

	buf.WriteString(NormalizeDomain(question.Name))
	buf.WriteByte(':')

	buf.WriteString(strconv.FormatUint(uint64(question.Qtype), 10))
	buf.WriteByte(':')
	buf.WriteString(strconv.FormatUint(uint64(question.Qclass), 10))

	if ecs != nil {
		buf.WriteString(":ecs:")
		buf.WriteString(ecs.Address.String())
		buf.WriteByte('/')
		buf.WriteString(strconv.FormatUint(uint64(ecs.SourcePrefix), 10))
	}

	if clientRequestedDNSSEC {
		buf.WriteString(":dnssec")
	}

	result := buf.String()
	if len(result) > MaxResultLength {
		hash := fnv.New64a()
		hash.Write([]byte(result))
		return fmt.Sprintf("h:%x", hash.Sum64())
	}
	return result
}

// calculateTTL calculates the minimum TTL from DNS records
func calculateTTL(rrs []dns.RR) int {
	if len(rrs) == 0 {
		return DefaultTTL
	}

	minTTL := int(rrs[0].Header().Ttl)
	for _, rr := range rrs {
		if rr == nil {
			continue
		}
		if ttl := int(rr.Header().Ttl); ttl > 0 && (minTTL == 0 || ttl < minTTL) {
			minTTL = ttl
		}
	}

	if minTTL <= 0 {
		minTTL = DefaultTTL
	}

	return minTTL
}

func cloneCompactRecords(records []*CompactRecord) []*CompactRecord {
	if len(records) == 0 {
		return nil
	}

	cloned := make([]*CompactRecord, len(records))
	for i, r := range records {
		if r == nil {
			continue
		}
		rr := *r
		cloned[i] = &rr
	}
	return cloned
}

func cloneCacheEntry(entry *CacheEntry) *CacheEntry {
	if entry == nil {
		return nil
	}

	cloned := *entry
	cloned.Answer = cloneCompactRecords(entry.Answer)
	cloned.Authority = cloneCompactRecords(entry.Authority)
	cloned.Additional = cloneCompactRecords(entry.Additional)
	return &cloned
}

// =============================================================================
// Server Helpers
// =============================================================================

// ExtractIPsFromServers extracts IP addresses from server addresses
func ExtractIPsFromServers(servers []string) []string {
	ips := make([]string, len(servers))
	for i, server := range servers {
		host, _, err := net.SplitHostPort(server)
		if err != nil {
			ips[i] = server
		} else {
			ips[i] = host
		}
	}
	return ips
}

// ToRRSlice converts a typed slice to dns.RR slice
func ToRRSlice[T dns.RR](records []T) []dns.RR {
	result := make([]dns.RR, len(records))
	for i, r := range records {
		result[i] = r
	}
	return result
}

// =============================================================================
// Concurrency Helpers
// =============================================================================

// shuffleSlice shuffles a slice randomly
func shuffleSlice[T any](slice []T) []T {
	if len(slice) <= 1 {
		return slice
	}

	shuffled := make([]T, len(slice))
	copy(shuffled, slice)

	for i := len(shuffled) - 1; i > 0; i-- {
		j := globalRNG.Intn(i + 1)
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	}

	return shuffled
}

// calculateConcurrencyLimit calculates the concurrency limit based on server count
func calculateConcurrencyLimit(serverCount int) int {
	if serverCount <= 0 {
		return 1
	}

	switch {
	case serverCount <= 4:
		return serverCount
	case serverCount <= 12:
		return (serverCount*2 + 2) / 3
	case serverCount <= 20:
		return (serverCount + 1) / 2
	default:
		limit := serverCount / 3
		if limit < 8 {
			return 8
		}
		return limit
	}
}

// =============================================================================
// Version Info
// =============================================================================

// getVersion returns the version string
func getVersion() string {
	return fmt.Sprintf("v%s-%s@%s (%s)", Version, CommitHash, BuildTime, runtime.Version())
}

// =============================================================================
// Example Config Generation
// =============================================================================

// GenerateExampleConfig generates an example configuration
func GenerateExampleConfig() string {
	cm := &ConfigManager{}
	config := cm.getDefaultConfig()

	config.Redis.Address = "127.0.0.1:6379"

	config.Server.Pprof = DefaultPprofPort
	config.Server.LogLevel = DefaultLogLevel
	config.Server.DefaultECS = "auto"
	config.Server.StatsInterval = 0
	config.Server.Stats = &StatsSettings{}
	config.Server.TLS.CertFile = "/path/to/cert.pem"
	config.Server.TLS.KeyFile = "/path/to/key.pem"

	config.Server.LatencyProbe = []LatencyProbeStep{
		{Protocol: "ping", Timeout: 100},
		{Protocol: "tcp", Port: 443, Timeout: 100},
		{Protocol: "tcp", Port: 80, Timeout: 100},
		{Protocol: "udp", Port: 53, Timeout: 100},
		{Protocol: "http", Port: 80, Timeout: 100},
		{Protocol: "https", Port: 443, Timeout: 100},
		{Protocol: "http3", Port: 443, Timeout: 100},
	}

	config.CIDR = []CIDRConfig{
		{File: "whitelist.txt", Tag: "file"},
		{Rules: []string{"192.168.0.0/16", "10.0.0.0/8", "2001:db8::/32"}, Tag: "rules"},
		{File: "blacklist.txt", Rules: []string{"127.0.0.1/32"}, Tag: "mixed"},
	}

	config.Upstream = []UpstreamServer{
		{Address: "223.5.5.5:53", Protocol: "tcp"},
		{Address: "223.6.6.6:53", Protocol: "udp"},
		{Address: "223.5.5.5:853", Protocol: "tls", ServerName: "dns.alidns.com"},
		{Address: "223.6.6.6:853", Protocol: "quic", ServerName: "dns.alidns.com", SkipTLSVerify: true},
		{Address: "https://223.5.5.5:443/dns-query", Protocol: "https", ServerName: "dns.alidns.com", Match: []string{"mixed"}},
		{Address: "https://223.6.6.6:443/dns-query", Protocol: "http3", ServerName: "dns.alidns.com", Match: []string{"!mixed"}},
		{Address: RecursiveIndicator},
	}

	config.Fallback = []UpstreamServer{
		{Address: "builtin_recursive"},
	}

	config.Rewrite = []RewriteRule{
		{ExcludeClients: []string{"10.0.0.100"}},
		{Name: "client-specific.example.com", IncludeClients: []string{"192.168.0.0/24"}, Records: []DNSRecordConfig{{Type: "A", Content: "127.0.0.1", TTL: DefaultTTL}}},
		{Name: "blocked.example.com", ExcludeClients: []string{"192.168.1.0/24"}, Records: []DNSRecordConfig{{Type: "A", Content: "127.0.0.1", TTL: DefaultTTL}}},
		{Name: "ipv6.blocked.example.com", Records: []DNSRecordConfig{{Type: "AAAA", Content: "::1", TTL: DefaultTTL}}},
	}

	data, _ := json.MarshalIndent(config, "", "  ")
	return string(data)
}

// =============================================================================
// IPDetector Implementation
// =============================================================================

// detectPublicIP detects the public IP address using Cloudflare's trace service
func (d *IPDetector) detectPublicIP(forceIPv6 bool) net.IP {
	if d == nil {
		return nil
	}

	// Create transport with forced IPv4 or IPv6
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: DefaultTimeout}
			if forceIPv6 {
				return dialer.DialContext(ctx, "tcp6", addr)
			}
			return dialer.DialContext(ctx, "tcp4", addr)
		},
	}

	client := &http.Client{Timeout: OperationTimeout, Transport: transport}
	defer transport.CloseIdleConnections()

	// Use Cloudflare's trace service for IP detection
	resp, err := client.Get("https://api.cloudflare.com/cdn-cgi/trace")
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	// Parse IP from response
	re := regexp.MustCompile(`ip=([^\s\n]+)`)
	matches := re.FindStringSubmatch(string(body))
	if len(matches) < 2 {
		return nil
	}

	ip := net.ParseIP(matches[1])
	if ip == nil {
		return nil
	}

	// Validate IP version matches request
	if forceIPv6 && ip.To4() != nil {
		return nil
	}
	if !forceIPv6 && ip.To4() == nil {
		return nil
	}

	return ip
}

// FormatAllRecords outputs raw DNS records with section headers for logging.
func FormatAllRecords(answers, authority, additional []dns.RR) string {
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
