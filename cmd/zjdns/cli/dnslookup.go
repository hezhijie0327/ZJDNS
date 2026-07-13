package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
	"zjdns/config"
	"zjdns/server/client"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	zdnsutil "zjdns/internal/dnsutil"
)

// dnslookupResult wraps the query outcome for JSON output.
type dnslookupResult struct {
	Server     string   `json:"server"`
	Protocol   string   `json:"protocol"`
	DurationMs int64    `json:"duration_ms"`
	Response   *dns.Msg `json:"response,omitempty"`
	Error      string   `json:"error,omitempty"`
}

// parseServerURL maps a user-provided server URL to a protocol string and
// address suitable for config.UpstreamServer. The scheme determines the
// protocol:
//
//	(no prefix)       → udp (port 53)
//	tcp://host:port   → tcp (port 53)
//	tls://, dot://    → dot (port 853)
//	quic://, doq://   → doq (port 853)
//	https://, doh://  → doh (port 443)
//	h3://, doh3://    → doh3 (port 443)
//	sdns://...        → dnscrypt
func parseServerURL(raw string) (proto, addr string, err error) {
	// DNSCrypt stamp — pass through as-is.
	if strings.HasPrefix(raw, "sdns://") {
		return config.ProtoDNSCrypt, raw, nil
	}

	// No scheme → plain UDP DNS.
	if !strings.Contains(raw, "://") {
		return config.ProtoUDP, joinHostPort(raw, "53"), nil
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", "", fmt.Errorf("invalid server URL %q: %w", raw, err)
	}

	switch strings.ToLower(u.Scheme) {
	case "tcp":
		return config.ProtoTCP, joinHostPort(u.Host, "53"), nil
	case "tls", "dot":
		return config.ProtoDOT, joinHostPort(u.Host, "853"), nil
	case "quic", "doq":
		return config.ProtoDOQ, joinHostPort(u.Host, "853"), nil
	case "https", "doh":
		return config.ProtoDOH, raw, nil
	case "h3", "doh3":
		return config.ProtoDOH3, raw, nil
	default:
		return "", "", fmt.Errorf("unsupported protocol scheme %q in %q", u.Scheme, raw)
	}
}

// joinHostPort appends defaultPort to host if no port is already present.
func joinHostPort(host, defaultPort string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, defaultPort)
}

// extractServerName returns the hostname from addr for use as TLS SNI.
func extractServerName(proto, addr string) string {
	if proto == config.ProtoDOH || proto == config.ProtoDOH3 {
		if u, err := url.Parse(addr); err == nil {
			return u.Hostname()
		}
		return ""
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return host
}

// execDNSLookup executes a DNS query and prints the result.
func execDNSLookup(serverURL, domain string, qtype, qclass uint16, insecure, dnssec, jsonOut bool) error {
	proto, addr, err := parseServerURL(serverURL)
	if err != nil {
		return err
	}

	// Build DNS message.
	msg := new(dns.Msg)
	dnsutil.SetQuestion(msg, dnsutil.Fqdn(domain), qtype)
	if dnssec {
		msg.UDPSize = 1232
		msg.Security = true // DNSSEC OK (DO) bit
	}

	// Build upstream server config.
	server := &config.UpstreamServer{
		Address:       addr,
		Protocol:      proto,
		SkipTLSVerify: insecure,
	}

	// Set ServerName for TLS SNI on secure protocols (not needed for sdns://).
	if zdnsutil.IsSecureProtocol(proto) && !strings.HasPrefix(addr, "sdns://") {
		server.ServerName = extractServerName(proto, addr)
	}

	// Execute query.
	c := client.New()
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), config.DefaultDNSQueryTimeout)
	defer cancel()

	start := time.Now()
	result := c.ExecuteQuery(ctx, msg, server)
	elapsed := time.Since(start)

	if jsonOut {
		return printDNSLookupJSON(serverURL, proto, elapsed, result)
	}
	return printDNSLookupText(serverURL, proto, elapsed, result)
}

// printDNSLookupText prints the query result in human-readable dig-like format.
func printDNSLookupText(serverURL, proto string, elapsed time.Duration, result *client.Result) error {
	fmt.Printf("; Server: %s\n", serverURL)
	fmt.Printf("; Protocol: %s\n", proto)
	fmt.Printf("; Duration: %s\n\n", elapsed.Round(time.Microsecond))

	if result.Error != nil {
		return fmt.Errorf("query failed: %w", result.Error)
	}

	fmt.Println(result.Response)
	return nil
}

// printDNSLookupJSON prints the query result as JSON.
func printDNSLookupJSON(serverURL, proto string, elapsed time.Duration, result *client.Result) error {
	out := dnslookupResult{
		Server:     serverURL,
		Protocol:   proto,
		DurationMs: elapsed.Milliseconds(),
	}

	if result.Error != nil {
		out.Error = result.Error.Error()
	} else if result.Response != nil {
		out.Response = result.Response
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
