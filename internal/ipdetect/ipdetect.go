// Package ipdetect detects public IP addresses via external service.
package ipdetect

import (
	"context"
	"io"
	"net"
	"net/http"
	"regexp"
	"time"
)

// DefaultTraceURL is the default endpoint used for public IP detection.
const DefaultTraceURL = "https://api.cloudflare.com/cdn-cgi/trace"

// IP detection timeouts.
const (
	ipDetectDialTimeout = 2 * time.Second
	ipDetectTimeout     = 3 * time.Second
)

var ipPattern = regexp.MustCompile(`ip=([^\s\n]+)`)

// Detector detects public IP addresses via an HTTP trace endpoint.
type Detector struct {
	// TraceURL is the HTTP(S) endpoint used for IP detection.
	// If empty, DefaultTraceURL is used.
	TraceURL string
}

// IPv4 returns the detected public IPv4 address.
func (d *Detector) IPv4() net.IP { return d.detect(false) }

// IPv6 returns the detected public IPv6 address.
func (d *Detector) IPv6() net.IP { return d.detect(true) }

func (d *Detector) detect(forceIPv6 bool) net.IP {
	traceURL := d.TraceURL
	if traceURL == "" {
		traceURL = DefaultTraceURL
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: ipDetectDialTimeout}
			if forceIPv6 {
				return dialer.DialContext(ctx, "tcp6", addr)
			}
			return dialer.DialContext(ctx, "tcp4", addr)
		},
	}
	client := &http.Client{Timeout: ipDetectTimeout, Transport: transport}
	defer transport.CloseIdleConnections()

	resp, err := client.Get(traceURL)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	matches := ipPattern.FindStringSubmatch(string(body))
	if len(matches) < 2 {
		return nil
	}
	ip := net.ParseIP(matches[1])
	if ip == nil {
		return nil
	}
	if forceIPv6 && ip.To4() != nil {
		return nil
	}
	if !forceIPv6 && ip.To4() == nil {
		return nil
	}
	return ip
}
