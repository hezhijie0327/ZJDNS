// Package ipdetect detects the server's public IP for ECS auto-configuration.
package ipdetect

import (
	"context"
	"io"
	"net"
	"net/http"
	"regexp"
	"time"
)

var ipPattern = regexp.MustCompile(`ip=([^\s\n]+)`)

// Detector detects public IP addresses via Cloudflare's trace service.
type Detector struct{}

// IPv4 returns the server's public IPv4 address.
func (d *Detector) IPv4() net.IP { return detect(false) }

// IPv6 returns the server's public IPv6 address.
func (d *Detector) IPv6() net.IP { return detect(true) }

func detect(forceIPv6 bool) net.IP {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: 2 * time.Second}
			if forceIPv6 {
				return dialer.DialContext(ctx, "tcp6", addr)
			}
			return dialer.DialContext(ctx, "tcp4", addr)
		},
	}
	client := &http.Client{Timeout: 3 * time.Second, Transport: transport}
	defer transport.CloseIdleConnections()

	resp, err := client.Get("https://api.cloudflare.com/cdn-cgi/trace")
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
