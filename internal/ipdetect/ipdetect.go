// Package ipdetect detects public IP addresses via external services.
//
// Both detection paths use Cloudflare infrastructure: a DNS CHAOS TXT
// query (whoami.cloudflare) is tried first — the authoritative answer
// carries the querying client's source IP — with the HTTP trace endpoint
// (api.cloudflare.com/cdn-cgi/trace) as automatic fallback.
package ipdetect

import (
	"context"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// Detector detects public IP addresses.  DNS detection (whoami.cloudflare)
// runs first, with the HTTP trace endpoint as automatic fallback.
type Detector struct {
	// TraceURL is the HTTP(S) trace endpoint used for the fallback path.
	// If empty, DefaultTraceURL is used.
	TraceURL string
}

const (
	ipDetectDialTimeout = 2 * time.Second // dial timeout for detection probes
	ipDetectTimeout     = 3 * time.Second // overall detection timeout

	// DefaultTraceURL is the default HTTP trace endpoint used by the
	// fallback detection path.
	DefaultTraceURL = "https://api.cloudflare.com/cdn-cgi/trace"

	// whoamiDomain is Cloudflare's "who am I" CHAOS TXT record: the
	// authoritative answer carries the querying client's source IP.
	//
	// The query MUST go straight to Cloudflare's servers (1.1.1.1 /
	// 2606:4700:4700::1111) on the requested address family — the answer
	// is generated per client and must not be cached by an intermediate
	// resolver.
	whoamiDomain = "whoami.cloudflare"
)

var ipPattern = regexp.MustCompile(`ip=(\S+)`)

// IPv4 returns the detected public IPv4 address.
func (d *Detector) IPv4() net.IP { return d.detect(false) }

// IPv6 returns the detected public IPv6 address.
func (d *Detector) IPv6() net.IP { return d.detect(true) }

// detect is startup-only — called during server init to discover public IPs.
// DNS first (whoami.cloudflare), HTTP trace as fallback.
func (d *Detector) detect(forceIPv6 bool) net.IP {
	family := "IPv4"
	if forceIPv6 {
		family = "IPv6"
	}

	if ip := d.detectViaDNS(forceIPv6); ip != nil {
		log.Debugf("IPDETECT: %s -> DNS: %s", family, ip)
		return ip
	}
	log.Debugf("IPDETECT: %s DNS failed, trying HTTP fallback", family)

	if ip := d.detectViaHTTP(forceIPv6); ip != nil {
		log.Debugf("IPDETECT: %s -> HTTP: %s", family, ip)
		return ip
	}
	log.Warnf("IPDETECT: %s all methods failed", family)
	return nil
}

// detectViaDNS queries whoami.cloudflare (class CH, type TXT) and returns
// the public IP of the requested family.
func (d *Detector) detectViaDNS(forceIPv6 bool) net.IP {
	network := "udp4"
	server := "1.1.1.1:53"
	if forceIPv6 {
		network = "udp6"
		server = "[2606:4700:4700::1111]:53"
	}

	msg := new(dns.Msg)
	msg.Question = []dns.RR{&dns.TXT{
		Hdr: dns.Header{Name: dnsutil.Fqdn(whoamiDomain), Class: dns.ClassCHAOS},
	}}

	client := dns.NewClient()
	client.Dialer = &net.Dialer{Timeout: ipDetectDialTimeout}
	client.ReadTimeout = ipDetectTimeout
	client.WriteTimeout = ipDetectTimeout

	ctx, cancel := context.WithTimeout(context.Background(), ipDetectTimeout)
	defer cancel()
	resp, _, err := client.Exchange(ctx, msg, network, server)
	if err != nil || resp == nil {
		return nil
	}

	var txts []string
	for _, rr := range resp.Answer {
		if txt, ok := rr.(*dns.TXT); ok {
			txts = append(txts, txt.Txt...)
		}
	}
	return ipFromTXT(txts, forceIPv6)
}

// detectViaHTTP queries the HTTP trace endpoint and parses the "ip="
// field of the plain-text response.
func (d *Detector) detectViaHTTP(forceIPv6 bool) net.IP {
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
	defer func() { _ = resp.Body.Close() }() // _ = error: body close after read, best-effort

	// Any non-2xx is a failed detection — the body may be an error page
	// whose contents must not be interpreted as an IP.
	if resp.StatusCode != http.StatusOK {
		return nil
	}

	// Bound the body: TraceURL is operator-configurable and a hostile/
	// misconfigured endpoint must not buffer unbounded data at startup.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if err != nil {
		return nil
	}
	matches := ipPattern.FindStringSubmatch(string(body))
	if len(matches) < 2 {
		return nil
	}
	return validateDetectedIP(net.ParseIP(matches[1]), forceIPv6)
}

// ipFromTXT extracts the first public IP of the requested family from a
// list of TXT record contents.
func ipFromTXT(txts []string, forceIPv6 bool) net.IP {
	for _, txt := range txts {
		// TXT data may be wrapped in quotes by some resolvers/servers.
		candidate := strings.Trim(strings.TrimSpace(txt), `"`)
		if ip := validateDetectedIP(net.ParseIP(candidate), forceIPv6); ip != nil {
			return ip
		}
	}
	return nil
}

// validateDetectedIP rejects unusable addresses: a broken or malicious
// endpoint must not hand us a private, loopback, link-local, or
// unspecified address that would then be used as the server's public
// identity, and the address family must match the requested one.
func validateDetectedIP(ip net.IP, forceIPv6 bool) net.IP {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
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
