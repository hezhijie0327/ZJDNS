// Package latency provides A/AAAA latency probing and record reordering for
// optimized client connectivity.
package latency

import (
	"context"
	cryptotls "crypto/tls"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
	servertls "zjdns/server/tls"
)

// CacheSetter is the interface for updating the DNS cache with reordered
// records after latency probing.
type CacheSetter interface {
	Set(cacheKey string, answer, authority, additional []dns.RR, validated bool, ecs *edns.ECSOption)
}

// Prober measures network latency to resolved IP addresses and reorders A/AAAA
// records in the cache to prioritize faster endpoints.
type Prober struct {
	cache           CacheSetter
	bgGroup         func(func() error)
	bgCtx           context.Context
	latencyProbeCfg []config.LatencyProbeStep
}

// New creates a new Prober with the given cache setter, background group
// executor, context, and probe configuration steps.
func New(cache CacheSetter, bgGroup func(func() error), bgCtx context.Context, steps []config.LatencyProbeStep) *Prober {
	return &Prober{
		cache:           cache,
		bgGroup:         bgGroup,
		bgCtx:           bgCtx,
		latencyProbeCfg: steps,
	}
}

// Start initiates a background latency probe for A/AAAA records when multiple
// addresses exist. If probing finds a faster ordering, the cache is updated.
func (p *Prober) Start(question dns.Question, cacheKey string, answer, authority, additional []dns.RR, validated bool, ecsResponse *edns.ECSOption) {
	if p == nil || len(p.latencyProbeCfg) == 0 {
		log.Debugf("LATENCY: probe skipped for %s because latency_probe is not configured", question.Name)
		return
	}
	if question.Qtype != dns.TypeA && question.Qtype != dns.TypeAAAA {
		log.Debugf("LATENCY: probe skipped for %s because query type is not A/AAAA", question.Name)
		return
	}
	if len(answer) <= 1 {
		log.Debugf("LATENCY: probe skipped for %s because answer length <= 1", question.Name)
		return
	}

	var aaaaCount int
	for _, rr := range answer {
		if isAOrAAAA(rr) {
			aaaaCount++
			if aaaaCount > 1 {
				break
			}
		}
	}
	if aaaaCount <= 1 {
		log.Debugf("LATENCY: probe skipped for %s because only one A/AAAA record present", question.Name)
		return
	}

	log.Debugf("LATENCY: starting background latency probe for %s with %d steps", question.Name, len(p.latencyProbeCfg))

	p.bgGroup(func() error {
		defer dnsutil.HandlePanic("latency probe")
		if err := p.probeAndReorder(p.bgCtx, cacheKey, answer, authority, additional, validated, ecsResponse); err != nil {
			log.Debugf("LATENCY: background probe failed for %s: %v", question.Name, err)
		}
		return nil
	})
}

func (p *Prober) probeAndReorder(ctx context.Context, cacheKey string, answer, authority, additional []dns.RR, validated bool, ecsResponse *edns.ECSOption) error {
	if ctx == nil {
		ctx = context.Background()
	}

	log.Debugf("LATENCY: performing latency probe for cache key %s", cacheKey)
	sortedAnswer, changed := sortByLatency(ctx, answer, p.latencyProbeCfg)
	if !changed {
		log.Debugf("LATENCY: no faster A/AAAA order found for %s", cacheKey)
		return nil
	}

	p.cache.Set(cacheKey, sortedAnswer, authority, additional, validated, ecsResponse)
	log.Debugf("LATENCY: reordered A/AAAA records for %s", cacheKey)
	return nil
}

func sortByLatency(ctx context.Context, answer []dns.RR, steps []config.LatencyProbeStep) ([]dns.RR, bool) {
	indices := make([]int, 0, len(answer))
	for i, rr := range answer {
		if isAOrAAAA(rr) {
			indices = append(indices, i)
		}
	}
	if len(indices) <= 1 || len(steps) == 0 {
		return answer, false
	}

	type candidate struct {
		idx     int
		rr      dns.RR
		latency time.Duration
	}

	candidates := make([]candidate, len(indices))
	for i, idx := range indices {
		candidates[i] = candidate{idx: idx, rr: answer[idx], latency: time.Duration(math.MaxInt64)}
	}

	const maxProbes = 16
	sem := make(chan struct{}, maxProbes)
	results := make(chan candidate, len(candidates))
	for _, c := range candidates {
		c := c
		go func() {
			defer dnsutil.HandlePanic("latency probe worker")
			sem <- struct{}{}
			defer func() { <-sem }()
			c.latency = measureRecordLatency(ctx, c.rr, steps)
			results <- c
		}()
	}

	for i := 0; i < len(candidates); i++ {
		candidates[i] = <-results
	}
	close(results)

	for _, c := range candidates {
		log.Debugf("LATENCY: probe result %s latency=%s", c.rr.String(), c.latency)
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].latency < candidates[j].latency
	})

	changed := false
	sortedAnswer := make([]dns.RR, len(answer))
	copy(sortedAnswer, answer)
	pos := 0
	for _, idx := range indices {
		sortedAnswer[idx] = candidates[pos].rr
		if candidates[pos].rr.String() != answer[idx].String() {
			changed = true
		}
		pos++
	}

	return sortedAnswer, changed
}

func measureRecordLatency(ctx context.Context, rr dns.RR, steps []config.LatencyProbeStep) time.Duration {
	ip := extractIPAddress(rr)
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return time.Duration(math.MaxInt64)
	}

	start := time.Now()
	for _, step := range steps {
		protocol := strings.ToLower(strings.TrimSpace(step.Protocol))
		if protocol == "icmp" {
			protocol = "ping"
		}
		stepTimeout := time.Duration(step.Timeout) * time.Millisecond
		if stepTimeout <= 0 {
			stepTimeout = config.DefaultLatencyProbeTimeout
		}

		stepCtx, cancel := context.WithTimeout(ctx, stepTimeout)
		if err := probeAddress(stepCtx, ip, config.LatencyProbeStep{Protocol: protocol, Port: step.Port}); err == nil {
			cancel()
			return time.Since(start)
		}
		cancel()
	}

	return time.Duration(math.MaxInt64)
}

func probeAddress(ctx context.Context, ip net.IP, step config.LatencyProbeStep) error {
	protocol := strings.ToLower(strings.TrimSpace(step.Protocol))
	switch protocol {
	case "ping", "icmp":
		return probeICMP(ctx, ip)
	case "tcp":
		port := step.Port
		if port <= 0 {
			port = 80
		}
		return probeTCP(ctx, ip, port)
	case "udp":
		port := step.Port
		if port <= 0 {
			port = 53
		}
		return probeUDP(ctx, ip, port)
	case "http":
		port := step.Port
		if port <= 0 {
			port = 80
		}
		return probeHTTP(ctx, ip, port, false, false)
	case "https":
		port := step.Port
		if port <= 0 {
			port = 443
		}
		return probeHTTP(ctx, ip, port, true, false)
	case "http3":
		port := step.Port
		if port <= 0 {
			port = 443
		}
		return probeHTTP(ctx, ip, port, true, true)
	default:
		return fmt.Errorf("unsupported probe protocol: %s", step.Protocol)
	}
}

func probeHTTP(ctx context.Context, ip net.IP, port int, useTLS, useHTTP3 bool) error {
	scheme := "http"
	if useTLS {
		scheme = "https"
	}

	url := fmt.Sprintf("%s://%s/", scheme, net.JoinHostPort(ip.String(), fmt.Sprint(port)))
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "")
	req.Host = ip.String()

	var client *http.Client
	if useHTTP3 {
		tlsConfig := &cryptotls.Config{
			InsecureSkipVerify: true,
			NextProtos:         servertls.NextProtoDoH3,
		}
		transport := &http3.Transport{TLSClientConfig: tlsConfig}
		defer func() { _ = transport.Close() }()
		client = &http.Client{Transport: transport}
	} else {
		tlsConfig := &cryptotls.Config{InsecureSkipVerify: true}
		transport := &http.Transport{
			Proxy:             nil,
			DisableKeepAlives: true,
			ForceAttemptHTTP2: false,
			TLSClientConfig:   tlsConfig,
			DialContext:       (&net.Dialer{}).DialContext,
			IdleConnTimeout:   config.DefaultLatencyProbeTimeout,
		}
		client = &http.Client{Transport: transport}
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	return nil
}

func probeUDP(ctx context.Context, ip net.IP, port int) error {
	addr := net.JoinHostPort(ip.String(), fmt.Sprint(port))
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "udp", addr)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	if _, err := conn.Write([]byte{0}); err != nil {
		return err
	}

	buffer := make([]byte, 512)
	_, err = conn.Read(buffer)
	if err != nil {
		return err
	}

	return nil
}

func probeTCP(ctx context.Context, ip net.IP, port int) error {
	addr := net.JoinHostPort(ip.String(), fmt.Sprint(port))
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

func probeICMP(ctx context.Context, ip net.IP) error {
	var network string
	var proto int
	var echoType icmp.Type
	var replyType icmp.Type
	if ip.To4() != nil {
		network = "ip4:icmp"
		proto = 1
		echoType = ipv4.ICMPTypeEcho
		replyType = ipv4.ICMPTypeEchoReply
	} else {
		network = "ip6:ipv6-icmp"
		proto = 58
		echoType = ipv6.ICMPTypeEchoRequest
		replyType = ipv6.ICMPTypeEchoReply
	}

	conn, err := icmp.ListenPacket(network, "")
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	message := icmp.Message{
		Type: echoType,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: make([]byte, 56),
		},
	}
	messageData, err := message.Marshal(nil)
	if err != nil {
		return err
	}

	if _, err := conn.WriteTo(messageData, &net.IPAddr{IP: ip}); err != nil {
		return err
	}

	buffer := make([]byte, 1500)
	for {
		n, peer, err := conn.ReadFrom(buffer)
		if err != nil {
			return err
		}

		rm, err := icmp.ParseMessage(proto, buffer[:n])
		if err != nil {
			continue
		}

		if rm.Type != replyType {
			continue
		}

		switch p := peer.(type) {
		case *net.IPAddr:
			if p.IP.Equal(ip) {
				return nil
			}
		case *net.UDPAddr:
			if p.IP.Equal(ip) {
				return nil
			}
		}
	}
}

func extractIPAddress(rr dns.RR) net.IP {
	switch record := rr.(type) {
	case *dns.A:
		return record.A
	case *dns.AAAA:
		return record.AAAA
	default:
		return nil
	}
}

func isAOrAAAA(rr dns.RR) bool {
	if rr == nil {
		return false
	}
	rtype := rr.Header().Rrtype
	return rtype == dns.TypeA || rtype == dns.TypeAAAA
}
