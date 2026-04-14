package main

import (
	"context"
	"fmt"
	"math"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// startLatencyProbe starts a background latency probe for A/AAAA records when configured.
// It will reorder cached answers if a faster ordering is discovered.
func (s *DNSServer) startLatencyProbe(question dns.Question, cacheKey string, answer, authority, additional []dns.RR, validated bool, ecsResponse *ECSOption) {
	if s == nil || len(s.config.Server.LatencyProbe) == 0 {
		LogDebug("LATENCY: probe skipped for %s because latency_probe is not configured", question.Name)
		return
	}
	if question.Qtype != dns.TypeA && question.Qtype != dns.TypeAAAA {
		LogDebug("LATENCY: probe skipped for %s because query type is not A/AAAA", question.Name)
		return
	}
	if len(answer) <= 1 {
		LogDebug("LATENCY: probe skipped for %s because answer length <= 1", question.Name)
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
		LogDebug("LATENCY: probe skipped for %s because only one A/AAAA record present", question.Name)
		return
	}

	steps := s.config.Server.LatencyProbe
	LogDebug("LATENCY: starting background latency probe for %s with %d steps", question.Name, len(steps))

	s.backgroundGroup.Go(func() error {
		defer HandlePanic("latency probe")
		if err := s.performLatencyProbeAndReorder(s.backgroundCtx, cacheKey, answer, authority, additional, validated, ecsResponse, steps); err != nil {
			LogDebug("LATENCY: background probe failed for %s: %v", question.Name, err)
		}
		return nil
	})
}

func (s *DNSServer) performLatencyProbeAndReorder(ctx context.Context, cacheKey string, answer, authority, additional []dns.RR, validated bool, ecsResponse *ECSOption, steps []LatencyProbeStep) error {
	if ctx == nil {
		ctx = context.Background()
	}

	LogDebug("LATENCY: performing latency probe for cache key %s", cacheKey)
	sortedAnswer, changed := sortAAndAAAARecordsByLatency(ctx, answer, steps)
	if !changed {
		LogDebug("LATENCY: no faster A/AAAA order found for %s", cacheKey)
		return nil
	}

	s.cacheMgr.Set(cacheKey, sortedAnswer, authority, additional, validated, ecsResponse)
	LogDebug("LATENCY: reordered A/AAAA records for %s", cacheKey)
	return nil
}

func sortAAndAAAARecordsByLatency(ctx context.Context, answer []dns.RR, steps []LatencyProbeStep) ([]dns.RR, bool) {
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

	results := make(chan candidate, len(candidates))
	for _, c := range candidates {
		c := c
		go func() {
			c.latency = measureRecordLatency(ctx, c.rr, steps)
			results <- c
		}()
	}

	for i := 0; i < len(candidates); i++ {
		candidates[i] = <-results
	}
	close(results)

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

func measureRecordLatency(ctx context.Context, rr dns.RR, steps []LatencyProbeStep) time.Duration {
	ip := extractIPAddress(rr)
	if ip == nil {
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
			stepTimeout = DefaultLatencyProbeTimeout
		}

		stepCtx, cancel := context.WithTimeout(ctx, stepTimeout)
		if err := probeAddress(stepCtx, ip, LatencyProbeStep{Protocol: protocol, Port: step.Port}); err == nil {
			cancel()
			return time.Since(start)
		}
		cancel()
	}

	return time.Duration(math.MaxInt64)
}

func probeAddress(ctx context.Context, ip net.IP, step LatencyProbeStep) error {
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
	default:
		return fmt.Errorf("unsupported probe protocol: %s", step.Protocol)
	}
}

func probeUDP(ctx context.Context, ip net.IP, port int) error {
	addr := net.JoinHostPort(ip.String(), fmt.Sprint(port))
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

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

	conn, err := icmp.ListenPacket(network, "0.0.0.0")
	if err != nil {
		return err
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	message := icmp.Message{
		Type: echoType,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("zjdns-latency-probe"),
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
