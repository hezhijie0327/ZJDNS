package latency

import (
	"context"
	"fmt"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"zjdns/config"
)

// icmpBufPool reuses ICMP read buffers to avoid per-probe 1500-byte allocations.
var icmpBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, probeICMPReadBufSize)
		return &buf
	},
}

// Probe buffer and payload sizes.
const (
	probeUDPReadBufSize  = 512  // UDP probe read buffer
	probeICMPDataSize    = 56   // ICMP echo data payload
	probeICMPReadBufSize = 1500 // ICMP response read buffer
)

// measureIPLatency probes a single IP using the configured steps and returns
// the total elapsed time for the first successful probe. The bgCtx is the
// Prober's background context checked during long-running operations.
func measureIPLatency(ctx context.Context, ip net.IP, steps []config.LatencyProbeStep, httpPool *httpClientPool) time.Duration {
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return time.Duration(math.MaxInt64)
	}

	start := time.Now()
	for _, step := range steps {
		stepTimeout := time.Duration(step.Timeout) * time.Millisecond
		if stepTimeout <= 0 {
			stepTimeout = config.DefaultLatencyProbeTimeout
		}

		stepCtx, cancel := context.WithTimeout(ctx, stepTimeout)
		err := probeAddress(stepCtx, ip, step, httpPool)
		cancel()
		if err == nil {
			return time.Since(start)
		}
	}

	return time.Duration(math.MaxInt64)
}

func probeAddress(ctx context.Context, ip net.IP, step config.LatencyProbeStep, httpPool *httpClientPool) error {
	switch step.Protocol {
	case config.ProtoPing, config.ProtoICMP:
		return probeICMP(ctx, ip)
	case config.ProtoTCP:
		port := step.Port
		if port <= 0 {
			port = config.DefaultProbePortHTTP
		}
		return probeTCP(ctx, ip, port)
	case config.ProtoUDP:
		port := step.Port
		if port <= 0 {
			port = config.DefaultProbePortDNS
		}
		return probeUDP(ctx, ip, port)
	case config.ProtoHTTPPlain:
		port := step.Port
		if port <= 0 {
			port = config.DefaultProbePortHTTP
		}
		return probeHTTP(ctx, ip, port, false, false, httpPool)
	case config.ProtoHTTP:
		port := step.Port
		if port <= 0 {
			port = config.DefaultProbePortHTTPS
		}
		return probeHTTP(ctx, ip, port, true, false, httpPool)
	case config.ProtoHTTP3:
		port := step.Port
		if port <= 0 {
			port = config.DefaultProbePortHTTPS
		}
		return probeHTTP(ctx, ip, port, true, true, httpPool)
	default:
		return fmt.Errorf("unsupported probe protocol: %s", step.Protocol)
	}
}

func probeTCP(ctx context.Context, ip net.IP, port int) error {
	addr := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

func probeUDP(ctx context.Context, ip net.IP, port int) error {
	addr := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "udp", addr)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	// Send a single-byte datagram — valid per RFC 768 §3.1 and
	// universally applicable regardless of the target service. The Read
	// will return either a response from the service or an ICMP
	// port-unreachable that manifests as a read error; either way we
	// get an RTT measurement.
	if _, err := conn.Write([]byte{0}); err != nil {
		return err
	}

	buffer := make([]byte, probeUDPReadBufSize)
	_, err = conn.Read(buffer)
	return err
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

	// Use a random ID + seq per probe to prevent concurrent probes
	// to the same IP from stealing each other's echo replies.
	echoID := uint16(rand.Uint32())
	echoSeq := uint16(rand.Uint32())

	message := icmp.Message{
		Type: echoType,
		Code: 0,
		Body: &icmp.Echo{
			ID:   int(echoID),
			Seq:  int(echoSeq),
			Data: make([]byte, probeICMPDataSize),
		},
	}
	messageData, err := message.Marshal(nil)
	if err != nil {
		return err
	}

	if _, err := conn.WriteTo(messageData, &net.IPAddr{IP: ip}); err != nil {
		return err
	}

	bufPtr := icmpBufPool.Get().(*[]byte)
	defer icmpBufPool.Put(bufPtr)
	buffer := *bufPtr
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

		// Verify the echo reply matches our request to prevent
		// concurrent probes from stealing each other's responses.
		if echo, ok := rm.Body.(*icmp.Echo); ok {
			if uint16(echo.ID) != echoID || uint16(echo.Seq) != echoSeq {
				continue
			}
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
		case *net.TCPAddr:
			if p.IP.Equal(ip) {
				return nil
			}
		default:
			// Fallback: extract IP from any net.Addr via SplitHostPort.
			if host, _, err := net.SplitHostPort(peer.String()); err == nil {
				if peerIP := net.ParseIP(host); peerIP != nil && peerIP.Equal(ip) {
					return nil
				}
			}
		}
	}
}

func probeHTTP(ctx context.Context, ip net.IP, port int, useTLS, useHTTP3 bool, httpPool *httpClientPool) error {
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s/", scheme, net.JoinHostPort(ip.String(), strconv.Itoa(port)))
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "")
	req.Host = ip.String()

	client := httpPool.get(port, useTLS, useHTTP3)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	return nil
}
