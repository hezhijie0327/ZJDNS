package cli

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"codeberg.org/miekg/dns"

	eTLS "gitlab.com/go-extension/tls"
)

// Probe timeout and count constants.
const (
	probeTLSHandshakeTimeout = 5 * time.Second
	probeDefaultReadTimeout  = 5 * time.Second
	probeDefaultWriteTimeout = 10 * time.Second
	probePipelineReadTimeout = 5 * time.Second
	probeIdleReadTimeout     = 30 * time.Second
	probePipelineNumQueries  = 5
	probeConnReuseNumQueries = 3
	defaultTCPPort           = 53
	defaultTLSPort           = 853
)

// runProbe dispatches to the requested probe type.
func runProbe(probeType, addr string) error {
	switch probeType {
	case "pipeline":
		return probePipeline(addr)
	case "conn-reuse":
		return probeConnReuse(addr)
	case "idle-timeout":
		return probeIdleTimeout(addr)
	default:
		return fmt.Errorf("unknown probe type %q (supported: pipeline, conn-reuse, idle-timeout)", probeType)
	}
}

// dialProbeTarget parses a [tcp|tls|dot]://host:port address and returns
// a connected net.Conn.  Default ports are 53 for TCP, 853 for TLS.
func dialProbeTarget(addr string) (net.Conn, error) {
	protocol, host, ok := strings.Cut(addr, "://")
	if !ok || protocol == "" || host == "" {
		return nil, fmt.Errorf("invalid address %q (expected tcp://host:port or tls://host:port)", addr)
	}

	tryAddPort := func(h string, defaultPort int) string {
		_, _, err := net.SplitHostPort(h)
		if err != nil {
			return net.JoinHostPort(h, strconv.Itoa(defaultPort))
		}
		return h
	}

	switch protocol {
	case "tcp":
		host = tryAddPort(host, defaultTCPPort)
		return net.Dial("tcp", host)

	case "tls", "dot":
		host = tryAddPort(host, defaultTLSPort)
		serverName, _, _ := net.SplitHostPort(host)
		tlsCfg := &eTLS.Config{
			MinVersion:         eTLS.VersionTLS12,
			ServerName:         serverName,
			InsecureSkipVerify: true,
			CurvePreferences:   []eTLS.CurveID{},
		}
		tcpConn, err := net.Dial("tcp", host)
		if err != nil {
			return nil, err
		}
		tlsConn := eTLS.Client(tcpConn, tlsCfg)
		if err := tlsConn.SetDeadline(time.Now().Add(probeTLSHandshakeTimeout)); err != nil {
			_ = tcpConn.Close()
			return nil, fmt.Errorf("set deadline: %w", err)
		}
		if err := tlsConn.Handshake(); err != nil {
			_ = tcpConn.Close()
			return nil, fmt.Errorf("TLS handshake: %w", err)
		}
		if err := tlsConn.SetDeadline(time.Time{}); err != nil {
			_ = tcpConn.Close()
			return nil, fmt.Errorf("clear deadline: %w", err)
		}
		return tlsConn, nil

	default:
		return nil, fmt.Errorf("unsupported protocol %q (supported: tcp, tls, dot)", protocol)
	}
}

// writeDNSMsg packs a DNS message and writes it to conn with a 2-byte
// TCP length prefix.
func writeDNSMsg(conn net.Conn, msg *dns.Msg) error {
	if err := msg.Pack(); err != nil {
		return fmt.Errorf("pack: %w", err)
	}
	data := msg.Data
	var prefix [2]byte
	binary.BigEndian.PutUint16(prefix[:], uint16(len(data))) //nolint:gosec // G115: DNS data length fits in uint16
	if _, err := conn.Write(append(prefix[:], data...)); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

// readDNSMsg reads a DNS message with a 2-byte TCP length prefix from conn,
// unpacks it, and returns the result.
func readDNSMsg(conn net.Conn) (*dns.Msg, error) {
	var prefix [2]byte
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		return nil, fmt.Errorf("read prefix: %w", err)
	}
	length := binary.BigEndian.Uint16(prefix[:])
	if length == 0 || length > dns.MaxMsgSize {
		return nil, fmt.Errorf("invalid message length: %d", length)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	msg := &dns.Msg{}
	msg.Data = buf
	if err := msg.Unpack(); err != nil {
		return nil, fmt.Errorf("unpack: %w", err)
	}
	return msg, nil
}

// newQuery creates a new DNS A query for the given name with the given message ID.
func newQuery(name string, id uint16) *dns.Msg {
	msg := &dns.Msg{}
	msg.RecursionDesired = true
	msg.ID = id
	msg.Question = []dns.RR{
		&dns.A{Hdr: dns.Header{Name: name, Class: dns.ClassINET}},
	}
	return msg
}

// isTimeoutOrEOF reports whether err is a timeout or EOF — conditions that
// indicate the server does not support pipelining (dropped the connection).
func isTimeoutOrEOF(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return strings.Contains(err.Error(), "EOF") || strings.Contains(err.Error(), "broken pipe")
}

// probePipeline tests whether the server supports RFC 7766 query pipelining.
// It sends 5 queries without waiting for replies, then reads responses.  If
// responses arrive out-of-order (ID mismatch), the server pipelines correctly.
// If the server drops the connection after partial responses, it does not
// support pipelining.
func probePipeline(addr string) error {
	conn, err := dialProbeTarget(addr)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	// Generate random domain names so each query reaches the authoritative path.
	domains := make([]string, probePipelineNumQueries)
	for i := 0; i < probePipelineNumQueries; i++ {
		var b [8]byte
		_, _ = rand.Read(b[:])
		domains[i] = fmt.Sprintf("www.%x.com.", b)
	}

	fmt.Printf("Probing %s for RFC 7766 query pipelining support...\n\n", addr)

	// Fire all queries without waiting for responses.
	for i, d := range domains {
		_ = conn.SetWriteDeadline(time.Now().Add(probeDefaultWriteTimeout))
		q := newQuery(d, uint16(i))
		if err := writeDNSMsg(conn, q); err != nil {
			return fmt.Errorf("write query #%d: %w", i, err)
		}
		fmt.Printf("  → sent query #%d: %s\n", i, d)
	}

	fmt.Println()

	// Read responses — they may arrive out of order.
	ooo := false
	received := 0
	start := time.Now()
	for i := range domains {
		_ = conn.SetReadDeadline(time.Now().Add(probePipelineReadTimeout))
		resp, err := readDNSMsg(conn)
		if err != nil {
			if received == 0 {
				return fmt.Errorf("no response received: %w", err)
			}
			if isTimeoutOrEOF(err) {
				fmt.Printf("\n⚠️  Server closed connection after %d/%d responses — does NOT support pipelining\n", received, probePipelineNumQueries)
				fmt.Println("   (Servers that support pipelining process all queries before responding)")
				return nil
			}
			return fmt.Errorf("read response #%d: %w", i, err)
		}
		received++
		latency := time.Since(start).Milliseconds()
		fmt.Printf("  ← response #%d (%dms) rcode=%s\n", resp.ID, latency, dns.RcodeToString[resp.Rcode])
		if resp.ID != uint16(i) {
			ooo = true
		}
	}

	fmt.Println()
	if ooo {
		fmt.Println("✅ Server supports RFC 7766 query pipelining (out-of-order responses observed)")
	} else {
		fmt.Println("⚠️  No out-of-order responses observed — server may not support pipelining")
	}
	return nil
}

// probeConnReuse tests whether the server supports RFC 1035 connection reuse.
// It sends 3 sequential queries on the same connection.
func probeConnReuse(addr string) error {
	conn, err := dialProbeTarget(addr)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	fmt.Printf("Probing %s for RFC 1035 connection reuse...\n\n", addr)

	for i := 0; i < probeConnReuseNumQueries; i++ {
		_ = conn.SetDeadline(time.Now().Add(probeDefaultReadTimeout))
		q := newQuery("www.cloudflare.com.", uint16(i))
		if err := writeDNSMsg(conn, q); err != nil {
			return fmt.Errorf("write query #%d: %w", i, err)
		}
		fmt.Printf("  → sent query #%d\n", i)
		if _, err := readDNSMsg(conn); err != nil {
			return fmt.Errorf("read response #%d: %w", i, err)
		}
		fmt.Printf("  ← received response #%d\n", i)
	}

	fmt.Println()
	fmt.Println("✅ Server supports RFC 1035 connection reuse")
	return nil
}

// probeIdleTimeout measures the server's idle connection timeout by waiting
// for the server to close the connection after an initial query/response.
func probeIdleTimeout(addr string) error {
	conn, err := dialProbeTarget(addr)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(probeDefaultReadTimeout))
	q := newQuery("www.cloudflare.com.", 0)
	if err := writeDNSMsg(conn, q); err != nil {
		return fmt.Errorf("write query: %w", err)
	}
	if _, err := readDNSMsg(conn); err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	fmt.Printf("Probing %s for idle connection timeout...\n", addr)
	fmt.Println("Waiting for server to close the connection (may take several minutes)...")

	start := time.Now()
	for {
		_ = conn.SetReadDeadline(time.Now().Add(probeIdleReadTimeout))
		_, err := readDNSMsg(conn)
		if err != nil {
			fmt.Printf("\nConnection closed by server after %.1fs\n", time.Since(start).Seconds())
			return nil
		}
	}
}
