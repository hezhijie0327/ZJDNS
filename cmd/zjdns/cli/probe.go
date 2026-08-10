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
	"syscall"
	"time"
	"zjdns/config"

	"codeberg.org/miekg/dns"

	eTLS "gitlab.com/go-extension/tls"
)

// Probe constants.
const (
	probeTLSHandshakeTimeout = 5 * time.Second
	probeDefaultReadTimeout  = 5 * time.Second
	probeDefaultWriteTimeout = 10 * time.Second
	probePipelineReadTimeout = 5 * time.Second
	probeIdleReadTimeout     = 30 * time.Second
	probePipelineNumQueries  = 5
	probeConnReuseNumQueries = 3
	probeDialTimeout         = 10 * time.Second // fail fast on blackholed targets
)

// Probe port defaults are the config package's constants — duplicated
// literals here would drift (M-3-6).
var (
	defaultProbePort    = mustPort(config.DefaultUDPPort)
	defaultProbeTLSPort = mustPort(config.DefaultTLSPort)
)

func mustPort(s string) int {
	p, err := strconv.Atoi(s)
	if err != nil {
		panic("config default port is not numeric: " + s)
	}
	return p
}

// runProbe dispatches to the requested probe type.
func runProbe(probeType, addr string) error {
	switch probeType {
	case "pipeline":
		return probePipeline(addr)
	case "conn-reuse":
		return probeConnReuse(addr)
	case "idle-timeout":
		return probeIdleTimeout(addr)
	case "mqtype":
		return probeMQType(addr)
	default:
		return fmt.Errorf("unknown probe type %q (supported: pipeline, conn-reuse, idle-timeout, mqtype)", probeType)
	}
}

// dialProbeTarget parses a [tcp|tls]://host:port address and returns
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
		host = tryAddPort(host, defaultProbePort)
		d := net.Dialer{Timeout: probeDialTimeout}
		return d.Dial("tcp", host)

	case "tls":
		host = tryAddPort(host, defaultProbeTLSPort)
		serverName, _, _ := net.SplitHostPort(host)
		tlsCfg := &eTLS.Config{
			MinVersion:         eTLS.VersionTLS12,
			ServerName:         serverName,
			InsecureSkipVerify: true, // probe may test servers with self-signed certificates
			CurvePreferences:   []eTLS.CurveID{},
		}
		// Bound the connect itself — a black-holed target would otherwise
		// block far beyond probeDialTimeout (R3-L10).
		tcpConn, err := net.DialTimeout("tcp", host, probeDialTimeout)
		if err != nil {
			return nil, err
		}
		tlsConn := eTLS.Client(tcpConn, tlsCfg)
		if err := tlsConn.SetDeadline(time.Now().Add(probeTLSHandshakeTimeout)); err != nil {
			_ = tcpConn.Close() // _ = error: best-effort cleanup close
			return nil, fmt.Errorf("set deadline: %w", err)
		}
		if err := tlsConn.Handshake(); err != nil {
			_ = tcpConn.Close() // _ = error: best-effort cleanup close
			return nil, fmt.Errorf("TLS handshake: %w", err)
		}
		if err := tlsConn.SetDeadline(time.Time{}); err != nil {
			_ = tcpConn.Close() // _ = error: best-effort cleanup close
			return nil, fmt.Errorf("clear deadline: %w", err)
		}
		return tlsConn, nil

	default:
		return nil, fmt.Errorf("unsupported protocol %q (supported: tcp, tls)", protocol)
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
	// Note: this fork's packQuestion derives the QTYPE from the concrete RR
	// type (RRToType), so the *dns.A question packs as TYPE A correctly.
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
	netErr, ok := errors.AsType[net.Error](err)
	if ok && netErr.Timeout() {
		return true
	}
	// EPIPE (local peer closed) and ECONNRESET (remote reset) cover the
	// "connection died mid-pipeline" probes. String matching for "broken
	// pipe" was previously needed for wrapped errors; errors.Is unwraps.
	return errors.Is(err, io.EOF) || errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET)
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
	defer func() { _ = conn.Close() }() // _ = error: best-effort cleanup close

	// Generate random domain names so each query reaches the authoritative path.
	domains := make([]string, probePipelineNumQueries)
	for i := range probePipelineNumQueries {
		var b [8]byte
		_, _ = rand.Read(b[:]) // _ = error: CLI probe randomness — failure yields a fixed query name, still valid
		domains[i] = fmt.Sprintf("www.%x.com.", b)
	}

	fmt.Printf("Probing %s for RFC 7766 query pipelining support...\n\n", addr)

	// Monotonicity tracker for out-of-order detection.
	lastID := uint16(0)

	// Fire all queries without waiting for responses.
	for i, d := range domains {
		_ = conn.SetWriteDeadline(time.Now().Add(probeDefaultWriteTimeout)) // _ = error: deadline advisory
		q := newQuery(d, uint16(i))
		if err := writeDNSMsg(conn, q); err != nil {
			return fmt.Errorf("write query #%d: %w", i, err)
		}
		fmt.Printf("  → sent query #%d: %s\n", i, d)
	}

	fmt.Println()

	// Read responses — they may arrive out of order.
	// OOO detection uses a presence bitmap: track which message IDs have
	// been received. Duplicate IDs or IDs outside the expected range
	// indicate out-of-order or anomalous delivery.
	ooo := false
	received := 0
	seen := make([]bool, probePipelineNumQueries)
	start := time.Now()
	for range domains {
		_ = conn.SetReadDeadline(time.Now().Add(probePipelineReadTimeout)) // _ = error: deadline advisory
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
			return fmt.Errorf("read response: %w", err)
		}
		received++
		latency := time.Since(start).Milliseconds()
		fmt.Printf("  ← response #%d (%dms) rcode=%s\n", resp.ID, latency, dns.RcodeToString[resp.Rcode])
		if resp.ID >= uint16(probePipelineNumQueries) || seen[resp.ID] {
			ooo = true
		}
		// A server that permutes response order (unique IDs, any order) is
		// only detectable via monotonicity: flag any later ID smaller than
		// the highest seen so far.
		if resp.ID < lastID {
			ooo = true
		}
		if resp.ID > lastID {
			lastID = resp.ID
		}
		if resp.ID < uint16(probePipelineNumQueries) {
			seen[resp.ID] = true
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
	defer func() { _ = conn.Close() }() // _ = error: best-effort cleanup close

	fmt.Printf("Probing %s for RFC 1035 connection reuse...\n\n", addr)

	for i := range probeConnReuseNumQueries {
		_ = conn.SetDeadline(time.Now().Add(probeDefaultReadTimeout)) // _ = error: deadline advisory
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

// probeMQType tests whether the server supports RFC 10029 MQTYPE: a query
// carrying an MQTYPE-Query EDNS option (asking to merge AAAA and HTTPS into
// an A query) must come back with an MQTYPE-Response option — even with an
// empty list, §3.4's support signal.  The option's String() in this fork
// drops the first type on multi-type lists, so the types are formatted
// manually.
func probeMQType(addr string) error {
	conn, err := dialProbeTarget(addr)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }() // _ = error: best-effort cleanup close

	_ = conn.SetDeadline(time.Now().Add(probeDefaultReadTimeout)) // _ = error: deadline advisory
	q := newQuery("www.cloudflare.com.", 0)
	q.UDPSize = 1232
	q.Security = true // DO bit (fork v2 API — options live in Pseudo)
	q.Pseudo = append(q.Pseudo, &dns.MQQUERY{Types: []uint16{dns.TypeAAAA, dns.TypeHTTPS}})
	if err := writeDNSMsg(conn, q); err != nil {
		return fmt.Errorf("write query: %w", err)
	}

	fmt.Printf("Probing %s for RFC 10029 MQTYPE support...\n\n", addr)
	fmt.Println("  → sent query: www.cloudflare.com A + MQTYPE-Query{AAAA HTTPS}")

	resp, err := readDNSMsg(conn)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	var mqr *dns.MQRESPONSE
	seen := 0
	invalid := false
	for _, rr := range resp.Pseudo {
		switch opt := rr.(type) {
		case *dns.MQRESPONSE:
			seen++
			if seen > 1 {
				invalid = true // more than one MQTYPE-Response (RFC 10029 §3.5)
			}
			mqr = opt
		case *dns.MQQUERY:
			invalid = true // MQTYPE-Query in a response (RFC 10029 §3.5)
		}
	}
	if invalid {
		fmt.Printf("  ← response: rcode=%s, MQTYPE options malformed\n\n", dns.RcodeToString[resp.Rcode])
		fmt.Println("⚠️  Server returns a malformed MQTYPE response — partial/buggy implementation")
		return nil
	}
	if mqr == nil {
		fmt.Printf("  ← response: rcode=%s, no MQTYPE-Response\n\n", dns.RcodeToString[resp.Rcode])
		fmt.Println("⚠️  Server does not support RFC 10029 MQTYPE (no MQTYPE-Response in reply)")
		return nil
	}
	if len(mqr.Types) == 0 {
		fmt.Printf("  ← response: rcode=%s, MQTYPE-Response: [empty]\n\n", dns.RcodeToString[resp.Rcode])
		fmt.Println("✅ Server supports RFC 10029 MQTYPE (merged nothing)")
		return nil
	}
	merged := make([]string, 0, len(mqr.Types))
	for _, t := range mqr.Types {
		merged = append(merged, dns.TypeToString[t])
	}
	fmt.Printf("  ← response: rcode=%s, MQTYPE-Response: %s\n\n", dns.RcodeToString[resp.Rcode], strings.Join(merged, " "))
	fmt.Printf("✅ Server supports RFC 10029 MQTYPE (merged: %s)\n", strings.Join(merged, " "))
	return nil
}

// probeIdleTimeout measures the server's idle connection timeout by waiting
// for the server to close the connection after an initial query/response.
func probeIdleTimeout(addr string) error {
	conn, err := dialProbeTarget(addr)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }() // _ = error: best-effort cleanup close

	_ = conn.SetDeadline(time.Now().Add(probeDefaultReadTimeout)) // _ = error: deadline advisory
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
		_ = conn.SetReadDeadline(time.Now().Add(probeIdleReadTimeout)) // _ = error: deadline advisory
		_, err := readDNSMsg(conn)
		if err != nil {
			// A read deadline expiring while the server keeps the connection
			// alive is NOT a server-side close — keep waiting. Only an
			// io.EOF/reset indicates the server actually closed.
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				fmt.Printf("  server still alive after %.1fs — waiting for close...\n", time.Since(start).Seconds())
				continue
			}
			// Only EOF/reset is a server-side close — any other read error
			// (protocol violation, RST mid-frame) must not be mislabeled
			// (R3-L12).
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				fmt.Printf("\nConnection closed by server after %.1fs\n", time.Since(start).Seconds())
				return nil
			}
			fmt.Printf("\nConnection error: %v\n", err)
			return nil
		}
	}
}
