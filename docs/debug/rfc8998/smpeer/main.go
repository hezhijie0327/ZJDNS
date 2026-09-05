// smpeer is an RFC 8998 (ShangMi cipher suites for TLS 1.3) test peer for
// real-instance ZJDNS E2E tests. It speaks ONLY the SM cipher suites
// (TLS_SM4_GCM_SM3/TLS_SM4_CCM_SM3) and CurveSM2, so any completed
// handshake proves the peer under test has RFC 8998 enabled.
//
// Modes:
//
//	smpeer -mode client -addr 127.0.0.1:10853                  # SM-only DoT query
//	smpeer -mode doh    -addr 127.0.0.1:10443 -name a.com      # SM-only DoH GET (HTTP/1.1)
//	smpeer -mode server -addr 127.0.0.1:11853                  # SM-only DoT server → UDP forwarder
//
// The server mode accepts DoT connections, forces SM negotiation, and
// forwards queries to a plain UDP resolver (-forward, default 223.5.5.5:53)
// — used to test ZJDNS's own upstream client against an SM-only server.
//
// See docs/debug/DEBUG.md § RFC 8998 for the full test procedure.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	eTLS "gitlab.com/go-extension/tls"
)

const (
	defaultForward   = "223.5.5.5:53"
	defaultQueryName = "www.baidu.com"
	exchangeTimeout  = 5 * time.Second
	certValidity     = time.Hour
)

func main() {
	mode := flag.String("mode", "client", "client | doh | server")
	addr := flag.String("addr", "127.0.0.1:10853", "dial address (client/doh) or listen address (server)")
	name := flag.String("name", defaultQueryName, "query name")
	qtype := flag.String("type", "A", "query type (A, AAAA, ...)")
	serverName := flag.String("server-name", "zjdns-test.local", "TLS SNI / Host header")
	path := flag.String("path", "/dns-query", "DoH endpoint path")
	forward := flag.String("forward", defaultForward, "UDP resolver for server mode")
	flag.Parse()

	var err error
	switch *mode {
	case "client":
		err = runClient(*addr, *serverName, *name, *qtype)
	case "doh":
		err = runDoH(*addr, *serverName, *path, *name, *qtype)
	case "server":
		err = runServer(*addr, *forward)
	default:
		err = fmt.Errorf("unknown mode %q (supported: client, doh, server)", *mode)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "smpeer: %v\n", err)
		os.Exit(1)
	}
}

// smCipherSuites / smCurves pin the peer to RFC 8998 algorithms only.
func smCipherSuites() []uint16 {
	return []uint16{eTLS.TLS_SM4_GCM_SM3, eTLS.TLS_SM4_CCM_SM3}
}

func smCurves() []eTLS.CurveID {
	return []eTLS.CurveID{eTLS.CurveSM2}
}

func smClientConfig(serverName string, nextProtos []string) *eTLS.Config {
	return &eTLS.Config{
		MinVersion:         eTLS.VersionTLS13,
		ServerName:         serverName,
		NextProtos:         nextProtos,
		CipherSuites:       smCipherSuites(),
		CurvePreferences:   smCurves(),
		InsecureSkipVerify: true, //nolint:gosec // ZJDNS loopback tests use self-signed certificates
	}
}

func reportHandshake(tag string, cs *eTLS.ConnectionState) {
	fmt.Printf("%s: version=%s cipher=%s group=%s alpn=%q\n",
		tag, eTLS.VersionName(cs.Version), eTLS.CipherSuiteName(cs.CipherSuite), cs.CurveID, cs.NegotiatedProtocol)
}

// newQuery packs a recursive query for name/qtype (random message ID).
func newQuery(name, qtype string) ([]byte, error) {
	qtypeVal, ok := dns.StringToType[qtype]
	if !ok {
		return nil, fmt.Errorf("unknown query type %q", qtype)
	}
	msg := new(dns.Msg)
	dnsutil.SetQuestion(msg, dnsutil.Fqdn(name), qtypeVal)
	msg.RecursionDesired = true
	if err := msg.Pack(); err != nil {
		return nil, fmt.Errorf("pack query: %w", err)
	}
	return msg.Data, nil
}

func printAnswer(wire []byte) error {
	resp := new(dns.Msg)
	resp.Data = wire
	if err := resp.Unpack(); err != nil {
		return fmt.Errorf("unpack response: %w", err)
	}
	fmt.Printf("answer: rcode=%s rrs=%d\n", dns.RcodeToString[resp.Rcode], len(resp.Answer))
	for _, rr := range resp.Answer {
		fmt.Printf("  %s\n", rr.String())
	}
	return nil
}

// runClient performs a single SM-only DoT query and reports the negotiated
// parameters plus the answer.
func runClient(addr, serverName, name, qtype string) error {
	query, err := newQuery(name, qtype)
	if err != nil {
		return err
	}
	conn, err := eTLS.Dial("tcp", addr, smClientConfig(serverName, nil))
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	cs := conn.ConnectionState()
	reportHandshake("negotiated", &cs)

	if err := writeFramed(conn, query); err != nil {
		return err
	}
	wire, err := readFramed(conn)
	if err != nil {
		return err
	}
	return printAnswer(wire)
}

// runDoH performs a single SM-only DoH GET request over raw HTTP/1.1 and
// reports the negotiated parameters plus the answer.
func runDoH(addr, serverName, path, name, qtype string) error {
	query, err := newQuery(name, qtype)
	if err != nil {
		return err
	}
	conn, err := eTLS.Dial("tcp", addr, smClientConfig(serverName, []string{"http/1.1"}))
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	cs := conn.ConnectionState()
	reportHandshake("negotiated", &cs)

	dnsParam := base64.RawURLEncoding.EncodeToString(query)
	host := serverName
	if h, _, splitErr := net.SplitHostPort(addr); splitErr == nil {
		host = h
	}
	req := fmt.Sprintf("GET %s?dns=%s HTTP/1.1\r\nHost: %s\r\nAccept: application/dns-message\r\nConnection: close\r\n\r\n",
		path, dnsParam, host)
	if _, err := conn.Write([]byte(req)); err != nil {
		return fmt.Errorf("write http request: %w", err)
	}
	raw, err := io.ReadAll(conn)
	if err != nil {
		return fmt.Errorf("read http response: %w", err)
	}
	head, body, ok := strings.Cut(string(raw), "\r\n\r\n")
	if !ok {
		return errors.New("malformed http response: no header/body separator")
	}
	statusLine, _, _ := strings.Cut(head, "\r\n")
	fmt.Printf("http: %s body=%d bytes\n", statusLine, len(body))
	if !strings.Contains(statusLine, "200") {
		return fmt.Errorf("non-200 response: %s", statusLine)
	}
	return printAnswer([]byte(body))
}

// runServer listens for DoT connections, forcing SM negotiation, and
// forwards every query to the configured UDP resolver.
func runServer(listen, forward string) error {
	cert, err := selfSignedCert()
	if err != nil {
		return err
	}
	cfg := &eTLS.Config{
		MinVersion:       eTLS.VersionTLS13,
		CipherSuites:     smCipherSuites(),
		CurvePreferences: smCurves(),
		Certificates:     []eTLS.Certificate{cert},
	}
	ln, err := eTLS.Listen("tcp", listen, cfg)
	if err != nil {
		return fmt.Errorf("listen %s: %w", listen, err)
	}
	defer func() { _ = ln.Close() }()
	fmt.Printf("smpeer server: listening on %s (SM-only, forward %s)\n", listen, forward)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("accept: %w", err)
		}
		go serveConn(conn, forward)
	}
}

func serveConn(conn net.Conn, forward string) {
	defer func() { _ = conn.Close() }()
	// Accept() returns before the lazy handshake runs — force it so the
	// reported ConnectionState reflects the negotiated parameters.
	if tlsConn, ok := conn.(*eTLS.Conn); ok {
		if err := tlsConn.Handshake(); err != nil {
			fmt.Fprintf(os.Stderr, "smpeer: handshake: %v\n", err)
			return
		}
		cs := tlsConn.ConnectionState()
		reportHandshake("connection", &cs)
	}
	for {
		query, err := readFramed(conn)
		if err != nil {
			return
		}
		answer, err := exchangeUDP(forward, query)
		if err != nil {
			fmt.Fprintf(os.Stderr, "smpeer: forward: %v\n", err)
			return
		}
		if err := writeFramed(conn, answer); err != nil {
			return
		}
	}
}

// exchangeUDP forwards one query datagram to the plain resolver.
func exchangeUDP(forward string, query []byte) ([]byte, error) {
	var d net.Dialer
	conn, err := d.Dial("udp", forward)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(exchangeTimeout)); err != nil {
		return nil, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, dns.MaxMsgSize)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// writeFramed / readFramed implement the RFC 1035 2-byte length prefix used
// by DoT over stream transports.
func writeFramed(conn net.Conn, payload []byte) error {
	frame := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(frame, uint16(len(payload))) //nolint:gosec // G115: DNS data length fits in uint16
	copy(frame[2:], payload)
	_, err := conn.Write(frame)
	return err
}

func readFramed(conn net.Conn) ([]byte, error) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return nil, err
	}
	payload := make([]byte, binary.BigEndian.Uint16(head))
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// selfSignedCert mints a throwaway ECDSA P-256 certificate for server mode.
func selfSignedCert() (eTLS.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return eTLS.Certificate{}, fmt.Errorf("generate key: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "smpeer.local"},
		NotBefore:    time.Now().Add(-certValidity),
		NotAfter:     time.Now().Add(certValidity),
		DNSNames:     []string{"smpeer.local"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return eTLS.Certificate{}, fmt.Errorf("create certificate: %w", err)
	}
	return eTLS.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
