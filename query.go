// Package main implements ZJDNS - High Performance DNS Server
package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

// QueryResult contains the result of a DNS query execution.
type QueryResult struct {
	Response   *dns.Msg
	Answer     []dns.RR
	Authority  []dns.RR
	Additional []dns.RR
	Server     string
	Error      error
	Duration   time.Duration
	Protocol   string
	Validated  bool
	ECS        *ECSOption
}

// UpstreamQueryResult contains internal upstream query fields used during aggregation.
type UpstreamQueryResult struct {
	answer     []dns.RR
	authority  []dns.RR
	additional []dns.RR
	validated  bool
	ecs        *ECSOption
	server     string
}

// QueryClient is responsible for executing DNS queries to upstream servers using various protocols (UDP, TCP, DoT, DoH, DoQ).
type QueryClient struct {
	timeout    time.Duration
	udpClient  *dns.Client
	tcpClient  *dns.Client
	tlsClient  *dns.Client
	dohClient  *http.Client
	doh3Client *http.Client
}

// NewQueryClient creates a new QueryClient with configured UDP, TCP, TLS, DoH, and DoH3 clients.
// The client is configured with appropriate timeouts and buffer sizes for DNS queries.
func NewQueryClient() *QueryClient {
	// Configure UDP client
	udpClient := &dns.Client{
		Timeout: OperationTimeout,
		Net:     "udp",
		UDPSize: UDPBufferSize,
	}

	// Configure TCP client
	tcpClient := &dns.Client{
		Timeout: OperationTimeout,
		Net:     "tcp",
	}

	// Configure TLS client for DoT
	tlsClient := &dns.Client{
		Timeout: OperationTimeout,
		Net:     "tcp-tls",
	}

	// Configure HTTP/2 transport for DoH
	dohTransport := &http.Transport{
		MaxIdleConns:        1,
		MaxIdleConnsPerHost: 1,
		IdleConnTimeout:     IdleTimeout,
		DisableCompression:  false,
		ForceAttemptHTTP2:   true,
	}

	// Configure HTTP/3 transport for DoH3
	doh3Transport := &http.Transport{
		MaxIdleConns:        1,
		MaxIdleConnsPerHost: 1,
		IdleConnTimeout:     IdleTimeout,
		DisableCompression:  false,
		ForceAttemptHTTP2:   false,
	}

	return &QueryClient{
		timeout:   OperationTimeout,
		udpClient: udpClient,
		tcpClient: tcpClient,
		tlsClient: tlsClient,
		dohClient: &http.Client{
			Timeout:   OperationTimeout,
			Transport: dohTransport,
		},
		doh3Client: &http.Client{
			Timeout:   OperationTimeout,
			Transport: doh3Transport,
		},
	}
}

// ExecuteQuery executes a DNS query to the specified upstream server.
// It automatically selects the appropriate protocol and handles fallback from UDP to TCP if needed.
func (qc *QueryClient) ExecuteQuery(ctx context.Context, msg *dns.Msg, server *UpstreamServer) *QueryResult {
	start := time.Now()
	result := &QueryResult{Server: server.Address, Protocol: server.Protocol}

	qname := ""
	if len(msg.Question) > 0 {
		qname = msg.Question[0].Name
	}
	LogDebug("QUERY: querying %s (%s) for %s", server.Address, strings.ToUpper(server.Protocol), qname)

	// Create query context with timeout
	queryCtx, cancel := context.WithTimeout(ctx, qc.timeout)
	defer cancel()

	protocol := strings.ToLower(server.Protocol)

	// Execute query based on protocol type
	if IsSecureProtocol(protocol) {
		result.Response, result.Error = qc.executeSecureQuery(queryCtx, msg, server, protocol)
	} else {
		result.Response, result.Error = qc.executeTraditionalQuery(queryCtx, msg, server)

		// Handle TCP fallback for truncated UDP responses
		if qc.needsTCPFallback(result, protocol) {
			LogDebug("QUERY: UDP truncated/failed for %s, falling back to TCP for %s", qname, server.Address)
			tcpServer := *server
			tcpServer.Protocol = "tcp"

			if tcpResp, tcpErr := qc.executeTraditionalQuery(queryCtx, msg, &tcpServer); tcpErr == nil {
				result.Response = tcpResp
				result.Error = nil
				result.Protocol = "TCP"
				LogDebug("QUERY: TCP fallback succeeded for %s via %s", qname, server.Address)
			} else {
				LogDebug("QUERY: TCP fallback failed for %s via %s: %v", qname, server.Address, tcpErr)
			}
		}
	}

	result.Duration = time.Since(start)
	result.Protocol = strings.ToUpper(protocol)

	if result.Error != nil {
		LogDebug("QUERY: failed for %s via %s (%s) in %v, error=%v", qname, server.Address, result.Protocol, result.Duration, result.Error)
	} else if result.Response != nil {
		LogDebug("QUERY: success for %s via %s (%s) in %v, rcode=%s, answer=%d", qname, server.Address, result.Protocol, result.Duration, dns.RcodeToString[result.Response.Rcode], len(result.Response.Answer))
	}

	return result
}

// executeSecureQuery executes a DNS query over a secure protocol (TLS, QUIC, HTTPS, HTTP3).
func (qc *QueryClient) executeSecureQuery(ctx context.Context, msg *dns.Msg, server *UpstreamServer, protocol string) (*dns.Msg, error) {
	// Configure TLS
	tlsConfig := &tls.Config{
		CurvePreferences:   []tls.CurveID{},
		InsecureSkipVerify: server.SkipTLSVerify,
		MinVersion:         tls.VersionTLS12,
		ServerName:         server.ServerName,
	}

	if server.SkipTLSVerify {
		LogDebug("QUERY: TLS verification disabled for %s - security risk!", server.ServerName)
	}

	// Route to appropriate protocol handler
	switch protocol {
	case "dot", "tls":
		return qc.executeTLS(ctx, msg, server, tlsConfig)
	case "doq", "quic":
		return qc.executeQUIC(ctx, msg, server, tlsConfig)
	case "doh", "https":
		return qc.executeDoH(ctx, msg, server, tlsConfig)
	case "doh3", "http3":
		return qc.executeDoH3(ctx, msg, server, tlsConfig)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", protocol)
	}
}

// executeTLS executes a DNS query over DNS over TLS (DoT).
func (qc *QueryClient) executeTLS(ctx context.Context, msg *dns.Msg, server *UpstreamServer, tlsConfig *tls.Config) (*dns.Msg, error) {
	qc.tlsClient.TLSConfig = tlsConfig
	response, _, err := qc.tlsClient.ExchangeContext(ctx, msg, server.Address)
	return response, err
}

// executeQUIC executes a DNS query over DNS over QUIC (DoQ).
func (qc *QueryClient) executeQUIC(ctx context.Context, msg *dns.Msg, server *UpstreamServer, tlsConfig *tls.Config) (*dns.Msg, error) {
	// Clone and configure TLS for DoQ
	tlsConfig = tlsConfig.Clone()
	tlsConfig.NextProtos = NextProtoDoQ

	// Configure QUIC
	quicConfig := &quic.Config{
		MaxIdleTimeout:        IdleTimeout,
		MaxIncomingStreams:    MaxIncomingStreams,
		MaxIncomingUniStreams: MaxIncomingStreams,
		EnableDatagrams:       true,
		Allow0RTT:             false,
	}

	// Dial QUIC connection
	dialCtx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()

	conn, err := quic.DialAddr(dialCtx, server.Address, tlsConfig, quicConfig)
	if err != nil {
		return nil, fmt.Errorf("QUIC dial: %w", err)
	}
	defer func() {
		_ = conn.CloseWithError(QUICCodeNoError, "query completed")
	}()

	// Open stream
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}
	defer func() { _ = stream.Close() }()

	_ = stream.SetDeadline(time.Now().Add(qc.timeout))

	// Set message ID to 0 for QUIC (per RFC)
	originalID := msg.Id
	msg.Id = 0

	// Pack message
	msgData, err := msg.Pack()
	if err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("pack: %w", err)
	}

	// Write message with length prefix
	buf := bufferPool.Get()
	defer bufferPool.Put(buf)

	if len(buf) < 2+len(msgData) {
		buf = make([]byte, 2+len(msgData))
	}

	binary.BigEndian.PutUint16(buf[:2], uint16(len(msgData)))
	copy(buf[2:], msgData)

	if _, err := stream.Write(buf[:2+len(msgData)]); err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("write: %w", err)
	}

	// Read response
	respBuf := bufferPool.Get()
	defer bufferPool.Put(respBuf)

	n, err := stream.Read(respBuf)
	if err != nil && n == 0 {
		msg.Id = originalID
		return nil, fmt.Errorf("read: %w", err)
	}

	if n < 2 {
		msg.Id = originalID
		return nil, fmt.Errorf("response too short: %d", n)
	}

	// Parse response
	response := messagePool.Get()
	if err := response.Unpack(respBuf[2:n]); err != nil {
		msg.Id = originalID
		messagePool.Put(response)
		return nil, fmt.Errorf("unpack: %w", err)
	}

	msg.Id = originalID
	response.Id = originalID

	return response, nil
}

// executeDoH executes a DNS query over DNS over HTTPS (DoH/HTTP2).
func (qc *QueryClient) executeDoH(ctx context.Context, msg *dns.Msg, server *UpstreamServer, tlsConfig *tls.Config) (*dns.Msg, error) {
	// Parse URL
	parsedURL, err := url.Parse(server.Address)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}

	// Add default port if not specified
	if parsedURL.Port() == "" {
		parsedURL.Host = net.JoinHostPort(parsedURL.Host, DefaultDOHPort)
	}

	// Configure HTTP/2 transport
	dohTransport := qc.dohClient.Transport.(*http.Transport)
	dohTransport.TLSClientConfig = tlsConfig.Clone()
	if err := http2.ConfigureTransport(dohTransport); err != nil {
		return nil, fmt.Errorf("configure HTTP/2: %w", err)
	}

	// Set message ID to 0 for DoH (privacy consideration)
	originalID := msg.Id
	msg.Id = 0

	// Pack message
	buf, err := msg.Pack()
	if err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("pack: %w", err)
	}

	// Build request URL
	q := url.Values{"dns": []string{base64.RawURLEncoding.EncodeToString(buf)}}
	u := url.URL{
		Scheme:   parsedURL.Scheme,
		Host:     parsedURL.Host,
		Path:     parsedURL.Path,
		RawQuery: q.Encode(),
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Accept", "application/dns-message")
	httpReq.Header.Set("User-Agent", "")

	// Execute request
	httpResp, err := qc.dohClient.Do(httpReq)
	if err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	if httpResp.StatusCode != http.StatusOK {
		msg.Id = originalID
		return nil, fmt.Errorf("HTTP status: %d", httpResp.StatusCode)
	}

	// Read response body
	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("read body: %w", err)
	}

	// Parse DNS response
	response := messagePool.Get()
	if err := response.Unpack(body); err != nil {
		msg.Id = originalID
		messagePool.Put(response)
		return nil, fmt.Errorf("unpack: %w", err)
	}

	msg.Id = originalID
	response.Id = originalID

	return response, nil
}

// executeDoH3 executes a DNS query over DNS over HTTPS/3 (DoH3/HTTP3).
func (qc *QueryClient) executeDoH3(ctx context.Context, msg *dns.Msg, server *UpstreamServer, tlsConfig *tls.Config) (*dns.Msg, error) {
	// Parse URL
	parsedURL, err := url.Parse(server.Address)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}

	// Add default port if not specified
	if parsedURL.Port() == "" {
		parsedURL.Host = net.JoinHostPort(parsedURL.Host, DefaultDOHPort)
	}

	// Configure TLS for HTTP/3
	tlsConfig = tlsConfig.Clone()
	tlsConfig.NextProtos = NextProtoDoH3

	// Create HTTP/3 transport
	transport := &http3.Transport{
		TLSClientConfig: tlsConfig,
		QUICConfig: &quic.Config{
			MaxIdleTimeout:        IdleTimeout,
			MaxIncomingStreams:    MaxIncomingStreams,
			MaxIncomingUniStreams: MaxIncomingStreams,
			EnableDatagrams:       true,
			Allow0RTT:             false,
		},
	}

	qc.doh3Client.Transport = transport

	// Set message ID to 0 for DoH (privacy consideration)
	originalID := msg.Id
	msg.Id = 0

	// Pack message
	buf, err := msg.Pack()
	if err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("pack: %w", err)
	}

	// Build request URL
	q := url.Values{"dns": []string{base64.RawURLEncoding.EncodeToString(buf)}}
	u := url.URL{
		Scheme:   parsedURL.Scheme,
		Host:     parsedURL.Host,
		Path:     parsedURL.Path,
		RawQuery: q.Encode(),
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Accept", "application/dns-message")
	httpReq.Header.Set("User-Agent", "")

	// Execute request
	httpResp, err := qc.doh3Client.Do(httpReq)
	if err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	if httpResp.StatusCode != http.StatusOK {
		msg.Id = originalID
		return nil, fmt.Errorf("HTTP status: %d", httpResp.StatusCode)
	}

	// Read response body
	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("read body: %w", err)
	}

	// Parse DNS response
	response := messagePool.Get()
	if err := response.Unpack(body); err != nil {
		msg.Id = originalID
		messagePool.Put(response)
		return nil, fmt.Errorf("unpack: %w", err)
	}

	msg.Id = originalID
	response.Id = originalID

	return response, nil
}

// executeTraditionalQuery executes a DNS query over traditional UDP or TCP.
func (qc *QueryClient) executeTraditionalQuery(ctx context.Context, msg *dns.Msg, server *UpstreamServer) (*dns.Msg, error) {
	var client *dns.Client

	switch server.Protocol {
	case "tcp":
		client = qc.tcpClient
	default:
		client = qc.udpClient
	}

	response, _, err := client.ExchangeContext(ctx, msg, server.Address)
	return response, err
}

// needsTCPFallback checks if a query result requires fallback to TCP.
// This happens when UDP queries are truncated or fail.
func (qc *QueryClient) needsTCPFallback(result *QueryResult, protocol string) bool {
	return protocol != "tcp" && (result.Error != nil || (result.Response != nil && result.Response.Truncated))
}

// SetTimeout sets the query timeout duration.
func (qc *QueryClient) SetTimeout(timeout time.Duration) {
	qc.timeout = timeout
	qc.udpClient.Timeout = timeout
	qc.tcpClient.Timeout = timeout
	qc.tlsClient.Timeout = timeout
}

// GetTimeout returns the current query timeout duration.
func (qc *QueryClient) GetTimeout() time.Duration {
	return qc.timeout
}
