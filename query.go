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

	"codeberg.org/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

// =============================================================================
// QueryClient Implementation
// =============================================================================

// NewQueryClient creates a new QueryClient with configured UDP, TCP, TLS, DoH, and DoH3 clients.
// The client is configured with appropriate timeouts and buffer sizes for DNS queries.
func NewQueryClient() *QueryClient {
	// Configure UDP client
	udpClient := &dns.Client{Transport: dns.NewTransport()}
	udpClient.Transport.Dialer = &net.Dialer{Timeout: OperationTimeout}
	udpClient.Transport.ReadTimeout = OperationTimeout
	udpClient.Transport.WriteTimeout = OperationTimeout

	// Configure TCP client
	tcpClient := &dns.Client{Transport: dns.NewTransport()}
	tcpClient.Transport.Dialer = &net.Dialer{Timeout: OperationTimeout}
	tcpClient.Transport.ReadTimeout = OperationTimeout
	tcpClient.Transport.WriteTimeout = OperationTimeout

	// Configure TLS client for DoT
	tlsClient := &dns.Client{Transport: dns.NewTransport()}
	tlsClient.Transport.Dialer = &net.Dialer{Timeout: OperationTimeout}
	tlsClient.Transport.ReadTimeout = OperationTimeout
	tlsClient.Transport.WriteTimeout = OperationTimeout

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
			tcpServer := *server
			tcpServer.Protocol = "tcp"
			if tcpResp, tcpErr := qc.executeTraditionalQuery(queryCtx, msg, &tcpServer); tcpErr == nil {
				result.Response = tcpResp
				result.Error = nil
				result.Protocol = "TCP"
			}
		}
	}

	result.Duration = time.Since(start)
	result.Protocol = strings.ToUpper(protocol)

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
	response, _, err := qc.tlsClient.Exchange(ctx, msg, "tcp", server.Address)
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
	originalID := msg.ID
	msg.ID = 0

	// Pack message
	if err := msg.Pack(); err != nil {
		msg.ID = originalID
		return nil, fmt.Errorf("pack: %w", err)
	}
	msgData := msg.Data

	// Write message with length prefix
	buf := bufferPool.Get()
	defer bufferPool.Put(buf)

	if len(buf) < 2+len(msgData) {
		buf = make([]byte, 2+len(msgData))
	}

	binary.BigEndian.PutUint16(buf[:2], uint16(len(msgData)))
	copy(buf[2:], msgData)

	if _, err := stream.Write(buf[:2+len(msgData)]); err != nil {
		msg.ID = originalID
		return nil, fmt.Errorf("write: %w", err)
	}

	// Read response
	respBuf := bufferPool.Get()
	defer bufferPool.Put(respBuf)

	n, err := stream.Read(respBuf)
	if err != nil && n == 0 {
		msg.ID = originalID
		return nil, fmt.Errorf("read: %w", err)
	}

	if n < 2 {
		msg.ID = originalID
		return nil, fmt.Errorf("response too short: %d", n)
	}

	// Parse response
	response := messagePool.Get()
	response.Data = respBuf[2:n]
	if err := response.Unpack(); err != nil {
		msg.ID = originalID
		messagePool.Put(response)
		return nil, fmt.Errorf("unpack: %w", err)
	}

	msg.ID = originalID
	response.ID = originalID

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
	originalID := msg.ID
	msg.ID = 0

	if err := msg.Pack(); err != nil {
		msg.ID = originalID
		return nil, fmt.Errorf("pack: %w", err)
	}
	buf := msg.Data

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
		msg.ID = originalID
		return nil, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Accept", "application/dns-message")
	httpReq.Header.Set("User-Agent", "")

	// Execute request
	httpResp, err := qc.dohClient.Do(httpReq)
	if err != nil {
		msg.ID = originalID
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	if httpResp.StatusCode != http.StatusOK {
		msg.ID = originalID
		return nil, fmt.Errorf("HTTP status: %d", httpResp.StatusCode)
	}

	// Read response body
	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		msg.ID = originalID
		return nil, fmt.Errorf("read body: %w", err)
	}

	// Parse DNS response
	response := messagePool.Get()
	response.Data = body
	if err := response.Unpack(); err != nil {
		msg.ID = originalID
		messagePool.Put(response)
		return nil, fmt.Errorf("unpack: %w", err)
	}

	msg.ID = originalID
	response.ID = originalID

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
	originalID := msg.ID
	msg.ID = 0

	if err := msg.Pack(); err != nil {
		msg.ID = originalID
		return nil, fmt.Errorf("pack: %w", err)
	}
	buf := msg.Data

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
		msg.ID = originalID
		return nil, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Accept", "application/dns-message")
	httpReq.Header.Set("User-Agent", "")

	// Execute request
	httpResp, err := qc.doh3Client.Do(httpReq)
	if err != nil {
		msg.ID = originalID
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	if httpResp.StatusCode != http.StatusOK {
		msg.ID = originalID
		return nil, fmt.Errorf("HTTP status: %d", httpResp.StatusCode)
	}

	// Read response body
	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		msg.ID = originalID
		return nil, fmt.Errorf("read body: %w", err)
	}

	// Parse DNS response
	response := messagePool.Get()
	response.Data = body
	if err := response.Unpack(); err != nil {
		msg.ID = originalID
		messagePool.Put(response)
		return nil, fmt.Errorf("unpack: %w", err)
	}

	msg.ID = originalID
	response.ID = originalID

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

	response, _, err := client.Exchange(ctx, msg, server.Protocol, server.Address)
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
	if qc.udpClient != nil && qc.udpClient.Transport != nil {
		qc.udpClient.Transport.ReadTimeout = timeout
		qc.udpClient.Transport.WriteTimeout = timeout
		if qc.udpClient.Transport.Dialer != nil {
			qc.udpClient.Transport.Dialer.Timeout = timeout
		}
	}
	if qc.tcpClient != nil && qc.tcpClient.Transport != nil {
		qc.tcpClient.Transport.ReadTimeout = timeout
		qc.tcpClient.Transport.WriteTimeout = timeout
		if qc.tcpClient.Transport.Dialer != nil {
			qc.tcpClient.Transport.Dialer.Timeout = timeout
		}
	}
	if qc.tlsClient != nil && qc.tlsClient.Transport != nil {
		qc.tlsClient.Transport.ReadTimeout = timeout
		qc.tlsClient.Transport.WriteTimeout = timeout
		if qc.tlsClient.Transport.Dialer != nil {
			qc.tlsClient.Transport.Dialer.Timeout = timeout
		}
	}
}

// GetTimeout returns the current query timeout duration.
func (qc *QueryClient) GetTimeout() time.Duration {
	return qc.timeout
}
