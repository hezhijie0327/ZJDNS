// Package main implements ZJDNS - High Performance DNS Server
package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"
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
	ECS        *edns.ECSOption
}

// UpstreamQueryResult contains internal upstream query fields used during aggregation.
type UpstreamQueryResult struct {
	answer     []dns.RR
	authority  []dns.RR
	additional []dns.RR
	validated  bool
	ecs        *edns.ECSOption
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

	// Connection pools for secure protocols to avoid per-query setup overhead.
	dohTransportMu sync.Mutex
	dohTransports  map[string]*http.Client // keyed by address|servername|skipVerify

	doh3TransportMu sync.Mutex
	doh3Transports  map[string]*http.Client // keyed by address|servername|skipVerify

	// QUIC connection pool for DoQ query multiplexing.
	quicPool *quicPool

	// Shared TLS session cache for QUIC 0-RTT resumption across secure connections.
	sessionCache tls.ClientSessionCache

	// Pipelined TCP/DoT connection pools (RFC 7766).
	tcpPool *connPool // plain TCP, keyed by address
	dotPool *connPool // DoT, keyed by "address|servername|skipVerify"
}

// NewQueryClient creates a new QueryClient with configured UDP, TCP, TLS, DoH, and DoH3 clients.
// The client is configured with appropriate timeouts and buffer sizes for DNS queries.
func NewQueryClient() *QueryClient {
	// Configure UDP client
	udpClient := &dns.Client{
		Timeout: OperationTimeout,
		Net:     "udp",
		UDPSize: pool.UDPBufferSize,
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
		IdleConnTimeout:     config.IdleTimeout,
		DisableCompression:  false,
		ForceAttemptHTTP2:   true,
	}

	// Configure HTTP/3 transport for DoH3
	doh3Transport := &http.Transport{
		MaxIdleConns:        1,
		MaxIdleConnsPerHost: 1,
		IdleConnTimeout:     config.IdleTimeout,
		DisableCompression:  false,
		ForceAttemptHTTP2:   false,
	}

	qc := &QueryClient{
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
		dohTransports:  make(map[string]*http.Client),
		doh3Transports: make(map[string]*http.Client),
		quicPool:       newQuicPool(defaultMaxConns),
		sessionCache:   tls.NewLRUClientSessionCache(32),
		tcpPool:        newConnPool(defaultMaxConns, defaultMaxPipe),
		dotPool:        newConnPool(defaultMaxConns, defaultMaxPipe),
	}
	return qc
}

// ExecuteQuery executes a DNS query to the specified upstream server.
// It automatically selects the appropriate protocol and handles fallback from UDP to TCP if needed.
func (qc *QueryClient) ExecuteQuery(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer) *QueryResult {
	start := time.Now()
	result := &QueryResult{Server: server.Address, Protocol: server.Protocol}

	qname := ""
	if len(msg.Question) > 0 {
		qname = msg.Question[0].Name
	}
	log.Debugf("UPSTREAM: querying %s (%s) for %s", server.Address, strings.ToUpper(server.Protocol), qname)

	// Create query context with timeout
	queryCtx, cancel := context.WithTimeout(ctx, qc.timeout)
	defer cancel()

	protocol := strings.ToLower(server.Protocol)

	// Execute query based on protocol type
	if dnsutil.IsSecureProtocol(protocol) {
		result.Response, result.Error = qc.executeSecureQuery(queryCtx, msg, server, protocol)
	} else {
		result.Response, result.Error = qc.executeTraditionalQuery(queryCtx, msg, server)

		// Handle TCP fallback for truncated UDP responses
		if qc.needsTCPFallback(result, protocol) {
			log.Debugf("UPSTREAM: UDP truncated/failed for %s, falling back to TCP for %s", qname, server.Address)
			tcpServer := *server
			tcpServer.Protocol = "tcp"

			if tcpResp, tcpErr := qc.executeTraditionalQuery(queryCtx, msg, &tcpServer); tcpErr == nil {
				result.Response = tcpResp
				result.Error = nil
				result.Protocol = "TCP"
				log.Debugf("UPSTREAM: TCP fallback succeeded for %s via %s", qname, server.Address)
			} else {
				log.Debugf("UPSTREAM: TCP fallback failed for %s via %s: %v", qname, server.Address, tcpErr)
			}
		}
	}

	result.Duration = time.Since(start)
	result.Protocol = strings.ToUpper(protocol)

	if result.Error != nil {
		log.Debugf("UPSTREAM: query failed for %s via %s (%s) in %v, error=%v", qname, server.Address, result.Protocol, result.Duration, result.Error)
	} else if result.Response != nil {
		log.Debugf("UPSTREAM: success for %s via %s (%s) in %v, rcode=%s, answer=%d", qname, server.Address, result.Protocol, result.Duration, dns.RcodeToString[result.Response.Rcode], len(result.Response.Answer))
	}

	return result
}

// executeSecureQuery executes a DNS query over a secure protocol (TLS, QUIC, HTTPS, HTTP3).
func (qc *QueryClient) executeSecureQuery(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer, protocol string) (*dns.Msg, error) {
	// Configure TLS
	tlsConfig := &tls.Config{
		CurvePreferences:   []tls.CurveID{}, // empty = use Go defaults
		InsecureSkipVerify: server.SkipTLSVerify,
		MinVersion:         tls.VersionTLS12,
		ServerName:         server.ServerName,
		ClientSessionCache: qc.sessionCache,
	}

	if server.SkipTLSVerify {
		log.Debugf("UPSTREAM: TLS verification disabled for %s - security risk!", server.ServerName)
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
// Uses a pipelined connection pool for connection reuse and query multiplexing.
// Falls back to single-shot ExchangeContext if the pool is unavailable.
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
