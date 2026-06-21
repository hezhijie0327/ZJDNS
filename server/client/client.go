// Package client implements outbound DNS query execution over UDP, TCP, DoT,
// DoQ, DoH, and DoH3 with connection pooling.
package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go/http3"

	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"

	connpool "zjdns/server/client/pool"
)

// MaxIncomingStreams is the maximum number of concurrent incoming QUIC streams
// per connection.
const MaxIncomingStreams = 256

// Re-exported pool constants for backward compatibility.
const (
	DefaultMaxPipe   = connpool.DefaultMaxPipe
	DefaultMaxConns  = connpool.DefaultMaxConns
	DefaultTimeout   = connpool.DefaultTimeout
	OperationTimeout = connpool.OperationTimeout
)

// NextProtoDoQ is the ALPN protocol identifier for DNS over QUIC.
var NextProtoDoQ = []string{"doq"}

// NextProtoDoH3 is the ALPN protocol identifier for DNS over HTTP/3.
var NextProtoDoH3 = []string{"h3"}

// Result holds the outcome of a single DNS query including response, timing,
// and metadata.
type Result struct {
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

// Client manages outbound DNS queries across multiple transport protocols with
// pooling.
type Client struct {
	timeout    time.Duration
	udpClient  *dns.Client
	tcpClient  *dns.Client
	tlsClient  *dns.Client
	dohClient  *http.Client
	doh3Client *http.Client

	dohTransportMu sync.RWMutex
	dohTransports  map[string]*http.Client

	doh3TransportMu sync.RWMutex
	doh3Transports  map[string]*http.Client

	quicPool *connpool.QuicPool

	SessionCache tls.ClientSessionCache

	tcpPool *connpool.Pool
	dotPool *connpool.Pool
}

// New creates a Client with default timeouts, transport pools, and session
// caches.
func New() *Client {
	udpClient := &dns.Client{
		Timeout: connpool.OperationTimeout,
		Net:     "udp",
		UDPSize: pool.UDPBufferSize,
	}

	tcpClient := &dns.Client{
		Timeout: connpool.OperationTimeout,
		Net:     "tcp",
	}

	tlsClient := &dns.Client{
		Timeout: connpool.OperationTimeout,
		Net:     "tcp-tls",
	}

	dohTransport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 25,
		IdleConnTimeout:     config.IdleTimeout,
		DisableCompression:  false,
		ForceAttemptHTTP2:   true,
	}

	doh3Transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 25,
		IdleConnTimeout:     config.IdleTimeout,
		DisableCompression:  false,
		ForceAttemptHTTP2:   false,
	}

	return &Client{
		timeout:   connpool.OperationTimeout,
		udpClient: udpClient,
		tcpClient: tcpClient,
		tlsClient: tlsClient,
		dohClient: &http.Client{
			Timeout:   connpool.OperationTimeout,
			Transport: dohTransport,
		},
		doh3Client: &http.Client{
			Timeout:   connpool.OperationTimeout,
			Transport: doh3Transport,
		},
		dohTransports:  make(map[string]*http.Client),
		doh3Transports: make(map[string]*http.Client),
		quicPool:       connpool.NewQuicPool(connpool.DefaultMaxConns),
		SessionCache:   tls.NewLRUClientSessionCache(32),
		tcpPool:        connpool.NewPool(connpool.DefaultMaxConns, connpool.DefaultMaxPipe),
		dotPool:        connpool.NewPool(connpool.DefaultMaxConns, connpool.DefaultMaxPipe),
	}
}

// ExecuteQuery sends a DNS query to an upstream server and returns the result.
func (c *Client) ExecuteQuery(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer) *Result {
	start := time.Now()
	result := &Result{Server: server.Address, Protocol: server.Protocol}

	qname := ""
	if len(msg.Question) > 0 {
		qname = msg.Question[0].Name
	}
	log.Debugf("UPSTREAM: querying %s (%s) for %s", server.Address, strings.ToUpper(server.Protocol), qname)

	queryCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	protocol := strings.ToLower(server.Protocol)

	if dnsutil.IsSecureProtocol(protocol) {
		result.Response, result.Error = c.executeSecureQuery(queryCtx, msg, server, protocol)
	} else {
		result.Response, result.Error = c.executeTraditionalQuery(queryCtx, msg, server)

		if c.needsTCPFallback(result, protocol) {
			log.Debugf("UPSTREAM: UDP truncated/failed for %s, falling back to TCP for %s", qname, server.Address)
			tcpServer := *server
			tcpServer.Protocol = "tcp"

			if tcpResp, tcpErr := c.executeTraditionalQuery(queryCtx, msg, &tcpServer); tcpErr == nil {
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

func (c *Client) executeSecureQuery(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer, protocol string) (*dns.Msg, error) {
	tlsConfig := &tls.Config{
		CurvePreferences:   []tls.CurveID{},
		InsecureSkipVerify: server.SkipTLSVerify,
		MinVersion:         tls.VersionTLS13,
		ServerName:         server.ServerName,
		ClientSessionCache: c.SessionCache,
	}

	if server.SkipTLSVerify {
		log.Debugf("UPSTREAM: TLS verification disabled for %s - security risk!", server.ServerName)
	}

	switch protocol {
	case "dot", "tls":
		return c.executeTLS(ctx, msg, server, tlsConfig)
	case "doq", "quic":
		return c.executeQUIC(ctx, msg, server, tlsConfig)
	case "doh", "https":
		return c.executeDoH(ctx, msg, server, tlsConfig)
	case "doh3", "http3":
		return c.executeDoH3(ctx, msg, server, tlsConfig)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", protocol)
	}
}

// Close shuts down all pooled connections and transports, releasing file
// descriptors and goroutines. Safe to call multiple times.
func (c *Client) Close() {
	if c == nil {
		return
	}

	// Close DoH transports (HTTP/2 connections)
	c.dohTransportMu.Lock()
	for _, client := range c.dohTransports {
		if t, ok := client.Transport.(*http.Transport); ok {
			t.CloseIdleConnections()
		}
	}
	c.dohTransports = nil
	c.dohTransportMu.Unlock()

	// Close DoH3 transports (QUIC/HTTP3 connections)
	c.doh3TransportMu.Lock()
	for _, client := range c.doh3Transports {
		if t, ok := client.Transport.(*http3.Transport); ok {
			_ = t.Close()
		}
	}
	c.doh3Transports = nil
	c.doh3TransportMu.Unlock()

	// Close pooled TCP/DoT connections
	if c.tcpPool != nil {
		c.tcpPool.Shutdown()
	}
	if c.dotPool != nil {
		c.dotPool.Shutdown()
	}

	// Close pooled QUIC connections
	if c.quicPool != nil {
		c.quicPool.Shutdown()
	}
}
