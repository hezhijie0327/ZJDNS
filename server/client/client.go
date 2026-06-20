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

	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"
)

// MaxIncomingStreams is the maximum number of concurrent incoming QUIC streams
// per connection.
const MaxIncomingStreams = 256

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

// UpstreamResult contains the parsed answer sections from an upstream DNS
// response.
type UpstreamResult struct {
	Answer     []dns.RR
	Authority  []dns.RR
	Additional []dns.RR
	Validated  bool
	ECS        *edns.ECSOption
	Server     string
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

	dohTransportMu sync.Mutex
	dohTransports  map[string]*http.Client

	doh3TransportMu sync.Mutex
	doh3Transports  map[string]*http.Client

	quicPool *QuicPool

	SessionCache tls.ClientSessionCache

	tcpPool *Pool
	dotPool *Pool
}

// New creates a Client with default timeouts, transport pools, and session
// caches.
func New() *Client {
	udpClient := &dns.Client{
		Timeout: OperationTimeout,
		Net:     "udp",
		UDPSize: pool.UDPBufferSize,
	}

	tcpClient := &dns.Client{
		Timeout: OperationTimeout,
		Net:     "tcp",
	}

	tlsClient := &dns.Client{
		Timeout: OperationTimeout,
		Net:     "tcp-tls",
	}

	dohTransport := &http.Transport{
		MaxIdleConns:        1,
		MaxIdleConnsPerHost: 1,
		IdleConnTimeout:     config.IdleTimeout,
		DisableCompression:  false,
		ForceAttemptHTTP2:   true,
	}

	doh3Transport := &http.Transport{
		MaxIdleConns:        1,
		MaxIdleConnsPerHost: 1,
		IdleConnTimeout:     config.IdleTimeout,
		DisableCompression:  false,
		ForceAttemptHTTP2:   false,
	}

	return &Client{
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
		quicPool:       NewQuicPool(DefaultMaxConns),
		SessionCache:   tls.NewLRUClientSessionCache(32),
		tcpPool:        NewPool(DefaultMaxConns, DefaultMaxPipe),
		dotPool:        NewPool(DefaultMaxConns, DefaultMaxPipe),
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
		MinVersion:         tls.VersionTLS12,
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

// SetTimeout sets the per-query timeout for all transport protocols.
func (c *Client) SetTimeout(timeout time.Duration) {
	c.timeout = timeout
	c.udpClient.Timeout = timeout
	c.tcpClient.Timeout = timeout
	c.tlsClient.Timeout = timeout
}

// Timeout returns the current per-query timeout duration.
func (c *Client) Timeout() time.Duration {
	return c.timeout
}
