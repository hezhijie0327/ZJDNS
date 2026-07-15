// Package client implements outbound DNS query execution over UDP, TCP, DoT,
// DoQ, DoH, DoH3, DNSCrypt, TLCP, and DTLCP with connection pooling.
package upstream

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"zjdns/config"
	"zjdns/internal/log"
	"zjdns/server/upstream/dnscrypt"
	"zjdns/server/upstream/pool"
	"zjdns/server/upstream/traditional"

	zdnsutil "zjdns/internal/dnsutil"

	socks5 "zjdns/server/upstream/socks5"
	tlcpclient "zjdns/server/upstream/tlcp"
	tlsclient "zjdns/server/upstream/tls"

	"codeberg.org/miekg/dns"
	eHTTP "gitlab.com/go-extension/http"
	eTLS "gitlab.com/go-extension/tls"
)

// Result holds the outcome of a single DNS query including response, timing,
// and metadata.
type Result struct {
	Response  *dns.Msg
	Server    string
	Error     error
	Duration  time.Duration
	Protocol  string
	Validated bool
}

// Client manages outbound DNS queries across multiple transport protocols with
// pooling. Protocol-specific logic is delegated to sub-packages.
type Client struct {
	timeout     time.Duration
	traditional *traditional.Client
	tlsClient   *tlsclient.Client
	tlcpClient  *tlcpclient.Client
	dnscrypt    *dnscrypt.Client

	proxyDialers map[string]*socks5.Dialer
	proxyMu      sync.Mutex

	warmWg sync.WaitGroup // tracks in-flight WarmUpConnections goroutines
}

// New creates a Client with default timeouts, transport pools, and session
// caches. Sub-clients for each protocol family are created and wired with
// shared resources (proxy dialers, connection pools).
func New() *Client {
	defaultTransport := &dns.Transport{
		Dialer: &net.Dialer{
			Timeout:   config.DefaultDNSQueryTimeout,
			KeepAlive: 30 * time.Second,
		},
		ReadTimeout:  config.DefaultDNSQueryTimeout,
		WriteTimeout: config.DefaultDNSQueryTimeout,
	}

	udpClient := &dns.Client{Transport: defaultTransport}
	tcpClient := &dns.Client{Transport: defaultTransport}
	tlsDNSClient := &dns.Client{Transport: defaultTransport}

	dohTransport := &eHTTP.Transport{
		MaxIdleConns:        config.DefaultMaxIdleConns,
		MaxIdleConnsPerHost: config.DefaultMaxIdleConnsPerHost,
		IdleConnTimeout:     config.DefaultHTTPIdleConnTimeout,
		DisableCompression:  true,
		ForceAttemptHTTP2:   true,
	}
	dohClient := &eHTTP.Client{
		Timeout:   config.DefaultDNSQueryTimeout,
		Transport: dohTransport,
	}
	doh3Client := &http.Client{
		Timeout: config.DefaultDNSQueryTimeout,
	}

	timeout := config.DefaultDNSQueryTimeout
	sessionCache := eTLS.NewLRUClientSessionCache(config.DefaultTLSSessionCacheSize)
	tcpPool := pool.NewPool(config.DefaultMaxConns, config.DefaultMaxPipe)
	dotPool := pool.NewPool(config.DefaultMaxConns, config.DefaultMaxPipe)
	quicPool := pool.NewQUICPool(config.DefaultMaxConns)

	c := &Client{
		timeout:      timeout,
		proxyDialers: make(map[string]*socks5.Dialer),
	}

	c.traditional = traditional.New(udpClient, tcpClient, tcpPool, c.getProxyDialer, timeout)
	c.tlsClient = tlsclient.New(tlsDNSClient, dohClient, doh3Client, dotPool, quicPool, sessionCache, c.getProxyDialer, timeout)
	c.tlcpClient = tlcpclient.New(c.getProxyDialer, timeout)
	c.dnscrypt = dnscrypt.New(c.getProxyDialer)

	return c
}

// ExecuteQuery sends a DNS query to an upstream server and returns the result.
func (c *Client) ExecuteQuery(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer) *Result {
	start := time.Now()
	result := &Result{Server: server.Address, Protocol: server.Protocol}

	qname := ""
	if len(msg.Question) > 0 {
		qname = msg.Question[0].Header().Name
	}
	log.Debugf("UPSTREAM: querying %s (%s) for %s", server.Address, strings.ToUpper(server.Protocol), qname)

	queryCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	protocol := strings.ToLower(server.Protocol)

	if protocol == config.ProtoDNSCrypt || protocol == config.ProtoDNSCryptTCP {
		useTCP := protocol == config.ProtoDNSCryptTCP
		result.Response, result.Error = c.dnscrypt.Execute(queryCtx, msg, server, useTCP)

		if !useTCP && result.Error == nil && result.Response != nil && result.Response.Truncated {
			log.Debugf("UPSTREAM: DNSCrypt UDP response truncated for %s, falling back to TCP", qname)
			useTCP = true
		} else if !useTCP && result.Error != nil {
			log.Debugf("UPSTREAM: DNSCrypt UDP query failed for %s, falling back to TCP: %v", qname, result.Error)
			useTCP = true
		}

		if useTCP && protocol == config.ProtoDNSCrypt {
			if queryCtx.Err() == nil {
				result.Response, result.Error = c.dnscrypt.Execute(queryCtx, msg, server, true)
				if result.Error == nil {
					protocol = config.ProtoDNSCryptTCP
					log.Debugf("UPSTREAM: DNSCrypt TCP fallback succeeded for %s", qname)
				} else {
					log.Debugf("UPSTREAM: DNSCrypt TCP fallback failed for %s: %v", qname, result.Error)
				}
			}
		} else if result.Error != nil {
			log.Debugf("UPSTREAM: DNSCrypt query failed for %s via %s: %v", qname, server.Address, result.Error)
		}

		result.Duration = time.Since(start)
		result.Protocol = strings.ToUpper(protocol)
		return result
	}

	if zdnsutil.IsSecureProtocol(protocol) {
		result.Response, result.Error = c.executeSecureQuery(queryCtx, msg, server, protocol)
	} else {
		if protocol == config.ProtoTCP {
			result.Response, result.Error = c.traditional.ExecuteTCP(queryCtx, msg, server)
		} else {
			result.Response, result.Error = c.traditional.ExecuteUDP(queryCtx, msg, server)
		}

		if c.needsTCPFallback(result, protocol) {
			if queryCtx.Err() != nil {
				return result
			}

			if result.Response != nil && result.Response.Truncated {
				log.Debugf("UPSTREAM: UDP response truncated for %s, falling back to TCP for %s", qname, server.Address)
			} else {
				log.Debugf("UPSTREAM: UDP query failed for %s, falling back to TCP for %s: %v", qname, server.Address, result.Error)
			}

			tcpServer := *server
			tcpServer.Protocol = config.ProtoTCP

			if tcpResp, tcpErr := c.traditional.ExecuteTCP(queryCtx, msg, &tcpServer); tcpErr == nil {
				result.Response = tcpResp
				result.Error = nil
				result.Protocol = config.ProtoTCP
				log.Debugf("UPSTREAM: TCP fallback succeeded for %s via %s", qname, server.Address)
			} else {
				log.Debugf("UPSTREAM: TCP fallback failed for %s via %s: %v", qname, server.Address, tcpErr)
			}
		}
	}

	result.Duration = time.Since(start)
	result.Protocol = strings.ToUpper(server.Protocol)

	if result.Error != nil {
		log.Debugf("UPSTREAM: query failed for %s via %s (%s) in %v, error=%v", qname, server.Address, result.Protocol, result.Duration, result.Error)
	} else if result.Response != nil {
		log.Debugf("UPSTREAM: success for %s via %s (%s) in %v, rcode=%s, answer=%d", qname, server.Address, result.Protocol, result.Duration, dns.RcodeToString[result.Response.Rcode], len(result.Response.Answer))
	}

	return result
}

func (c *Client) executeSecureQuery(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer, protocol string) (*dns.Msg, error) {
	if server.SkipTLSVerify {
		log.Warnf("UPSTREAM: TLS verification disabled for %s — connection is vulnerable to MITM attacks!", server.ServerName)
	}

	switch protocol {
	case config.ProtoTLS:
		return c.tlsClient.ExecuteTLS(ctx, msg, server)
	case config.ProtoQUIC:
		return c.tlsClient.ExecuteQUIC(ctx, msg, server)
	case config.ProtoHTTPS:
		return c.tlsClient.ExecuteHTTPS(ctx, msg, server)
	case config.ProtoHTTP3:
		return c.tlsClient.ExecuteHTTP3(ctx, msg, server)
	case config.ProtoDTLS:
		return c.tlsClient.ExecuteDTLS(ctx, msg, server)
	case config.ProtoTLCP:
		return c.tlcpClient.ExecuteTLCP(ctx, msg, server)
	case config.ProtoHTTPTLCP:
		return c.tlcpClient.ExecuteHTTPTLCP(ctx, msg, server)
	case config.ProtoDTLCP:
		return c.tlcpClient.ExecuteDTLCP(ctx, msg, server)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", protocol)
	}
}

// SetKTLS configures kernel TLS offload for upstream DoT/DoH connections.
func (c *Client) SetKTLS(tx, rx bool) {
	c.tlsClient.SetKTLS(tx, rx)
}

// Close shuts down all pooled connections and transports.
func (c *Client) Close() {
	if c == nil {
		return
	}

	c.warmWg.Wait()

	c.tlsClient.Close()

	c.proxyMu.Lock()
	for _, d := range c.proxyDialers {
		if d != nil {
			_ = d.Close()
		}
	}
	c.proxyDialers = nil
	c.proxyMu.Unlock()

	c.dnscrypt.Close()
}

// needsTCPFallback checks whether a UDP result should be retried over TCP.
func (c *Client) needsTCPFallback(result *Result, protocol string) bool {
	return protocol != config.ProtoTCP && (result.Error != nil || (result.Response != nil && result.Response.Truncated))
}
