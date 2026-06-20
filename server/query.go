// Package main implements ZJDNS - High Performance DNS Server
package server

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
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"

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

// quicPoolConn wraps a QUIC connection managed by the quicPool.
type quicPoolConn struct {
	conn      *quic.Conn
	addr      string
	closed    atomic.Bool
	closeOnce sync.Once
}

func (qpc *quicPoolConn) close() {
	qpc.closeOnce.Do(func() {
		qpc.closed.Store(true)
		_ = qpc.conn.CloseWithError(QUICCodeNoError, "pool connection closed")
	})
}

func (qpc *quicPoolConn) isDead() bool {
	return qpc.closed.Load()
}

// quicPool manages a set of QUIC connections per upstream address,
// enabling concurrent query multiplexing over pooled connections.
// Unlike TCP/DoT pipelining, QUIC handles stream multiplexing natively,
// so multiple goroutines can safely use the same connection concurrently.
type quicPool struct {
	mu       sync.Mutex
	conns    map[string][]*quicPoolConn
	maxConns int
}

func newQuicPool(maxConns int) *quicPool {
	if maxConns <= 0 {
		maxConns = defaultMaxConns
	}
	return &quicPool{
		conns:    make(map[string][]*quicPoolConn),
		maxConns: maxConns,
	}
}

// acquire returns a live QUIC connection for the given key. It prefers an
// existing live connection; if none exists and under the limit, dials a new one.
// QUIC handles stream multiplexing natively, so multiple goroutines may use the
// same connection concurrently without a capacity semaphore.
func (qp *quicPool) acquire(ctx context.Context, key string, dialFunc func(context.Context, string) (*quic.Conn, error)) (*quicPoolConn, error) {
	qp.mu.Lock()

	// Sweep dead connections, return first live one.
	conns := qp.conns[key]
	live := conns[:0]
	for _, pc := range conns {
		if pc.isDead() {
			continue
		}
		live = append(live, pc)
	}
	qp.conns[key] = live

	if len(live) > 0 {
		pc := live[0]
		qp.mu.Unlock()
		return pc, nil
	}

	// No live connection — dial if under limit.
	if len(live) < qp.maxConns {
		qp.mu.Unlock()
		conn, err := dialFunc(ctx, key)
		if err != nil {
			return nil, fmt.Errorf("quicpool: dial %s: %w", key, err)
		}
		pc := &quicPoolConn{conn: conn, addr: key}
		qp.mu.Lock()
		// Double-check: concurrent acquires might have filled the pool.
		if len(qp.conns[key]) >= qp.maxConns {
			qp.mu.Unlock()
			pc.close()
			return nil, fmt.Errorf("quicpool: pool filled during dial for %s", key)
		}
		qp.conns[key] = append(qp.conns[key], pc)
		n := len(qp.conns[key])
		qp.mu.Unlock()
		log.Debugf("UPSTREAM: dialed new QUIC connection to %s (pool=%d/%d)", key, n, qp.maxConns)
		return pc, nil
	}

	qp.mu.Unlock()
	return nil, fmt.Errorf("quicpool: no available connection to %s", key)
}

// put adds a successfully used connection back to the pool for reuse.
// If the pool is at capacity, the connection is closed.
func (qp *quicPool) put(key string, conn *quic.Conn) {
	pc := &quicPoolConn{conn: conn, addr: key}
	qp.mu.Lock()
	defer qp.mu.Unlock()
	if len(qp.conns[key]) >= qp.maxConns {
		pc.close()
		return
	}
	qp.conns[key] = append(qp.conns[key], pc)
}

// remove evicts a dead connection from the pool and closes it.
func (qp *quicPool) remove(pc *quicPoolConn) {
	qp.mu.Lock()
	defer qp.mu.Unlock()
	conns := qp.conns[pc.addr]
	for i, c := range conns {
		if c == pc {
			qp.conns[pc.addr] = append(conns[:i], conns[i+1:]...)
			if len(qp.conns[pc.addr]) == 0 {
				delete(qp.conns, pc.addr)
			}
			pc.close()
			return
		}
	}
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
func (qc *QueryClient) executeTLS(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer, tlsConfig *tls.Config) (*dns.Msg, error) {
	key := dohTransportKey(server.Address, server.ServerName, server.SkipTLSVerify)

	// Try pipelined pool first (if enabled).
	if qc.dotPool != nil {
		pc, err := qc.dotPool.acquire(ctx, key, server.Address, func(dialCtx context.Context, addr string) (net.Conn, error) {
			dialer := tls.Dialer{Config: tlsConfig.Clone()}
			return dialer.DialContext(dialCtx, "tcp", addr)
		})
		if err == nil {
			response, err := pc.Exchange(ctx, msg)
			if err == nil {
				return response, nil
			}
			// Query failed — if the connection died, remove it from the pool.
			if pc.isDead() {
				qc.dotPool.remove(pc)
			}
			log.Debugf("UPSTREAM: pipelined DoT query to %s failed: %v, falling back", server.Address, err)
		}
	}

	// Fallback: single-shot ExchangeContext.
	client := *qc.tlsClient
	client.TLSConfig = tlsConfig
	response, _, err := client.ExchangeContext(ctx, msg, server.Address)
	return response, err
}

// executeQUIC executes a DNS query over DNS over QUIC (DoQ).
// Uses a connection pool for connection reuse and concurrent query multiplexing.
// Falls back to a single-shot connection if the pool is unavailable.
func (qc *QueryClient) executeQUIC(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer, tlsConfig *tls.Config) (*dns.Msg, error) {
	key := server.Address

	quicCfg := &quic.Config{
		MaxIdleTimeout:        config.IdleTimeout,
		MaxIncomingStreams:    MaxIncomingStreams,
		MaxIncomingUniStreams: MaxIncomingStreams,
		EnableDatagrams:       true,
		Allow0RTT:             false,
	}

	dialQUIC := func(dialCtx context.Context, addr string) (*quic.Conn, error) {
		dialTLS := tlsConfig.Clone()
		dialTLS.NextProtos = NextProtoDoQ
		timeoutCtx, cancel := context.WithTimeout(dialCtx, DefaultTimeout)
		defer cancel()
		return quic.DialAddr(timeoutCtx, addr, dialTLS, quicCfg)
	}

	// Try pooled connection first.
	if qc.quicPool != nil {
		pc, err := qc.quicPool.acquire(ctx, key, dialQUIC)
		if err == nil {
			response, err := qc.doQUICQuery(ctx, pc.conn, msg, qc.timeout)
			if err == nil {
				return response, nil
			}
			// Query failed — connection may be dead, remove from pool.
			qc.quicPool.remove(pc)
			log.Debugf("UPSTREAM: pooled DoQ query to %s failed: %v, retrying with new connection", server.Address, err)
		}
	}

	// Fallback: single-shot connection.
	conn, err := dialQUIC(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("QUIC dial: %w", err)
	}

	response, err := qc.doQUICQuery(ctx, conn, msg, qc.timeout)
	if err != nil {
		_ = conn.CloseWithError(QUICCodeNoError, "query failed")
		return nil, err
	}

	// Return successful connection to pool for reuse.
	if qc.quicPool != nil {
		qc.quicPool.put(key, conn)
	} else {
		_ = conn.CloseWithError(QUICCodeNoError, "no pool, discarding")
	}
	return response, nil
}

// doQUICQuery performs the actual QUIC stream write/read on an established connection.
func (qc *QueryClient) doQUICQuery(ctx context.Context, conn *quic.Conn, msg *dns.Msg, timeout time.Duration) (*dns.Msg, error) {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}
	defer func() { _ = stream.Close() }()

	_ = stream.SetDeadline(time.Now().Add(timeout))

	originalID := msg.Id
	msg.Id = 0

	msgData, err := msg.Pack()
	if err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("pack: %w", err)
	}

	buf := pool.DefaultBufferPool.Get()
	defer pool.DefaultBufferPool.Put(buf)

	writeBuf := buf
	if len(buf) < 2+len(msgData) {
		writeBuf = make([]byte, 2+len(msgData))
	}

	binary.BigEndian.PutUint16(writeBuf[:2], uint16(len(msgData)))
	copy(writeBuf[2:], msgData)

	if _, err := stream.Write(writeBuf[:2+len(msgData)]); err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("write: %w", err)
	}

	respBuf := pool.DefaultBufferPool.Get()
	defer pool.DefaultBufferPool.Put(respBuf)

	if _, err := io.ReadFull(stream, respBuf[:2]); err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("read length prefix: %w", err)
	}
	msgLen := binary.BigEndian.Uint16(respBuf[:2])
	if msgLen == 0 || int(msgLen) > len(respBuf)-2 {
		msg.Id = originalID
		return nil, fmt.Errorf("invalid response length: %d", msgLen)
	}

	if _, err := io.ReadFull(stream, respBuf[2:2+msgLen]); err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("read message body: %w", err)
	}

	response := pool.DefaultMessagePool.Get()
	if err := response.Unpack(respBuf[2 : 2+msgLen]); err != nil {
		msg.Id = originalID
		pool.DefaultMessagePool.Put(response)
		return nil, fmt.Errorf("unpack: %w", err)
	}

	msg.Id = originalID
	response.Id = originalID

	return response, nil
}

// executeDoH executes a DNS query over DNS over HTTPS (DoH/HTTP2).
// Uses a cached transport pool keyed by (address, serverName, skipVerify) to avoid
// per-query transport cloning.
func (qc *QueryClient) executeDoH(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer, tlsConfig *tls.Config) (*dns.Msg, error) {
	parsedURL, err := url.Parse(server.Address)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}

	if parsedURL.Port() == "" {
		parsedURL.Host = net.JoinHostPort(parsedURL.Host, config.DefaultDOHPort)
	}

	client := qc.getDoHClient(parsedURL.Host, server.ServerName, server.SkipTLSVerify)
	if client == nil {
		client = qc.createDoHClient(parsedURL.Host, server.ServerName, server.SkipTLSVerify, tlsConfig)
	}

	originalID := msg.Id
	msg.Id = 0

	buf, err := msg.Pack()
	if err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("pack: %w", err)
	}

	q := url.Values{"dns": []string{base64.RawURLEncoding.EncodeToString(buf)}}
	u := url.URL{
		Scheme:   parsedURL.Scheme,
		Host:     parsedURL.Host,
		Path:     parsedURL.Path,
		RawQuery: q.Encode(),
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Accept", "application/dns-message")
	httpReq.Header.Set("User-Agent", "")

	httpResp, err := client.Do(httpReq)
	if err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	if httpResp.StatusCode != http.StatusOK {
		msg.Id = originalID
		return nil, fmt.Errorf("HTTP status: %d", httpResp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(httpResp.Body, dns.MaxMsgSize))
	if err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("read body: %w", err)
	}

	response := pool.DefaultMessagePool.Get()
	if err := response.Unpack(body); err != nil {
		msg.Id = originalID
		pool.DefaultMessagePool.Put(response)
		return nil, fmt.Errorf("unpack: %w", err)
	}

	msg.Id = originalID
	response.Id = originalID

	return response, nil
}

// dohTransportKey builds a cache key for DoH transport pooling.
func dohTransportKey(host, serverName string, skipVerify bool) string {
	return fmt.Sprintf("%s|%s|%t", host, serverName, skipVerify)
}

// getDoHClient retrieves a cached DoH HTTP client, or nil if not present.
func (qc *QueryClient) getDoHClient(host, serverName string, skipVerify bool) *http.Client {
	qc.dohTransportMu.Lock()
	defer qc.dohTransportMu.Unlock()
	return qc.dohTransports[dohTransportKey(host, serverName, skipVerify)]
}

// createDoHClient builds and caches a DoH HTTP client for the given parameters.
func (qc *QueryClient) createDoHClient(host, serverName string, skipVerify bool, tlsConfig *tls.Config) *http.Client {
	qc.dohTransportMu.Lock()
	defer qc.dohTransportMu.Unlock()

	key := dohTransportKey(host, serverName, skipVerify)
	if client, ok := qc.dohTransports[key]; ok {
		return client
	}

	transport := qc.dohClient.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig.Clone()
	_ = http2.ConfigureTransport(transport)

	client := &http.Client{
		Timeout:   qc.dohClient.Timeout,
		Transport: transport,
	}
	qc.dohTransports[key] = client
	return client
}

// executeDoH3 executes a DNS query over DNS over HTTPS/3 (DoH3/HTTP3).
// Uses a cached transport pool to avoid per-query transport creation.
func (qc *QueryClient) executeDoH3(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer, tlsConfig *tls.Config) (*dns.Msg, error) {
	parsedURL, err := url.Parse(server.Address)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}

	if parsedURL.Port() == "" {
		parsedURL.Host = net.JoinHostPort(parsedURL.Host, config.DefaultDOHPort)
	}

	client := qc.getDoH3Client(parsedURL.Host, server.ServerName, server.SkipTLSVerify)
	if client == nil {
		client = qc.createDoH3Client(parsedURL.Host, server.ServerName, server.SkipTLSVerify, tlsConfig)
	}

	originalID := msg.Id
	msg.Id = 0

	buf, err := msg.Pack()
	if err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("pack: %w", err)
	}

	q := url.Values{"dns": []string{base64.RawURLEncoding.EncodeToString(buf)}}
	u := url.URL{
		Scheme:   parsedURL.Scheme,
		Host:     parsedURL.Host,
		Path:     parsedURL.Path,
		RawQuery: q.Encode(),
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Accept", "application/dns-message")
	httpReq.Header.Set("User-Agent", "")

	httpResp, err := client.Do(httpReq)
	if err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	if httpResp.StatusCode != http.StatusOK {
		msg.Id = originalID
		return nil, fmt.Errorf("HTTP status: %d", httpResp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(httpResp.Body, dns.MaxMsgSize))
	if err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("read body: %w", err)
	}

	response := pool.DefaultMessagePool.Get()
	if err := response.Unpack(body); err != nil {
		msg.Id = originalID
		pool.DefaultMessagePool.Put(response)
		return nil, fmt.Errorf("unpack: %w", err)
	}

	msg.Id = originalID
	response.Id = originalID

	return response, nil
}

// getDoH3Client retrieves a cached DoH3 HTTP client, or nil if not present.
func (qc *QueryClient) getDoH3Client(host, serverName string, skipVerify bool) *http.Client {
	qc.doh3TransportMu.Lock()
	defer qc.doh3TransportMu.Unlock()
	return qc.doh3Transports[dohTransportKey(host, serverName, skipVerify)]
}

// createDoH3Client builds and caches a DoH3 HTTP client for the given parameters.
func (qc *QueryClient) createDoH3Client(host, serverName string, skipVerify bool, tlsConfig *tls.Config) *http.Client {
	qc.doh3TransportMu.Lock()
	defer qc.doh3TransportMu.Unlock()

	key := dohTransportKey(host, serverName, skipVerify)
	if client, ok := qc.doh3Transports[key]; ok {
		return client
	}

	tlsCfg := tlsConfig.Clone()
	tlsCfg.NextProtos = NextProtoDoH3

	transport := &http3.Transport{
		TLSClientConfig: tlsCfg,
		QUICConfig: &quic.Config{
			MaxIdleTimeout:        config.IdleTimeout,
			MaxIncomingStreams:    MaxIncomingStreams,
			MaxIncomingUniStreams: MaxIncomingStreams,
			EnableDatagrams:       true,
			Allow0RTT:             false,
		},
	}

	client := &http.Client{
		Timeout:   qc.doh3Client.Timeout,
		Transport: transport,
	}
	qc.doh3Transports[key] = client
	return client
}

// executeTraditionalQuery executes a DNS query over traditional UDP or TCP.
// TCP queries use a pipelined connection pool with fallback to single-shot.
func (qc *QueryClient) executeTraditionalQuery(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer) (*dns.Msg, error) {
	if server.Protocol == "tcp" && qc.tcpPool != nil {
		// Try pipelined pool first.
		pc, err := qc.tcpPool.acquire(ctx, server.Address, server.Address, func(dialCtx context.Context, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(dialCtx, "tcp", addr)
		})
		if err == nil {
			response, err := pc.Exchange(ctx, msg)
			if err == nil {
				return response, nil
			}
			if pc.isDead() {
				qc.tcpPool.remove(pc)
			}
			log.Debugf("UPSTREAM: pipelined TCP query to %s failed: %v, falling back", server.Address, err)
		}
	}

	// UDP or TCP fallback: single-shot ExchangeContext.
	var client *dns.Client
	if server.Protocol == "tcp" {
		client = qc.tcpClient
	} else {
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
