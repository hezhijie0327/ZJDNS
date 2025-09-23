package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

// ==================== DoH客户端实现 ====================

type DoHClient struct {
	addr         *url.URL
	tlsConfig    *tls.Config
	client       *http.Client
	clientMu     sync.Mutex
	quicConfig   *quic.Config
	timeout      time.Duration
	skipVerify   bool
	serverName   string
	addrRedacted string
	httpVersions []string
	closed       int32
}

func NewDoHClient(addr, serverName string, skipVerify bool, timeout time.Duration) (*DoHClient, error) {
	parsedURL, err := url.Parse(addr)
	if err != nil {
		return nil, fmt.Errorf("🌐 解析DoH地址失败: %w", err)
	}

	if parsedURL.Port() == "" {
		if parsedURL.Scheme == "https" || parsedURL.Scheme == "h3" {
			parsedURL.Host = net.JoinHostPort(parsedURL.Host, DefaultHTTPSPort)
		}
	}

	var httpVersions []string
	if parsedURL.Scheme == "h3" {
		parsedURL.Scheme = "https"
		httpVersions = NextProtoHTTP3
	} else {
		httpVersions = append(NextProtoHTTP2, NextProtoHTTP3...)
	}

	if serverName == "" {
		serverName = parsedURL.Hostname()
	}

	tlsConfig := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: skipVerify,
		NextProtos:         httpVersions,
		MinVersion:         tls.VersionTLS12,
		ClientSessionCache: tls.NewLRUClientSessionCache(0),
	}

	client := &DoHClient{
		addr:      parsedURL,
		tlsConfig: tlsConfig,
		quicConfig: &quic.Config{
			KeepAlivePeriod: SecureConnKeepAlive,
		},
		timeout:      timeout,
		skipVerify:   skipVerify,
		serverName:   serverName,
		addrRedacted: parsedURL.Redacted(),
		httpVersions: httpVersions,
	}

	runtime.SetFinalizer(client, (*DoHClient).Close)
	return client, nil
}

func (c *DoHClient) Exchange(msg *dns.Msg) (*dns.Msg, error) {
	if c == nil || msg == nil {
		return nil, errors.New("🌐 DoH客户端或消息为空")
	}

	originalID := msg.Id
	msg.Id = 0
	defer func() {
		msg.Id = originalID
	}()

	httpClient, isCached, err := c.getClient()
	if err != nil {
		return nil, fmt.Errorf("🔒 获取HTTP客户端失败: %w", err)
	}

	resp, err := c.exchangeHTTPS(httpClient, msg)

	// 重试逻辑
	for i := 0; isCached && c.shouldRetry(err) && i < 2; i++ {
		httpClient, err = c.resetClient(err)
		if err != nil {
			return nil, fmt.Errorf("🔄 重置HTTP客户端失败: %w", err)
		}
		resp, err = c.exchangeHTTPS(httpClient, msg)
	}

	if err != nil {
		if _, resetErr := c.resetClient(err); resetErr != nil {
			writeLog(LogDebug, "⚠️ 重置客户端失败: %v", resetErr)
		}
		return nil, err
	}

	if resp != nil {
		resp.Id = originalID
	}

	return resp, nil
}

func (c *DoHClient) exchangeHTTPS(client *http.Client, req *dns.Msg) (*dns.Msg, error) {
	if client == nil || req == nil {
		return nil, errors.New("🌐 HTTP客户端或请求为空")
	}

	buf, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("📦 打包DNS消息失败: %w", err)
	}

	method := http.MethodGet
	if c.isHTTP3(client) {
		method = http3.MethodGet0RTT
	}

	q := url.Values{
		"dns": []string{base64.RawURLEncoding.EncodeToString(buf)},
	}

	u := url.URL{
		Scheme:   c.addr.Scheme,
		Host:     c.addr.Host,
		Path:     c.addr.Path,
		RawQuery: q.Encode(),
	}

	httpReq, err := http.NewRequest(method, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("🌐 创建HTTP请求失败: %w", err)
	}

	httpReq.Header.Set("Accept", "application/dns-message")
	httpReq.Header.Set("User-Agent", "")

	httpResp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("🌐 发送HTTP请求失败: %w", err)
	}
	defer func() {
		if closeErr := httpResp.Body.Close(); closeErr != nil {
			writeLog(LogDebug, "⚠️ 关闭HTTP响应体失败: %v", closeErr)
		}
	}()

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("🌐 HTTP响应错误: %d", httpResp.StatusCode)
	}

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("📖 读取响应失败: %w", err)
	}

	resp := &dns.Msg{}
	if err := resp.Unpack(body); err != nil {
		return nil, fmt.Errorf("📦 解析DNS响应失败: %w", err)
	}

	return resp, nil
}

func (c *DoHClient) getClient() (*http.Client, bool, error) {
	if c == nil {
		return nil, false, errors.New("🌐 DoH客户端为空")
	}

	if atomic.LoadInt32(&c.closed) != 0 {
		return nil, false, errors.New("🔒 DoH客户端已关闭")
	}

	c.clientMu.Lock()
	defer c.clientMu.Unlock()

	if c.client != nil {
		return c.client, true, nil
	}

	var err error
	c.client, err = c.createClient()
	return c.client, false, err
}

func (c *DoHClient) createClient() (*http.Client, error) {
	transport, err := c.createTransport()
	if err != nil {
		return nil, fmt.Errorf("🚛 创建HTTP传输失败: %w", err)
	}

	return &http.Client{
		Transport: transport,
		Timeout:   c.timeout,
	}, nil
}

func (c *DoHClient) createTransport() (http.RoundTripper, error) {
	if c.supportsHTTP3() {
		if transport, err := c.createTransportH3(); err == nil {
			writeLog(LogDebug, "⚡ DoH客户端使用HTTP/3: %s", c.addrRedacted)
			return transport, nil
		} else {
			writeLog(LogDebug, "🔙 HTTP/3连接失败，回退到HTTP/2: %v", err)
		}
	}

	if !c.supportsHTTP() {
		return nil, errors.New("❌ 不支持HTTP/1.1或HTTP/2")
	}

	transport := &http.Transport{
		TLSClientConfig:    c.tlsConfig.Clone(),
		DisableCompression: true,
		IdleConnTimeout:    DoHIdleConnTimeout,
		MaxConnsPerHost:    DoHMaxConnsPerHost,
		MaxIdleConns:       DoHMaxIdleConns,
		ForceAttemptHTTP2:  true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: c.timeout}
			return dialer.DialContext(ctx, network, addr)
		},
	}

	_, err := http2.ConfigureTransports(transport)
	if err != nil {
		return nil, err
	}

	return transport, nil
}

func (c *DoHClient) createTransportH3() (http.RoundTripper, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	conn, err := quic.DialAddr(ctx, c.addr.Host, c.tlsConfig, c.quicConfig)
	if err != nil {
		return nil, fmt.Errorf("🚀 QUIC连接失败: %w", err)
	}

	if closeErr := conn.CloseWithError(QUICCodeNoError, ""); closeErr != nil {
		writeLog(LogDebug, "⚠️ 关闭QUIC连接失败: %v", closeErr)
	}

	return nil, errors.New("💥 DoH3传输创建失败")
}

func (c *DoHClient) resetClient(resetErr error) (*http.Client, error) {
	if c == nil {
		return nil, errors.New("🌐 DoH客户端为空")
	}

	c.clientMu.Lock()
	defer c.clientMu.Unlock()

	if errors.Is(resetErr, quic.Err0RTTRejected) {
		c.quicConfig = &quic.Config{
			KeepAlivePeriod: SecureConnKeepAlive,
		}
	}

	oldClient := c.client
	if oldClient != nil {
		c.closeClient(oldClient)
	}

	var err error
	c.client, err = c.createClient()
	return c.client, err
}

func (c *DoHClient) closeClient(client *http.Client) {
	if c == nil || client == nil {
		return
	}

	if c.isHTTP3(client) {
		if closer, ok := client.Transport.(io.Closer); ok {
			if closeErr := closer.Close(); closeErr != nil {
				writeLog(LogDebug, "⚠️ 关闭HTTP3传输失败: %v", closeErr)
			}
		}
	}
}

func (c *DoHClient) shouldRetry(err error) bool {
	if c == nil {
		return false
	}
	return globalSecureConnErrorHandler.IsRetryableError("https", err)
}

func (c *DoHClient) supportsHTTP3() bool {
	for _, proto := range c.httpVersions {
		if proto == "h3" {
			return true
		}
	}
	return false
}

func (c *DoHClient) supportsHTTP() bool {
	for _, proto := range c.httpVersions {
		if proto == http2.NextProtoTLS || proto == "http/1.1" {
			return true
		}
	}
	return false
}

func (c *DoHClient) isHTTP3(client *http.Client) bool {
	_, ok := client.Transport.(*http3Transport)
	return ok
}

func (c *DoHClient) Close() error {
	if c == nil || !atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
		return nil
	}

	runtime.SetFinalizer(c, nil)

	c.clientMu.Lock()
	defer c.clientMu.Unlock()

	if c.client != nil {
		c.closeClient(c.client)
		c.client = nil
	}

	return nil
}

// HTTP/3 传输包装器
type http3Transport struct {
	baseTransport *http3.Transport
	closed        bool
	mu            sync.RWMutex
}

func (h *http3Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if h == nil || h.baseTransport == nil {
		return nil, errors.New("⚡ HTTP/3传输为空")
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.closed {
		return nil, net.ErrClosed
	}

	resp, err := h.baseTransport.RoundTripOpt(req, http3.RoundTripOpt{OnlyCachedConn: true})
	if errors.Is(err, http3.ErrNoCachedConn) {
		resp, err = h.baseTransport.RoundTrip(req)
	}

	return resp, err
}

func (h *http3Transport) Close() error {
	if h == nil {
		return nil
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	h.closed = true
	if h.baseTransport != nil {
		return h.baseTransport.Close()
	}
	return nil
}

// ==================== 统一安全连接客户端 ====================

type UnifiedSecureClient struct {
	protocol        string
	serverName      string
	skipVerify      bool
	timeout         time.Duration
	tlsConn         *tls.Conn
	quicConn        *quic.Conn
	dohClient       *DoHClient
	isQUICConnected bool
	lastActivity    time.Time
	mu              sync.Mutex
}

func NewUnifiedSecureClient(protocol, addr, serverName string, skipVerify bool) (*UnifiedSecureClient, error) {
	client := &UnifiedSecureClient{
		protocol:     strings.ToLower(protocol),
		serverName:   serverName,
		skipVerify:   skipVerify,
		timeout:      SecureConnQueryTimeout,
		lastActivity: time.Now(),
	}

	switch client.protocol {
	case "https", "http3":
		var err error
		client.dohClient, err = NewDoHClient(addr, serverName, skipVerify, SecureConnQueryTimeout)
		if err != nil {
			return nil, fmt.Errorf("🌐 创建DoH客户端失败: %w", err)
		}
	default:
		if err := client.connect(addr); err != nil {
			return nil, err
		}
	}

	return client, nil
}

func (c *UnifiedSecureClient) connect(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("🔍 解析地址失败: %w", err)
	}

	switch c.protocol {
	case "tls":
		return c.connectTLS(host, port)
	case "quic":
		return c.connectQUIC(net.JoinHostPort(host, port))
	default:
		return fmt.Errorf("❌ 不支持的协议: %s", c.protocol)
	}
}

func (c *UnifiedSecureClient) connectTLS(host, port string) error {
	tlsConfig := &tls.Config{
		ServerName:         c.serverName,
		InsecureSkipVerify: c.skipVerify,
	}

	dialer := &net.Dialer{
		Timeout:   SecureConnHandshakeTimeout,
		KeepAlive: SecureConnKeepAlive,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, port), tlsConfig)
	if err != nil {
		return fmt.Errorf("🔐 TLS连接失败: %w", err)
	}

	if tcpConn, ok := conn.NetConn().(*net.TCPConn); ok {
		if keepAliveErr := tcpConn.SetKeepAlive(true); keepAliveErr != nil {
			writeLog(LogDebug, "⚠️ 设置TCP KeepAlive失败: %v", keepAliveErr)
		}
		if keepAlivePeriodErr := tcpConn.SetKeepAlivePeriod(SecureConnKeepAlive); keepAlivePeriodErr != nil {
			writeLog(LogDebug, "⚠️ 设置TCP KeepAlive周期失败: %v", keepAlivePeriodErr)
		}
	}

	c.tlsConn = conn
	c.lastActivity = time.Now()
	return nil
}

func (c *UnifiedSecureClient) connectQUIC(addr string) error {
	tlsConfig := &tls.Config{
		ServerName:         c.serverName,
		InsecureSkipVerify: c.skipVerify,
		NextProtos:         NextProtoQUIC,
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	conn, err := quic.DialAddr(ctx, addr, tlsConfig, &quic.Config{
		MaxIdleTimeout:        SecureConnIdleTimeout,
		MaxIncomingStreams:    math.MaxUint16,
		MaxIncomingUniStreams: math.MaxUint16,
		KeepAlivePeriod:       SecureConnKeepAlive,
		Allow0RTT:             true,
	})
	if err != nil {
		return fmt.Errorf("🚀 QUIC连接失败: %w", err)
	}

	c.quicConn = conn
	c.isQUICConnected = true
	c.lastActivity = time.Now()
	return nil
}

func (c *UnifiedSecureClient) isConnectionAlive() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	switch c.protocol {
	case "tls":
		return c.tlsConn != nil && time.Since(c.lastActivity) <= SecureConnIdleTimeout
	case "quic":
		return c.quicConn != nil && c.isQUICConnected &&
			time.Since(c.lastActivity) <= SecureConnIdleTimeout
	case "https", "http3":
		return c.dohClient != nil
	}
	return false
}

func (c *UnifiedSecureClient) Exchange(msg *dns.Msg, addr string) (*dns.Msg, error) {
	switch c.protocol {
	case "https", "http3":
		return c.dohClient.Exchange(msg)
	case "tls":
		if !c.isConnectionAlive() {
			if err := c.connect(addr); err != nil {
				return nil, fmt.Errorf("🔄 重连失败: %w", err)
			}
		}
		resp, err := c.exchangeTLS(msg)
		if err != nil && globalSecureConnErrorHandler.IsRetryableError("tls", err) {
			writeLog(LogDebug, "🔄 TLS连接错误，尝试重连: %v", err)
			if c.connect(addr) == nil {
				return c.exchangeTLS(msg)
			}
		}
		return resp, err
	case "quic":
		if !c.isConnectionAlive() {
			if err := c.connect(addr); err != nil {
				return nil, fmt.Errorf("🔄 重连失败: %w", err)
			}
		}
		return c.exchangeQUIC(msg)
	default:
		return nil, fmt.Errorf("❌ 不支持的协议: %s", c.protocol)
	}
}

func (c *UnifiedSecureClient) exchangeTLS(msg *dns.Msg) (*dns.Msg, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.tlsConn == nil {
		return nil, errors.New("🔐 TLS连接未建立")
	}

	deadline := time.Now().Add(c.timeout)
	if deadlineErr := c.tlsConn.SetDeadline(deadline); deadlineErr != nil {
		writeLog(LogDebug, "⚠️ 设置TLS连接截止时间失败: %v", deadlineErr)
	}
	defer func() {
		if deadlineErr := c.tlsConn.SetDeadline(time.Time{}); deadlineErr != nil {
			writeLog(LogDebug, "⚠️ 重置TLS连接截止时间失败: %v", deadlineErr)
		}
	}()

	msgData, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("📦 消息打包失败: %w", err)
	}

	buf := make([]byte, 2+len(msgData))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(msgData)))
	copy(buf[2:], msgData)

	if _, err := c.tlsConn.Write(buf); err != nil {
		return nil, fmt.Errorf("🔐 发送TLS查询失败: %w", err)
	}

	lengthBuf := make([]byte, 2)
	if _, err := io.ReadFull(c.tlsConn, lengthBuf); err != nil {
		return nil, fmt.Errorf("📖 读取响应长度失败: %w", err)
	}

	respLength := binary.BigEndian.Uint16(lengthBuf)
	if respLength == 0 || respLength > UpstreamUDPBufferSizeBytes {
		return nil, fmt.Errorf("⚠️ 响应长度异常: %d", respLength)
	}

	respBuf := make([]byte, respLength)
	if _, err := io.ReadFull(c.tlsConn, respBuf); err != nil {
		return nil, fmt.Errorf("📖 读取响应内容失败: %w", err)
	}

	response := new(dns.Msg)
	if err := response.Unpack(respBuf); err != nil {
		return nil, fmt.Errorf("📦 响应解析失败: %w", err)
	}

	c.lastActivity = time.Now()
	return response, nil
}

func (c *UnifiedSecureClient) exchangeQUIC(msg *dns.Msg) (*dns.Msg, error) {
	originalID := msg.Id
	msg.Id = 0
	defer func() {
		msg.Id = originalID
	}()

	resp, err := c.exchangeQUICDirect(msg)
	if resp != nil {
		resp.Id = originalID
	}
	return resp, err
}

func (c *UnifiedSecureClient) exchangeQUICDirect(msg *dns.Msg) (*dns.Msg, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.quicConn == nil || !c.isQUICConnected {
		return nil, errors.New("🚀 QUIC连接未建立")
	}

	msgData, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("📦 消息打包失败: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	stream, err := c.quicConn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("🚀 创建QUIC流失败: %w", err)
	}
	defer func() {
		if closeErr := stream.Close(); closeErr != nil {
			writeLog(LogDebug, "⚠️ 关闭QUIC流失败: %v", closeErr)
		}
	}()

	if c.timeout > 0 {
		if err := stream.SetDeadline(time.Now().Add(c.timeout)); err != nil {
			return nil, fmt.Errorf("⏰ 设置流超时失败: %w", err)
		}
	}

	buf := make([]byte, 2+len(msgData))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(msgData)))
	copy(buf[2:], msgData)

	if _, err = stream.Write(buf); err != nil {
		return nil, fmt.Errorf("🚀 发送QUIC查询失败: %w", err)
	}

	if err := stream.Close(); err != nil {
		writeLog(LogDebug, "⚠️ 关闭QUIC流写方向失败: %v", err)
	}

	resp, err := c.readQUICMsg(stream)
	if err == nil {
		c.lastActivity = time.Now()
	}
	return resp, err
}

func (c *UnifiedSecureClient) readQUICMsg(stream *quic.Stream) (*dns.Msg, error) {
	respBuf := make([]byte, SecureConnBufferSizeBytes)

	n, err := stream.Read(respBuf)
	if err != nil && n == 0 {
		return nil, fmt.Errorf("📖 读取QUIC响应失败: %w", err)
	}

	stream.CancelRead(0)

	if n < 2 {
		return nil, fmt.Errorf("📏 QUIC响应太短: %d字节", n)
	}

	msgLen := binary.BigEndian.Uint16(respBuf[:2])
	if int(msgLen) != n-2 {
		writeLog(LogDebug, "⚠️ QUIC响应长度不匹配: 声明=%d, 实际=%d", msgLen, n-2)
	}

	response := new(dns.Msg)
	if err := response.Unpack(respBuf[2:n]); err != nil {
		return nil, fmt.Errorf("📦 QUIC响应解析失败: %w", err)
	}

	return response, nil
}

func (c *UnifiedSecureClient) Close() error {
	if c == nil {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	switch c.protocol {
	case "tls":
		if c.tlsConn != nil {
			if closeErr := c.tlsConn.Close(); closeErr != nil {
				writeLog(LogDebug, "⚠️ 关闭TLS连接失败: %v", closeErr)
			}
			c.tlsConn = nil
		}
	case "quic":
		if c.quicConn != nil {
			if closeErr := c.quicConn.CloseWithError(QUICCodeNoError, ""); closeErr != nil {
				writeLog(LogDebug, "⚠️ 关闭QUIC连接失败: %v", closeErr)
			}
			c.quicConn = nil
			c.isQUICConnected = false
		}
	case "https", "http3":
		if c.dohClient != nil {
			if closeErr := c.dohClient.Close(); closeErr != nil {
				writeLog(LogDebug, "⚠️ 关闭DoH客户端失败: %v", closeErr)
			}
			c.dohClient = nil
		}
	}

	return nil
}

// ==================== 安全DNS管理器 ====================

type SecureDNSManager struct {
	server        *RecursiveDNSServer
	tlsConfig     *tls.Config
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	tlsListener   net.Listener
	quicConn      *net.UDPConn
	quicListener  *quic.EarlyListener
	quicTransport *quic.Transport
	httpsServer   *http.Server
	h3Server      *http3.Server
	httpsListener net.Listener
	h3Listener    *quic.EarlyListener
}

func NewSecureDNSManager(server *RecursiveDNSServer, config *ServerConfig) (*SecureDNSManager, error) {
	cert, err := tls.LoadX509KeyPair(config.Server.TLS.CertFile, config.Server.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("🔐 加载证书失败: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &SecureDNSManager{
		server:    server,
		tlsConfig: tlsConfig,
		ctx:       ctx,
		cancel:    cancel,
	}, nil
}

func (sm *SecureDNSManager) Start(httpsPort string) error {
	serverCount := 2 // DoT + DoQ

	if httpsPort != "" {
		serverCount += 2 // DoH + DoH3
	}

	errChan := make(chan error, serverCount)
	wg := sync.WaitGroup{}
	wg.Add(serverCount)

	// 启动DoT服务器
	go func() {
		defer wg.Done()
		defer func() { handlePanicWithContext("关键-DoT服务器") }()
		if err := sm.startTLSServer(); err != nil {
			errChan <- fmt.Errorf("🔐 DoT启动失败: %w", err)
		}
	}()

	// 启动DoQ服务器
	go func() {
		defer wg.Done()
		defer func() { handlePanicWithContext("关键-DoQ服务器") }()
		if err := sm.startQUICServer(); err != nil {
			errChan <- fmt.Errorf("🚀 DoQ启动失败: %w", err)
		}
	}()

	if httpsPort != "" {
		// 启动DoH服务器
		go func() {
			defer wg.Done()
			defer func() { handlePanicWithContext("关键-DoH服务器") }()
			if err := sm.startDoHServer(httpsPort); err != nil {
				errChan <- fmt.Errorf("🌐 DoH启动失败: %w", err)
			}
		}()

		// 启动DoH3服务器
		go func() {
			defer wg.Done()
			defer func() { handlePanicWithContext("关键-DoH3服务器") }()
			if err := sm.startDoH3Server(httpsPort); err != nil {
				errChan <- fmt.Errorf("⚡ DoH3启动失败: %w", err)
			}
		}()
	}

	go func() {
		wg.Wait()
		close(errChan)
	}()

	for err := range errChan {
		if err != nil {
			return err
		}
	}

	return nil
}

func (sm *SecureDNSManager) startTLSServer() error {
	listener, err := net.Listen("tcp", ":"+sm.server.config.Server.TLS.Port)
	if err != nil {
		return fmt.Errorf("🔐 DoT监听失败: %w", err)
	}

	sm.tlsListener = tls.NewListener(listener, sm.tlsConfig)
	writeLog(LogInfo, "🔐 DoT服务器启动: %s", sm.tlsListener.Addr())

	sm.wg.Add(1)
	go func() {
		defer sm.wg.Done()
		defer func() { handlePanicWithContext("DoT服务器") }()
		sm.handleTLSConnections()
	}()

	return nil
}

func (sm *SecureDNSManager) startQUICServer() error {
	addr := ":" + sm.server.config.Server.TLS.Port

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("🔍 解析UDP地址失败: %w", err)
	}

	sm.quicConn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("📡 UDP监听失败: %w", err)
	}

	sm.quicTransport = &quic.Transport{
		Conn: sm.quicConn,
	}

	quicTLSConfig := sm.tlsConfig.Clone()
	quicTLSConfig.NextProtos = NextProtoQUIC

	quicConfig := &quic.Config{
		MaxIdleTimeout:        SecureConnIdleTimeout,
		MaxIncomingStreams:    math.MaxUint16,
		MaxIncomingUniStreams: math.MaxUint16,
		KeepAlivePeriod:       SecureConnKeepAlive,
		Allow0RTT:             true,
	}

	sm.quicListener, err = sm.quicTransport.ListenEarly(quicTLSConfig, quicConfig)
	if err != nil {
		if closeErr := sm.quicConn.Close(); closeErr != nil {
			writeLog(LogDebug, "⚠️ 关闭QUIC连接失败: %v", closeErr)
		}
		return fmt.Errorf("🚀 DoQ监听失败: %w", err)
	}

	writeLog(LogInfo, "🚀 DoQ服务器启动: %s", sm.quicListener.Addr())

	sm.wg.Add(1)
	go func() {
		defer sm.wg.Done()
		defer func() { handlePanicWithContext("DoQ服务器") }()
		sm.handleQUICConnections()
	}()

	return nil
}

func (sm *SecureDNSManager) startDoHServer(port string) error {
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return fmt.Errorf("🌐 DoH监听失败: %w", err)
	}

	tlsConfig := sm.tlsConfig.Clone()
	tlsConfig.NextProtos = []string{http2.NextProtoTLS, "http/1.1"}

	sm.httpsListener = tls.NewListener(listener, tlsConfig)
	writeLog(LogInfo, "🌐 DoH服务器启动: %s", sm.httpsListener.Addr())

	sm.httpsServer = &http.Server{
		Handler:           sm,
		ReadHeaderTimeout: DoHReadHeaderTimeout,
		WriteTimeout:      DoHWriteTimeout,
	}

	sm.wg.Add(1)
	go func() {
		defer sm.wg.Done()
		defer func() { handlePanicWithContext("DoH服务器") }()
		if err := sm.httpsServer.Serve(sm.httpsListener); err != nil && err != http.ErrServerClosed {
			writeLog(LogError, "💥 DoH服务器错误: %v", err)
		}
	}()

	return nil
}

func (sm *SecureDNSManager) startDoH3Server(port string) error {
	addr := ":" + port

	tlsConfig := sm.tlsConfig.Clone()
	tlsConfig.NextProtos = NextProtoHTTP3

	quicConfig := &quic.Config{
		MaxIdleTimeout:        SecureConnIdleTimeout,
		MaxIncomingStreams:    math.MaxUint16,
		MaxIncomingUniStreams: math.MaxUint16,
		Allow0RTT:             true,
	}

	quicListener, err := quic.ListenAddrEarly(addr, tlsConfig, quicConfig)
	if err != nil {
		return fmt.Errorf("⚡ DoH3监听失败: %w", err)
	}

	sm.h3Listener = quicListener
	writeLog(LogInfo, "⚡ DoH3服务器启动: %s", sm.h3Listener.Addr())

	sm.h3Server = &http3.Server{
		Handler: sm,
	}

	sm.wg.Add(1)
	go func() {
		defer sm.wg.Done()
		defer func() { handlePanicWithContext("DoH3服务器") }()
		if err := sm.h3Server.ServeListener(sm.h3Listener); err != nil && err != http.ErrServerClosed {
			writeLog(LogError, "💥 DoH3服务器错误: %v", err)
		}
	}()

	return nil
}

func (sm *SecureDNSManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if sm == nil || sm.server == nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	expectedPath := sm.server.config.Server.TLS.HTTPS.Endpoint
	if expectedPath == "" {
		expectedPath = DefaultDNSQueryPath
	}
	if !strings.HasPrefix(expectedPath, "/") {
		expectedPath = "/" + expectedPath
	}

	if r.URL.Path != expectedPath {
		http.NotFound(w, r)
		return
	}

	if GetLogLevel() >= LogDebug {
		writeLog(LogDebug, "🌐 收到DoH请求: %s %s", r.Method, r.URL.Path)
	}

	req, statusCode := sm.parseDoHRequest(r)
	if req == nil {
		http.Error(w, http.StatusText(statusCode), statusCode)
		return
	}

	response := sm.server.ProcessDNSQuery(req, nil, true)
	if err := sm.respondDoH(w, response); err != nil {
		writeLog(LogError, "💥 DoH响应发送失败: %v", err)
	}
}

func (sm *SecureDNSManager) parseDoHRequest(r *http.Request) (*dns.Msg, int) {
	var buf []byte
	var err error

	switch r.Method {
	case http.MethodGet:
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" {
			writeLog(LogDebug, "❌ DoH GET请求缺少dns参数")
			return nil, http.StatusBadRequest
		}
		buf, err = base64.RawURLEncoding.DecodeString(dnsParam)
		if err != nil {
			writeLog(LogDebug, "💥 DoH GET请求dns参数解码失败: %v", err)
			return nil, http.StatusBadRequest
		}

	case http.MethodPost:
		contentType := r.Header.Get("Content-Type")
		if contentType != "application/dns-message" {
			writeLog(LogDebug, "❌ DoH POST请求Content-Type不支持: %s", contentType)
			return nil, http.StatusUnsupportedMediaType
		}

		r.Body = http.MaxBytesReader(nil, r.Body, DoHMaxRequestSize)
		buf, err = io.ReadAll(r.Body)
		if err != nil {
			writeLog(LogDebug, "💥 DoH POST请求体读取失败: %v", err)
			return nil, http.StatusBadRequest
		}
		defer func() {
			if closeErr := r.Body.Close(); closeErr != nil {
				writeLog(LogDebug, "⚠️ 关闭请求体失败: %v", closeErr)
			}
		}()

	default:
		writeLog(LogDebug, "❌ DoH请求方法不支持: %s", r.Method)
		return nil, http.StatusMethodNotAllowed
	}

	if len(buf) == 0 {
		writeLog(LogDebug, "❌ DoH请求数据为空")
		return nil, http.StatusBadRequest
	}

	req := new(dns.Msg)
	if err := req.Unpack(buf); err != nil {
		writeLog(LogDebug, "💥 DoH DNS消息解析失败: %v", err)
		return nil, http.StatusBadRequest
	}

	return req, http.StatusOK
}

func (sm *SecureDNSManager) respondDoH(w http.ResponseWriter, response *dns.Msg) error {
	if response == nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return nil
	}

	bytes, err := response.Pack()
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return fmt.Errorf("📦 响应打包失败: %w", err)
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "max-age=0")

	_, err = w.Write(bytes)
	return err
}

func (sm *SecureDNSManager) handleTLSConnections() {
	for {
		select {
		case <-sm.ctx.Done():
			return
		default:
		}

		conn, err := sm.tlsListener.Accept()
		if err != nil {
			if sm.ctx.Err() != nil {
				return
			}
			writeLog(LogError, "💥 DoT连接接受失败: %v", err)
			continue
		}

		sm.wg.Add(1)
		go func() {
			defer sm.wg.Done()
			defer func() { handlePanicWithContext("DoT连接处理") }()
			defer func() {
				if closeErr := conn.Close(); closeErr != nil {
					writeLog(LogDebug, "⚠️ 关闭DoT连接失败: %v", closeErr)
				}
			}()
			sm.handleSecureDNSConnection(conn, "DoT")
		}()
	}
}

func (sm *SecureDNSManager) handleQUICConnections() {
	for {
		select {
		case <-sm.ctx.Done():
			return
		default:
		}

		conn, err := sm.quicListener.Accept(sm.ctx)
		if err != nil {
			if sm.ctx.Err() != nil {
				return
			}
			sm.logQUICError("accepting quic conn", err)
			continue
		}

		sm.wg.Add(1)
		go func() {
			defer sm.wg.Done()
			defer func() { handlePanicWithContext("DoQ连接处理") }()
			sm.handleQUICConnection(conn)
		}()
	}
}

func (sm *SecureDNSManager) handleQUICConnection(conn *quic.Conn) {
	defer func() {
		if conn != nil {
			if closeErr := conn.CloseWithError(QUICCodeNoError, ""); closeErr != nil {
				writeLog(LogDebug, "⚠️ 关闭QUIC连接失败: %v", closeErr)
			}
		}
	}()

	for {
		select {
		case <-sm.ctx.Done():
			return
		default:
		}

		stream, err := conn.AcceptStream(sm.ctx)
		if err != nil {
			if conn != nil {
				sm.logQUICError("accepting quic stream", err)
			}
			return
		}

		if stream == nil {
			continue
		}

		sm.wg.Add(1)
		go func(s *quic.Stream) {
			defer sm.wg.Done()
			defer func() { handlePanicWithContext("DoQ流处理") }()
			if s != nil {
				defer func() {
					if closeErr := s.Close(); closeErr != nil {
						writeLog(LogDebug, "⚠️ 关闭QUIC流失败: %v", closeErr)
					}
				}()
				sm.handleQUICStream(s, conn)
			}
		}(stream)
	}
}

func (sm *SecureDNSManager) handleQUICStream(stream *quic.Stream, conn *quic.Conn) {
	buf := make([]byte, SecureConnBufferSizeBytes)
	n, err := sm.readAll(stream, buf)

	if err != nil && err != io.EOF {
		writeLog(LogDebug, "💥 DoQ流读取失败: %v", err)
		return
	}

	if n < MinDNSPacketSizeBytes {
		writeLog(LogDebug, "📏 DoQ消息太短: %d字节", n)
		return
	}

	req := new(dns.Msg)
	var msgData []byte

	packetLen := binary.BigEndian.Uint16(buf[:2])
	if packetLen == uint16(n-2) {
		msgData = buf[2:n]
	} else {
		writeLog(LogDebug, "❌ DoQ不支持的消息格式")
		if closeErr := conn.CloseWithError(QUICCodeProtocolError, ""); closeErr != nil {
			writeLog(LogDebug, "⚠️ 关闭QUIC连接失败: %v", closeErr)
		}
		return
	}

	if err := req.Unpack(msgData); err != nil {
		writeLog(LogDebug, "💥 DoQ消息解析失败: %v", err)
		if closeErr := conn.CloseWithError(QUICCodeProtocolError, ""); closeErr != nil {
			writeLog(LogDebug, "⚠️ 关闭QUIC连接失败: %v", closeErr)
		}
		return
	}

	if !sm.validQUICMsg(req) {
		if closeErr := conn.CloseWithError(QUICCodeProtocolError, ""); closeErr != nil {
			writeLog(LogDebug, "⚠️ 关闭QUIC连接失败: %v", closeErr)
		}
		return
	}

	clientIP := sm.getSecureClientIP(conn)
	response := sm.server.ProcessDNSQuery(req, clientIP, true)

	if err := sm.respondQUIC(stream, response); err != nil {
		writeLog(LogDebug, "💥 DoQ响应发送失败: %v", err)
	}
}

func (sm *SecureDNSManager) handleSecureDNSConnection(conn net.Conn, protocol string) {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return
	}

	if deadlineErr := tlsConn.SetReadDeadline(time.Now().Add(SecureConnQueryTimeout)); deadlineErr != nil {
		writeLog(LogDebug, "⚠️ 设置TLS读取截止时间失败: %v", deadlineErr)
	}

	for {
		select {
		case <-sm.ctx.Done():
			return
		default:
		}

		lengthBuf := make([]byte, 2)
		if _, err := io.ReadFull(tlsConn, lengthBuf); err != nil {
			if err != io.EOF {
				writeLog(LogDebug, "💥 %s长度读取失败: %v", protocol, err)
			}
			return
		}

		msgLength := binary.BigEndian.Uint16(lengthBuf)
		if msgLength == 0 || msgLength > UpstreamUDPBufferSizeBytes {
			writeLog(LogWarn, "⚠️ %s消息长度异常: %d", protocol, msgLength)
			return
		}

		msgBuf := make([]byte, msgLength)
		if _, err := io.ReadFull(tlsConn, msgBuf); err != nil {
			writeLog(LogDebug, "💥 %s消息读取失败: %v", protocol, err)
			return
		}

		req := new(dns.Msg)
		if err := req.Unpack(msgBuf); err != nil {
			writeLog(LogDebug, "💥 %s消息解析失败: %v", protocol, err)
			return
		}

		clientIP := sm.getSecureClientIP(tlsConn)
		response := sm.server.ProcessDNSQuery(req, clientIP, true)

		respBuf, err := response.Pack()
		if err != nil {
			writeLog(LogError, "💥 %s响应打包失败: %v", protocol, err)
			return
		}

		lengthPrefix := make([]byte, 2)
		binary.BigEndian.PutUint16(lengthPrefix, uint16(len(respBuf)))

		if _, err := tlsConn.Write(lengthPrefix); err != nil {
			writeLog(LogDebug, "💥 %s响应长度写入失败: %v", protocol, err)
			return
		}

		if _, err := tlsConn.Write(respBuf); err != nil {
			writeLog(LogDebug, "💥 %s响应写入失败: %v", protocol, err)
			return
		}

		if deadlineErr := tlsConn.SetReadDeadline(time.Now().Add(SecureConnQueryTimeout)); deadlineErr != nil {
			writeLog(LogDebug, "⚠️ 更新TLS读取截止时间失败: %v", deadlineErr)
		}
	}
}

func (sm *SecureDNSManager) getSecureClientIP(conn interface{}) net.IP {
	switch c := conn.(type) {
	case *tls.Conn:
		if addr, ok := c.RemoteAddr().(*net.TCPAddr); ok {
			return addr.IP
		}
	case *quic.Conn:
		if addr, ok := c.RemoteAddr().(*net.UDPAddr); ok {
			return addr.IP
		}
	}
	return nil
}

func (sm *SecureDNSManager) validQUICMsg(req *dns.Msg) bool {
	if req == nil {
		return false
	}

	if opt := req.IsEdns0(); opt != nil {
		for _, option := range opt.Option {
			if option.Option() == dns.EDNS0TCPKEEPALIVE {
				writeLog(LogDebug, "❌ DoQ客户端发送了不允许的TCP keepalive选项")
				return false
			}
		}
	}
	return true
}

func (sm *SecureDNSManager) respondQUIC(stream *quic.Stream, response *dns.Msg) error {
	if response == nil {
		return errors.New("❌ 响应消息为空")
	}

	respBuf, err := response.Pack()
	if err != nil {
		return fmt.Errorf("📦 响应打包失败: %w", err)
	}

	buf := make([]byte, 2+len(respBuf))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(respBuf)))
	copy(buf[2:], respBuf)

	n, err := stream.Write(buf)
	if err != nil {
		return fmt.Errorf("💥 流写入失败: %w", err)
	}

	if n != len(buf) {
		return fmt.Errorf("⚠️ 写入长度不匹配: %d != %d", n, len(buf))
	}

	return nil
}

func (sm *SecureDNSManager) logQUICError(prefix string, err error) {
	if sm.isQUICErrorForDebugLog(err) {
		writeLog(LogDebug, "🔄 DoQ连接关闭: %s - %v", prefix, err)
	} else {
		writeLog(LogError, "💥 DoQ错误: %s - %v", prefix, err)
	}
}

func (sm *SecureDNSManager) isQUICErrorForDebugLog(err error) bool {
	if errors.Is(err, quic.ErrServerClosed) {
		return true
	}

	var qAppErr *quic.ApplicationError
	if errors.As(err, &qAppErr) &&
		(qAppErr.ErrorCode == quic.ApplicationErrorCode(quic.NoError) ||
			qAppErr.ErrorCode == quic.ApplicationErrorCode(quic.ApplicationErrorErrorCode)) {
		return true
	}

	if errors.Is(err, quic.Err0RTTRejected) {
		return true
	}

	var qIdleErr *quic.IdleTimeoutError
	return errors.As(err, &qIdleErr)
}

func (sm *SecureDNSManager) readAll(r io.Reader, buf []byte) (int, error) {
	var n int
	for n < len(buf) {
		read, err := r.Read(buf[n:])
		n += read

		if err != nil {
			if err == io.EOF {
				return n, nil
			}
			return n, err
		}

		if n == len(buf) {
			return n, io.ErrShortBuffer
		}
	}
	return n, nil
}

func (sm *SecureDNSManager) Shutdown() error {
	writeLog(LogInfo, "🛑 正在关闭安全DNS服务器...")

	sm.cancel()

	if sm.tlsListener != nil {
		if closeErr := sm.tlsListener.Close(); closeErr != nil {
			writeLog(LogDebug, "⚠️ 关闭TLS监听器失败: %v", closeErr)
		}
	}
	if sm.quicListener != nil {
		if closeErr := sm.quicListener.Close(); closeErr != nil {
			writeLog(LogDebug, "⚠️ 关闭QUIC监听器失败: %v", closeErr)
		}
	}
	if sm.quicConn != nil {
		if closeErr := sm.quicConn.Close(); closeErr != nil {
			writeLog(LogDebug, "⚠️ 关闭QUIC连接失败: %v", closeErr)
		}
	}

	if sm.httpsServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if shutdownErr := sm.httpsServer.Shutdown(ctx); shutdownErr != nil {
			writeLog(LogDebug, "⚠️ 关闭HTTPS服务器失败: %v", shutdownErr)
		}
	}

	if sm.h3Server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if shutdownErr := sm.h3Server.Shutdown(ctx); shutdownErr != nil {
			writeLog(LogDebug, "⚠️ 关闭HTTP/3服务器失败: %v", shutdownErr)
		}
	}

	if sm.httpsListener != nil {
		if closeErr := sm.httpsListener.Close(); closeErr != nil {
			writeLog(LogDebug, "⚠️ 关闭HTTPS监听器失败: %v", closeErr)
		}
	}

	if sm.h3Listener != nil {
		if closeErr := sm.h3Listener.Close(); closeErr != nil {
			writeLog(LogDebug, "⚠️ 关闭HTTP/3监听器失败: %v", closeErr)
		}
	}

	sm.wg.Wait()
	writeLog(LogInfo, "✅ 安全DNS服务器已关闭")
	return nil
}
