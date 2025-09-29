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
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

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
