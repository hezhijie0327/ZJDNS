package security

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
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"

	"zjdns/types"
	"zjdns/utils"
)

// handlePanicWithContext 处理带上下文的panic
func handlePanicWithContext(operation string) {
	if r := recover(); r != nil {
		buf := make([]byte, 2048)
		n := runtime.Stack(buf, false)
		stackTrace := string(buf[:n])

		// 合并日志输出，包含操作信息、panic详情和堆栈跟踪
		utils.WriteLog(utils.LogError, "🚨 Panic触发 [%s]: %v\n堆栈:\n%s\n💥 程序因panic退出",
			operation, r, stackTrace)

		os.Exit(1)
	}
}

// NewSecureDNSManager 创建新的安全DNS管理器
func NewSecureDNSManager(server DNSProcessor, config *types.ServerConfig) (*SecureDNSManager, error) {
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

// Start 启动安全DNS服务器
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

// startTLSServer 启动TLS服务器
func (sm *SecureDNSManager) startTLSServer() error {
	listener, err := net.Listen("tcp", ":"+sm.server.GetConfig().Server.TLS.Port)
	if err != nil {
		return fmt.Errorf("🔐 DoT监听失败: %w", err)
	}

	sm.tlsListener = tls.NewListener(listener, sm.tlsConfig)
	utils.WriteLog(utils.LogInfo, "🔐 DoT服务器启动: %s", sm.tlsListener.Addr())

	sm.wg.Add(1)
	go func() {
		defer sm.wg.Done()
		defer func() { handlePanicWithContext("DoT服务器") }()
		sm.handleTLSConnections()
	}()

	return nil
}

// startQUICServer 启动QUIC服务器
func (sm *SecureDNSManager) startQUICServer() error {
	addr := ":" + sm.server.GetConfig().Server.TLS.Port

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
			utils.WriteLog(utils.LogDebug, "⚠️ 关闭QUIC连接失败: %v", closeErr)
		}
		return fmt.Errorf("🚀 DoQ监听失败: %w", err)
	}

	utils.WriteLog(utils.LogInfo, "🚀 DoQ服务器启动: %s", sm.quicListener.Addr())

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
	utils.WriteLog(utils.LogInfo, "🌐 DoH服务器启动: %s", sm.httpsListener.Addr())

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
			utils.WriteLog(utils.LogError, "💥 DoH服务器错误: %v", err)
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
	utils.WriteLog(utils.LogInfo, "⚡ DoH3服务器启动: %s", sm.h3Listener.Addr())

	sm.h3Server = &http3.Server{
		Handler: sm,
	}

	sm.wg.Add(1)
	go func() {
		defer sm.wg.Done()
		defer func() { handlePanicWithContext("DoH3服务器") }()
		if err := sm.h3Server.ServeListener(sm.h3Listener); err != nil && err != http.ErrServerClosed {
			utils.WriteLog(utils.LogError, "💥 DoH3服务器错误: %v", err)
		}
	}()

	return nil
}

func (sm *SecureDNSManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if sm == nil || sm.server == nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	expectedPath := sm.server.GetConfig().Server.TLS.HTTPS.Endpoint
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

	if utils.GetLogLevel() >= utils.LogDebug {
		utils.WriteLog(utils.LogDebug, "🌐 收到DoH请求: %s %s", r.Method, r.URL.Path)
	}

	req, statusCode := sm.parseDoHRequest(r)
	if req == nil {
		http.Error(w, http.StatusText(statusCode), statusCode)
		return
	}

	response := sm.server.ProcessDNSQuery(req, nil, true)
	if err := sm.respondDoH(w, response); err != nil {
		utils.WriteLog(utils.LogError, "💥 DoH响应发送失败: %v", err)
	}
}

func (sm *SecureDNSManager) parseDoHRequest(r *http.Request) (*dns.Msg, int) {
	var buf []byte
	var err error

	switch r.Method {
	case http.MethodGet:
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" {
			utils.WriteLog(utils.LogDebug, "❌ DoH GET请求缺少dns参数")
			return nil, http.StatusBadRequest
		}
		buf, err = base64.RawURLEncoding.DecodeString(dnsParam)
		if err != nil {
			utils.WriteLog(utils.LogDebug, "💥 DoH GET请求dns参数解码失败: %v", err)
			return nil, http.StatusBadRequest
		}

	case http.MethodPost:
		contentType := r.Header.Get("Content-Type")
		if contentType != "application/dns-message" {
			utils.WriteLog(utils.LogDebug, "❌ DoH POST请求Content-Type不支持: %s", contentType)
			return nil, http.StatusUnsupportedMediaType
		}

		r.Body = http.MaxBytesReader(nil, r.Body, DoHMaxRequestSize)
		buf, err = io.ReadAll(r.Body)
		if err != nil {
			utils.WriteLog(utils.LogDebug, "💥 DoH POST请求体读取失败: %v", err)
			return nil, http.StatusBadRequest
		}
		defer func() {
			if closeErr := r.Body.Close(); closeErr != nil {
				utils.WriteLog(utils.LogDebug, "⚠️ 关闭请求体失败: %v", closeErr)
			}
		}()

	default:
		utils.WriteLog(utils.LogDebug, "❌ DoH请求方法不支持: %s", r.Method)
		return nil, http.StatusMethodNotAllowed
	}

	if len(buf) == 0 {
		utils.WriteLog(utils.LogDebug, "❌ DoH请求数据为空")
		return nil, http.StatusBadRequest
	}

	req := new(dns.Msg)
	if err := req.Unpack(buf); err != nil {
		utils.WriteLog(utils.LogDebug, "💥 DoH DNS消息解析失败: %v", err)
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
			utils.WriteLog(utils.LogError, "💥 DoT连接接受失败: %v", err)
			continue
		}

		sm.wg.Add(1)
		go func() {
			defer sm.wg.Done()
			defer func() { handlePanicWithContext("DoT连接处理") }()
			defer func() {
				if closeErr := conn.Close(); closeErr != nil {
					utils.WriteLog(utils.LogDebug, "⚠️ 关闭DoT连接失败: %v", closeErr)
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
				utils.WriteLog(utils.LogDebug, "⚠️ 关闭QUIC连接失败: %v", closeErr)
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
						utils.WriteLog(utils.LogDebug, "⚠️ 关闭QUIC流失败: %v", closeErr)
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
		utils.WriteLog(utils.LogDebug, "💥 DoQ流读取失败: %v", err)
		return
	}

	if n < MinDNSPacketSizeBytes {
		utils.WriteLog(utils.LogDebug, "📏 DoQ消息太短: %d字节", n)
		return
	}

	req := new(dns.Msg)
	var msgData []byte

	packetLen := binary.BigEndian.Uint16(buf[:2])
	if packetLen == uint16(n-2) {
		msgData = buf[2:n]
	} else {
		utils.WriteLog(utils.LogDebug, "❌ DoQ不支持的消息格式")
		if closeErr := conn.CloseWithError(QUICCodeProtocolError, ""); closeErr != nil {
			utils.WriteLog(utils.LogDebug, "⚠️ 关闭QUIC连接失败: %v", closeErr)
		}
		return
	}

	if err := req.Unpack(msgData); err != nil {
		utils.WriteLog(utils.LogDebug, "💥 DoQ消息解析失败: %v", err)
		if closeErr := conn.CloseWithError(QUICCodeProtocolError, ""); closeErr != nil {
			utils.WriteLog(utils.LogDebug, "⚠️ 关闭QUIC连接失败: %v", closeErr)
		}
		return
	}

	if !sm.validQUICMsg(req) {
		if closeErr := conn.CloseWithError(QUICCodeProtocolError, ""); closeErr != nil {
			utils.WriteLog(utils.LogDebug, "⚠️ 关闭QUIC连接失败: %v", closeErr)
		}
		return
	}

	clientIP := sm.getSecureClientIP(conn)
	response := sm.server.ProcessDNSQuery(req, clientIP, true)

	if err := sm.respondQUIC(stream, response); err != nil {
		utils.WriteLog(utils.LogDebug, "💥 DoQ响应发送失败: %v", err)
	}
}

func (sm *SecureDNSManager) handleSecureDNSConnection(conn net.Conn, protocol string) {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return
	}

	if deadlineErr := tlsConn.SetReadDeadline(time.Now().Add(SecureConnQueryTimeout)); deadlineErr != nil {
		utils.WriteLog(utils.LogDebug, "⚠️ 设置TLS读取截止时间失败: %v", deadlineErr)
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
				utils.WriteLog(utils.LogDebug, "💥 %s长度读取失败: %v", protocol, err)
			}
			return
		}

		msgLength := binary.BigEndian.Uint16(lengthBuf)
		if msgLength == 0 || msgLength > UpstreamUDPBufferSizeBytes {
			utils.WriteLog(utils.LogWarn, "⚠️ %s消息长度异常: %d", protocol, msgLength)
			return
		}

		msgBuf := make([]byte, msgLength)
		if _, err := io.ReadFull(tlsConn, msgBuf); err != nil {
			utils.WriteLog(utils.LogDebug, "💥 %s消息读取失败: %v", protocol, err)
			return
		}

		req := new(dns.Msg)
		if err := req.Unpack(msgBuf); err != nil {
			utils.WriteLog(utils.LogDebug, "💥 %s消息解析失败: %v", protocol, err)
			return
		}

		clientIP := sm.getSecureClientIP(tlsConn)
		response := sm.server.ProcessDNSQuery(req, clientIP, true)

		respBuf, err := response.Pack()
		if err != nil {
			utils.WriteLog(utils.LogError, "💥 %s响应打包失败: %v", protocol, err)
			return
		}

		lengthPrefix := make([]byte, 2)
		binary.BigEndian.PutUint16(lengthPrefix, uint16(len(respBuf)))

		if _, err := tlsConn.Write(lengthPrefix); err != nil {
			utils.WriteLog(utils.LogDebug, "💥 %s响应长度写入失败: %v", protocol, err)
			return
		}

		if _, err := tlsConn.Write(respBuf); err != nil {
			utils.WriteLog(utils.LogDebug, "💥 %s响应写入失败: %v", protocol, err)
			return
		}

		if deadlineErr := tlsConn.SetReadDeadline(time.Now().Add(SecureConnQueryTimeout)); deadlineErr != nil {
			utils.WriteLog(utils.LogDebug, "⚠️ 更新TLS读取截止时间失败: %v", deadlineErr)
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
				utils.WriteLog(utils.LogDebug, "❌ DoQ客户端发送了不允许的TCP keepalive选项")
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
		utils.WriteLog(utils.LogDebug, "🔄 DoQ连接关闭: %s - %v", prefix, err)
	} else {
		utils.WriteLog(utils.LogError, "💥 DoQ错误: %s - %v", prefix, err)
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
	utils.WriteLog(utils.LogInfo, "🛑 正在关闭安全DNS服务器...")

	sm.cancel()

	if sm.tlsListener != nil {
		if closeErr := sm.tlsListener.Close(); closeErr != nil {
			utils.WriteLog(utils.LogDebug, "⚠️ 关闭TLS监听器失败: %v", closeErr)
		}
	}
	if sm.quicListener != nil {
		if closeErr := sm.quicListener.Close(); closeErr != nil {
			utils.WriteLog(utils.LogDebug, "⚠️ 关闭QUIC监听器失败: %v", closeErr)
		}
	}
	if sm.quicConn != nil {
		if closeErr := sm.quicConn.Close(); closeErr != nil {
			utils.WriteLog(utils.LogDebug, "⚠️ 关闭QUIC连接失败: %v", closeErr)
		}
	}

	if sm.httpsServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if shutdownErr := sm.httpsServer.Shutdown(ctx); shutdownErr != nil {
			utils.WriteLog(utils.LogDebug, "⚠️ 关闭HTTPS服务器失败: %v", shutdownErr)
		}
	}

	if sm.h3Server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if shutdownErr := sm.h3Server.Shutdown(ctx); shutdownErr != nil {
			utils.WriteLog(utils.LogDebug, "⚠️ 关闭HTTP/3服务器失败: %v", shutdownErr)
		}
	}

	if sm.httpsListener != nil {
		if closeErr := sm.httpsListener.Close(); closeErr != nil {
			utils.WriteLog(utils.LogDebug, "⚠️ 关闭HTTPS监听器失败: %v", closeErr)
		}
	}

	if sm.h3Listener != nil {
		if closeErr := sm.h3Listener.Close(); closeErr != nil {
			utils.WriteLog(utils.LogDebug, "⚠️ 关闭HTTP/3监听器失败: %v", closeErr)
		}
	}

	sm.wg.Wait()
	utils.WriteLog(utils.LogInfo, "✅ 安全DNS服务器已关闭")
	return nil
}
