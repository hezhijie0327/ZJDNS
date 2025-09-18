package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// ==================== 上游管理器 ====================

type UpstreamManager struct {
	servers []*UpstreamServer
	mu      sync.RWMutex
}

func NewUpstreamManager(servers []UpstreamServer) *UpstreamManager {
	activeServers := make([]*UpstreamServer, 0, len(servers))

	for i := range servers {
		server := &servers[i]
		if server.Protocol == "" {
			server.Protocol = "udp"
		}
		activeServers = append(activeServers, server)
	}

	return &UpstreamManager{
		servers: activeServers,
	}
}

func (um *UpstreamManager) GetServers() []*UpstreamServer {
	um.mu.RLock()
	defer um.mu.RUnlock()
	return um.servers
}

// ==================== 安全连接错误处理器 ====================

type SecureConnErrorHandler struct{}

func NewSecureConnErrorHandler() *SecureConnErrorHandler {
	return &SecureConnErrorHandler{}
}

func (h *SecureConnErrorHandler) IsRetryableError(protocol string, err error) bool {
	if h == nil || err == nil {
		return false
	}

	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}

	protocol = strings.ToLower(protocol)

	switch protocol {
	case "quic", "http3":
		return h.handleQUICErrors(err)
	case "tls":
		return h.handleTLSErrors(err)
	case "https":
		return h.handleHTTPErrors(err)
	default:
		return false
	}
}

func (h *SecureConnErrorHandler) handleQUICErrors(err error) bool {
	var qAppErr *quic.ApplicationError
	if errors.As(err, &qAppErr) {
		return qAppErr.ErrorCode == 0 || qAppErr.ErrorCode == quic.ApplicationErrorCode(0x100)
	}

	var qIdleErr *quic.IdleTimeoutError
	if errors.As(err, &qIdleErr) {
		return true
	}

	var resetErr *quic.StatelessResetError
	if errors.As(err, &resetErr) {
		return true
	}

	var qTransportError *quic.TransportError
	if errors.As(err, &qTransportError) && qTransportError.ErrorCode == quic.NoError {
		return true
	}

	return errors.Is(err, quic.Err0RTTRejected)
}

func (h *SecureConnErrorHandler) handleTLSErrors(err error) bool {
	errStr := err.Error()
	connectionErrors := []string{
		"broken pipe", "connection reset", "use of closed network connection",
		"connection refused", "no route to host", "network is unreachable",
	}

	for _, connErr := range connectionErrors {
		if strings.Contains(errStr, connErr) {
			return true
		}
	}

	return errors.Is(err, io.EOF)
}

func (h *SecureConnErrorHandler) handleHTTPErrors(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	return h.handleQUICErrors(err)
}

var globalSecureConnErrorHandler = NewSecureConnErrorHandler()

// ==================== 统一查询客户端 ====================

type UnifiedQueryClient struct {
	connectionPool *ConnectionPoolManager
	errorHandler   *SecureConnErrorHandler
	timeout        time.Duration
}

func NewUnifiedQueryClient(connectionPool *ConnectionPoolManager, timeout time.Duration) *UnifiedQueryClient {
	return &UnifiedQueryClient{
		connectionPool: connectionPool,
		errorHandler:   globalSecureConnErrorHandler,
		timeout:        timeout,
	}
}

func (uqc *UnifiedQueryClient) ExecuteQuery(ctx context.Context, msg *dns.Msg, server *UpstreamServer, tracker *RequestTracker) *QueryResult {
	start := time.Now()
	result := &QueryResult{
		Server:   server.Address,
		Protocol: server.Protocol,
	}

	if tracker != nil {
		tracker.AddStep("🚀 开始查询服务器: %s (%s)", server.Address, server.Protocol)
	}

	queryCtx, cancel := context.WithTimeout(ctx, uqc.timeout)
	defer cancel()

	protocol := strings.ToLower(server.Protocol)

	// 安全连接协议
	if isSecureProtocol(protocol) {
		result.Response, result.Error = uqc.executeSecureQuery(queryCtx, msg, server, tracker)
		result.Duration = time.Since(start)
		result.Protocol = strings.ToUpper(protocol)
		return result
	}

	// 传统UDP/TCP协议
	result.Response, result.Error = uqc.executeTraditionalQuery(queryCtx, msg, server, tracker)
	result.Duration = time.Since(start)

	// TCP回退处理
	if uqc.needsTCPFallback(result, protocol) {
		if tracker != nil {
			tracker.AddStep("🔙 需要TCP回退")
		}

		tcpServer := *server
		tcpServer.Protocol = "tcp"
		tcpResponse, tcpErr := uqc.executeTraditionalQuery(queryCtx, msg, &tcpServer, tracker)

		if tcpErr != nil {
			if result.Response != nil && result.Response.Rcode != dns.RcodeServerFailure {
				if tracker != nil {
					tracker.AddStep("🔙 TCP回退失败，使用UDP响应")
				}
				return result
			}
			result.Error = tcpErr
		} else {
			result.Response = tcpResponse
			result.Error = nil
			result.UsedTCP = true
			result.Protocol = "TCP"
			if tracker != nil {
				tracker.AddStep("✅ TCP回退成功")
			}
		}
		result.Duration = time.Since(start)
	}

	return result
}

func (uqc *UnifiedQueryClient) executeSecureQuery(ctx context.Context, msg *dns.Msg, server *UpstreamServer, tracker *RequestTracker) (*dns.Msg, error) {
	client, err := uqc.connectionPool.GetSecureClient(server.Protocol, server.Address, server.ServerName, server.SkipTLSVerify)
	if err != nil {
		return nil, fmt.Errorf("🔒 获取%s客户端失败: %w", strings.ToUpper(server.Protocol), err)
	}

	response, err := client.Exchange(msg, server.Address)
	if err != nil {
		return nil, err
	}

	if tracker != nil && response != nil {
		protocolEmoji := getProtocolEmoji(server.Protocol)
		tracker.AddStep("%s %s查询成功，响应码: %s", protocolEmoji, strings.ToUpper(server.Protocol), dns.RcodeToString[response.Rcode])
	}

	return response, nil
}

func (uqc *UnifiedQueryClient) executeTraditionalQuery(ctx context.Context, msg *dns.Msg, server *UpstreamServer, tracker *RequestTracker) (*dns.Msg, error) {
	// 创建消息的副本以保证安全性和避免并发问题
	// Copy() 方法会正确初始化所有切片字段，防止 nil panic
	var msgCopy *dns.Msg
	if msg != nil {
		msgCopy = msg.Copy()
	} else {
		msgCopy = new(dns.Msg)
	}


	var client *dns.Client
	if server.Protocol == "tcp" {
		client = uqc.connectionPool.GetTCPClient()
	} else {
		client = uqc.connectionPool.GetUDPClient()
		defer uqc.connectionPool.PutUDPClient(client)
	}

	response, _, err := client.ExchangeContext(ctx, msgCopy, server.Address)

	if tracker != nil && err == nil && response != nil {
		protocolName := "UDP"
		emoji := "📡"
		if server.Protocol == "tcp" {
			protocolName = "TCP"
			emoji = "🔌"
		}
		tracker.AddStep("%s %s查询成功，响应码: %s", emoji, protocolName, dns.RcodeToString[response.Rcode])
	}

	return response, err
}

func (uqc *UnifiedQueryClient) needsTCPFallback(result *QueryResult, protocol string) bool {
	if protocol == "tcp" {
		return false
	}

	if result.Error != nil {
		return true
	}

	if result.Response != nil && result.Response.Truncated {
		return true
	}

	return false
}
