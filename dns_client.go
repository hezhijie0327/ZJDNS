package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

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
		result.Response, result.Error = uqc.executeSecureQuery(msg, server, tracker)
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

func (uqc *UnifiedQueryClient) executeSecureQuery(msg *dns.Msg, server *UpstreamServer, tracker *RequestTracker) (*dns.Msg, error) {
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
	// 使用SafeCopyDNSMessage函数防止nil切片导致的slice bounds out of range panic
	// SafeCopyDNSMessage内部使用sync.Pool优化性能
	msgCopy := SafeCopyDNSMessage(msg)

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

	// 将复制的消息对象返回到对象池
	if msgCopy != nil {
		globalResourceManager.PutDNSMessage(msgCopy)
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
