package main

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// ==================== 连接池管理器 ====================

type ConnectionPoolManager struct {
	clients       chan *dns.Client
	secureClients map[string]SecureClient
	timeout       time.Duration
	mu            sync.RWMutex
	closed        int32
}

func NewConnectionPoolManager() *ConnectionPoolManager {
	return &ConnectionPoolManager{
		clients:       make(chan *dns.Client, 50),
		secureClients: make(map[string]SecureClient),
		timeout:       StandardQueryTimeout,
	}
}

func (cpm *ConnectionPoolManager) createClient() *dns.Client {
	return &dns.Client{
		Timeout:        cpm.timeout,
		Net:            "udp",
		UDPSize:        UpstreamUDPBufferSizeBytes,
		SingleInflight: false,
	}
}

func (cpm *ConnectionPoolManager) GetUDPClient() *dns.Client {
	if atomic.LoadInt32(&cpm.closed) != 0 {
		return cpm.createClient()
	}

	select {
	case client := <-cpm.clients:
		return client
	default:
		return cpm.createClient()
	}
}

func (cpm *ConnectionPoolManager) GetTCPClient() *dns.Client {
	return &dns.Client{
		Timeout:        cpm.timeout,
		Net:            "tcp",
		SingleInflight: false,
	}
}

func (cpm *ConnectionPoolManager) GetSecureClient(protocol, addr, serverName string, skipVerify bool) (SecureClient, error) {
	if atomic.LoadInt32(&cpm.closed) != 0 {
		return nil, errors.New("🔒 连接池已关闭")
	}

	cacheKey := fmt.Sprintf("%s:%s:%s:%v", protocol, addr, serverName, skipVerify)

	cpm.mu.RLock()
	if client, exists := cpm.secureClients[cacheKey]; exists {
		cpm.mu.RUnlock()

		if unifiedClient, ok := client.(*UnifiedSecureClient); ok && unifiedClient != nil {
			if unifiedClient.isConnectionAlive() {
				return client, nil
			} else {
				cpm.cleanupClient(cacheKey, client)
			}
		}
	} else {
		cpm.mu.RUnlock()
	}

	client, err := NewUnifiedSecureClient(protocol, addr, serverName, skipVerify)
	if err != nil {
		return nil, err
	}

	cpm.mu.Lock()
	if atomic.LoadInt32(&cpm.closed) == 0 {
		cpm.secureClients[cacheKey] = client
	}
	cpm.mu.Unlock()

	return client, nil
}

func (cpm *ConnectionPoolManager) cleanupClient(key string, client SecureClient) {
	cpm.mu.Lock()
	defer cpm.mu.Unlock()

	if currentClient, exists := cpm.secureClients[key]; exists && currentClient == client {
		delete(cpm.secureClients, key)
		go func() {
			defer handlePanicWithContext("连接清理", nil)
			if err := client.Close(); err != nil {
				writeLog(LogWarn, "⚠️ 安全客户端关闭失败: %v", err)
			}
		}()
	}
}

func (cpm *ConnectionPoolManager) PutUDPClient(client *dns.Client) {
	if client == nil || atomic.LoadInt32(&cpm.closed) != 0 {
		return
	}
	select {
	case cpm.clients <- client:
	default:
	}
}

func (cpm *ConnectionPoolManager) Close() error {
	if !atomic.CompareAndSwapInt32(&cpm.closed, 0, 1) {
		return nil
	}

	writeLog(LogInfo, "🏊 正在关闭连接池...")

	cpm.mu.Lock()
	defer cpm.mu.Unlock()

	for key, client := range cpm.secureClients {
		if err := client.Close(); err != nil {
			writeLog(LogWarn, "⚠️ 关闭安全客户端失败 [%s]: %v", key, err)
		}
	}
	cpm.secureClients = make(map[string]SecureClient)

	close(cpm.clients)
	for range cpm.clients {
	}

	writeLog(LogInfo, "✅ 连接池已关闭")
	return nil
}
