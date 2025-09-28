package network

import (
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/miekg/dns"

	"zjdns/utils"
)

// NewConnectionPoolManager 创建新的连接池管理器
func NewConnectionPoolManager() *ConnectionPoolManager {
	return &ConnectionPoolManager{
		clients:       make(chan *dns.Client, 50),
		secureClients: make(map[string]SecureClient),
		timeout:       StandardQueryTimeout,
	}
}

// createClient 创建新的DNS客户端
func (cpm *ConnectionPoolManager) createClient() *dns.Client {
	return &dns.Client{
		Timeout:        cpm.timeout,
		Net:            "udp",
		UDPSize:        UpstreamUDPBufferSizeBytes,
		SingleInflight: false,
	}
}

// GetUDPClient 获取UDP客户端
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

// GetTCPClient 获取TCP客户端
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

		if unifiedClient, ok := client.(interface{ IsConnectionAlive() bool }); ok && unifiedClient != nil {
			if unifiedClient.IsConnectionAlive() {
				return client, nil
			} else {
				cpm.cleanupClient(cacheKey, client)
			}
		}
	} else {
		cpm.mu.RUnlock()
	}

	// 创建新的安全客户端
	cpm.mu.Lock()
	defer cpm.mu.Unlock()

	// 双重检查，确保在获取写锁期间没有其他goroutine创建了客户端
	if client, exists := cpm.secureClients[cacheKey]; exists {
		if unifiedClient, ok := client.(interface{ IsConnectionAlive() bool }); ok && unifiedClient != nil {
			if unifiedClient.IsConnectionAlive() {
				return client, nil
			}
		}
	}

	// 使用工厂函数创建安全客户端
	newClient, err := createSecureClient(protocol, addr, serverName, skipVerify)
	if err != nil {
		return nil, fmt.Errorf("🔒 创建安全客户端失败: %w", err)
	}

	// 缓存新创建的客户端
	cpm.secureClients[cacheKey] = newClient
	return newClient, nil
}

// createSecureClient 是一个工厂函数，用于创建安全客户端
// 这样可以避免 network 包直接依赖 security 包，解决循环依赖问题
var createSecureClient = func(protocol, addr, serverName string, skipVerify bool) (SecureClient, error) {
	return nil, errors.New("🔒 安全客户端工厂函数未初始化")
}

// SetSecureClientFactory 设置安全客户端工厂函数
func SetSecureClientFactory(factory func(protocol, addr, serverName string, skipVerify bool) (SecureClient, error)) {
	createSecureClient = factory
}

func (cpm *ConnectionPoolManager) cleanupClient(key string, client SecureClient) {
	cpm.mu.Lock()
	defer cpm.mu.Unlock()

	if currentClient, exists := cpm.secureClients[key]; exists && currentClient == client {
		delete(cpm.secureClients, key)
		go func() {
			defer func() { utils.HandlePanicWithContext("连接清理") }()
			if err := client.Close(); err != nil {
				utils.WriteLog(utils.LogWarn, "⚠️ 安全客户端关闭失败: %v", err)
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

	utils.WriteLog(utils.LogInfo, "🏊 正在关闭连接池...")

	cpm.mu.Lock()
	defer cpm.mu.Unlock()

	for key, client := range cpm.secureClients {
		if err := client.Close(); err != nil {
			utils.WriteLog(utils.LogWarn, "⚠️ 关闭安全客户端失败 [%s]: %v", key, err)
		}
	}
	cpm.secureClients = make(map[string]SecureClient)

	close(cpm.clients)
	for range cpm.clients {
	}

	utils.WriteLog(utils.LogInfo, "✅ 连接池已关闭")
	return nil
}
