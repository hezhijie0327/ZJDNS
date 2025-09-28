package dns

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	cache_pkg "zjdns/cache"
	"zjdns/network"
	"zjdns/security"
	"zjdns/types"
	"zjdns/utils"

	"github.com/miekg/dns"
)

// NewDNSServer 创建新的DNS服务器实例
func NewDNSServer(config *types.ServerConfig) (*RecursiveDNSServer, error) {
	rootServersV4 := []string{
		"198.41.0.4:53", "170.247.170.2:53", "192.33.4.12:53", "199.7.91.13:53",
		"192.203.230.10:53", "192.5.5.241:53", "192.112.36.4:53", "198.97.190.53:53",
		"192.36.148.17:53", "192.58.128.30:53", "193.0.14.129:53", "199.7.83.42:53", "202.12.27.33:53",
	}

	rootServersV6 := []string{
		"[2001:503:ba3e::2:30]:53", "[2801:1b8:10::b]:53", "[2001:500:2::c]:53", "[2001:500:2d::d]:53",
		"[2001:500:a8::e]:53", "[2001:500:2f::f]:53", "[2001:500:12::d0d]:53", "[2001:500:1::53]:53",
		"[2001:7fe::53]:53", "[2001:503:c27::2:30]:53", "[2001:7fd::1]:53", "[2001:500:9f::42]:53", "[2001:dc3::35]:53",
	}

	ctx, cancel := context.WithCancel(context.Background())

	ednsManager, err := network.NewEDNSManager(config.Server.DefaultECS, config.Server.Features.Padding)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("🌍 EDNS管理器初始化失败: %w", err)
	}

	ipFilter := network.NewIPFilter()
	if config.Server.TrustedCIDRFile != "" {
		if err := ipFilter.LoadCIDRs(config.Server.TrustedCIDRFile); err != nil {
			cancel()
			return nil, fmt.Errorf("🌍 加载可信CIDR文件失败: %w", err)
		}
	}

	dnsRewriter := NewDNSRewriter()
	if len(config.Rewrite) > 0 {
		// Convert types.RewriteRule to dns.RewriteRule
		dnsRewriteRules := make([]RewriteRule, len(config.Rewrite))
		for i, rule := range config.Rewrite {
			dnsRewriteRules[i] = RewriteRule{
				Name: rule.Name,
			}
			if rule.ResponseCode != nil {
				dnsRewriteRules[i].ResponseCode = rule.ResponseCode
			}
			// Convert Records
			dnsRewriteRules[i].Records = make([]utils.DNSRecordConfig, len(rule.Records))
			for j, record := range rule.Records {
				dnsRewriteRules[i].Records[j] = utils.DNSRecordConfig{
					Name:         record.Name,
					Type:         record.Type,
					TTL:          record.TTL,
					Content:      record.Content,
					ResponseCode: record.ResponseCode,
				}
			}
			// Convert Additional
			dnsRewriteRules[i].Additional = make([]utils.DNSRecordConfig, len(rule.Additional))
			for j, record := range rule.Additional {
				dnsRewriteRules[i].Additional[j] = utils.DNSRecordConfig{
					Name:         record.Name,
					Type:         record.Type,
					TTL:          record.TTL,
					Content:      record.Content,
					ResponseCode: record.ResponseCode,
				}
			}
		}
		if err := dnsRewriter.LoadRules(dnsRewriteRules); err != nil {
			cancel()
			return nil, fmt.Errorf("🔄 加载DNS重写规则失败: %w", err)
		}
	}

	// Convert types.UpstreamServer to dns.UpstreamServer
	dnsUpstreamServers := make([]UpstreamServer, len(config.Upstream))
	for i, server := range config.Upstream {
		dnsUpstreamServers[i] = UpstreamServer{
			Address:       server.Address,
			Policy:        server.Policy,
			Protocol:      server.Protocol,
			ServerName:    server.ServerName,
			SkipTLSVerify: server.SkipTLSVerify,
		}
	}
	upstreamManager := NewUpstreamManager(dnsUpstreamServers)
	connectionPool := network.NewConnectionPoolManager()

	// 设置安全客户端工厂函数，解决循环依赖问题
	network.SetSecureClientFactory(func(protocol, addr, serverName string, skipVerify bool) (network.SecureClient, error) {
		return security.NewUnifiedSecureClient(protocol, addr, serverName, skipVerify)
	})

	taskManager := utils.NewTaskManager(MaxGlobalConcurrency)
	queryClient := NewUnifiedQueryClient(connectionPool, network.StandardQueryTimeout)
	hijackPrevention := NewDNSHijackPrevention(config.Server.Features.HijackProtection)

	server := &RecursiveDNSServer{
		config:            config,
		rootServersV4:     rootServersV4,
		rootServersV6:     rootServersV6,
		connectionPool:    connectionPool,
		dnssecValidator:   utils.NewDNSSECValidator(),
		concurrencyLimit:  make(chan struct{}, MaxGlobalConcurrency),
		ctx:               ctx,
		cancel:            cancel,
		shutdown:          make(chan struct{}),
		ipFilter:          ipFilter,
		dnsRewriter:       dnsRewriter,
		upstreamManager:   upstreamManager,
		queryClient:       queryClient,
		hijackPrevention:  hijackPrevention,
		taskManager:       taskManager,
		ednsManager:       ednsManager,
		speedtestDebounce: make(map[string]time.Time),
		speedtestMutex:    sync.Mutex{},
		speedtestInterval: SpeedTestDebounceInterval, // 使用常量中的防抖间隔
	}

	if config.Server.TLS.CertFile != "" && config.Server.TLS.KeyFile != "" {
		secureDNSManager, err := security.NewSecureDNSManager(server, config)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("🔐 安全DNS管理器初始化失败: %w", err)
		}
		server.secureDNSManager = secureDNSManager
	}

	var cache DNSCache
	if config.Redis.Address == "" {
		cache = cache_pkg.NewNullCache()
	} else {
		redisCache, err := cache_pkg.NewRedisDNSCache(config, server)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("💾 Redis缓存初始化失败: %w", err)
		}
		cache = redisCache
	}

	server.cache = cache
	server.setupSignalHandling()
	return server, nil
}

func (r *RecursiveDNSServer) setupSignalHandling() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer func() { utils.HandlePanicWithContext("信号处理器") }()

		select {
		case sig := <-sigChan:
			utils.WriteLog(utils.LogInfo, "🛑 收到信号 %v，开始优雅关闭...", sig)
			r.shutdownServer()
		case <-r.ctx.Done():
			return
		}
	}()
}

func (r *RecursiveDNSServer) shutdownServer() {
	if !atomic.CompareAndSwapInt32(&r.closed, 0, 1) {
		return
	}

	utils.WriteLog(utils.LogInfo, "🛑 开始关闭DNS服务器...")

	// 清理速度测试防抖记录
	r.cleanupSpeedtestDebounce()

	if r.cancel != nil {
		r.cancel()
	}

	if r.cache != nil {
		r.cache.Shutdown()
	}

	if r.secureDNSManager != nil {
		if err := r.secureDNSManager.Shutdown(); err != nil {
			utils.WriteLog(utils.LogError, "💥 安全DNS管理器关闭失败: %v", err)
		}
	}

	if r.connectionPool != nil {
		if err := r.connectionPool.Close(); err != nil {
			utils.WriteLog(utils.LogError, "💥 连接池关闭失败: %v", err)
		}
	}

	if r.taskManager != nil {
		if err := r.taskManager.Shutdown(GracefulShutdownTimeout); err != nil {
			utils.WriteLog(utils.LogError, "💥 任务管理器关闭失败: %v", err)
		}
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		r.wg.Wait()
	}()

	select {
	case <-done:
		utils.WriteLog(utils.LogInfo, "✅ 所有组件已安全关闭")
	case <-time.After(GracefulShutdownTimeout):
		utils.WriteLog(utils.LogWarn, "⏰ 组件关闭超时")
	}

	if r.shutdown != nil {
		close(r.shutdown)
	}

	time.Sleep(100 * time.Millisecond)
	os.Exit(0)
}

// Start 启动DNS服务器
func (r *RecursiveDNSServer) Start() error {
	if atomic.LoadInt32(&r.closed) != 0 {
		return errors.New("🔒 服务器已关闭")
	}

	var wg sync.WaitGroup
	serverCount := 2

	if r.secureDNSManager != nil {
		serverCount += 1
	}

	errChan := make(chan error, serverCount)

	utils.WriteLog(utils.LogInfo, "🚀 启动 ZJDNS Server")
	utils.WriteLog(utils.LogInfo, "🌐 监听端口: %s", r.config.Server.Port)

	r.displayInfo()

	wg.Add(serverCount)

	// 启动UDP服务器
	go func() {
		defer wg.Done()
		defer func() { utils.HandlePanicWithContext("关键-UDP服务器") }()
		server := &dns.Server{
			Addr:    ":" + r.config.Server.Port,
			Net:     "udp",
			Handler: dns.HandlerFunc(r.handleDNSRequest),
			UDPSize: ClientUDPBufferSizeBytes,
		}
		utils.WriteLog(utils.LogInfo, "📡 UDP服务器启动: [::]:%s", r.config.Server.Port)
		if err := server.ListenAndServe(); err != nil {
			errChan <- fmt.Errorf("📡 UDP启动失败: %w", err)
		}
	}()

	// 启动TCP服务器
	go func() {
		defer wg.Done()
		defer func() { utils.HandlePanicWithContext("关键-TCP服务器") }()
		server := &dns.Server{
			Addr:    ":" + r.config.Server.Port,
			Net:     "tcp",
			Handler: dns.HandlerFunc(r.handleDNSRequest),
		}
		utils.WriteLog(utils.LogInfo, "🔌 TCP服务器启动: [::]:%s", r.config.Server.Port)
		if err := server.ListenAndServe(); err != nil {
			errChan <- fmt.Errorf("🔌 TCP启动失败: %w", err)
		}
	}()

	// 启动安全DNS服务器
	if r.secureDNSManager != nil {
		go func() {
			defer wg.Done()
			defer func() { utils.HandlePanicWithContext("关键-安全DNS服务器") }()
			httpsPort := r.config.Server.TLS.HTTPS.Port
			if err := r.secureDNSManager.Start(httpsPort); err != nil {
				errChan <- fmt.Errorf("🔐 安全DNS启动失败: %w", err)
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

	<-r.shutdown
	return nil
}

func (r *RecursiveDNSServer) displayInfo() {
	servers := r.upstreamManager.GetServers()
	if len(servers) > 0 {
		for _, server := range servers {
			if server.IsRecursive() {
				utils.WriteLog(utils.LogInfo, "🔗 上游服务器: 🔄 递归解析 - %s", server.Policy)
			} else {
				protocol := strings.ToUpper(server.Protocol)
				emoji := utils.GetProtocolEmoji(server.Protocol)
				if protocol == "" {
					protocol = "UDP"
					emoji = "📡"
				}
				serverInfo := fmt.Sprintf("%s %s (%s) - %s", emoji, server.Address, protocol, server.Policy)
				if server.SkipTLSVerify && utils.IsSecureProtocol(strings.ToLower(server.Protocol)) {
					serverInfo += " [跳过TLS验证]"
				}
				utils.WriteLog(utils.LogInfo, "🔗 上游服务器: %s", serverInfo)
			}
		}
		utils.WriteLog(utils.LogInfo, "🔗 上游模式: 共 %d 个服务器", len(servers))
	} else {
		if r.config.Redis.Address == "" {
			utils.WriteLog(utils.LogInfo, "🚫 递归模式 (无缓存)")
		} else {
			utils.WriteLog(utils.LogInfo, "💾 递归模式 + Redis缓存: %s", r.config.Redis.Address)
		}
	}

	if r.secureDNSManager != nil {
		utils.WriteLog(utils.LogInfo, "🔐 监听安全DNS协议端口: %s (DoT/DoQ)", r.config.Server.TLS.Port)

		httpsPort := r.config.Server.TLS.HTTPS.Port
		if httpsPort != "" {
			endpoint := r.config.Server.TLS.HTTPS.Endpoint
			if endpoint == "" {
				endpoint = strings.TrimPrefix(DefaultDNSQueryPath, "/")
			}
			utils.WriteLog(utils.LogInfo, "🌐 监听安全DNS协议端口: %s (DoH/DoH3, 端点: %s)", httpsPort, endpoint)
		}
	}

	if r.ipFilter.HasData() {
		utils.WriteLog(utils.LogInfo, "🌍 IP过滤器: 已启用 (配置文件: %s)", r.config.Server.TrustedCIDRFile)
	}
	if r.dnsRewriter.HasRules() {
		utils.WriteLog(utils.LogInfo, "🔄 DNS重写器: 已启用 (%d条规则)", len(r.config.Rewrite))
	}
	if r.config.Server.Features.HijackProtection {
		utils.WriteLog(utils.LogInfo, "🛡️ DNS劫持预防: 已启用")
	}
	if defaultECS := r.ednsManager.GetDefaultECS(); defaultECS != nil {
		utils.WriteLog(utils.LogInfo, "🌍 默认ECS: %s/%d", defaultECS.Address, defaultECS.SourcePrefix)
	}
	if r.ednsManager.IsPaddingEnabled() {
		utils.WriteLog(utils.LogInfo, "📦 DNS Padding: 已启用")
	}

	// 添加路由检测功能状态的显示
	if len(r.config.Speedtest) > 0 {
		utils.WriteLog(utils.LogInfo, "📍 速度测试: 已启用")
	} else {
		utils.WriteLog(utils.LogInfo, "📍 速度测试: 未启用")
	}

	utils.WriteLog(utils.LogInfo, "⚡ 最大并发: %d", MaxGlobalConcurrency)
}
