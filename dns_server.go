package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

// ==================== 主DNS递归服务器 ====================

type RecursiveDNSServer struct {
	config           *ServerConfig
	cache            DNSCache
	rootServersV4    []string
	rootServersV6    []string
	connectionPool   *ConnectionPoolManager
	dnssecValidator  *DNSSECValidator
	concurrencyLimit chan struct{}
	ctx              context.Context
	cancel           context.CancelFunc
	shutdown         chan struct{}
	ipFilter         *IPFilter
	dnsRewriter      *DNSRewriter
	upstreamManager  *UpstreamManager
	wg               sync.WaitGroup
	taskManager      *TaskManager
	hijackPrevention *DNSHijackPrevention
	ednsManager      *EDNSManager
	queryClient      *UnifiedQueryClient
	secureDNSManager *SecureDNSManager
	closed           int32
}

func (r *RecursiveDNSServer) QueryForRefresh(question dns.Question, ecs *ECSOption, serverDNSSECEnabled bool) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, error) {
	defer handlePanicWithContext("缓存刷新查询", nil)

	if atomic.LoadInt32(&r.closed) != 0 {
		return nil, nil, nil, false, nil, errors.New("🔒 服务器已关闭")
	}

	refreshCtx, cancel := context.WithTimeout(r.ctx, ExtendedQueryTimeout)
	defer cancel()

	servers := r.upstreamManager.GetServers()
	if len(servers) > 0 {
		return r.queryUpstreamServers(question, ecs, serverDNSSECEnabled, nil)
	} else {
		return r.resolveWithCNAME(refreshCtx, question, ecs, nil)
	}
}

func NewDNSServer(config *ServerConfig) (*RecursiveDNSServer, error) {
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

	ednsManager, err := NewEDNSManager(config.Server.DefaultECS, config.Server.Features.Padding)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("🌍 EDNS管理器初始化失败: %w", err)
	}

	ipFilter := NewIPFilter()
	if config.Server.TrustedCIDRFile != "" {
		if err := ipFilter.LoadCIDRs(config.Server.TrustedCIDRFile); err != nil {
			cancel()
			return nil, fmt.Errorf("🌍 加载可信CIDR文件失败: %w", err)
		}
	}

	dnsRewriter := NewDNSRewriter()
	if len(config.Rewrite) > 0 {
		if err := dnsRewriter.LoadRules(config.Rewrite); err != nil {
			cancel()
			return nil, fmt.Errorf("🔄 加载DNS重写规则失败: %w", err)
		}
	}

	upstreamManager := NewUpstreamManager(config.Upstream)
	connectionPool := NewConnectionPoolManager()
	taskManager := NewTaskManager(MaxGlobalConcurrency)
	queryClient := NewUnifiedQueryClient(connectionPool, StandardQueryTimeout)
	hijackPrevention := NewDNSHijackPrevention(config.Server.Features.HijackProtection)

	server := &RecursiveDNSServer{
		config:           config,
		rootServersV4:    rootServersV4,
		rootServersV6:    rootServersV6,
		connectionPool:   connectionPool,
		dnssecValidator:  NewDNSSECValidator(),
		concurrencyLimit: make(chan struct{}, MaxGlobalConcurrency),
		ctx:              ctx,
		cancel:           cancel,
		shutdown:         make(chan struct{}),
		ipFilter:         ipFilter,
		dnsRewriter:      dnsRewriter,
		upstreamManager:  upstreamManager,
		taskManager:      taskManager,
		hijackPrevention: hijackPrevention,
		ednsManager:      ednsManager,
		queryClient:      queryClient,
	}

	if config.Server.TLS.CertFile != "" && config.Server.TLS.KeyFile != "" {
		secureDNSManager, err := NewSecureDNSManager(server, config)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("🔐 安全DNS管理器初始化失败: %w", err)
		}
		server.secureDNSManager = secureDNSManager
	}

	var cache DNSCache
	if config.Redis.Address == "" {
		cache = NewNullCache()
	} else {
		redisCache, err := NewRedisDNSCache(config, server)
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
		defer handlePanicWithContext("信号处理器", nil)

		select {
		case sig := <-sigChan:
			writeLog(LogInfo, "🛑 收到信号 %v，开始优雅关闭...", sig)
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

	writeLog(LogInfo, "🛑 开始关闭DNS服务器...")

	if r.cancel != nil {
		r.cancel()
	}

	if r.cache != nil {
		r.cache.Shutdown()
	}

	if r.secureDNSManager != nil {
		if err := r.secureDNSManager.Shutdown(); err != nil {
			writeLog(LogError, "💥 安全DNS管理器关闭失败: %v", err)
		}
	}

	if r.connectionPool != nil {
		if err := r.connectionPool.Close(); err != nil {
			writeLog(LogError, "💥 连接池关闭失败: %v", err)
		}
	}

	if r.taskManager != nil {
		if err := r.taskManager.Shutdown(GracefulShutdownTimeout); err != nil {
			writeLog(LogError, "💥 任务管理器关闭失败: %v", err)
		}
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		r.wg.Wait()
	}()

	select {
	case <-done:
		writeLog(LogInfo, "✅ 所有组件已安全关闭")
	case <-time.After(GracefulShutdownTimeout):
		writeLog(LogWarn, "⏰ 组件关闭超时")
	}

	if r.shutdown != nil {
		close(r.shutdown)
	}

	time.Sleep(100 * time.Millisecond)
	os.Exit(0)
}

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

	writeLog(LogInfo, "🚀 启动 ZJDNS Server")
	writeLog(LogInfo, "🌐 监听端口: %s", r.config.Server.Port)

	r.displayInfo()

	wg.Add(serverCount)

	// 启动UDP服务器
	go func() {
		defer wg.Done()
		defer handlePanicWithContext("关键-UDP服务器", nil)
		server := &dns.Server{
			Addr:    ":" + r.config.Server.Port,
			Net:     "udp",
			Handler: dns.HandlerFunc(r.handleDNSRequest),
			UDPSize: ClientUDPBufferSizeBytes,
		}
		writeLog(LogInfo, "📡 UDP服务器启动: [::]:%s", r.config.Server.Port)
		if err := server.ListenAndServe(); err != nil {
			errChan <- fmt.Errorf("📡 UDP启动失败: %w", err)
		}
	}()

	// 启动TCP服务器
	go func() {
		defer wg.Done()
		defer handlePanicWithContext("关键-TCP服务器", nil)
		server := &dns.Server{
			Addr:    ":" + r.config.Server.Port,
			Net:     "tcp",
			Handler: dns.HandlerFunc(r.handleDNSRequest),
		}
		writeLog(LogInfo, "🔌 TCP服务器启动: [::]:%s", r.config.Server.Port)
		if err := server.ListenAndServe(); err != nil {
			errChan <- fmt.Errorf("🔌 TCP启动失败: %w", err)
		}
	}()

	// 启动安全DNS服务器
	if r.secureDNSManager != nil {
		go func() {
			defer wg.Done()
			defer handlePanicWithContext("关键-安全DNS服务器", nil)
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
				writeLog(LogInfo, "🔗 上游服务器: 🔄 递归解析 - %s", server.Policy)
			} else {
				protocol := strings.ToUpper(server.Protocol)
				emoji := getProtocolEmoji(server.Protocol)
				if protocol == "" {
					protocol = "UDP"
					emoji = "📡"
				}
				serverInfo := fmt.Sprintf("%s %s (%s) - %s", emoji, server.Address, protocol, server.Policy)
				if server.SkipTLSVerify && isSecureProtocol(strings.ToLower(server.Protocol)) {
					serverInfo += " [跳过TLS验证]"
				}
				writeLog(LogInfo, "🔗 上游服务器: %s", serverInfo)
			}
		}
		writeLog(LogInfo, "🔗 上游模式: 共 %d 个服务器", len(servers))
	} else {
		if r.config.Redis.Address == "" {
			writeLog(LogInfo, "🚫 递归模式 (无缓存)")
		} else {
			writeLog(LogInfo, "💾 递归模式 + Redis缓存: %s", r.config.Redis.Address)
		}
	}

	if r.secureDNSManager != nil {
		writeLog(LogInfo, "🔐 监听安全DNS协议端口: %s (DoT/DoQ)", r.config.Server.TLS.Port)

		httpsPort := r.config.Server.TLS.HTTPS.Port
		if httpsPort != "" {
			endpoint := r.config.Server.TLS.HTTPS.Endpoint
			if endpoint == "" {
				endpoint = strings.TrimPrefix(DefaultDNSQueryPath, "/")
			}
			writeLog(LogInfo, "🌐 监听安全DNS协议端口: %s (DoH/DoH3, 端点: %s)", httpsPort, endpoint)
		}
	}

	if r.ipFilter.HasData() {
		writeLog(LogInfo, "🌍 IP过滤器: 已启用 (配置文件: %s)", r.config.Server.TrustedCIDRFile)
	}
	if r.dnsRewriter.HasRules() {
		writeLog(LogInfo, "🔄 DNS重写器: 已启用 (%d条规则)", len(r.config.Rewrite))
	}
	if r.config.Server.Features.HijackProtection {
		writeLog(LogInfo, "🛡️ DNS劫持预防: 已启用")
	}
	if defaultECS := r.ednsManager.GetDefaultECS(); defaultECS != nil {
		writeLog(LogInfo, "🌍 默认ECS: %s/%d", defaultECS.Address, defaultECS.SourcePrefix)
	}
	if r.ednsManager.IsPaddingEnabled() {
		writeLog(LogInfo, "📦 DNS Padding: 已启用")
	}

	writeLog(LogInfo, "⚡ 最大并发: %d", MaxGlobalConcurrency)
}

func (r *RecursiveDNSServer) handleDNSRequest(w dns.ResponseWriter, req *dns.Msg) {
	err := executeWithRecovery("DNS请求处理", func() error {
		select {
		case <-r.ctx.Done():
			return nil
		default:
		}

		response := r.ProcessDNSQuery(req, GetClientIP(w), false)
		if response != nil {
			return w.WriteMsg(response)
		}
		return nil
	}, nil)
	if err != nil {
		writeLog(LogError, "💥 DNS请求处理失败: %v", err)
	}
}

func (r *RecursiveDNSServer) ProcessDNSQuery(req *dns.Msg, clientIP net.IP, isSecureConnection bool) *dns.Msg {
	if atomic.LoadInt32(&r.closed) != 0 {
		msg := r.buildResponse(req)
		if msg != nil {
			msg.Rcode = dns.RcodeServerFailure
		}
		return msg
	}

	if req == nil {
		msg := &dns.Msg{}
		msg.SetReply(&dns.Msg{})
		msg.Rcode = dns.RcodeFormatError
		return msg
	}

	if len(req.Question) == 0 {
		msg := &dns.Msg{}
		if len(req.Question) > 0 {
			msg.SetReply(req)
		} else {
			msg.Response = true
		}
		msg.Rcode = dns.RcodeFormatError
		return msg
	}

	question := req.Question[0]
	if len(question.Name) > MaxDomainNameLengthRFC {
		msg := &dns.Msg{}
		msg.SetReply(req)
		msg.Rcode = dns.RcodeFormatError
		return msg
	}

	var tracker *RequestTracker
	if GetLogLevel() >= LogDebug {
		clientIPStr := "unknown"
		if clientIP != nil {
			clientIPStr = clientIP.String()
		}
		tracker = NewRequestTracker(
			question.Name,
			dns.TypeToString[question.Qtype],
			clientIPStr,
		)
		if tracker != nil {
			defer tracker.Finish()
		}
	}

	if tracker != nil {
		tracker.AddStep("🚀 开始处理查询: %s %s", question.Name, dns.TypeToString[question.Qtype])
		if isSecureConnection {
			tracker.AddStep("🔐 安全连接查询，将启用DNS Padding")
		}
	}

	// DNS重写处理
	if r.dnsRewriter.HasRules() {
		if rewritten, changed := r.dnsRewriter.Rewrite(question.Name, question.Qtype); changed {
			if tracker != nil {
				tracker.AddStep("🔄 域名重写: %s -> %s", question.Name, rewritten)
			}

			// 如果重写结果是IP地址，则直接返回IP响应
			if ip := net.ParseIP(strings.TrimSuffix(rewritten, ".")); ip != nil {
				return r.createDirectIPResponse(req, question.Qtype, ip, tracker)
			}

			// 否则更新问题域名继续处理
			question.Name = rewritten
		}
	}

	// 检查是否为DDR查询
	if IsDDRQuery(req, r.config.Server.DDR.Domain, r.config.Server.Port) {
		// 检查是否满足DDR功能启用条件
		// 需要配置域名，且至少配置一个IP地址（IPv4或IPv6）
		if r.config.Server.DDR.Domain != "" &&
			(r.config.Server.DDR.IPv4 != "" || r.config.Server.DDR.IPv6 != "") {
			if tracker != nil {
				tracker.AddStep("🔍 检测到DDR查询")
			}

			// 创建DDR记录生成器
			var ipv4Addr, ipv6Addr net.IP
			if r.config.Server.DDR.IPv4 != "" {
				ipv4Addr = net.ParseIP(r.config.Server.DDR.IPv4)
			}
			if r.config.Server.DDR.IPv6 != "" {
				ipv6Addr = net.ParseIP(r.config.Server.DDR.IPv6)
			}

			// 创建DDR记录生成器
			ddrGenerator := NewDDRRecordGenerator(r.config.Server.DDR.Domain, ipv4Addr, ipv6Addr)
			
			response := ddrGenerator.CreateDDRResponse(req, r.config)

			if tracker != nil {
				tracker.AddStep("✅ 生成DDR响应: %d条记录", len(response.Answer))
			}

			return response
		}
	}

	// IP地址直接响应
	if ip := net.ParseIP(strings.TrimSuffix(question.Name, ".")); ip != nil {
		return r.createDirectIPResponse(req, question.Qtype, ip, tracker)
	}

	clientRequestedDNSSEC := false
	clientHasEDNS := false
	var ecsOpt *ECSOption

	// 使用 IsEdns0() 自动处理 nil Extra 的情况
	if opt := req.IsEdns0(); opt != nil {
		clientHasEDNS = true
		clientRequestedDNSSEC = opt.Do()
		ecsOpt = r.ednsManager.ParseFromDNS(req)
		if tracker != nil && ecsOpt != nil {
			tracker.AddStep("🌍 客户端ECS: %s/%d", ecsOpt.Address, ecsOpt.SourcePrefix)
		}
	}

	if ecsOpt == nil {
		ecsOpt = r.ednsManager.GetDefaultECS()
		if tracker != nil && ecsOpt != nil {
			tracker.AddStep("🌍 使用默认ECS: %s/%d", ecsOpt.Address, ecsOpt.SourcePrefix)
		}
	}

	serverDNSSECEnabled := r.config.Server.Features.DNSSEC
	cacheKey := globalCacheUtils.BuildKey(question, ecsOpt, serverDNSSECEnabled)

	if tracker != nil {
		tracker.AddStep("🔑 缓存键: %s", cacheKey)
	}

	if entry, found, isExpired := r.cache.Get(cacheKey); found {
		return r.processCacheHit(req, entry, isExpired, question, clientRequestedDNSSEC, clientHasEDNS, ecsOpt, cacheKey, tracker, isSecureConnection)
	}

	if tracker != nil {
		tracker.AddStep("❌ 缓存未命中，开始查询")
	}
	return r.processCacheMiss(req, question, ecsOpt, clientRequestedDNSSEC, clientHasEDNS, serverDNSSECEnabled, cacheKey, tracker, isSecureConnection)
}

func (r *RecursiveDNSServer) buildResponse(req *dns.Msg) *dns.Msg {
	msg := globalResourceManager.GetDNSMessage()
	if msg == nil {
		msg = &dns.Msg{}
	}

	if req != nil {
		if len(req.Question) > 0 {
			if msg.Question == nil {
				msg.Question = make([]dns.Question, 0, len(req.Question))
			}
			msg.SetReply(req)
		} else {
			msg.Response = true
			msg.Rcode = dns.RcodeFormatError
		}
	}

	msg.Authoritative = false
	msg.RecursionAvailable = true
	return msg
}

func (r *RecursiveDNSServer) createDirectIPResponse(req *dns.Msg, qtype uint16, ip net.IP, tracker *RequestTracker) *dns.Msg {
	if tracker != nil {
		tracker.AddStep("🎯 创建直接IP响应: %s", ip.String())
	}

	msg := r.buildResponse(req)

	// 根据查询类型和IP地址类型返回相应记录
	if qtype == dns.TypeA && ip.To4() != nil {
		// IPv4地址查询
		msg.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{
				Name:   req.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    uint32(DefaultCacheTTLSeconds),
			},
			A: ip,
		}}
	} else if qtype == dns.TypeAAAA && ip.To4() == nil {
		// IPv6地址查询
		msg.Answer = []dns.RR{&dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   req.Question[0].Name,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    uint32(DefaultCacheTTLSeconds),
			},
			AAAA: ip,
		}}
	}
	// 对于IPv4地址查询但得到IPv6地址，或IPv6地址查询但得到IPv4地址的情况，返回空答案

	return msg
}

func (r *RecursiveDNSServer) processCacheHit(req *dns.Msg, entry *CacheEntry, isExpired bool,
	question dns.Question, clientRequestedDNSSEC bool, clientHasEDNS bool, ecsOpt *ECSOption,
	cacheKey string, tracker *RequestTracker, isSecureConnection bool) *dns.Msg {

	responseTTL := entry.GetRemainingTTL()

	if tracker != nil {
		tracker.CacheHit = true
		if isExpired {
			tracker.AddStep("🎯 缓存命中(过期): TTL=%ds", responseTTL)
		} else {
			tracker.AddStep("🎯 缓存命中: TTL=%ds", responseTTL)
		}
	}

	msg := r.buildResponse(req)
	if msg == nil {
		msg = &dns.Msg{}
		msg.SetReply(req)
		msg.Rcode = dns.RcodeServerFailure
		return msg
	}

	msg.Answer = globalRecordHandler.ProcessRecords(globalRecordHandler.ExpandRecords(entry.Answer), responseTTL, clientRequestedDNSSEC)
	msg.Ns = globalRecordHandler.ProcessRecords(globalRecordHandler.ExpandRecords(entry.Authority), responseTTL, clientRequestedDNSSEC)
	msg.Extra = globalRecordHandler.ProcessRecords(globalRecordHandler.ExpandRecords(entry.Additional), responseTTL, clientRequestedDNSSEC)

	if r.config.Server.Features.DNSSEC && entry.Validated {
		msg.AuthenticatedData = true
		if tracker != nil {
			tracker.AddStep("🔐 设置AD标志: 缓存记录已验证")
		}
	}

	responseECS := entry.GetECSOption()
	if responseECS == nil {
		responseECS = ecsOpt
	}

	shouldAddEDNS := clientHasEDNS || responseECS != nil || r.ednsManager.IsPaddingEnabled() ||
		(clientRequestedDNSSEC && r.config.Server.Features.DNSSEC)

	if shouldAddEDNS {
		r.ednsManager.AddToMessage(msg, responseECS, clientRequestedDNSSEC && r.config.Server.Features.DNSSEC, isSecureConnection)
		if tracker != nil && responseECS != nil {
			tracker.AddStep("🌍 添加响应ECS: %s/%d", responseECS.Address, responseECS.SourcePrefix)
		}
	}

	if isExpired && r.config.Server.Features.ServeStale && r.config.Server.Features.Prefetch && entry.ShouldRefresh() {
		if tracker != nil {
			tracker.AddStep("🔄 启动后台预取刷新")
		}
		r.cache.RequestRefresh(RefreshRequest{
			Question:            question,
			ECS:                 ecsOpt,
			CacheKey:            cacheKey,
			ServerDNSSECEnabled: r.config.Server.Features.DNSSEC,
		})
	}

	r.restoreOriginalDomain(msg, req.Question[0].Name, question.Name)
	return msg
}

func (r *RecursiveDNSServer) processCacheMiss(req *dns.Msg, question dns.Question, ecsOpt *ECSOption,
	clientRequestedDNSSEC bool, clientHasEDNS bool, serverDNSSECEnabled bool, cacheKey string,
	tracker *RequestTracker, isSecureConnection bool) *dns.Msg {

	var answer, authority, additional []dns.RR
	var validated bool
	var ecsResponse *ECSOption
	var err error

	servers := r.upstreamManager.GetServers()
	if len(servers) > 0 {
		if tracker != nil {
			tracker.AddStep("🔗 使用上游服务器查询 (%d个可用)", len(servers))
		}
		answer, authority, additional, validated, ecsResponse, err = r.queryUpstreamServers(
			question, ecsOpt, serverDNSSECEnabled, tracker)
	} else {
		if tracker != nil {
			tracker.AddStep("🔄 使用递归解析")
		}
		ctx, cancel := context.WithTimeout(r.ctx, RecursiveQueryTimeout)
		defer cancel()
		answer, authority, additional, validated, ecsResponse, err = r.resolveWithCNAME(ctx, question, ecsOpt, tracker)
	}

	if err != nil {
		return r.processQueryError(req, err, cacheKey, question, clientRequestedDNSSEC,
			clientHasEDNS, ecsOpt, tracker, isSecureConnection)
	}

	return r.processQuerySuccess(req, question, ecsOpt, clientRequestedDNSSEC, clientHasEDNS, cacheKey,
		answer, authority, additional, validated, ecsResponse, tracker, isSecureConnection)
}

func (r *RecursiveDNSServer) processQueryError(req *dns.Msg, err error, cacheKey string,
	question dns.Question, clientRequestedDNSSEC bool, clientHasEDNS bool, ecsOpt *ECSOption,
	tracker *RequestTracker, isSecureConnection bool) *dns.Msg {

	if tracker != nil {
		tracker.AddStep("💥 查询失败: %v", err)
	}

	if r.config.Server.Features.ServeStale {
		if entry, found, _ := r.cache.Get(cacheKey); found {
			if tracker != nil {
				tracker.AddStep("🔙 使用过期缓存回退")
			}

			responseTTL := uint32(StaleTTLSeconds)
			msg := r.buildResponse(req)
			if msg == nil {
				msg = &dns.Msg{}
				msg.SetReply(req)
				msg.Rcode = dns.RcodeServerFailure
				return msg
			}

			msg.Answer = globalRecordHandler.ProcessRecords(globalRecordHandler.ExpandRecords(entry.Answer), responseTTL, clientRequestedDNSSEC)
			msg.Ns = globalRecordHandler.ProcessRecords(globalRecordHandler.ExpandRecords(entry.Authority), responseTTL, clientRequestedDNSSEC)
			msg.Extra = globalRecordHandler.ProcessRecords(globalRecordHandler.ExpandRecords(entry.Additional), responseTTL, clientRequestedDNSSEC)

			if r.config.Server.Features.DNSSEC && entry.Validated {
				msg.AuthenticatedData = true
			}

			responseECS := entry.GetECSOption()
			if responseECS == nil {
				responseECS = ecsOpt
			}

			shouldAddEDNS := clientHasEDNS || responseECS != nil || r.ednsManager.IsPaddingEnabled() ||
				(clientRequestedDNSSEC && r.config.Server.Features.DNSSEC)

			if shouldAddEDNS {
				r.ednsManager.AddToMessage(msg, responseECS, clientRequestedDNSSEC && r.config.Server.Features.DNSSEC, isSecureConnection)
			}

			r.restoreOriginalDomain(msg, req.Question[0].Name, question.Name)
			return msg
		}
	}

	msg := r.buildResponse(req)
	if msg == nil {
		msg = &dns.Msg{}
		msg.SetReply(req)
	}
	msg.Rcode = dns.RcodeServerFailure
	return msg
}

func (r *RecursiveDNSServer) processQuerySuccess(req *dns.Msg, question dns.Question, ecsOpt *ECSOption,
	clientRequestedDNSSEC bool, clientHasEDNS bool, cacheKey string,
	answer, authority, additional []dns.RR, validated bool, ecsResponse *ECSOption,
	tracker *RequestTracker, isSecureConnection bool) *dns.Msg {

	if tracker != nil {
		tracker.AddStep("✅ 查询成功: 答案=%d, 授权=%d, 附加=%d", len(answer), len(authority), len(additional))
		if validated {
			tracker.AddStep("🔐 DNSSEC验证通过")
		}
	}

	msg := r.buildResponse(req)
	if msg == nil {
		msg = &dns.Msg{}
		msg.SetReply(req)
	}

	if r.config.Server.Features.DNSSEC && validated {
		msg.AuthenticatedData = true
		if tracker != nil {
			tracker.AddStep("🔐 设置AD标志: 查询结果已验证")
		}
	}

	responseECS := ecsResponse
	if responseECS == nil && ecsOpt != nil {
		responseECS = &ECSOption{
			Family:       ecsOpt.Family,
			SourcePrefix: ecsOpt.SourcePrefix,
			ScopePrefix:  ecsOpt.ScopePrefix,
			Address:      ecsOpt.Address,
		}
	}

	r.cache.Set(cacheKey, answer, authority, additional, validated, responseECS)

	msg.Answer = globalRecordHandler.ProcessRecords(answer, 0, clientRequestedDNSSEC)
	msg.Ns = globalRecordHandler.ProcessRecords(authority, 0, clientRequestedDNSSEC)
	msg.Extra = globalRecordHandler.ProcessRecords(additional, 0, clientRequestedDNSSEC)

	shouldAddEDNS := clientHasEDNS || responseECS != nil || r.ednsManager.IsPaddingEnabled() ||
		(clientRequestedDNSSEC && r.config.Server.Features.DNSSEC)

	if shouldAddEDNS {
		r.ednsManager.AddToMessage(msg, responseECS, clientRequestedDNSSEC && r.config.Server.Features.DNSSEC, isSecureConnection)
		if tracker != nil && responseECS != nil {
			tracker.AddStep("🌍 添加响应ECS: %s/%d", responseECS.Address, responseECS.SourcePrefix)
		}
	}

	r.restoreOriginalDomain(msg, req.Question[0].Name, question.Name)
	return msg
}

func (r *RecursiveDNSServer) restoreOriginalDomain(msg *dns.Msg, currentName, originalName string) {
	if msg == nil {
		return
	}

	for _, rr := range msg.Answer {
		if rr != nil && strings.EqualFold(rr.Header().Name, currentName) {
			rr.Header().Name = originalName
		}
	}
}

func (r *RecursiveDNSServer) queryUpstreamServers(question dns.Question, ecs *ECSOption,
	serverDNSSECEnabled bool, tracker *RequestTracker) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, error) {

	servers := r.upstreamManager.GetServers()
	if len(servers) == 0 {
		return nil, nil, nil, false, nil, errors.New("❌ 没有可用的上游服务器")
	}

	result, err := r.executeConcurrentQueries(r.ctx, question, ecs, serverDNSSECEnabled,
		servers, SingleQueryMaxConcurrency, tracker)
	if err != nil {
		return nil, nil, nil, false, nil, err
	}

	var ecsResponse *ECSOption
	if result.Response != nil {
		ecsResponse = r.ednsManager.ParseFromDNS(result.Response)
	}

	return result.Response.Answer, result.Response.Ns, result.Response.Extra,
		result.Validated, ecsResponse, nil
}

func (r *RecursiveDNSServer) executeConcurrentQueries(ctx context.Context, question dns.Question, ecs *ECSOption, serverDNSSECEnabled bool,
	servers []*UpstreamServer, maxConcurrency int, tracker *RequestTracker) (*QueryResult, error) {

	if len(servers) == 0 {
		return nil, errors.New("❌ 没有可用的服务器")
	}

	if tracker != nil {
		tracker.AddStep("🚀 开始并发查询 %d 个服务器", len(servers))
	}

	concurrency := len(servers)
	if maxConcurrency > 0 && concurrency > maxConcurrency {
		concurrency = maxConcurrency
	}

	resultChan := make(chan *QueryResult, concurrency)

	for i := 0; i < concurrency && i < len(servers); i++ {
		server := servers[i]
		msg := r.buildQueryMessage(question, ecs, serverDNSSECEnabled, true, false)
		defer globalResourceManager.PutDNSMessage(msg)

		r.taskManager.ExecuteAsync(fmt.Sprintf("ConcurrentQuery-%s", server.Address),
			func(ctx context.Context) error {
				result := r.queryClient.ExecuteQuery(ctx, msg, server, tracker)
				select {
				case resultChan <- result:
				case <-ctx.Done():
				}
				return nil
			})
	}

	for i := 0; i < concurrency; i++ {
		select {
		case result := <-resultChan:
			if result.Error == nil && result.Response != nil {
				rcode := result.Response.Rcode
				if rcode == dns.RcodeSuccess || rcode == dns.RcodeNameError {
					if tracker != nil {
						tracker.AddStep("✅ 并发查询成功，选择服务器: %s (%s)", result.Server, result.Protocol)
					}
					return result, nil
				}
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	return nil, errors.New("💥 所有并发查询均失败")
}

func (r *RecursiveDNSServer) buildQueryMessage(question dns.Question, ecs *ECSOption, dnssecEnabled bool, recursionDesired bool, isSecureConnection bool) *dns.Msg {
	msg := globalResourceManager.GetDNSMessage()

	// 确保消息状态正确
	if msg == nil {
		msg = &dns.Msg{}
	}

	// 安全设置问题
	if err := r.safeSetQuestion(msg, question.Name, question.Qtype); err != nil {
		writeLog(LogDebug, "💥 设置DNS问题失败: %v", err)
		msg = &dns.Msg{}
		msg.SetQuestion(dns.Fqdn(question.Name), question.Qtype)
	}

	msg.RecursionDesired = recursionDesired

	if r.ednsManager != nil {
		r.ednsManager.AddToMessage(msg, ecs, dnssecEnabled, isSecureConnection)
	}

	return msg
}

func (r *RecursiveDNSServer) safeSetQuestion(msg *dns.Msg, name string, qtype uint16) error {
	if msg == nil {
		return errors.New("❌ 消息为空")
	}

	if name == "" {
		return errors.New("❌ 域名为空")
	}

	if len(name) > MaxDomainNameLengthRFC {
		return errors.New("📏 域名过长")
	}

	if msg.Question == nil {
		msg.Question = make([]dns.Question, 0, 1)
	}

	defer func() {
		if r := recover(); r != nil {
			writeLog(LogError, "💥 设置DNS问题时发生panic: %v", r)
		}
	}()

	msg.SetQuestion(dns.Fqdn(name), qtype)
	return nil
}
