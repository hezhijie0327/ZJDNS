package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"

	cache_pkg "zjdns/cache"
	"zjdns/network"
	"zjdns/types"
	"zjdns/utils"

	"github.com/miekg/dns"
)

// handleDNSRequest 处理DNS请求
func (r *RecursiveDNSServer) handleDNSRequest(w dns.ResponseWriter, req *dns.Msg) {
	defer func() { utils.HandlePanicWithContext("DNS请求处理") }()

	select {
	case <-r.ctx.Done():
		return
	default:
	}

	response := r.ProcessDNSQuery(req, utils.GetClientIP(w), false)
	if response != nil {
		response.Compress = true
		_ = w.WriteMsg(response)
	}
}

func (r *RecursiveDNSServer) handleSuspiciousResponse(reason string, currentlyTCP bool, tracker *utils.RequestTracker) ([]dns.RR, []dns.RR, []dns.RR, bool, *utils.ECSOption, error) {

	if !currentlyTCP {
		if tracker != nil {
			tracker.AddStep("🛡️ 检测到DNS劫持，将切换到TCP模式: %s", reason)
		}
		return nil, nil, nil, false, nil, fmt.Errorf("DNS_HIJACK_DETECTED: %s", reason)
	} else {
		if tracker != nil {
			tracker.AddStep("🛡️ TCP模式下仍检测到DNS劫持，拒绝响应: %s", reason)
		}
		return nil, nil, nil, false, nil, fmt.Errorf("🛡️ 检测到DNS劫持(TCP模式): %s", reason)
	}
}

// ProcessDNSQuery 处理DNS查询
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

	var tracker *utils.RequestTracker
	if utils.GetLogLevel() >= utils.LogDebug {
		clientIPStr := "unknown"
		if clientIP != nil {
			clientIPStr = clientIP.String()
		}
		tracker = utils.NewRequestTracker(
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
		rewriteResult := r.dnsRewriter.RewriteWithDetails(question.Name, question.Qtype)
		if rewriteResult.ShouldRewrite {
			if tracker != nil {
				tracker.AddStep("🔄 域名重写: %s (QType: %s)", question.Name, dns.TypeToString[question.Qtype])
			}

			// 处理响应码重写
			if rewriteResult.ResponseCode != dns.RcodeSuccess {
				response := r.buildResponse(req)
				response.Rcode = rewriteResult.ResponseCode

				if tracker != nil {
					tracker.AddStep("📛 响应码重写: %d", rewriteResult.ResponseCode)
				}

				return response
			}

			// 处理自定义记录
			if len(rewriteResult.Records) > 0 {
				response := r.buildResponse(req)
				response.Answer = rewriteResult.Records
				response.Rcode = dns.RcodeSuccess

				// 如果有Additional Section记录，则添加到响应中
				if len(rewriteResult.Additional) > 0 {
					response.Extra = rewriteResult.Additional
				}

				if tracker != nil {
					tracker.AddStep("📝 返回自定义记录: %d条 (Answer), %d条 (Additional)",
						len(rewriteResult.Records), len(rewriteResult.Additional))
				}

				return response
			}

			// 处理域名重写
			if rewriteResult.Domain != question.Name {
				if tracker != nil {
					tracker.AddStep("🔄 域名重写: %s -> %s", question.Name, rewriteResult.Domain)
				}

				// 如果重写结果是IP地址，则直接返回IP响应
				if ip := net.ParseIP(strings.TrimSuffix(rewriteResult.Domain, ".")); ip != nil {
					return r.createDirectIPResponse(req, question.Qtype, ip, tracker)
				}

				// 否则更新问题域名继续处理
				question.Name = rewriteResult.Domain
			}
		}
	}

	// IP地址直接响应
	if ip := net.ParseIP(strings.TrimSuffix(question.Name, ".")); ip != nil {
		return r.createDirectIPResponse(req, question.Qtype, ip, tracker)
	}

	clientRequestedDNSSEC := false
	clientHasEDNS := false
	var ecsOpt *utils.ECSOption

	// 使用 IsEdns0() 自动处理 nil Extra 的情况
	if opt := req.IsEdns0(); opt != nil {
		clientHasEDNS = true
		clientRequestedDNSSEC = opt.Do()
		networkECS := r.ednsManager.ParseFromDNS(req)
		if networkECS != nil {
			ecsOpt = &utils.ECSOption{
				Family:       networkECS.Family,
				SourcePrefix: networkECS.SourcePrefix,
				ScopePrefix:  networkECS.ScopePrefix,
				Address:      networkECS.Address,
			}
		}
		if tracker != nil && ecsOpt != nil {
			tracker.AddStep("🌍 客户端ECS: %s/%d", ecsOpt.Address, ecsOpt.SourcePrefix)
		}
	}

	if ecsOpt == nil {
		networkECS := r.ednsManager.GetDefaultECS()
		if networkECS != nil {
			ecsOpt = &utils.ECSOption{
				Family:       networkECS.Family,
				SourcePrefix: networkECS.SourcePrefix,
				ScopePrefix:  networkECS.ScopePrefix,
				Address:      networkECS.Address,
			}
		}
		if tracker != nil && ecsOpt != nil {
			tracker.AddStep("🌍 使用默认ECS: %s/%d", ecsOpt.Address, ecsOpt.SourcePrefix)
		}
	}

	serverDNSSECEnabled := r.config.Server.Features.DNSSEC
	cacheKey := utils.GlobalCacheUtils.BuildKey(question, ecsOpt, serverDNSSECEnabled)

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

func (r *RecursiveDNSServer) processCacheHit(req *dns.Msg, entry *CacheEntry, isExpired bool,
	question dns.Question, clientRequestedDNSSEC bool, clientHasEDNS bool, ecsOpt *utils.ECSOption,
	cacheKey string, tracker *utils.RequestTracker, isSecureConnection bool) *dns.Msg {

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

	// 将cache.CompactDNSRecord转换为utils.CompactDNSRecord
	answerRecords := make([]*utils.CompactDNSRecord, len(entry.Answer))
	authorityRecords := make([]*utils.CompactDNSRecord, len(entry.Authority))
	additionalRecords := make([]*utils.CompactDNSRecord, len(entry.Additional))

	for i, record := range entry.Answer {
		answerRecords[i] = &utils.CompactDNSRecord{
			Text:    record.Text,
			OrigTTL: record.OrigTTL,
			Type:    record.Type,
		}
	}

	for i, record := range entry.Authority {
		authorityRecords[i] = &utils.CompactDNSRecord{
			Text:    record.Text,
			OrigTTL: record.OrigTTL,
			Type:    record.Type,
		}
	}

	for i, record := range entry.Additional {
		additionalRecords[i] = &utils.CompactDNSRecord{
			Text:    record.Text,
			OrigTTL: record.OrigTTL,
			Type:    record.Type,
		}
	}

	msg.Answer = utils.GlobalRecordHandler.ProcessRecords(utils.GlobalRecordHandler.ExpandRecords(answerRecords), responseTTL, clientRequestedDNSSEC)
	msg.Ns = utils.GlobalRecordHandler.ProcessRecords(utils.GlobalRecordHandler.ExpandRecords(authorityRecords), responseTTL, clientRequestedDNSSEC)
	msg.Extra = utils.GlobalRecordHandler.ProcessRecords(utils.GlobalRecordHandler.ExpandRecords(additionalRecords), responseTTL, clientRequestedDNSSEC)

	if r.config.Server.Features.DNSSEC && entry.Validated {
		msg.AuthenticatedData = true
		if tracker != nil {
			tracker.AddStep("🔐 设置AD标志: 缓存记录已验证")
		}
	}

	var responseECS *network.ECSOption
	cacheECS := entry.GetECSOption()
	if cacheECS != nil {
		// 将cache.ECSOption转换为network.ECSOption
		responseECS = &network.ECSOption{
			Family:       cacheECS.Family,
			SourcePrefix: cacheECS.SourcePrefix,
			ScopePrefix:  cacheECS.ScopePrefix,
			Address:      cacheECS.Address,
		}
	} else if ecsOpt != nil {
		// 将utils.ECSOption转换为network.ECSOption
		responseECS = &network.ECSOption{
			Family:       ecsOpt.Family,
			SourcePrefix: ecsOpt.SourcePrefix,
			ScopePrefix:  ecsOpt.ScopePrefix,
			Address:      ecsOpt.Address,
		}
	}

	shouldAddEDNS := clientHasEDNS || responseECS != nil || r.ednsManager.IsPaddingEnabled() ||
		(clientRequestedDNSSEC && r.config.Server.Features.DNSSEC)

	if shouldAddEDNS {
		// 将utils.ECSOption转换为network.ECSOption
		var networkECS *network.ECSOption
		if responseECS != nil {
			networkECS = &network.ECSOption{
				Family:       responseECS.Family,
				SourcePrefix: responseECS.SourcePrefix,
				ScopePrefix:  responseECS.ScopePrefix,
				Address:      responseECS.Address,
			}
		}

		r.ednsManager.AddToMessage(msg, networkECS, clientRequestedDNSSEC && r.config.Server.Features.DNSSEC, isSecureConnection)
		if tracker != nil && responseECS != nil {
			tracker.AddStep("🌍 添加响应ECS: %s/%d", responseECS.Address, responseECS.SourcePrefix)
		}
	}

	if isExpired && r.config.Server.Features.ServeStale && r.config.Server.Features.Prefetch && entry.ShouldRefresh() {
		if tracker != nil {
			tracker.AddStep("🔄 启动后台预取刷新")
		}
		// 将utils.ECSOption转换为cache.ECSOption
		var cacheECS *cache_pkg.ECSOption
		if ecsOpt != nil {
			cacheECS = &cache_pkg.ECSOption{
				Family:       ecsOpt.Family,
				SourcePrefix: ecsOpt.SourcePrefix,
				ScopePrefix:  ecsOpt.ScopePrefix,
				Address:      ecsOpt.Address,
			}
		}

		r.cache.RequestRefresh(cache_pkg.RefreshRequest{
			Question:            question,
			ECS:                 cacheECS,
			CacheKey:            cacheKey,
			ServerDNSSECEnabled: r.config.Server.Features.DNSSEC,
		})
	}

	r.restoreOriginalDomain(msg, req.Question[0].Name, question.Name)
	return msg
}

func (r *RecursiveDNSServer) processCacheMiss(req *dns.Msg, question dns.Question, ecsOpt *utils.ECSOption,
	clientRequestedDNSSEC bool, clientHasEDNS bool, serverDNSSECEnabled bool, cacheKey string,
	tracker *utils.RequestTracker, isSecureConnection bool) *dns.Msg {

	var answer, authority, additional []dns.RR
	var validated bool
	var ecsResponse *utils.ECSOption
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
	question dns.Question, clientRequestedDNSSEC bool, clientHasEDNS bool, ecsOpt *utils.ECSOption,
	tracker *utils.RequestTracker, isSecureConnection bool) *dns.Msg {

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

			// 将cache.CompactDNSRecord转换为utils.CompactDNSRecord
			answerRecords := make([]*utils.CompactDNSRecord, len(entry.Answer))
			authorityRecords := make([]*utils.CompactDNSRecord, len(entry.Authority))
			additionalRecords := make([]*utils.CompactDNSRecord, len(entry.Additional))

			for i, record := range entry.Answer {
				answerRecords[i] = &utils.CompactDNSRecord{
					Text:    record.Text,
					OrigTTL: record.OrigTTL,
					Type:    record.Type,
				}
			}

			for i, record := range entry.Authority {
				authorityRecords[i] = &utils.CompactDNSRecord{
					Text:    record.Text,
					OrigTTL: record.OrigTTL,
					Type:    record.Type,
				}
			}

			for i, record := range entry.Additional {
				additionalRecords[i] = &utils.CompactDNSRecord{
					Text:    record.Text,
					OrigTTL: record.OrigTTL,
					Type:    record.Type,
				}
			}

			msg.Answer = utils.GlobalRecordHandler.ProcessRecords(utils.GlobalRecordHandler.ExpandRecords(answerRecords), responseTTL, clientRequestedDNSSEC)
			msg.Ns = utils.GlobalRecordHandler.ProcessRecords(utils.GlobalRecordHandler.ExpandRecords(authorityRecords), responseTTL, clientRequestedDNSSEC)
			msg.Extra = utils.GlobalRecordHandler.ProcessRecords(utils.GlobalRecordHandler.ExpandRecords(additionalRecords), responseTTL, clientRequestedDNSSEC)

			if r.config.Server.Features.DNSSEC && entry.Validated {
				msg.AuthenticatedData = true
			}

			var responseECS *network.ECSOption
			cacheECS := entry.GetECSOption()
			if cacheECS != nil {
				// 将cache.ECSOption转换为network.ECSOption
				responseECS = &network.ECSOption{
					Family:       cacheECS.Family,
					SourcePrefix: cacheECS.SourcePrefix,
					ScopePrefix:  cacheECS.ScopePrefix,
					Address:      cacheECS.Address,
				}
			} else if ecsOpt != nil {
				// 将utils.ECSOption转换为network.ECSOption
				responseECS = &network.ECSOption{
					Family:       ecsOpt.Family,
					SourcePrefix: ecsOpt.SourcePrefix,
					ScopePrefix:  ecsOpt.ScopePrefix,
					Address:      ecsOpt.Address,
				}
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

func (r *RecursiveDNSServer) processQuerySuccess(req *dns.Msg, question dns.Question, ecsOpt *utils.ECSOption,
	clientRequestedDNSSEC bool, clientHasEDNS bool, cacheKey string,
	answer, authority, additional []dns.RR, validated bool, ecsResponse *utils.ECSOption,
	tracker *utils.RequestTracker, isSecureConnection bool) *dns.Msg {

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
		responseECS = &utils.ECSOption{
			Family:       ecsOpt.Family,
			SourcePrefix: ecsOpt.SourcePrefix,
			ScopePrefix:  ecsOpt.ScopePrefix,
			Address:      ecsOpt.Address,
		}
	}

	// 将utils.ECSOption转换为types.ECSOption
	var typesECS *types.ECSOption
	if responseECS != nil {
		typesECS = &types.ECSOption{
			Family:       responseECS.Family,
			SourcePrefix: responseECS.SourcePrefix,
			ScopePrefix:  responseECS.ScopePrefix,
			Address:      responseECS.Address,
		}
	}

	r.cache.Set(cacheKey, answer, authority, additional, validated, typesECS)

	msg.Answer = utils.GlobalRecordHandler.ProcessRecords(answer, 0, clientRequestedDNSSEC)
	msg.Ns = utils.GlobalRecordHandler.ProcessRecords(authority, 0, clientRequestedDNSSEC)
	msg.Extra = utils.GlobalRecordHandler.ProcessRecords(additional, 0, clientRequestedDNSSEC)

	// 速度测试：对A和AAAA记录进行测速和排序
	if len(r.config.Speedtest) > 0 {
		utils.WriteLog(utils.LogDebug, "📍 速度测试功能已启用")
		if tracker != nil {
			tracker.AddStep("📍 启用速度测试")
		}

		// 检查是否需要执行速度测试（防抖机制）
		shouldPerformSpeedTest := r.shouldPerformSpeedTest(question.Name)
		if shouldPerformSpeedTest {
			utils.WriteLog(utils.LogDebug, "📍 速度测试: 触发域名 %s 的后台检测", question.Name)
			// 在后台执行速度测试，不影响主响应
			// 克隆消息用于后台处理
			msgCopy := msg.Copy()
			r.taskManager.ExecuteAsync(fmt.Sprintf("speed-test-%s", question.Name), func(ctx context.Context) error {
				utils.WriteLog(utils.LogDebug, "📍 速度测试: 开始后台检测域名 %s", question.Name)
				// 创建临时的SpeedTester实例执行测速
				speedTester := utils.NewSpeedTester(r.config.Speedtest)
				// 执行速度测试和排序
				speedTester.PerformSpeedTestAndSort(msgCopy)

				// 更新缓存中的排序结果
				// 将utils.ECSOption转换为types.ECSOption
				var typesECS *types.ECSOption
				if responseECS != nil {
					typesECS = &types.ECSOption{
						Family:       responseECS.Family,
						SourcePrefix: responseECS.SourcePrefix,
						ScopePrefix:  responseECS.ScopePrefix,
						Address:      responseECS.Address,
					}
				}

				r.cache.Set(cacheKey,
					msgCopy.Answer,
					msgCopy.Ns,
					msgCopy.Extra,
					validated, typesECS)
				utils.WriteLog(utils.LogDebug, "📍 速度测试: 域名 %s 后台检测完成", question.Name)

				return nil
			})

			// 首次响应直接返回，不进行排序
			if tracker != nil {
				tracker.AddStep("⚡ 首次响应不排序，后台进行速度测试")
			}
		} else {
			utils.WriteLog(utils.LogDebug, "📍 速度测试: 域名 %s 被防抖机制跳过", question.Name)
			if tracker != nil {
				tracker.AddStep("⏰ 速度测试跳过（防抖机制）")
			}
		}
	} else {
		utils.WriteLog(utils.LogDebug, "📍 速度测试功能未启用")
	}

	shouldAddEDNS := clientHasEDNS || responseECS != nil || r.ednsManager.IsPaddingEnabled() ||
		(clientRequestedDNSSEC && r.config.Server.Features.DNSSEC)

	if shouldAddEDNS {
		// 将utils.ECSOption转换为network.ECSOption
		var networkECS *network.ECSOption
		if responseECS != nil {
			networkECS = &network.ECSOption{
				Family:       responseECS.Family,
				SourcePrefix: responseECS.SourcePrefix,
				ScopePrefix:  responseECS.ScopePrefix,
				Address:      responseECS.Address,
			}
		}

		r.ednsManager.AddToMessage(msg, networkECS, clientRequestedDNSSEC && r.config.Server.Features.DNSSEC, isSecureConnection)
		if tracker != nil && responseECS != nil {
			tracker.AddStep("🌍 添加响应ECS: %s/%d", responseECS.Address, responseECS.SourcePrefix)
		}
	}

	r.restoreOriginalDomain(msg, req.Question[0].Name, question.Name)
	return msg
}

func (r *RecursiveDNSServer) QueryForRefresh(question dns.Question, ecs *types.ECSOption, serverDNSSECEnabled bool) ([]dns.RR, []dns.RR, []dns.RR, bool, *types.ECSOption, error) {
	defer func() { utils.HandlePanicWithContext("缓存刷新查询") }()

	if atomic.LoadInt32(&r.closed) != 0 {
		return nil, nil, nil, false, nil, errors.New("🔒 服务器已关闭")
	}

	// 将types.ECSOption转换为utils.ECSOption
	var utilsECS *utils.ECSOption
	if ecs != nil {
		utilsECS = &utils.ECSOption{
			Family:       ecs.Family,
			SourcePrefix: ecs.SourcePrefix,
			ScopePrefix:  ecs.ScopePrefix,
			Address:      ecs.Address,
		}
	}

	refreshCtx, cancel := context.WithTimeout(r.ctx, ExtendedQueryTimeout)
	defer cancel()

	servers := r.upstreamManager.GetServers()
	if len(servers) > 0 {
		answer, authority, additional, validated, ecsResponse, err := r.queryUpstreamServers(question, utilsECS, serverDNSSECEnabled, nil)
		// 将utils.ECSOption转换为types.ECSOption
		var typesECS *types.ECSOption
		if ecsResponse != nil {
			typesECS = &types.ECSOption{
				Family:       ecsResponse.Family,
				SourcePrefix: ecsResponse.SourcePrefix,
				ScopePrefix:  ecsResponse.ScopePrefix,
				Address:      ecsResponse.Address,
			}
		}
		return answer, authority, additional, validated, typesECS, err
	} else {
		answer, authority, additional, validated, ecsResponse, err := r.resolveWithCNAME(refreshCtx, question, utilsECS, nil)
		// 将utils.ECSOption转换为types.ECSOption
		var typesECS *types.ECSOption
		if ecsResponse != nil {
			typesECS = &types.ECSOption{
				Family:       ecsResponse.Family,
				SourcePrefix: ecsResponse.SourcePrefix,
				ScopePrefix:  ecsResponse.ScopePrefix,
				Address:      ecsResponse.Address,
			}
		}
		return answer, authority, additional, validated, typesECS, err
	}
}
