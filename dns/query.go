package dns

import (
	"context"
	"errors"
	"fmt"

	"zjdns/network"
	"zjdns/utils"

	"github.com/miekg/dns"
)

func (r *RecursiveDNSServer) buildQueryMessage(question dns.Question, ecs *utils.ECSOption, dnssecEnabled bool, recursionDesired bool, isSecureConnection bool) *dns.Msg {
	msg := utils.GlobalResourceManager.GetDNSMessage()

	// 确保消息状态正确
	if msg == nil {
		msg = &dns.Msg{}
	}

	// 安全设置问题
	if err := r.safeSetQuestion(msg, question.Name, question.Qtype); err != nil {
		utils.WriteLog(utils.LogDebug, "💥 设置DNS问题失败: %v", err)
		msg = &dns.Msg{}
		msg.SetQuestion(dns.Fqdn(question.Name), question.Qtype)
	}

	msg.RecursionDesired = recursionDesired

	if r.ednsManager != nil {
		// 将utils.ECSOption转换为network.ECSOption
		var networkECS *network.ECSOption
		if ecs != nil {
			networkECS = &network.ECSOption{
				Family:       ecs.Family,
				SourcePrefix: ecs.SourcePrefix,
				ScopePrefix:  ecs.ScopePrefix,
				Address:      ecs.Address,
			}
		}

		r.ednsManager.AddToMessage(msg, networkECS, dnssecEnabled, isSecureConnection)
	}

	return msg
}

func (r *RecursiveDNSServer) queryUpstreamServers(question dns.Question, ecs *utils.ECSOption,
	serverDNSSECEnabled bool, tracker *utils.RequestTracker) ([]dns.RR, []dns.RR, []dns.RR, bool, *utils.ECSOption, error) {

	servers := r.upstreamManager.GetServers()
	if len(servers) == 0 {
		return nil, nil, nil, false, nil, errors.New("❌ 没有可用的上游服务器")
	}

	result, err := r.executeConcurrentQueries(r.ctx, question, ecs, serverDNSSECEnabled,
		servers, SingleQueryMaxConcurrency, tracker)
	if err != nil {
		return nil, nil, nil, false, nil, err
	}

	var ecsResponse *utils.ECSOption
	if result.Response != nil {
		networkECS := r.ednsManager.ParseFromDNS(result.Response)
		// 将network.ECSOption转换为utils.ECSOption
		if networkECS != nil {
			ecsResponse = &utils.ECSOption{
				Family:       networkECS.Family,
				SourcePrefix: networkECS.SourcePrefix,
				ScopePrefix:  networkECS.ScopePrefix,
				Address:      networkECS.Address,
			}
		}
	}

	return result.Response.Answer, result.Response.Ns, result.Response.Extra,
		result.Validated, ecsResponse, nil
}

func (r *RecursiveDNSServer) executeConcurrentQueries(ctx context.Context, question dns.Question, ecs *utils.ECSOption, serverDNSSECEnabled bool,
	servers []*UpstreamServer, maxConcurrency int, tracker *utils.RequestTracker) (*QueryResult, error) {

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
		// 为每个并发查询创建独立的消息副本，避免数据竞争
		// SafeCopyDNSMessage内部使用sync.Pool优化性能
		originalMsg := r.buildQueryMessage(question, ecs, serverDNSSECEnabled, true, false)
		msg := utils.SafeCopyDNSMessage(originalMsg)
		defer utils.GlobalResourceManager.PutDNSMessage(originalMsg)

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
