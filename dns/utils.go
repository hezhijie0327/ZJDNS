package dns

import (
	"errors"
	"strings"
	"time"
	"zjdns/types"
	"zjdns/utils"

	"github.com/miekg/dns"
)

func (r *RecursiveDNSServer) getRootServers() []string {
	if r.config.Server.Features.IPv6 {
		mixed := make([]string, 0, len(r.rootServersV4)+len(r.rootServersV6))
		mixed = append(mixed, r.rootServersV4...)
		mixed = append(mixed, r.rootServersV6...)
		return mixed
	}
	return r.rootServersV4
}

// GetConfig returns the server configuration
func (r *RecursiveDNSServer) GetConfig() *types.ServerConfig {
	return r.config
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
			utils.WriteLog(utils.LogError, "💥 设置DNS问题时发生panic: %v", r)
		}
	}()

	msg.SetQuestion(dns.Fqdn(name), qtype)
	return nil
}

// shouldPerformSpeedTest 检查是否应该对域名进行速度测试（防抖机制）
func (r *RecursiveDNSServer) shouldPerformSpeedTest(domain string) bool {
	// 如果没有配置speedtest，则不进行速度测试
	if len(r.config.Speedtest) == 0 {
		return false
	}

	r.speedtestMutex.Lock()
	defer r.speedtestMutex.Unlock()

	now := time.Now()
	lastCheck, exists := r.speedtestDebounce[domain]
	// 如果域名未被检查过，或者距离上次检查已经超过间隔时间，则应该检查
	if !exists || now.Sub(lastCheck) >= r.speedtestInterval {
		r.speedtestDebounce[domain] = now
		return true
	}

	return false
}

// cleanupSpeedtestDebounce 清理用于防抖的速度测试域名记录
func (r *RecursiveDNSServer) cleanupSpeedtestDebounce() {
	r.speedtestMutex.Lock()
	defer r.speedtestMutex.Unlock()

	now := time.Now()
	for domain, lastCheck := range r.speedtestDebounce {
		if now.Sub(lastCheck) >= r.speedtestInterval {
			delete(r.speedtestDebounce, domain)
		}
	}
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
