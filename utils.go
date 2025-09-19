package main

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ==================== 安全的错误处理和恢复系统 ====================

// SafeCopyDNSMessage 安全地复制DNS消息，防止在复制过程中出现panic
// 使用ResourceManager对象池优化性能
func SafeCopyDNSMessage(msg *dns.Msg) *dns.Msg {
	if msg == nil {
		newMsg := globalResourceManager.GetDNSMessage()
		return newMsg
	}

	// 从对象池获取消息对象
	msgCopy := globalResourceManager.GetDNSMessage()

	// 复制消息头部和压缩标志
	msgCopy.MsgHdr = msg.MsgHdr
	msgCopy.Compress = msg.Compress

	// 安全复制Question切片
	if msg.Question != nil {
		msgCopy.Question = append(msgCopy.Question[:0], msg.Question...)
	} else {
		msgCopy.Question = msgCopy.Question[:0]
	}

	// 安全复制Answer切片
	if msg.Answer != nil {
		msgCopy.Answer = msgCopy.Answer[:0]
		for _, rr := range msg.Answer {
			if rr != nil {
				msgCopy.Answer = append(msgCopy.Answer, dns.Copy(rr))
			}
		}
	} else {
		msgCopy.Answer = msgCopy.Answer[:0]
	}

	// 安全复制Ns切片
	if msg.Ns != nil {
		msgCopy.Ns = msgCopy.Ns[:0]
		for _, rr := range msg.Ns {
			if rr != nil {
				msgCopy.Ns = append(msgCopy.Ns, dns.Copy(rr))
			}
		}
	} else {
		msgCopy.Ns = msgCopy.Ns[:0]
	}

	// 安全复制Extra切片
	if msg.Extra != nil {
		msgCopy.Extra = msgCopy.Extra[:0]
		for _, rr := range msg.Extra {
			if rr != nil {
				msgCopy.Extra = append(msgCopy.Extra, dns.Copy(rr))
			}
		}
	} else {
		msgCopy.Extra = msgCopy.Extra[:0]
	}

	return msgCopy
}

func handlePanicWithContext(operation string) {
	if r := recover(); r != nil {
		buf := make([]byte, 2048)
		n := runtime.Stack(buf, false)
		stackTrace := string(buf[:n])

		// 合并日志输出，包含操作信息、panic详情和堆栈跟踪
		writeLog(LogError, "🚨 Panic触发 [%s]: %v\n堆栈:\n%s\n💥 程序因panic退出",
			operation, r, stackTrace)

		os.Exit(1)
	}
}

// ==================== 请求追踪系统 ====================

func NewRequestTracker(domain, qtype, clientIP string) *RequestTracker {
	return &RequestTracker{
		ID:        fmt.Sprintf("%x", time.Now().UnixNano()&0xFFFFFF),
		StartTime: time.Now(),
		Domain:    domain,
		QueryType: qtype,
		ClientIP:  clientIP,
		Steps:     make([]string, 0, 8),
	}
}

func (rt *RequestTracker) AddStep(step string, args ...interface{}) {
	if rt == nil || GetLogLevel() < LogDebug {
		return
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()

	timestamp := time.Since(rt.StartTime)
	stepMsg := fmt.Sprintf("[%v] %s", timestamp.Truncate(time.Microsecond), fmt.Sprintf(step, args...))
	rt.Steps = append(rt.Steps, stepMsg)

	writeLog(LogDebug, "🔍 [%s] %s", rt.ID, stepMsg)
}

func (rt *RequestTracker) Finish() {
	if rt == nil {
		return
	}

	rt.ResponseTime = time.Since(rt.StartTime)
	if GetLogLevel() >= LogInfo {
		cacheEmoji := "❌"
		if rt.CacheHit {
			cacheEmoji = "🎯"
		}

		writeLog(LogInfo, "📊 [%s] 查询完成: %s %s | 缓存:%s | 耗时:%v | 上游:%s",
			rt.ID, rt.Domain, rt.QueryType, cacheEmoji,
			rt.ResponseTime.Truncate(time.Microsecond), rt.Upstream)
	}
}

// ==================== DNS消息安全处理 ====================

// ==================== DNS记录转换工具 ====================

type DNSRecordHandler struct{}

func NewDNSRecordHandler() *DNSRecordHandler {
	return &DNSRecordHandler{}
}

func (drh *DNSRecordHandler) CompactRecord(rr dns.RR) *CompactDNSRecord {
	if drh == nil || rr == nil {
		return nil
	}
	return &CompactDNSRecord{
		Text:    rr.String(),
		OrigTTL: rr.Header().Ttl,
		Type:    rr.Header().Rrtype,
	}
}

func (drh *DNSRecordHandler) ExpandRecord(cr *CompactDNSRecord) dns.RR {
	if drh == nil || cr == nil || cr.Text == "" {
		return nil
	}
	rr, err := dns.NewRR(cr.Text)
	if err != nil {
		return nil
	}
	return rr
}

func (drh *DNSRecordHandler) CompactRecords(rrs []dns.RR) []*CompactDNSRecord {
	if drh == nil || len(rrs) == 0 {
		return nil
	}

	seen := make(map[string]bool, len(rrs))
	result := make([]*CompactDNSRecord, 0, len(rrs))

	for _, rr := range rrs {
		if rr == nil || rr.Header().Rrtype == dns.TypeOPT {
			continue
		}

		rrText := rr.String()
		if !seen[rrText] {
			seen[rrText] = true
			if cr := drh.CompactRecord(rr); cr != nil {
				result = append(result, cr)
			}
		}
	}
	return result
}

func (drh *DNSRecordHandler) ExpandRecords(crs []*CompactDNSRecord) []dns.RR {
	if drh == nil || len(crs) == 0 {
		return nil
	}
	result := make([]dns.RR, 0, len(crs))
	for _, cr := range crs {
		if rr := drh.ExpandRecord(cr); rr != nil {
			result = append(result, rr)
		}
	}
	return result
}

func (drh *DNSRecordHandler) ProcessRecords(rrs []dns.RR, ttl uint32, includeDNSSEC bool) []dns.RR {
	if drh == nil || len(rrs) == 0 {
		return nil
	}

	result := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		if rr == nil {
			continue
		}

		// 过滤DNSSEC记录
		if !includeDNSSEC {
			switch rr.(type) {
			case *dns.RRSIG, *dns.NSEC, *dns.NSEC3, *dns.DNSKEY, *dns.DS:
				continue
			}
		}

		// 调整TTL
		newRR := dns.Copy(rr)
		if newRR != nil {
			if ttl > 0 {
				newRR.Header().Ttl = ttl
			}
			result = append(result, newRR)
		}
	}
	return result
}

var globalRecordHandler = NewDNSRecordHandler()

// ==================== 缓存工具 ====================

type CacheUtils struct{}

func NewCacheUtils() *CacheUtils {
	return &CacheUtils{}
}

func (cu *CacheUtils) BuildKey(question dns.Question, ecs *ECSOption, dnssecEnabled bool) string {
	if cu == nil {
		return ""
	}

	// 使用string builder优化字符串拼接
	sb := globalResourceManager.GetStringBuilder()
	defer globalResourceManager.PutStringBuilder(sb)

	sb.WriteString(strings.ToLower(question.Name))
	sb.WriteByte(':')
	fmt.Fprintf(sb, "%d", question.Qtype)
	sb.WriteByte(':')
	fmt.Fprintf(sb, "%d", question.Qclass)

	if ecs != nil {
		sb.WriteByte(':')
		sb.WriteString(ecs.Address.String())
		sb.WriteByte('/')
		fmt.Fprintf(sb, "%d", ecs.SourcePrefix)
	}

	if dnssecEnabled {
		sb.WriteString(":dnssec")
	}

	result := sb.String()
	if len(result) > 512 {
		result = fmt.Sprintf("hash:%x", result)[:512]
	}
	return result
}

func (cu *CacheUtils) CalculateTTL(rrs []dns.RR) int {
	if cu == nil || len(rrs) == 0 {
		return DefaultCacheTTLSeconds
	}

	minTTL := int(rrs[0].Header().Ttl)
	for _, rr := range rrs {
		if rr == nil {
			continue
		}
		if ttl := int(rr.Header().Ttl); ttl > 0 && (minTTL == 0 || ttl < minTTL) {
			minTTL = ttl
		}
	}

	if minTTL <= 0 {
		minTTL = DefaultCacheTTLSeconds
	}

	return minTTL
}

var globalCacheUtils = NewCacheUtils()

// ==================== DNSSEC验证器 ====================

type DNSSECValidator struct{}

func NewDNSSECValidator() *DNSSECValidator {
	return &DNSSECValidator{}
}

func (v *DNSSECValidator) HasDNSSECRecords(response *dns.Msg) bool {
	if response == nil {
		return false
	}

	for _, sections := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
		for _, rr := range sections {
			switch rr.(type) {
			case *dns.RRSIG, *dns.NSEC, *dns.NSEC3, *dns.DNSKEY, *dns.DS:
				return true
			}
		}
	}
	return false
}

func (v *DNSSECValidator) IsValidated(response *dns.Msg) bool {
	if response == nil {
		return false
	}
	if response.AuthenticatedData {
		return true
	}
	return v.HasDNSSECRecords(response)
}

func (v *DNSSECValidator) ValidateResponse(response *dns.Msg, dnssecOK bool) bool {
	if !dnssecOK || response == nil {
		return false
	}
	return v.IsValidated(response)
}

// ==================== 通用工具函数 ====================

func GetClientIP(w dns.ResponseWriter) net.IP {
	if addr := w.RemoteAddr(); addr != nil {
		switch a := addr.(type) {
		case *net.UDPAddr:
			return a.IP
		case *net.TCPAddr:
			return a.IP
		}
	}
	return nil
}

func isSecureProtocol(protocol string) bool {
	switch protocol {
	case "tls", "quic", "https", "http3":
		return true
	default:
		return false
	}
}

func getProtocolEmoji(protocol string) string {
	switch strings.ToLower(protocol) {
	case "tls":
		return "🔐"
	case "quic":
		return "🚀"
	case "https":
		return "🌐"
	case "http3":
		return "⚡"
	case "tcp":
		return "🔌"
	case "udp":
		return "📡"
	default:
		return "📡"
	}
}

func isValidFilePath(path string) bool {
	if strings.Contains(path, "..") ||
		strings.HasPrefix(path, "/etc/") ||
		strings.HasPrefix(path, "/proc/") ||
		strings.HasPrefix(path, "/sys/") {
		return false
	}

	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().IsRegular()
}
