package utils

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/icmp"

	"zjdns/types"
)

// SpeedTestMethod 速度测试方法
type SpeedTestMethod struct {
	// 测试类型: icmp, tcp
	Type string `json:"type"`
	// 端口号（仅对TCP有效）
	Port string `json:"port,omitempty"`
	// 超时时间（毫秒）
	Timeout int `json:"timeout"`
}

// SpeedTester 速度测试器
type SpeedTester struct {
	// 测速超时时间
	timeout time.Duration
	// 并发测速数量
	concurrency int
	// 测速结果缓存
	cache map[string]*SpeedTestResult
	// 缓存锁
	cacheMutex sync.RWMutex
	// 缓存过期时间
	cacheTTL time.Duration
	// ICMP连接
	icmpConn4 *icmp.PacketConn
	// IPv6的ICMP连接
	icmpConn6 *icmp.PacketConn
	// 测试方法配置
	methods []types.SpeedTestMethod
}

// SpeedTestResult 测速结果
type SpeedTestResult struct {
	IP        string
	Latency   time.Duration
	Reachable bool
	Timestamp time.Time
}

// 增强日志系统
type LogLevel int

type LogConfig struct {
	level     LogLevel
	useColor  bool
	useEmojis bool
	mu        sync.RWMutex
}

// 优化的资源管理器
type ResourceManager struct {
	dnsMessages    sync.Pool
	buffers        sync.Pool
	stringBuilders sync.Pool
	stats          struct {
		gets int64
		puts int64
		news int64
	}
}

// 优化的任务管理器
type TaskManager struct {
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	semaphore   chan struct{}
	activeCount int64
	closed      int32
	stats       struct {
		executed int64
		failed   int64
		timeout  int64
	}
}

// RequestTracker 请求追踪器
type RequestTracker struct {
	ID           string
	StartTime    time.Time
	Domain       string
	QueryType    string
	ClientIP     string
	Steps        []string
	CacheHit     bool
	Upstream     string
	ResponseTime time.Duration
	mu           sync.Mutex
}

// CompactDNSRecord 紧凑DNS记录
type CompactDNSRecord struct {
	Text    string `json:"text"`
	OrigTTL uint32 `json:"orig_ttl"`
	Type    uint16 `json:"type"`
}

// DNSRecordConfig DNS记录配置，用于重写规则
type DNSRecordConfig struct {
	Name         string `json:"name,omitempty"`          // 可选的记录名称，如果未指定则使用RewriteRule.Name
	Type         string `json:"type"`                    // 记录类型字符串
	TTL          uint32 `json:"ttl,omitempty"`           // TTL值，默认使用300
	Content      string `json:"content"`                 // 记录内容（RDATA）
	ResponseCode *int   `json:"response_code,omitempty"` // 响应码
}

// ECSOption ECS选项配置
type ECSOption struct {
	Family       uint16 `json:"family"`
	SourcePrefix uint8  `json:"source_prefix"`
	ScopePrefix  uint8  `json:"scope_prefix"`
	Address      net.IP `json:"address"`
}

// DNS记录转换工具
type DNSRecordHandler struct{}

// IPDetector IP检测器
type IPDetector struct {
	httpClient *http.Client
}

// DNSSECValidator DNSSEC验证器
type DNSSECValidator struct{}

// 缓存工具
type CacheUtils struct{}
