package dns

import (
	"context"
	"sync"
	"time"

	"github.com/miekg/dns"

	"zjdns/cache"
	"zjdns/network"
	"zjdns/security"
	"zjdns/types"
	"zjdns/utils"
)

// QueryResult 查询结果
type QueryResult struct {
	Response  *dns.Msg
	Server    string
	Error     error
	Duration  time.Duration
	UsedTCP   bool
	Protocol  string
	Validated bool
}

// UpstreamServer 上游服务器配置
type UpstreamServer struct {
	Address       string `json:"address"`
	Policy        string `json:"policy"`
	Protocol      string `json:"protocol"`
	ServerName    string `json:"server_name"`
	SkipTLSVerify bool   `json:"skip_tls_verify"`
}

// CacheEntry 缓存条目
type CacheEntry = cache.CacheEntry

// SpeedTestMethod 速度测试方法
type SpeedTestMethod struct {
	// 测试类型: icmp, tcp
	Type string `json:"type"`
	// 端口号（仅对TCP有效）
	Port string `json:"port,omitempty"`
	// 超时时间（毫秒）
	Timeout int `json:"timeout"`
}

// RefreshRequest 刷新请求
type RefreshRequest = cache.RefreshRequest

// RewriteRule DNS重写规则
type RewriteRule struct {
	Name string `json:"name"` // 需要匹配的域名

	// 新增字段支持响应码重写（数字形式）
	ResponseCode *int `json:"response_code,omitempty"` // 响应码: 0=NOERROR, 2=SERVFAIL, 3=NXDOMAIN, 5=REFUSED 等

	// 新增字段支持所有类型DNS记录重写，使用更简单的格式
	Records []utils.DNSRecordConfig `json:"records,omitempty"` // DNS记录列表

	// 新增字段支持在Additional Section中添加记录，用于DDR等功能
	Additional []utils.DNSRecordConfig `json:"additional,omitempty"` // Additional Section记录列表
}

// ServerConfig 服务器配置
type ServerConfig = types.ServerConfig

// DNSCache 缓存接口
type DNSCache interface {
	Get(key string) (*CacheEntry, bool, bool)
	Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *types.ECSOption)
	RequestRefresh(req cache.RefreshRequest)
	Shutdown()
}

// 配置管理器
type ConfigManager struct{}

// 主DNS递归服务器
type RecursiveDNSServer struct {
	// 配置信息
	config *ServerConfig
	// 根服务器地址列表
	rootServersV4 []string
	rootServersV6 []string
	// 连接池管理器
	connectionPool *network.ConnectionPoolManager
	// DNSSEC验证器
	dnssecValidator *utils.DNSSECValidator
	// 并发控制通道
	concurrencyLimit chan struct{}
	// 上下文和取消函数
	ctx    context.Context
	cancel context.CancelFunc
	// 关闭通知通道
	shutdown chan struct{}
	// IP过滤器
	ipFilter *network.IPFilter
	// DNS重写器
	dnsRewriter *DNSRewriter
	// 上游服务器管理器
	upstreamManager *UpstreamManager
	// 统一查询客户端
	queryClient *UnifiedQueryClient
	// 缓存实例
	cache DNSCache
	// 任务管理器
	taskManager *utils.TaskManager
	// ECS管理器
	ednsManager *network.EDNSManager
	// 劫持预防器
	hijackPrevention *DNSHijackPrevention
	// 防抖间隔
	speedtestInterval time.Duration
	// 防抖机制
	speedtestDebounce map[string]time.Time
	// 速度测试防抖互斥锁
	speedtestMutex sync.Mutex
	// 安全DNS管理器
	secureDNSManager *security.SecureDNSManager
	// 等待组
	wg sync.WaitGroup
	// 关闭状态标志
	closed int32
}

// DNS重写器
type DNSRewriter struct {
	rules []RewriteRule
	mu    sync.RWMutex
}

// DNSRewriteResult DNS重写结果
type DNSRewriteResult struct {
	Domain        string
	ShouldRewrite bool
	ResponseCode  int
	Records       []dns.RR
	Additional    []dns.RR // Additional Section记录
}

// DNS劫持预防检查器
type DNSHijackPrevention struct {
	enabled bool
}

// 上游管理器
type UpstreamManager struct {
	servers []*UpstreamServer
	mu      sync.RWMutex
}

// 安全连接错误处理器
type SecureConnErrorHandler struct{}

// 统一查询客户端
type UnifiedQueryClient struct {
	connectionPool *network.ConnectionPoolManager
	errorHandler   *security.SecureConnErrorHandler
	timeout        time.Duration
}

// DNSSEC验证器
type DNSSECValidator struct{}
