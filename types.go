package main

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/redis/go-redis/v9"
	"golang.org/x/net/icmp"
)

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

// ECSOption ECS选项配置
type ECSOption struct {
	Family       uint16 `json:"family"`
	SourcePrefix uint8  `json:"source_prefix"`
	ScopePrefix  uint8  `json:"scope_prefix"`
	Address      net.IP `json:"address"`
}

// CompactDNSRecord 紧凑DNS记录
type CompactDNSRecord struct {
	Text    string `json:"text"`
	OrigTTL uint32 `json:"orig_ttl"`
	Type    uint16 `json:"type"`
}

// CacheEntry 缓存条目
type CacheEntry struct {
	Answer          []*CompactDNSRecord `json:"answer"`
	Authority       []*CompactDNSRecord `json:"authority"`
	Additional      []*CompactDNSRecord `json:"additional"`
	TTL             int                 `json:"ttl"`
	OriginalTTL     int                 `json:"original_ttl"`
	Timestamp       int64               `json:"timestamp"`
	Validated       bool                `json:"validated"`
	AccessTime      int64               `json:"access_time"`
	RefreshTime     int64               `json:"refresh_time,omitempty"`
	ECSFamily       uint16              `json:"ecs_family,omitempty"`
	ECSSourcePrefix uint8               `json:"ecs_source_prefix,omitempty"`
	ECSScopePrefix  uint8               `json:"ecs_scope_prefix,omitempty"`
	ECSAddress      string              `json:"ecs_address,omitempty"`
}

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
type RefreshRequest struct {
	Question            dns.Question
	ECS                 *ECSOption
	CacheKey            string
	ServerDNSSECEnabled bool
}

// RewriteRule DNS重写规则
type RewriteRule struct {
	Name string `json:"name"` // 需要匹配的域名

	// 新增字段支持响应码重写（数字形式）
	ResponseCode *int `json:"response_code,omitempty"` // 响应码: 0=NOERROR, 2=SERVFAIL, 3=NXDOMAIN, 5=REFUSED 等

	// 新增字段支持所有类型DNS记录重写，使用更简单的格式
	Records []DNSRecordConfig `json:"records,omitempty"` // DNS记录列表

	// 新增字段支持在Additional Section中添加记录，用于DDR等功能
	Additional []DNSRecordConfig `json:"additional,omitempty"` // Additional Section记录列表
}

// DNSRecordConfig DNS记录配置，用于重写规则
type DNSRecordConfig struct {
	Name         string `json:"name,omitempty"`          // 可选的记录名称，如果未指定则使用RewriteRule.Name
	Type         string `json:"type"`                    // 记录类型字符串
	TTL          uint32 `json:"ttl,omitempty"`           // TTL值，默认使用300
	Content      string `json:"content"`                 // 记录内容（RDATA）
	ResponseCode *int   `json:"response_code,omitempty"` // 响应码
}

// ServerConfig 服务器配置
type ServerConfig struct {
	Server struct {
		Port            string `json:"port"`
		LogLevel        string `json:"log_level"`
		DefaultECS      string `json:"default_ecs_subnet"`
		TrustedCIDRFile string `json:"trusted_cidr_file"`

		DDR struct {
			Domain string `json:"domain"`
			IPv4   string `json:"ipv4"`
			IPv6   string `json:"ipv6"`
		} `json:"ddr"`

		TLS struct {
			Port     string `json:"port"`
			CertFile string `json:"cert_file"`
			KeyFile  string `json:"key_file"`

			HTTPS struct {
				Port     string `json:"port"`
				Endpoint string `json:"endpoint"`
			} `json:"https"`
		} `json:"tls"`

		Features struct {
			ServeStale       bool `json:"serve_stale"`
			Prefetch         bool `json:"prefetch"`
			DNSSEC           bool `json:"dnssec"`
			HijackProtection bool `json:"hijack_protection"`
			Padding          bool `json:"padding"`
			IPv6             bool `json:"ipv6"`
		} `json:"features"`
	} `json:"server"`

	Redis struct {
		Address   string `json:"address"`
		Password  string `json:"password"`
		Database  int    `json:"database"`
		KeyPrefix string `json:"key_prefix"`
	} `json:"redis"`

	Speedtest []SpeedTestMethod `json:"speedtest"`
	Upstream  []UpstreamServer  `json:"upstream"`
	Rewrite   []RewriteRule     `json:"rewrite"`
}

// DNSCache 缓存接口
type DNSCache interface {
	Get(key string) (*CacheEntry, bool, bool)
	Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *ECSOption)
	RequestRefresh(req RefreshRequest)
	Shutdown()
}

// SecureClient 安全客户端接口
type SecureClient interface {
	Exchange(msg *dns.Msg, addr string) (*dns.Msg, error)
	Close() error
}

// 无缓存
type NullCache struct{}

// Redis缓存实现
type RedisDNSCache struct {
	client       *redis.Client
	config       *ServerConfig
	keyPrefix    string
	refreshQueue chan RefreshRequest
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	taskManager  *TaskManager
	server       *RecursiveDNSServer
	closed       int32
}

// 配置管理器
type ConfigManager struct{}

// 连接池管理器
type ConnectionPoolManager struct {
	clients       chan *dns.Client
	secureClients map[string]SecureClient
	timeout       time.Duration
	mu            sync.RWMutex
	closed        int32
}

// 主DNS递归服务器
type RecursiveDNSServer struct {
	// 配置信息
	config *ServerConfig
	// 根服务器地址列表
	rootServersV4 []string
	rootServersV6 []string
	// 连接池管理器
	connectionPool *ConnectionPoolManager
	// DNSSEC验证器
	dnssecValidator *DNSSECValidator
	// 并发控制通道
	concurrencyLimit chan struct{}
	// 上下文和取消函数
	ctx    context.Context
	cancel context.CancelFunc
	// 关闭通知通道
	shutdown chan struct{}
	// IP过滤器
	ipFilter *IPFilter
	// DNS重写器
	dnsRewriter *DNSRewriter
	// 上游服务器管理器
	upstreamManager *UpstreamManager
	// 统一查询客户端
	queryClient *UnifiedQueryClient
	// 缓存实例
	cache DNSCache
	// 任务管理器
	taskManager *TaskManager
	// ECS管理器
	ednsManager *EDNSManager
	// 劫持预防器
	hijackPrevention *DNSHijackPrevention
	// 防抖间隔
	speedtestInterval time.Duration
	// 防抖机制
	speedtestDebounce map[string]time.Time
	// 速度测试防抖互斥锁
	speedtestMutex sync.Mutex
	// 安全DNS管理器
	secureDNSManager *SecureDNSManager
	// 等待组
	wg sync.WaitGroup
	// 关闭状态标志
	closed int32
}

// ECS选项和EDNS管理器
type EDNSManager struct {
	defaultECS     *ECSOption
	detector       *IPDetector
	cache          sync.Map
	paddingEnabled bool
}

// IP过滤器
type IPFilter struct {
	trustedCIDRs   []*net.IPNet
	trustedCIDRsV6 []*net.IPNet
	mu             sync.RWMutex
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

// IP检测器
type IPDetector struct {
	httpClient *http.Client
}

// 增强日志系统
type LogLevel int

type LogConfig struct {
	level     LogLevel
	useColor  bool
	useEmojis bool
	mu        sync.RWMutex
}

// DoH客户端实现
type DoHClient struct {
	addr         *url.URL
	tlsConfig    *tls.Config
	client       *http.Client
	clientMu     sync.Mutex
	quicConfig   *quic.Config
	timeout      time.Duration
	skipVerify   bool
	serverName   string
	addrRedacted string
	httpVersions []string
	closed       int32
}

// HTTP/3 传输包装器
type http3Transport struct {
	baseTransport *http3.Transport
	closed        bool
	mu            sync.RWMutex
}

// 统一安全连接客户端
type UnifiedSecureClient struct {
	protocol        string
	serverName      string
	skipVerify      bool
	timeout         time.Duration
	tlsConn         *tls.Conn
	quicConn        *quic.Conn
	dohClient       *DoHClient
	isQUICConnected bool
	lastActivity    time.Time
	mu              sync.Mutex
}

// 安全DNS管理器
type SecureDNSManager struct {
	server        *RecursiveDNSServer
	tlsConfig     *tls.Config
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	tlsListener   net.Listener
	quicConn      *net.UDPConn
	quicListener  *quic.EarlyListener
	quicTransport *quic.Transport
	httpsServer   *http.Server
	h3Server      *http3.Server
	httpsListener net.Listener
	h3Listener    *quic.EarlyListener
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
	methods []SpeedTestMethod
}

// SpeedTestResult 测速结果
type SpeedTestResult struct {
	IP        string
	Latency   time.Duration
	Reachable bool
	Timestamp time.Time
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

// 上游管理器
type UpstreamManager struct {
	servers []*UpstreamServer
	mu      sync.RWMutex
}

// 安全连接错误处理器
type SecureConnErrorHandler struct{}

// 统一查询客户端
type UnifiedQueryClient struct {
	connectionPool *ConnectionPoolManager
	errorHandler   *SecureConnErrorHandler
	timeout        time.Duration
}

// DNS记录转换工具
type DNSRecordHandler struct{}

// 缓存工具
type CacheUtils struct{}

// DNSSEC验证器
type DNSSECValidator struct{}
