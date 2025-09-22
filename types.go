package main

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// ==================== 核心类型定义 ====================

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

func (u *UpstreamServer) IsRecursive() bool {
	return strings.ToLower(u.Address) == RecursiveServerIndicator
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

func (c *CacheEntry) IsExpired() bool {
	if c == nil {
		return true
	}
	return time.Now().Unix()-c.Timestamp > int64(c.TTL)
}

func (c *CacheEntry) IsStale() bool {
	if c == nil {
		return true
	}
	return time.Now().Unix()-c.Timestamp > int64(c.TTL+StaleMaxAgeSeconds)
}

func (c *CacheEntry) ShouldRefresh() bool {
	if c == nil {
		return false
	}

	now := time.Now().Unix()
	refreshInterval := int64(c.OriginalTTL)
	if refreshInterval <= 0 {
		refreshInterval = int64(c.TTL)
	}

	return c.IsExpired() &&
		(now-c.Timestamp) > refreshInterval &&
		(now-c.RefreshTime) > refreshInterval
}

func (c *CacheEntry) GetRemainingTTL() uint32 {
	if c == nil {
		return 0
	}

	now := time.Now().Unix()
	elapsed := now - c.Timestamp
	remaining := int64(c.TTL) - elapsed

	if remaining > 0 {
		return uint32(remaining)
	}

	staleElapsed := elapsed - int64(c.TTL)
	staleCycle := staleElapsed % int64(StaleTTLSeconds)
	staleTTLRemaining := int64(StaleTTLSeconds) - staleCycle

	if staleTTLRemaining <= 0 {
		staleTTLRemaining = int64(StaleTTLSeconds)
	}

	return uint32(staleTTLRemaining)
}

func (c *CacheEntry) GetECSOption() *ECSOption {
	if c == nil || c.ECSAddress == "" {
		return nil
	}
	if ip := net.ParseIP(c.ECSAddress); ip != nil {
		return &ECSOption{
			Family:       c.ECSFamily,
			SourcePrefix: c.ECSSourcePrefix,
			ScopePrefix:  c.ECSScopePrefix,
			Address:      ip,
		}
	}
	return nil
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
	Match   string `json:"match"`   // 需要匹配的域名
	Replace string `json:"replace"` // 替换的域名或IP地址
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
