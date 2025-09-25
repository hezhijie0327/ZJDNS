package types

import (
	"net"

	"github.com/miekg/dns"
)

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

// RecursiveDNSServer 递归DNS服务器接口
type RecursiveDNSServer interface {
	QueryForRefresh(question dns.Question, ecs *ECSOption, serverDNSSECEnabled bool) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, error)
	GetConfig() *ServerConfig
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

// SpeedTestMethod 速度测试方法
type SpeedTestMethod struct {
	// 测试类型: icmp, tcp
	Type string `json:"type"`
	// 端口号（仅对TCP有效）
	Port string `json:"port,omitempty"`
	// 超时时间（毫秒）
	Timeout int `json:"timeout"`
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

// UpstreamServer 上游服务器配置
type UpstreamServer struct {
	Address       string `json:"address"`
	Policy        string `json:"policy"`
	Protocol      string `json:"protocol"`
	ServerName    string `json:"server_name"`
	SkipTLSVerify bool   `json:"skip_tls_verify"`
}
