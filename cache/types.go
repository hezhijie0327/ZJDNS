package cache

import (
	"context"
	"net"
	"sync"

	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"

	"zjdns/types"
	"zjdns/utils"
)

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

// CompactDNSRecord 紧凑DNS记录
type CompactDNSRecord struct {
	Text    string `json:"text"`
	OrigTTL uint32 `json:"orig_ttl"`
	Type    uint16 `json:"type"`
}

// RefreshRequest 刷新请求
type RefreshRequest struct {
	Question            dns.Question
	ECS                 *ECSOption
	CacheKey            string
	ServerDNSSECEnabled bool
}

// ECSOption ECS选项配置
type ECSOption struct {
	Family       uint16 `json:"family"`
	SourcePrefix uint8  `json:"source_prefix"`
	ScopePrefix  uint8  `json:"scope_prefix"`
	Address      net.IP `json:"address"`
}

// DNSCache 缓存接口
type DNSCache interface {
	Get(key string) (*CacheEntry, bool, bool)
	Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *types.ECSOption)
	RequestRefresh(req RefreshRequest)
	Shutdown()
}

// 无缓存
type NullCache struct{}

// Redis缓存实现
type RedisDNSCache struct {
	client       *redis.Client
	config       *types.ServerConfig
	keyPrefix    string
	refreshQueue chan RefreshRequest
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	taskManager  *utils.TaskManager
	server       types.RecursiveDNSServer
	closed       int32
}
