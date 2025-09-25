package cache

import (
	"github.com/miekg/dns"

	"zjdns/types"
	"zjdns/utils"
)

// NewNullCache 创建新的空缓存实例
func NewNullCache() *NullCache {
	utils.WriteLog(utils.LogInfo, "🚫 无缓存模式")
	return &NullCache{}
}

// Get 从缓存中获取条目
func (nc *NullCache) Get(key string) (*CacheEntry, bool, bool) { return nil, false, false }

// Set 将条目设置到缓存中
func (nc *NullCache) Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *types.ECSOption) {
}

// RequestRefresh 请求缓存刷新
func (nc *NullCache) RequestRefresh(req RefreshRequest) {}

// Shutdown 关闭缓存
func (nc *NullCache) Shutdown() {}
