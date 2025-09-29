package main

import (
	"github.com/miekg/dns"
)

func NewNullCache() *NullCache {
	writeLog(LogInfo, "🚫 无缓存模式")
	return &NullCache{}
}

func (nc *NullCache) Get(key string) (*CacheEntry, bool, bool) { return nil, false, false }
func (nc *NullCache) Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *ECSOption) {
}
func (nc *NullCache) RequestRefresh(req RefreshRequest) {}
func (nc *NullCache) Shutdown()                         {}
