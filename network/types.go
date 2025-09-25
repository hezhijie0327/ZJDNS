package network

import (
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"zjdns/utils"
)

// SecureClient 安全客户端接口
type SecureClient interface {
	Exchange(msg *dns.Msg, addr string) (*dns.Msg, error)
	Close() error
	IsConnectionAlive() bool
}

// 连接池管理器
type ConnectionPoolManager struct {
	clients       chan *dns.Client
	secureClients map[string]SecureClient
	timeout       time.Duration
	mu            sync.RWMutex
	closed        int32
}

// ECS选项
type ECSOption struct {
	Family       uint16 `json:"family"`
	SourcePrefix uint8  `json:"source_prefix"`
	ScopePrefix  uint8  `json:"scope_prefix"`
	Address      net.IP `json:"address"`
}

// EDNS管理器
type EDNSManager struct {
	defaultECS     *ECSOption
	detector       *utils.IPDetector
	cache          sync.Map
	paddingEnabled bool
}

// IP检测器
// type IPDetector struct {
// 	httpClient *http.Client
// }

// IP过滤器
type IPFilter struct {
	trustedCIDRs   []*net.IPNet
	trustedCIDRsV6 []*net.IPNet
	mu             sync.RWMutex
}
