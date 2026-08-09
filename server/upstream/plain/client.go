// Package plain implements outbound DNS queries over plain UDP and TCP.
package plain

import (
	"sync"
	"time"
	"zjdns/config"
	"zjdns/server/defense"
	"zjdns/server/upstream/pool"
	socks5 "zjdns/server/upstream/socks5"

	"codeberg.org/miekg/dns"
)

// Client executes DNS queries over plain UDP and TCP transports.
type Client struct {
	udpClient      *dns.Client
	tcpClient      *dns.Client
	tcpPool        *pool.ConnPool
	udpPool        *pool.UDPPool
	getProxy       func(*config.UpstreamServer) *socks5.Dialer
	timeout        time.Duration
	hopGuard       *defense.HopGuard // shared LRU cache for TTL fingerprints
	hopguardWarned sync.Map          // per-address one-shot hopguard warning
}

// New creates a Client for plain UDP and TCP DNS queries.
// All parameters must be non-nil; the returned Client dereferences them
// unconditionally in ExecuteUDP/ExecuteTCP.
func New(udpClient, tcpClient *dns.Client, tcpPool *pool.ConnPool, getProxy func(*config.UpstreamServer) *socks5.Dialer, timeout time.Duration) *Client {
	return &Client{
		udpClient: udpClient,
		tcpClient: tcpClient,
		tcpPool:   tcpPool,
		udpPool: pool.NewUDPPool(config.DefaultMaxConns, config.DefaultMaxPipe, config.DefaultMaxUDPTotalConns, func(payload []byte) (string, bool) {
			// Plain DNS: the response echoes the query ID in the first two bytes.
			if len(payload) < 2 {
				return "", false
			}
			return string(payload[:2]), true
		}),
		getProxy: getProxy,
		timeout:  timeout,
		hopGuard: defense.NewHopGuard(),
	}
}

// Close shuts down the TCP and UDP pools, stopping all readLoop goroutines.
func (c *Client) Close() {
	if c != nil && c.tcpPool != nil {
		c.tcpPool.Shutdown()
	}
	if c != nil && c.udpPool != nil {
		c.udpPool.Shutdown()
	}
}

// ReapDeadUDP drops dead sockets from the UDP pool — an idle-recycled
// readLoop socket otherwise stays pinned under its address key until that
// address is queried again.  Called periodically by the server (H1).
func (c *Client) ReapDeadUDP() {
	if c != nil && c.udpPool != nil {
		c.udpPool.ReapDead()
	}
}
