// Package traditional implements outbound DNS queries over plain UDP and TCP.
package traditional

import (
	"time"
	"zjdns/config"
	"zjdns/server/upstream/pool"
	socks5 "zjdns/server/upstream/socks5"

	"codeberg.org/miekg/dns"
)

// Client executes DNS queries over plain UDP and TCP transports.
type Client struct {
	udpClient *dns.Client
	tcpClient *dns.Client
	tcpPool   *pool.Pool
	getProxy  func(*config.UpstreamServer) *socks5.Dialer
	timeout   time.Duration
}

// New creates a Client for plain UDP and TCP DNS queries.
func New(udpClient, tcpClient *dns.Client, tcpPool *pool.Pool, getProxy func(*config.UpstreamServer) *socks5.Dialer, timeout time.Duration) *Client {
	return &Client{
		udpClient: udpClient,
		tcpClient: tcpClient,
		tcpPool:   tcpPool,
		getProxy:  getProxy,
		timeout:   timeout,
	}
}
