// Package plain implements outbound DNS queries over plain UDP and TCP.
package plain

import (
	"time"
	"zjdns/config"
	"zjdns/server/upstream/pool"
	socks5 "zjdns/server/upstream/socks5"

	"codeberg.org/miekg/dns"
)

// Client executes DNS queries over plain UDP and TCP transports.
type Client struct {
	udpClient    *dns.Client
	tcpClient    *dns.Client
	tcpPool      *pool.ConnPool
	getProxy     func(*config.UpstreamServer) *socks5.Dialer
	timeout      time.Duration
	segmentSize  int
	segmentDelay time.Duration
}

// New creates a Client for plain UDP and TCP DNS queries.
func New(udpClient, tcpClient *dns.Client, tcpPool *pool.ConnPool, getProxy func(*config.UpstreamServer) *socks5.Dialer, timeout time.Duration) *Client {
	return &Client{
		udpClient: udpClient,
		tcpClient: tcpClient,
		tcpPool:   tcpPool,
		getProxy:  getProxy,
		timeout:   timeout,
	}
}

// SetSegmentation configures TCP DNS message segmentation. segSize=0 disables
// segmentation (normal Write). segSize>0 causes each TCP DNS frame to be split
// into segments of segSize bytes (first segment includes the 2-byte length prefix
// plus segSize bytes of payload).
func (c *Client) SetSegmentation(segSize int, delay time.Duration) {
	c.segmentSize = segSize
	c.segmentDelay = delay
	if c.tcpPool != nil {
		c.tcpPool.SetSegmentation(segSize, delay)
	}
}
