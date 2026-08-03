// Package plain implements outbound DNS queries over plain UDP and TCP.
package plain

import (
	"net"
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
	getProxy       func(*config.UpstreamServer) *socks5.Dialer
	timeout        time.Duration
	hopGuard       *defense.HopGuard // shared LRU cache for TTL fingerprints
	hopguardWarned sync.Map          // per-address one-shot hopguard warning

	udpPool   map[string]chan *net.UDPConn // per-upstream connected UDP socket pool
	udpPoolMu sync.Mutex                   // guards udpPool map
}

// New creates a Client for plain UDP and TCP DNS queries.
// All parameters must be non-nil; the returned Client dereferences them
// unconditionally in ExecuteUDP/ExecuteTCP.
func New(udpClient, tcpClient *dns.Client, tcpPool *pool.ConnPool, getProxy func(*config.UpstreamServer) *socks5.Dialer, timeout time.Duration) *Client {
	return &Client{
		udpClient: udpClient,
		tcpClient: tcpClient,
		tcpPool:   tcpPool,
		getProxy:  getProxy,
		timeout:   timeout,
		hopGuard:  defense.NewHopGuard(),
		udpPool:   make(map[string]chan *net.UDPConn),
	}
}

// Close shuts down the TCP connection pool, stopping all readLoop goroutines.
func (c *Client) Close() {
	if c != nil && c.tcpPool != nil {
		c.tcpPool.Shutdown()
	}
	if c != nil {
		c.udpPoolMu.Lock()
		for addr, ch := range c.udpPool {
			close(ch)
			for conn := range ch {
				_ = conn.Close()
			}
			delete(c.udpPool, addr)
		}
		c.udpPoolMu.Unlock()
	}
}

// getUDPConn returns a connected UDP socket for the given address, either from
// the pool or freshly dialed. The caller MUST call putUDPConn to return it.
func (c *Client) getUDPConn(addr string) (*net.UDPConn, error) {
	c.udpPoolMu.Lock()
	ch, ok := c.udpPool[addr]
	if !ok {
		ch = make(chan *net.UDPConn, 4) // small pool per upstream
		c.udpPool[addr] = ch
	}
	c.udpPoolMu.Unlock()

	select {
	case conn := <-ch:
		return conn, nil
	default:
		uaddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return nil, err
		}
		conn, err := net.DialUDP("udp", nil, uaddr)
		if err != nil {
			return nil, err
		}
		return conn, nil
	}
}

// putUDPConn returns a connected UDP socket to the pool.
func (c *Client) putUDPConn(addr string, conn *net.UDPConn) {
	c.udpPoolMu.Lock()
	ch, ok := c.udpPool[addr]
	c.udpPoolMu.Unlock()
	if !ok {
		_ = conn.Close()
		return
	}
	select {
	case ch <- conn:
	default:
		_ = conn.Close() // pool full
	}
}
