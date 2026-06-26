package client

import (
	"context"
	"net"

	"github.com/miekg/dns"

	"zjdns/config"
	"zjdns/internal/log"
)

func (c *Client) executeTraditionalQuery(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer) (*dns.Msg, error) {
	if server.Protocol == config.ProtoTCP && c.tcpPool != nil {
		pc, err := c.tcpPool.Acquire(ctx, server.Address, server.Address, func(dialCtx context.Context, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(dialCtx, "tcp", addr)
		})
		if err == nil {
			response, err := pc.Exchange(ctx, msg)
			if err == nil {
				return response, nil
			}
			if pc.IsDead() {
				c.tcpPool.Remove(pc)
			}
			log.Debugf("UPSTREAM: pipelined TCP query to %s failed: %v, falling back", server.Address, err)
		}
	}

	var client *dns.Client
	if server.Protocol == config.ProtoTCP {
		client = c.tcpClient
	} else {
		client = c.udpClient
	}
	response, _, err := client.ExchangeContext(ctx, msg, server.Address)
	return response, err
}

func (c *Client) needsTCPFallback(result *Result, protocol string) bool {
	return protocol != config.ProtoTCP && (result.Error != nil || (result.Response != nil && result.Response.Truncated))
}
