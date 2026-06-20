package server

import (
	"context"
	"net"

	"github.com/miekg/dns"

	"zjdns/config"
	"zjdns/internal/log"
)

// executeTraditionalQuery executes a DNS query over traditional UDP or TCP.
// TCP queries use a pipelined connection pool with fallback to single-shot.
func (qc *QueryClient) executeTraditionalQuery(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer) (*dns.Msg, error) {
	if server.Protocol == "tcp" && qc.tcpPool != nil {
		// Try pipelined pool first.
		pc, err := qc.tcpPool.acquire(ctx, server.Address, server.Address, func(dialCtx context.Context, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(dialCtx, "tcp", addr)
		})
		if err == nil {
			response, err := pc.Exchange(ctx, msg)
			if err == nil {
				return response, nil
			}
			if pc.isDead() {
				qc.tcpPool.remove(pc)
			}
			log.Debugf("UPSTREAM: pipelined TCP query to %s failed: %v, falling back", server.Address, err)
		}
	}

	// UDP or TCP fallback: single-shot ExchangeContext.
	var client *dns.Client
	if server.Protocol == "tcp" {
		client = qc.tcpClient
	} else {
		client = qc.udpClient
	}
	response, _, err := client.ExchangeContext(ctx, msg, server.Address)
	return response, err
}

// needsTCPFallback checks if a query result requires fallback to TCP.
// This happens when UDP queries are truncated or fail.
func (qc *QueryClient) needsTCPFallback(result *QueryResult, protocol string) bool {
	return protocol != "tcp" && (result.Error != nil || (result.Response != nil && result.Response.Truncated))
}
