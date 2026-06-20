package server

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/miekg/dns"

	"zjdns/config"
	"zjdns/internal/log"
)

// executeTLS executes a DNS query over DNS over TLS (DoT).
// Uses a pipelined connection pool for connection reuse and query multiplexing.
// Falls back to single-shot ExchangeContext if the pool is unavailable.
func (qc *QueryClient) executeTLS(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer, tlsConfig *tls.Config) (*dns.Msg, error) {
	key := dohTransportKey(server.Address, server.ServerName, server.SkipTLSVerify)

	// Try pipelined pool first (if enabled).
	if qc.dotPool != nil {
		pc, err := qc.dotPool.acquire(ctx, key, server.Address, func(dialCtx context.Context, addr string) (net.Conn, error) {
			dialer := tls.Dialer{Config: tlsConfig.Clone()}
			return dialer.DialContext(dialCtx, "tcp", addr)
		})
		if err == nil {
			response, err := pc.Exchange(ctx, msg)
			if err == nil {
				return response, nil
			}
			// Query failed — if the connection died, remove it from the pool.
			if pc.isDead() {
				qc.dotPool.remove(pc)
			}
			log.Debugf("UPSTREAM: pipelined DoT query to %s failed: %v, falling back", server.Address, err)
		}
	}

	// Fallback: single-shot ExchangeContext.
	client := *qc.tlsClient
	client.TLSConfig = tlsConfig
	response, _, err := client.ExchangeContext(ctx, msg, server.Address)
	return response, err
}
