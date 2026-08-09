package plain

import (
	"context"
	"fmt"
	"net"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
)

func (s *Server) startTCP(g Group, ctx context.Context, handler dns.Handler) error {
	if s.config.Server.Protocol.TCP == "" {
		return nil
	}

	addrs, err := zdnsutil.ResolveBindAddrs("tcp", s.config.Server.Protocol.TCP)
	if err != nil {
		return fmt.Errorf("TCP address resolution: %w", err)
	}
	log.Infof("PLAIN: TCP server started on %v", addrs)
	// Note: if one bind address fails, previously started listeners continue
	// serving. The caller should cancel the context to stop them.
	for _, addr := range addrs {
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("TCP listen on %s: %w", addr, err)
		}

		srv := &dns.Server{
			// The accept loop lives inside miekg/dns — cap concurrent
			// connections at the listener instead (connections queue in the
			// kernel backlog at the cap).
			Listener:    zdnsutil.NewLimitListener(&zdnsutil.TCPKeepAliveListener{Listener: listener}, config.DefaultServerGoroutineLimit),
			Handler:     handler,
			ReadTimeout: config.DefaultTCPIdleTimeout, // RFC 7766 §6.2.3
		}
		s.tcpServers = append(s.tcpServers, srv)
		g.Go(func() error {
			defer zdnsutil.HandlePanic("TCP server")
			err := srv.ListenAndServe()
			if err != nil {
				select {
				case <-ctx.Done():
					return nil
				default:
					return fmt.Errorf("TCP startup on %s: %w", addr, err)
				}
			}
			<-ctx.Done()
			return nil
		})
	}
	return nil
}
