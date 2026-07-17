package plain

import (
	"context"
	"fmt"
	"net"
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
	for _, addr := range addrs {
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("TCP listen on %s: %w", addr, err)
		}

		srv := &dns.Server{
			Listener: &zdnsutil.TCPKeepAliveListener{Listener: listener},
			Handler:  handler,
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
