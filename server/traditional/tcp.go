package traditional

import (
	"context"
	"fmt"
	"net"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/server/tls"

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
	for _, addr := range addrs {
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("TCP listen on %s: %w", addr, err)
		}

		srv := &dns.Server{
			Listener: &tls.TCPKeepAliveListener{Listener: listener},
			Handler:  handler,
		}
		s.tcpServers = append(s.tcpServers, srv)
		g.Go(func() error {
			defer zdnsutil.HandlePanic("TCP server")
			log.Infof("SERVER: TCP server started on %s", addr)
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
