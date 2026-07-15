package traditional

import (
	"context"
	"fmt"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"

	"codeberg.org/miekg/dns"
)

func (s *Server) startUDP(g Group, ctx context.Context, handler dns.Handler) error {
	if s.config.Server.Protocol.UDP == "" {
		return nil
	}

	addrs, err := zdnsutil.ResolveBindAddrs(config.ProtoUDP, s.config.Server.Protocol.UDP)
	if err != nil {
		return fmt.Errorf("UDP address resolution: %w", err)
	}
	for _, addr := range addrs {
		srv := &dns.Server{
			Addr:    addr,
			Net:     config.ProtoUDP,
			Handler: handler,
			UDPSize: pool.UDPBufferSize,
		}
		s.udpServers = append(s.udpServers, srv)
		g.Go(func() error {
			defer zdnsutil.HandlePanic("UDP server")
			log.Infof("SERVER: UDP server started on %s", addr)
			err := srv.ListenAndServe()
			if err != nil {
				select {
				case <-ctx.Done():
					return nil
				default:
					return fmt.Errorf("UDP startup on %s: %w", addr, err)
				}
			}
			<-ctx.Done()
			return nil
		})
	}
	return nil
}
