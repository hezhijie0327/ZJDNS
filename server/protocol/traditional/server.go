// Package traditional implements plain DNS over UDP and TCP listeners.
package traditional

import (
	"context"
	"zjdns/config"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
)

// Group is the subset of errgroup.Group used by Start.
type Group interface {
	Go(func() error)
}

// Server manages plain UDP and TCP DNS listeners.
type Server struct {
	config     *config.ServerConfig
	udpServers []*dns.Server
	tcpServers []*dns.Server
}

// New creates a Server for plain DNS listeners.
func New(cfg *config.ServerConfig) *Server {
	return &Server{config: cfg}
}

// Start binds UDP and TCP sockets and starts DNS listeners.  Each listener runs
// in its own goroutine via the provided errgroup.
func (s *Server) Start(g Group, ctx context.Context, handler dns.Handler) error {
	if err := s.startUDP(g, ctx, handler); err != nil {
		return err
	}
	return s.startTCP(g, ctx, handler)
}

// Shutdown gracefully stops all UDP and TCP listeners.
func (s *Server) Shutdown(ctx context.Context) {
	for _, srv := range s.udpServers {
		if srv != nil {
			srv.Shutdown(ctx)
		}
	}
	if len(s.udpServers) > 0 {
		log.Infof("SERVER: UDP server(s) shut down")
	}
	for _, srv := range s.tcpServers {
		if srv != nil {
			srv.Shutdown(ctx)
		}
	}
	if len(s.tcpServers) > 0 {
		log.Infof("SERVER: TCP server(s) shut down")
	}
}
