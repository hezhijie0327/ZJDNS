// Package plain implements plain DNS over UDP and TCP listeners.
package plain

import (
	"context"
	"net"
	"sync"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
)

// Group is the subset of errgroup.Group used by Start.
type Group interface {
	Go(func() error)
}

// Server manages plain UDP and TCP DNS listeners.
type Server struct {
	config       *config.ServerConfig
	udpServers   []*dns.Server
	tcpMu        sync.Mutex
	tcpListeners []net.Listener
	tcpConns     map[net.Conn]struct{}
}

// New creates a Server for plain DNS listeners.
func New(cfg *config.ServerConfig) *Server {
	if cfg == nil {
		return &Server{config: config.NewDefaultServerConfig()}
	}
	return &Server{config: cfg}
}

// Start binds UDP and TCP sockets and starts DNS listeners.  UDP runs on the
// miekg/dns listener; TCP uses the hand-rolled pipelining loop (tcp.go).
func (s *Server) Start(g Group, ctx context.Context, udpHandler dns.Handler, tcpHandler edns.DNSHandler) error {
	log.Debugf("PLAIN: starting listeners (UDP=%s TCP=%s)", s.config.Server.Protocol.UDP, s.config.Server.Protocol.TCP)
	if err := s.startUDP(g, ctx, udpHandler); err != nil {
		return err
	}
	return s.startTCP(g, ctx, tcpHandler)
}

// Shutdown gracefully stops all UDP and TCP listeners.
func (s *Server) Shutdown(ctx context.Context) {
	for _, srv := range s.udpServers {
		if srv != nil {
			srv.Shutdown(ctx)
		}
	}
	if len(s.udpServers) > 0 {
		log.Infof("PLAIN: UDP server(s) shut down")
	}
	s.shutdownTCP()
}
