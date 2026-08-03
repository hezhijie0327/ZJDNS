// Package plain implements plain DNS over UDP and TCP listeners.
package plain

import (
	"context"
	"errors"
	"sync"
	"time"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
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
	mu           sync.Mutex // guards the listener slices (Start appends, Shutdown iterates)
	shutdownOnce sync.Once  // miekg's dns.Server.Shutdown panics on double-close
	udpServers   []*dns.Server
	tcpServers   []*dns.Server
}

// New creates a Server for plain DNS listeners.
func New(cfg *config.ServerConfig) *Server {
	if cfg == nil {
		return &Server{config: config.NewDefaultServerConfig()}
	}
	return &Server{config: cfg}
}

// Start binds UDP and TCP sockets and starts DNS listeners.  Each listener runs
// in its own goroutine via the provided errgroup.
func (s *Server) Start(g Group, ctx context.Context, handler dns.Handler) error {
	if g == nil || handler == nil {
		return errors.New("plain: nil group or handler")
	}
	log.Debugf("PLAIN: starting listeners (UDP=%s TCP=%s)", s.config.Server.Protocol.UDP, s.config.Server.Protocol.TCP)
	if err := s.startUDP(g, ctx, handler); err != nil {
		return err
	}
	return s.startTCP(g, ctx, handler)
}

// Shutdown gracefully stops all UDP and TCP listeners. miekg's dns.Server
// Shutdown returns no error, so drain failures are surfaced via the context:
// if the deadline expires while connections are still draining, that is
// logged (the old code logged success unconditionally).
func (s *Server) Shutdown(ctx context.Context) {
	// The ctx watcher (startup-failure cleanup) and the server's shutdown
	// path can both fire; miekg's Shutdown is not idempotent.
	s.shutdownOnce.Do(func() {
		s.shutdownLocked(ctx)
	})
}

func (s *Server) shutdownLocked(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	const shutdownTimeout = 10 * time.Second
	for _, srv := range s.udpServers {
		if srv != nil {
			s.shutdownOne(srv, shutdownTimeout, "UDP")
		}
	}
	if len(s.udpServers) > 0 {
		log.Infof("PLAIN: UDP server(s) shut down")
	}
	for _, srv := range s.tcpServers {
		if srv != nil {
			s.shutdownOne(srv, shutdownTimeout, "TCP")
		}
	}
	if len(s.tcpServers) > 0 {
		log.Infof("PLAIN: TCP server(s) shut down")
	}
}

// shutdownOne calls dns.Server.Shutdown with a deadline because miekg's
// Shutdown ignores its context argument and blocks on the server's internal
// exited channel — which waits for all connection handlers to finish, which
// can take arbitrarily long for slow upstream queries.
func (s *Server) shutdownOne(srv *dns.Server, timeout time.Duration, label string) {
	done := make(chan struct{})
	go func() {
		defer zdnsutil.HandlePanic("plain shutdown " + label)
		srv.Shutdown(context.Background())
		close(done)
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		log.Warnf("PLAIN: %s server shutdown timed out after %v", label, timeout)
	}
}
