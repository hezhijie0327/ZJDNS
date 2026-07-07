package server

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"
	"time"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
)

// startBackgroundTasks launches all background goroutines owned by the server.
func (s *Server) startBackgroundTasks() {
	s.startCookieRotation()
	s.startECSRefresh()
	s.startPrefetchCooldownCleanup()
	s.startTCPWriteMuSweep()
	s.setupSignalHandling()
}

// runBackgroundTicker runs fn on each tick of a time.Ticker with the given
// interval. The ticker is automatically stopped on return. Panics in fn are
// recovered and logged with the given name. Returns via backgroundCtx cancellation.
func (s *Server) runBackgroundTicker(name string, interval time.Duration, fn func()) {
	s.backgroundGroup.Go(func() error {
		defer zdnsutil.HandlePanic(name)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				fn()
			case <-s.backgroundCtx.Done():
				return nil
			}
		}
	})
}

// startCookieRotation rotates the DNS cookie secret on a fixed interval.
func (s *Server) startCookieRotation() {
	ednsH := s.handler.Edns()
	if ednsH == nil || ednsH.CookieGenerator == nil {
		return
	}
	s.runBackgroundTicker("DNS cookie secret rotation", config.DefaultCookieSecretRotationInterval, func() {
		ednsH.CookieGenerator.RotateSecret()
		log.Debugf("EDNS: rotated DNS cookie secret")
	})
}

// refreshECSOnce attempts a single ECS refresh and logs the result.
func (s *Server) refreshECSOnce() {
	ecsList, changed, err := s.handler.Edns().RefreshDefaultECS()
	if err != nil {
		log.Warnf("EDNS: default ECS refresh failed: %v", err)
		return
	}
	if !changed {
		return
	}
	for _, ecs := range ecsList {
		if ecs != nil {
			log.Infof("EDNS: refreshed default ECS: %s/%d", ecs.Address, ecs.SourcePrefix)
		}
	}
}

// startECSRefresh periodically refreshes the default EDNS Client Subnet value.
func (s *Server) startECSRefresh() {
	ednsH := s.handler.Edns()
	if ednsH == nil || !ednsH.ShouldRefreshDefaultECS() {
		return
	}
	s.backgroundGroup.Go(func() error {
		defer zdnsutil.HandlePanic("EDNS default ECS refresh")
		s.refreshECSOnce()
		ticker := time.NewTicker(config.DefaultECSRefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.refreshECSOnce()
			case <-s.backgroundCtx.Done():
				return nil
			}
		}
	})
}

// startPrefetchCooldownCleanup periodically evicts stale entries from the prefetch cooldown map.
func (s *Server) startPrefetchCooldownCleanup() {
	s.runBackgroundTicker("prefetch cooldown cleanup", config.DefaultPrefetchThrottleInterval*10, func() {
		now := log.NowUnixNano()
		cooldown, mu := s.handler.PrefetchCooldown()
		mu.Lock()
		for key, ts := range cooldown {
			if now > ts {
				delete(cooldown, key)
			}
		}
		mu.Unlock()
	})
}

// startTCPWriteMuSweep periodically removes stale tcpWriteMu entries.
func (s *Server) startTCPWriteMuSweep() {
	s.runBackgroundTicker("tcpWriteMu sweep", config.DefaultSweepInterval, func() {
		cutoff := time.Now().Add(-config.DefaultTCPWriteMuStaleCutoff).UnixNano()
		s.tcpWriteMu.Range(func(key, value any) bool {
			entry, ok := value.(*tcpWriteEntry)
			if !ok || entry.lastAccess.Load() < cutoff {
				s.tcpWriteMu.Delete(key)
			}
			return true
		})
	})
}

func (s *Server) setupSignalHandling() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		defer zdnsutil.HandlePanic("Signal handler")
		defer signal.Stop(sigChan)
		select {
		case sig := <-sigChan:
			log.Infof("SIGNAL: Received signal %v, starting graceful shutdown", sig)
			s.shutdownServer()
		case <-s.ctx.Done():
		}
	}()
}

func (s *Server) shutdownServer() {
	s.handler.MarkClosed()

	log.Infof("SERVER: Starting DNS server shutdown")

	if s.cancel != nil {
		s.cancel(errors.New("server shutdown"))
	}

	// Cache is intentionally closed AFTER background tasks and cache-refresh
	// goroutines finish, so that inflight cache writes during shutdown are
	// completed rather than silently dropped.

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), config.DefaultShutdownTimeout)
	defer shutdownCancel()
	for _, srv := range s.udpServers {
		if srv != nil {
			srv.Shutdown(shutdownCtx)
		}
	}
	if len(s.udpServers) > 0 {
		log.Infof("SERVER: UDP server(s) shut down")
	}
	for _, srv := range s.tcpServers {
		if srv != nil {
			srv.Shutdown(shutdownCtx)
		}
	}
	if len(s.tcpServers) > 0 {
		log.Infof("SERVER: TCP server(s) shut down")
	}

	if s.tls != nil {
		if err := s.tls.Shutdown(); err != nil {
			log.Errorf("TLS: TLS server shutdown failed: %v", err)
		}
	}

	if s.pprofServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), config.DefaultShutdownTimeout)
		defer cancel()
		if err := s.pprofServer.Shutdown(ctx); err != nil {
			log.Errorf("PPROF: pprof server shutdown failed: %v", err)
		} else {
			log.Infof("PPROF: pprof server shut down successfully")
		}
	}

	// Wait for background and cache-refresh goroutines BEFORE closing the
	// query client — inflight refresh/resolve goroutines need outbound
	// connections to complete.
	bgDone := make(chan error, 1)
	go func() {
		defer zdnsutil.HandlePanic("Background group wait")
		bgDone <- s.backgroundGroup.Wait()
	}()

	bgTimer := time.NewTimer(config.DefaultBackgroundShutdownTimeout)
	defer bgTimer.Stop()
	select {
	case err := <-bgDone:
		if err != nil {
			log.Errorf("SERVER: Background goroutines finished with error: %v", err)
		}
		log.Infof("SERVER: All background tasks shut down")
	case <-bgTimer.C:
		log.Errorf("SERVER: Background tasks shutdown timeout")
	}

	refreshDone := make(chan error, 1)
	go func() {
		defer zdnsutil.HandlePanic("Cache refresh group wait")
		refreshDone <- s.handler.CacheRefreshGroup().Wait()
	}()

	refreshTimer := time.NewTimer(config.DefaultBackgroundShutdownTimeout)
	defer refreshTimer.Stop()
	select {
	case err := <-refreshDone:
		if err != nil {
			log.Errorf("SERVER: Cache refresh goroutines finished with error: %v", err)
		}
		log.Infof("SERVER: All cache refresh tasks shut down")
	case <-refreshTimer.C:
		log.Errorf("SERVER: Cache refresh tasks shutdown timeout")
	}

	// Close latency prober before the query client — it owns HTTP/3
	// QUIC connections that must be released explicitly.
	if p := s.handler.Prober(); p != nil {
		p.Close()
	}

	// Close pooled connections and transports now that all background
	// goroutines (including cache refresh) have finished.
	if s.queryClient != nil {
		s.queryClient.Close()
	}

	if cacheStore := s.handler.CacheStore(); cacheStore != nil {
		zdnsutil.CloseWithLog(cacheStore, "Cache store", "SERVER")
	}

	log.DefaultTimeCache.Stop()

	if s.shutdown != nil {
		close(s.shutdown)
	}

	log.Infof("SERVER: Shutdown complete")
}
