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
	s.startQueryJournalCleanup()
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
	ednsH := s.handler.EDNS()
	if ednsH == nil || ednsH.CookieGenerator == nil {
		return
	}
	s.runBackgroundTicker("DNS cookie secret rotation", config.DefaultCookieSecretRotationInterval, func() {
		if err := ednsH.CookieGenerator.RotateSecret(); err != nil {
			log.Warnf("EDNS: cookie secret rotation failed: %v", err)
			return
		}
		log.Debugf("EDNS: rotated DNS cookie secret")
	})
}

// refreshECSOnce attempts a single ECS refresh and logs the result.
func (s *Server) refreshECSOnce() {
	ednsH := s.handler.EDNS()
	if ednsH == nil {
		return
	}
	ecsList, changed, err := ednsH.RefreshDefaultECS()
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
	ednsH := s.handler.EDNS()
	if ednsH == nil || !ednsH.ShouldRefreshDefaultECS() {
		return
	}
	s.backgroundGroup.Go(func() error {
		defer zdnsutil.HandlePanic("EDNS default ECS refresh")
		// Skip the initial refresh if shutdown was already triggered — the
		// ECS lookup is a network round trip that must not run after close.
		select {
		case <-s.backgroundCtx.Done():
			return nil
		default:
		}
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
		s.handler.PrefetchCooldown().Cleanup(log.NowUnixNano(), config.DefaultPrefetchThrottleInterval.Nanoseconds())
	})
}

// startTCPWriteMuSweep periodically removes stale tcpWriteMu entries.
func (s *Server) startTCPWriteMuSweep() {
	s.runBackgroundTicker("tcpWriteMu sweep", config.DefaultSweepInterval, func() {
		cutoff := time.Now().Add(-config.DefaultTCPWriteMuStaleCutoff).UnixNano()
		var stale []string
		s.tcpWriteMu.Range(func(key, value any) bool {
			entry, ok := value.(*tcpWriteEntry)
			if !ok {
				stale = append(stale, key.(string))
				return true
			}
			// Only delete entries with no in-flight references: a
			// freshly-created entry (lastAccess 0) whose handler
			// goroutine is still running must not be recreated with a
			// separate writeMu — two writers would then race on the
			// same TCP stream, interleaving length-prefixed frames.
			if entry.refs.Load() != 0 {
				return true
			}
			if entry.lastAccess.Load() < cutoff {
				stale = append(stale, key.(string))
			}
			return true
		})
		for _, k := range stale {
			s.tcpWriteMu.Delete(k)
		}
	})
}

// startQueryJournalCleanup periodically removes stale query_stats and query_log
// rows to prevent unbounded disk growth.  Interval and retention are controlled
// by config.DefaultPruneInterval and config.DefaultQueryJournalRetention.
func (s *Server) startQueryJournalCleanup() {
	if s.handler == nil || s.handler.CacheStore() == nil {
		return
	}
	s.runBackgroundTicker("query journal cleanup", config.DefaultPruneInterval, func() {
		store := s.handler.CacheStore()
		n, err := store.PruneQueryJournal(config.DefaultQueryJournalRetention)
		if err != nil {
			log.Warnf("CACHE: query journal cleanup failed: %v", err)
			return
		}
		if n > 0 {
			log.Debugf("CACHE: cleaned up %d stale rows (query_stats + query_log)", n)
		}
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
	// NOTE: This goroutine is not tracked in any errgroup or WaitGroup.
	// It exits cleanly when sigChan receives or s.ctx is cancelled.
	// If Wait() dependencies are added to shutdownServer, this goroutine
	// must be tracked to avoid a shutdown hang.
}

func (s *Server) shutdownServer() {
	s.handler.MarkClosed()

	log.Infof("SERVER: Starting DNS server shutdown")

	// NOTE: This function does NOT wait for the protocol server errgroup (g)
	// created in Start(). That errgroup's goroutines (TLS, DNSCrypt, TLCP,
	// plain listeners) exit when their contexts are cancelled below. The
	// coordinator goroutine that calls g.Wait() is also orphaned — the
	// shutdown path uses cancel-only signalling instead of a coordinated
	// group wait.

	if s.cancel != nil {
		s.cancel(errors.New("server shutdown"))
	}

	// Cache is intentionally closed AFTER background tasks and cache-refresh
	// goroutines finish, so that inflight cache writes during shutdown are
	// completed rather than silently dropped.

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), config.DefaultShutdownTimeout)
	defer shutdownCancel()
	s.plain.Shutdown(shutdownCtx)

	if s.tls != nil {
		if err := s.tls.Shutdown(); err != nil {
			log.Errorf("TLS: TLS server shutdown failed: %v", err)
		}
	}

	if s.dnscryptServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), config.DefaultShutdownTimeout)
		defer cancel()
		if err := s.dnscryptServer.Shutdown(ctx); err != nil {
			log.Errorf("DNSCRYPT: shutdown failed: %v", err)
		} else {
			log.Infof("DNSCRYPT: server shut down successfully")
		}
	}

	for _, p := range s.pprofServers {
		ctx, cancel := context.WithTimeout(context.Background(), config.DefaultShutdownTimeout)
		if err := p.Shutdown(ctx); err != nil {
			log.Errorf("PPROF: pprof server shutdown failed: %v", err)
		}
		cancel()
	}

	if s.tlcpServer != nil {
		if err := s.tlcpServer.Shutdown(); err != nil {
			log.Errorf("TLCP: shutdown failed: %v", err)
		} else {
			log.Infof("TLCP: server shut down successfully")
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
			log.Warnf("SERVER: Background goroutines finished with error: %v", err)
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
			log.Warnf("SERVER: Cache refresh goroutines finished with error: %v", err)
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

	if s.shutdown != nil {
		close(s.shutdown)
	}

	log.Infof("SERVER: Shutdown complete")

	log.DefaultTimeCache.Stop()
}
