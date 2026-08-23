package server

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"
	"zjdns/cache"
	"zjdns/config"
	dnscryptcrypto "zjdns/internal/dnscryptcrypto"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/spillfile"
	"zjdns/internal/ttl"
)

// startBackgroundTasks launches all background goroutines owned by the server.
func (s *Server) startBackgroundTasks() {
	s.startCookieRotation()
	s.startECSRefresh()
	s.startPrefetchCooldownCleanup()
	s.startTCPWriteMuSweep()
	s.startPoolReap()
	s.startStateMaintenance()
	s.setupSignalHandling()
}

// startStateMaintenance periodically compacts the spill stores (dropping
// expired and over-cap records) and physically removes expired latency and
// delegation entries, when any state file is configured.  Spill records are
// written continuously on eviction, so no periodic save is needed — only
// compaction and expiry cleanup.
func (s *Server) startStateMaintenance() {
	feats := s.config.Server.Features
	cachePath, latencyPath, delegationPath := feats.CacheStateFile(), feats.LatencyStateFile(), feats.DelegationStateFile()
	if cachePath == "" && latencyPath == "" && delegationPath == "" {
		return
	}
	cacheStore := s.handler.CacheStore()
	if cacheStore == nil {
		return
	}
	cc, ok := cacheStore.(*cache.Cache)
	if !ok {
		return
	}

	s.runBackgroundTicker("state maintenance", config.DefaultCacheSnapshotInterval, func() {
		// Entries spill: rewrite when expired records dominate or the disk
		// cap is exceeded (dropping the oldest beyond cap).
		if spill := cc.SpillStore(); spill != nil {
			compactSpill(spill, cc.SpillCap())
		}
		if latencyPath != "" {
			// Physical expiry cleanup — gated on the latency state file (M7):
			// the cache-file branch is not the right owner, and a
			// latency-only deployment must still reap dead entries.
			cc.CleanupLatency()
			if spill := cc.LatencySpillStore(); spill != nil {
				compactSpill(spill, cc.LatencySpillCap())
			}
		}
		if delegationPath != "" {
			s.dnsResolver.CleanupDelegations()
			s.dnsResolver.CompactDelegationSpill()
		}
	})
}

// compactSpill rewrites a spill store keeping only fresh records, newest
// first within the disk cap (cap <= 0 = unbounded).  Runs when expired
// records dominate the index (> 50%) or the index exceeds the cap.
func compactSpill(spill *spillfile.Store, diskCap int) {
	entries := spill.Entries()
	if len(entries) == 0 {
		return
	}
	expired := 0
	for _, e := range entries {
		if !ttl.CanServeExpired(e.Ts, e.Ttl, config.DefaultStaleMaxAge) {
			expired++
		}
	}
	if expired*2 <= len(entries) && (diskCap <= 0 || len(entries) <= diskCap) {
		return // nothing worth rewriting
	}

	// Newest-first traversal — the disk cap keeps the newest fresh records.
	sort.Slice(entries, func(i, j int) bool { return entries[i].Ts > entries[j].Ts })
	keepSize := len(entries)
	if diskCap > 0 {
		keepSize = min(diskCap, keepSize)
	}
	keep := make(map[string]bool, keepSize)
	for _, e := range entries {
		if !ttl.CanServeExpired(e.Ts, e.Ttl, config.DefaultStaleMaxAge) { // past window — drop
			continue
		}
		if diskCap > 0 && len(keep) >= diskCap {
			break
		}
		keep[e.Key] = true
	}
	if err := spill.Compact(func(key string, _ int64, _ int) bool { return keep[key] }); err != nil {
		log.Warnf("CACHE: spill compact failed: %v", err)
	}
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

// startPoolReap periodically drops dead sockets/connections from all
// outbound pools — an idle-recycled socket otherwise stays pinned under its
// address key (counting against the global cap) until that address is
// queried again.  The short interval keeps dead sockets from starving the
// pools' caps between queries.
func (s *Server) startPoolReap() {
	s.runBackgroundTicker("pool reap", config.DefaultPoolReapInterval, func() {
		if s.queryClient != nil {
			s.queryClient.ReapDeadConns()
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
		s.sweepTCPWriteMu(time.Now().Add(-config.DefaultTCPWriteMuStaleCutoff).UnixNano())
	})
}

// sweepTCPWriteMu deletes TCP write-registry entries with no in-flight
// references whose last access predates the cutoff.
func (s *Server) sweepTCPWriteMu(cutoff int64) {
	// The refs==0 check and the delete are one critical section per shard
	// (the request path lookup-or-creates + adds its in-flight ref under the
	// same shard lock). Without this, a request arriving between check and
	// delete would hold a writeMu detached from the map while the next
	// request created a second one — two writers interleaving
	// length-prefixed frames on the same TCP stream.
	for i := range s.tcpWriteShards {
		shard := &s.tcpWriteShards[i]
		shard.mu.Lock()
		for addr, entry := range shard.entries {
			// Only delete entries with no in-flight references.
			if entry.refs.Load() != 0 {
				continue
			}
			if entry.lastAccess.Load() < cutoff {
				delete(shard.entries, addr)
			}
		}
		shard.mu.Unlock()
	}
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
			// ErrServerNotStarted is benign: a signal can arrive between
			// New() and listener start (M-low).
			if errors.Is(err, dnscryptcrypto.ErrServerNotStarted) {
				log.Debugf("DNSCRYPT: server not started, skipping shutdown")
			} else {
				log.Errorf("DNSCRYPT: shutdown failed: %v", err)
			}
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

	if s.sharedManager != nil {
		s.sharedManager.Shutdown()
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
		// Push the in-memory tiers to their spill stores before closing
		// (entries + latency; the delegation spill flushes in the resolver's
		// own shutdown hook).  Bounded by DefaultShutdownTimeout: a stalled
		// disk must not hang shutdown forever (L3).
		saveDone := make(chan struct{})
		go func() {
			defer zdnsutil.HandlePanic("Shutdown state save")
			defer close(saveDone)
			cc, ok := cacheStore.(*cache.Cache)
			if !ok {
				return
			}
			cc.Flush()
			s.dnsResolver.FlushDelegationSpill()
		}()
		select {
		case <-saveDone:
		case <-time.After(config.DefaultShutdownTimeout):
			log.Warnf("SERVER: state flush timed out — exiting without final spill flush")
		}
		zdnsutil.CloseWithLog(cacheStore, "Cache store", "SERVER")
	}

	if s.shutdown != nil {
		// Idempotent: the signal handler and the shutdown-timeout path can
		// both reach here — a second close would panic (M-3-6).
		s.shutdownOnce.Do(func() { close(s.shutdown) })
	}

	log.Infof("SERVER: Shutdown complete")

	log.DefaultTimeCache.Stop()
}
