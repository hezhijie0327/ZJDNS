package resolver

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"strings"
	"sync/atomic"
	"time"
	"zjdns/config"
	"zjdns/edns"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	"zjdns/server/resolver/dnssec"
	"zjdns/server/upstream"

	"codeberg.org/miekg/dns"
	"golang.org/x/sync/errgroup"
)

// captureUpstreamEDE extracts the EDE option from an upstream response for
// passthrough to downstream clients. Upstream resolvers attach EDE codes
// (e.g. DNSSEC Bogus) to any rcode. The copied EDE is RETURNED so the caller
// carries it per-goroutine into its own result — reloading the shared atomic
// at send time can attribute a DIFFERENT upstream's EDE to the winning
// response (a slower SERVFAIL/DNSSEC-bogus responder could Store after this
// one captured). The atomic is still updated for the all-servers-failed
// fallback path.
func captureUpstreamEDE(lastEDE *atomic.Pointer[dns.EDE], resp *dns.Msg, serverAddr string) *dns.EDE {
	if resp == nil {
		return nil
	}
	for _, rr := range resp.Pseudo {
		if ede, ok := rr.(*dns.EDE); ok {
			// Copy the EDE out of the pooled response — the source server
			// stays in the Debug log, not in client-facing ExtraText
			// (RFC 8914 §3: forwarding is implementation dependent).
			copied := &dns.EDE{InfoCode: ede.InfoCode, ExtraText: ede.ExtraText}
			lastEDE.Store(copied)
			log.Debugf("UPSTREAM: captured EDE %d (%s) from %s (rcode=%s)",
				ede.InfoCode, dns.ExtendedErrorToString[ede.InfoCode], serverAddr, dns.RcodeToString[resp.Rcode])
			return copied
		}
	}
	return nil
}

// isSecureUpstream reports whether an upstream uses an encrypted transport
// where hijacking is impossible and first-wins needs no defense gating.
// DNSCrypt carries its own crypto on the DNS layer — not a TLS transport.
func isSecureUpstream(server *config.UpstreamServer) bool {
	return zdnsutil.IsSecureProtocol(server.Protocol) &&
		server.Protocol != config.ProtoDNSCrypt &&
		server.Protocol != config.ProtoDNSCryptTCP
}

func (r *Resolver) queryUpstream(ctx context.Context, question Question, ecs *edns.ECSOption, servers []*config.UpstreamServer) QueryResult {
	if len(servers) == 0 {
		return QueryResult{Err: errors.New("no upstream servers")}
	}

	// Per-query EDE capture — avoids cross-query data race on the resolver.
	var lastUpstreamEDE atomic.Pointer[dns.EDE]

	if log.Default.Level() >= log.Debug {
		serverAddrs := make([]string, 0, len(servers))
		for _, s := range servers {
			proto := s.Protocol
			if proto == "" {
				proto = config.ProtoUDP
			}
			serverAddrs = append(serverAddrs, fmt.Sprintf("%s(%s)", s.Address, proto))
		}
		log.Debugf("UPSTREAM: querying %d servers for %s: %v", len(servers), question.Name, serverAddrs)
	}

	// Fallback upstreams race from t=0 but are only adopted after the
	// fallback timeout elapses without a usable primary result.  When
	// present, the fan-out runs under a detached context (primaryCtx) so
	// the primaries survive the adoption return and background-fill the
	// cache with the first late primary result.
	hasFallback := false
	for _, s := range servers {
		if s.Fallback {
			hasFallback = true
			break
		}
	}
	// After adoption the wait loop is gone but late primary senders still
	// deliver — size the buffer so their send never blocks.
	chanCap := 1
	if hasFallback {
		chanCap = len(servers)
	}
	resultChan := make(chan QueryResult, chanCap)
	var nxdomainResult atomic.Pointer[QueryResult]
	// nxdomainCh wakes the wait loop on the first collected NXDOMAIN so the
	// deferral window starts from the earliest possible instant.
	nxdomainCh := make(chan struct{}, 1)
	queryCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(errors.New("query completed"))

	fanoutParent := queryCtx
	var coord *fallbackCoord
	if hasFallback {
		primaryCtx, primaryCancel := context.WithCancelCause(ctx)
		coord = &fallbackCoord{
			fallbackReady: make(chan struct{}, 1),
			cancelPrimary: primaryCancel,
			question:      question,
			ecs:           ecs,
		}
		// Non-adoption returns (primary win, NXDOMAIN, all-failed) cancel
		// the detached primaries; after adoption the background fill owns
		// the cancel (fillCacheFromResult).
		defer func() {
			if !coord.adopted.Load() {
				primaryCancel(errors.New("query completed"))
			}
		}()
		fanoutParent = primaryCtx
	}

	g, groupCtx := errgroup.WithContext(fanoutParent)
	// No query cap: SetLimit made the launch loop block once the limit was
	// reached, delaying first-wins until a queued slot freed (a rate-limited
	// upstream — common for public resolvers under burst — held its slot for
	// the full query timeout while healthy peers queued).  First-wins is
	// served the instant any upstream answers; cancel() aborts the rest.

	var activeConnections atomic.Int32
	var cidrFilterRefused atomic.Bool
	// activePrimaries counts not-yet-exited primary (non-fallback) workers.
	// When it reaches zero no primary result can arrive anymore, so the
	// fallback adoption gate has nothing left to protect: primariesDone
	// wakes the wait loop to adopt the stash immediately instead of idling
	// out the rest of the fallback timeout (a dead primary plus a 30 ms
	// fallback previously still cost the client the full gate).
	activePrimaries := make(chan struct{})
	var nPrimaries atomic.Int32
	finishPrimary := func() {
		if nPrimaries.Add(-1) == 0 {
			close(activePrimaries)
		}
	}

	// One base query per connection class (plain vs secure), built once
	// before the fan-out: the EDNS options (ECS, padding) are identical for
	// every upstream of a class — per-server variation is only the RFC 10029
	// MQTYPE list, appended to each copy.  Sharing avoids N-1 wasted
	// ApplyToMessage + padding passes under a multi-upstream fan-out
	// (mirrors the recursive walk's baseMsg pattern).
	var needPlain, needSecure bool
	for _, s := range servers {
		if s.IsRecursive() {
			continue
		}
		if isSecureUpstream(s) {
			needSecure = true
		} else {
			needPlain = true
		}
	}
	var basePlain, baseSecure *dns.Msg
	if needPlain {
		basePlain = r.buildMsg(question, ecs, true, false)
	}
	if needSecure {
		baseSecure = r.buildMsg(question, ecs, true, true)
	}

	//nolint:gosec // non-crypto random for server load balancing
	startIdx := rand.IntN(len(servers))
	for i := range servers {
		srv := servers[(startIdx+i)%len(servers)]
		server := srv
		if !server.Fallback {
			nPrimaries.Add(1)
		}

		g.Go(func() error {
			defer zdnsutil.HandlePanic("UPSTREAM query")
			if !server.Fallback {
				defer finishPrimary()
			}
			select {
			case <-groupCtx.Done():
				return nil
			default:
			}

			activeConnections.Add(1)
			defer activeConnections.Add(-1)

			// Fallback queries run under the request context so the
			// adoption return cancels them; primaries run under the fan-out
			// context (detached after adoption for the background fill).
			execCtx := groupCtx
			if server.Fallback {
				execCtx = queryCtx
			}

			switch {
			case server.IsRecursive():
				if handled := r.handleRecursiveQuery(execCtx, server, question, ecs, resultChan, cancel, &cidrFilterRefused, coord); handled {
					return nil
				}

			default:
				// TCP/TLS/other: encrypted or single-response —
				// no hijacking possible, first-wins is fine.
				base := basePlain
				if isSecureUpstream(server) {
					base = baseSecure
				}
				msg := pool.DefaultMessage.Get()
				// Copy the shared base (the pooled msg starts nil, so each
				// copy owns its Question/Pseudo backing arrays — no shared
				// array between workers).
				if len(base.Question) > 0 {
					msg.Question = append(msg.Question, base.Question[0])
				}
				msg.RecursionDesired = base.RecursionDesired
				msg.CheckingDisabled = base.CheckingDisabled
				msg.Security = base.Security
				msg.CompactAnswers = base.CompactAnswers
				msg.UDPSize = base.UDPSize
				msg.Pseudo = append(msg.Pseudo, base.Pseudo...)
				// RFC 10029: attach the configured list minus the primary
				// QTYPE.  Client MQTYPE-Query options are never forwarded —
				// the server-side MQTYPE middleware merges locally.
				attachMQType(msg, server.MQType, question.Qtype)
				queryResult := r.queryClient.ExecuteQuery(execCtx, msg, server)
				// RFC 10029 fallback, mirroring the recursive walk
				// (nameserver.go): an upstream that drops, times out or
				// refuses MQTYPE-Query queries — observed in the wild with
				// CN public resolvers returning SERVFAIL for the unknown
				// EDNS option — answers the optionless retry.  "operation
				// was canceled" is a normal first-success race, not a
				// failure.  The retry carries its own fresh timeout so an
				// exhausted execCtx cannot block it.
				if hasMQQUERY(msg.Pseudo) &&
					!errors.Is(queryResult.Error, context.Canceled) &&
					(queryResult.Error != nil || (queryResult.Response != nil &&
						queryResult.Response.Rcode != dns.RcodeSuccess && queryResult.Response.Rcode != dns.RcodeNameError)) {
					if queryResult.Response != nil {
						pool.DefaultMessage.Put(queryResult.Response)
					}
					msg.Pseudo = removeMQQUERY(msg.Pseudo)
					retryCtx, retryCancel := context.WithTimeout(context.WithoutCancel(ctx), config.DefaultMQTypeResolveTimeout)
					queryResult = r.queryClient.ExecuteQuery(retryCtx, msg, server)
					retryCancel()
				}
				pool.DefaultMessage.Put(msg)

				if queryResult.Error == nil && queryResult.Response != nil {
					if handled := r.processUpstreamResponse(queryResult, server, question, resultChan, &nxdomainResult, nxdomainCh, &activeConnections, cancel, groupCtx, &cidrFilterRefused, &lastUpstreamEDE, coord); handled {
						return nil
					}
				}
			}
			return nil
		})
	}

	go func() {
		defer zdnsutil.HandlePanic("UPSTREAM errgroup wait")
		_ = g.Wait() // _ = error: upstream fan-out errors surface per-query via resultChan; group errors are best-effort
		// basePlain/baseSecure are read by every worker (including stragglers
		// still winding down) — return them here, after g.Wait, so no worker
		// reads a pooled message that was already zeroed or reused (mirrors
		// the recursive walk's baseMsg lifecycle).
		if basePlain != nil {
			pool.DefaultMessage.Put(basePlain)
		}
		if baseSecure != nil {
			pool.DefaultMessage.Put(baseSecure)
		}
		if cidrFilterRefused.Load() {
			select {
			case resultChan <- QueryResult{Err: ErrCIDRFilterRefused}:
			default:
			}
		}
		close(resultChan)
	}()

	// First-wins: wait for the first successful result from any upstream.
	// The first collected NXDOMAIN arms a bounded deferral window
	// (DefaultNXDOMAINDeferralWindow, 0 = serve immediately — GFW pollution
	// toward trusted forwarding resolvers is A/AAAA injection, not NXDOMAIN;
	// spoofguard covers the injection case).  Without the early return, an
	// all-NXDOMAIN fan-out waited for EVERY upstream — one hung resolver
	// (9s timeout) delayed a 10ms NXDOMAIN to its full tail.
	var deferralTimer *time.Timer
	var deferralCh <-chan time.Time
	defer func() {
		if deferralTimer != nil {
			deferralTimer.Stop()
		}
	}()
	// Fallback adoption gate: until the timer fires, fallback results only
	// accumulate in the stash (the fallbackReady case is a no-op); once it
	// fires, tryAdopt serves any pending primary first, then the stash.
	var fallbackTimer *time.Timer
	var fallbackCh <-chan time.Time
	var fallbackReadyCh <-chan struct{}
	// primariesDoneCh is nil without fallbacks — a nil channel blocks
	// forever, disabling the early-adoption case.
	var primariesDoneCh <-chan struct{}
	fallbackFired := false
	if coord != nil {
		fallbackTimeout := r.fallbackTimeout
		if fallbackTimeout <= 0 {
			fallbackTimeout = config.DefaultFallbackTimeout
		}
		fallbackTimer = time.NewTimer(fallbackTimeout)
		fallbackCh = fallbackTimer.C
		fallbackReadyCh = coord.fallbackReady
		primariesDoneCh = activePrimaries
		defer fallbackTimer.Stop()
	}
waitLoop:
	for {
		select {
		case res, ok := <-resultChan:
			if ok {
				if errors.Is(res.Err, ErrCIDRFilterRefused) {
					return QueryResult{Err: ErrCIDRFilterRefused}
				}
				if res.Server != "" {
					return res
				}
				continue
			}
			break waitLoop
		case <-fallbackCh:
			fallbackFired = true
			if res, done := coord.tryAdopt(resultChan, &nxdomainResult); done {
				return res
			}
			// Timer fired before any fallback result landed — phase 2:
			// keep racing; the fallbackReady case re-checks on arrival and
			// primary results keep winning through the cases above.
		case <-primariesDoneCh:
			// Every primary exited without delivering a usable result —
			// no primary answer can arrive anymore, so the gate has
			// nothing left to protect.  Same semantics as the timer
			// firing, just earlier.
			fallbackFired = true
			if res, done := coord.tryAdopt(resultChan, &nxdomainResult); done {
				return res
			}
		case <-fallbackReadyCh:
			if fallbackFired {
				if res, done := coord.tryAdopt(resultChan, &nxdomainResult); done {
					return res
				}
			}
		case <-nxdomainCh:
			if deferralTimer == nil {
				deferralTimer = time.NewTimer(config.DefaultNXDOMAINDeferralWindow)
				deferralCh = deferralTimer.C
			}
		case <-deferralCh:
			// A NOERROR winner may have landed concurrently with the
			// deferral firing — serve it first (mirrors the recursive
			// walk's winner drain).
			select {
			case res, ok := <-resultChan:
				if ok {
					if errors.Is(res.Err, ErrCIDRFilterRefused) {
						return QueryResult{Err: ErrCIDRFilterRefused}
					}
					if res.Server != "" {
						return res
					}
				}
			default:
			}
			if nx := nxdomainResult.Load(); nx != nil && nx.Server != "" {
				return *nx
			}
			continue
		case <-queryCtx.Done():
			// When processUpstreamResponse cancels queryCtx after sending
			// a result to resultChan, the select can pick either branch.
			// Drain any pending result from the buffered channel before
			// falling back to the timeout/error path.
			select {
			case res, ok := <-resultChan:
				if ok {
					if errors.Is(res.Err, ErrCIDRFilterRefused) {
						return QueryResult{Err: ErrCIDRFilterRefused}
					}
					if res.Server != "" {
						return res
					}
				}
			default:
			}
			// Check for captured EDE codes here too so they are
			// not lost to a "context canceled" error.
			if opt := lastUpstreamEDE.Load(); opt != nil {
				return QueryResult{Err: dnssecEDEError(uint64(opt.InfoCode)), UpstreamEDE: opt}
			}
			return QueryResult{Err: queryCtx.Err()}
		}
	}

	// All upstreams finished without a first-win: NXDOMAIN fallback (the
	// deferral may have been bypassed), then a stashed fallback answer
	// (it may have landed as the fan-out closed — the closed-channel case
	// can win the select race against fallbackReady), then EDE, then failure.
	if nxRes := nxdomainResult.Load(); nxRes != nil && nxRes.Server != "" {
		return *nxRes
	}
	if coord != nil {
		if fb := coord.fallbackResult.Load(); fb != nil {
			coord.adopted.Store(true)
			return *fb
		}
	}
	// Propagate any EDE code captured from upstream SERVFAIL.
	if opt := lastUpstreamEDE.Load(); opt != nil {
		log.Debugf("UPSTREAM: all %d servers failed for %s, propagating EDE %d", len(servers), question.Name, opt.InfoCode)
		return QueryResult{Err: dnssecEDEError(uint64(opt.InfoCode)), UpstreamEDE: opt}
	}
	log.Debugf("UPSTREAM: all %d servers failed for %s", len(servers), question.Name)
	return QueryResult{Err: errors.New("all upstream queries failed")}
}

func (r *Resolver) filterRecordsByCIDR(records []dns.RR, matchTags []string) ([]dns.RR, bool) {
	if r.crd == nil || len(matchTags) == 0 {
		return records, false
	}

	// Pre-filter tags: keep only those that have CIDR rules so we call
	// HasIPTag once per tag instead of once per record per tag.
	type tagKey struct {
		raw string
	}
	ipTags := make([]tagKey, 0, len(matchTags))
	for _, t := range matchTags {
		name := t
		if t != "" && t[0] == '!' {
			name = t[1:]
		}
		if r.crd.HasIPTag(name) {
			ipTags = append(ipTags, tagKey{raw: t})
		}
	}

	filtered := make([]dns.RR, 0, len(records))
	for _, rr := range records {
		var ip net.IP
		switch record := rr.(type) {
		case *dns.A:
			ip = net.IP(record.Addr.AsSlice())
		case *dns.AAAA:
			ip = net.IP(record.Addr.AsSlice())
		default:
			filtered = append(filtered, rr)
			continue
		}

		// AND semantics: every pre-filtered tag must be satisfied. The old
		// accept-on-first-match let a record inside tagB but outside tagA
		// bypass a negated '!tagA' rule (the negate field was never used).
		accepted := len(ipTags) == 0
		ipStr := ip.String()
		for _, t := range ipTags {
			matched, exists := r.crd.MatchIP(ipStr, t.raw)
			if !exists {
				return nil, true
			}
			if !matched {
				accepted = false
				break
			}
		}
		if accepted {
			filtered = append(filtered, rr)
		}
	}
	if len(filtered) == 0 {
		return nil, true
	}
	return filtered, false
}

// processUpstreamResponse handles the response from a forwarding upstream server.
//
// RFC 8767 §4 note: the AA-bit check for stale refresh applies only to authoritative
// answers. ZJDNS in forwarding mode queries recursive resolvers (always AA=0), so the
// check is intentionally skipped — it would incorrectly reject all recursive responses.
// Returns true if the goroutine should return (result sent or handled).
func (r *Resolver) processUpstreamResponse(queryResult *upstream.Result, server *config.UpstreamServer, question Question, resultChan chan<- QueryResult, nxdomainResult *atomic.Pointer[QueryResult], nxdomainCh chan<- struct{}, activeConnections *atomic.Int32, cancel context.CancelCauseFunc, groupCtx context.Context, cidrFilterRefused *atomic.Bool, lastEDE *atomic.Pointer[dns.EDE], coord *fallbackCoord) bool {
	// RFC 5452 §9.3: reject responses that do not echo the query's question.
	// The forwarding path already checks the response ID (spoofguard); the
	// question echo closes the cross-name replay variant (R3-H1).
	if !responseEchoesQuestion(queryResult.Response, question) {
		log.Debugf("UPSTREAM: %s question echo mismatch for %s %s", server.Address, question.Name, dns.TypeToString[question.Qtype])
		pool.DefaultMessage.Put(queryResult.Response)
		return false
	}
	rcode := queryResult.Response.Rcode
	serverDesc := server.Address
	if server.Protocol != "" && server.Protocol != config.ProtoUDP {
		serverDesc = server.Address + " (" + strings.ToUpper(server.Protocol) + ")"
	}

	upstreamEDE := captureUpstreamEDE(lastEDE, queryResult.Response, server.Address)
	// A cascaded ZJDNS marks fallback-served responses with its private EDE
	// — adopt them as ordinary first-wins results but never cache them (the
	// marker keeps propagating to our own clients).
	fallbackMarked := edns.IsFallbackEDE(upstreamEDE)

	// RFC 10029: the configured mqtype list warms the cache with the
	// upstream's merged records and strips them from the client-facing
	// response.  Client-sent MQTYPE-Query options never reach here — the
	// server-side MQTYPE middleware merges locally.
	mqr, mqInvalid := parseMQResponse(queryResult.Response)

	switch rcode {
	case dns.RcodeSuccess:
		if len(server.Match) > 0 {
			filteredAnswer, shouldRefuse := r.filterRecordsByCIDR(queryResult.Response.Answer, server.Match)
			if shouldRefuse {
				cidrFilterRefused.Store(true)
				pool.DefaultMessage.Put(queryResult.Response)
				return false
			}
			queryResult.Response.Answer = filteredAnswer
		}

		queryResult.Validated = dnssec.IsResponseValid(queryResult.Response, true)
		log.Debugf("UPSTREAM: DNSSEC validation result=%t for %s via %s", queryResult.Validated, question.Name, server.Address)
		ecsResponse := r.edns.ParseFromDNS(queryResult.Response)

		// RFC 9824 §5.1: the upstream may answer with a compact NODATA
		// (NOERROR + NSEC/NSEC3 NXNAME signal) for a nonexistent name — we
		// set the CO bit on upstream queries, so restore the NXDOMAIN
		// semantic before serving.
		rcode := uint16(dns.RcodeSuccess)
		if dnssec.HasCompactNXNAME(queryResult.Response) {
			log.Debugf("UPSTREAM: compact NODATA with NXNAME signal for %s via %s — restoring NXDOMAIN", question.Name, server.Address)
			rcode = dns.RcodeNameError
		}

		// Fallback upstreams never win the race directly: their result is
		// stashed and only adopted after the fallback timeout.  Never
		// cacheable, always marked with the ZJDNS fallback EDE.
		if server.Fallback {
			coord.stash(&QueryResult{
				Answer:        queryResult.Response.Answer,
				Authority:     queryResult.Response.Ns,
				Additional:    queryResult.Response.Extra,
				Validated:     queryResult.Validated,
				Authoritative: queryResult.Response.Authoritative,
				Cacheable:     false,
				ECS:           ecsResponse,
				Server:        serverDesc,
				UpstreamEDE:   fallbackMarkEDE(),
				Truncated:     queryResult.Response.Truncated,
				Rcode:         rcode,
			})
			pool.DefaultMessage.Put(queryResult.Response)
			return true
		}

		// RFC 10029: warm the merged types and strip them from the answer —
		// the strip uses the completed list, never server.MQType, which
		// would remove the primary records.  A fallback-marked response
		// (65280 from a cascaded ZJDNS) must not warm the cache either.
		if len(server.MQType) > 0 && mqr != nil && !mqInvalid && r.cache != nil && !server.SkipCache && !fallbackMarked {
			r.warmFromMQResponse(queryResult.Response, question.Name, question.Qclass, mqr, ecsResponse, queryResult.Validated)
			queryResult.Response.Answer = stripMQBundled(queryResult.Response.Answer, mqr.Types)
		}

		res := QueryResult{Answer: queryResult.Response.Answer, Authority: queryResult.Response.Ns, Additional: queryResult.Response.Extra, Validated: queryResult.Validated, Authoritative: queryResult.Response.Authoritative, Cacheable: !server.SkipCache && !fallbackMarked, ECS: ecsResponse, Server: serverDesc, UpstreamEDE: upstreamEDE, Truncated: queryResult.Response.Truncated, Rcode: rcode}
		select {
		case resultChan <- res:
			remaining := activeConnections.Load() - 1
			if remaining > 0 {
				log.Debugf("UPSTREAM: First win achieved, terminating %d remaining connections", remaining)
			}
			cancel(errors.New("successful result"))
			// A fallback may have been adopted while this result was in
			// flight — fill the cache directly instead of racing for a
			// client the wait loop already answered.
			coord.maybeBackfill(func() { r.fillCacheFromResult(coord, &res) })
			pool.DefaultMessage.Put(queryResult.Response)
			return true
		case <-groupCtx.Done():
			pool.DefaultMessage.Put(queryResult.Response)
			return true
		}
	case dns.RcodeNameError:
		// Fallback NXDOMAIN is stashed like a fallback NOERROR — adopted
		// only after the timeout, never cached, and it must not arm the
		// NXDOMAIN deferral window (that machinery is primary-only).
		if server.Fallback {
			coord.stash(&QueryResult{
				Answer:        queryResult.Response.Answer,
				Authority:     queryResult.Response.Ns,
				Additional:    queryResult.Response.Extra,
				Validated:     false,
				Authoritative: queryResult.Response.Authoritative,
				Cacheable:     false,
				Rcode:         dns.RcodeNameError,
				ECS:           r.edns.ParseFromDNS(queryResult.Response),
				Server:        serverDesc,
				UpstreamEDE:   fallbackMarkEDE(),
			})
			pool.DefaultMessage.Put(queryResult.Response)
			return true
		}
		nxRes := QueryResult{
			Answer:        queryResult.Response.Answer,
			Authority:     queryResult.Response.Ns,
			Additional:    queryResult.Response.Extra,
			Validated:     false,
			Authoritative: queryResult.Response.Authoritative,
			Cacheable:     !server.SkipCache && !fallbackMarked,
			Rcode:         dns.RcodeNameError,
			ECS:           r.edns.ParseFromDNS(queryResult.Response),
			Server:        serverDesc,
			UpstreamEDE:   upstreamEDE,
		}
		if nxdomainResult.CompareAndSwap(nil, &nxRes) {
			// First NXDOMAIN collected — arm the deferral window in the
			// wait loop (first-wins; same principle as the recursive walk).
			select {
			case nxdomainCh <- struct{}{}:
			default:
			}
			// A fallback may have been adopted between this CAS and now —
			// fill the negative cache directly (mirrors the NOERROR path).
			coord.maybeBackfill(func() { r.fillCacheFromResult(coord, &nxRes) })
		}
		pool.DefaultMessage.Put(queryResult.Response)
	default:
		pool.DefaultMessage.Put(queryResult.Response)
	}
	return false
}

// handleRecursiveQuery dispatches a single query to the built-in recursive
// resolver with CIDR filtering. Returns true if a successful result was sent.
func (r *Resolver) handleRecursiveQuery(recursiveParentCtx context.Context, server *config.UpstreamServer, question Question, ecs *edns.ECSOption, resultChan chan<- QueryResult, cancel context.CancelCauseFunc, cidrFilterRefused *atomic.Bool, coord *fallbackCoord) bool {
	recursiveCtx, recursiveCancel := context.WithTimeout(recursiveParentCtx, config.DefaultRecursiveResolveTimeout)
	defer recursiveCancel()

	qr := r.cname.resolve(recursiveCtx, question, ecs)
	qr.Cacheable = !server.SkipCache
	if qr.Err != nil {
		return false
	}
	// Empty response (no Answer AND no Authority): nothing to forward as a
	// first-win — the query is dropped here.  Note this only matches fully
	// empty responses: real denials carry the SOA/NSEC/NSEC3 proof in
	// Authority, so they ARE forwarded as first-wins — consistent with the
	// forwarding fan-out, where a collected NXDOMAIN is served after the
	// (default zero) deferral window without waiting for the slowest
	// upstream.
	if len(qr.Answer) == 0 && len(qr.Authority) == 0 {
		return false
	}

	if len(server.Match) > 0 {
		filteredAnswer, shouldRefuse := r.filterRecordsByCIDR(qr.Answer, server.Match)
		if shouldRefuse {
			cidrFilterRefused.Store(true)
			return false
		}
		qr.Answer = filteredAnswer
	}

	// Recursive fallback upstreams follow the same delayed-adoption rule as
	// forwarding fallbacks: stash, never cache, mark with the fallback EDE.
	if server.Fallback {
		qr.Cacheable = false
		qr.UpstreamEDE = fallbackMarkEDE()
		coord.stash(&qr)
		return true
	}

	select {
	case resultChan <- qr:
		cancel(errors.New("successful result"))
		return true
	case <-recursiveCtx.Done():
		return true
	}
}
