package resolver

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"strings"
	"sync/atomic"
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

	resultChan := make(chan QueryResult, 1)
	var nxdomainResult atomic.Pointer[QueryResult]
	queryCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(errors.New("query completed"))

	g, groupCtx := errgroup.WithContext(queryCtx)
	g.SetLimit(concurrencyLimit(len(servers)))

	var activeConnections atomic.Int32
	var cidrFilterRefused atomic.Bool

	//nolint:gosec // non-crypto random for server load balancing
	startIdx := rand.IntN(len(servers))
	for i := range servers {
		srv := servers[(startIdx+i)%len(servers)]
		server := srv

		g.Go(func() error {
			defer zdnsutil.HandlePanic("UPSTREAM query")
			select {
			case <-groupCtx.Done():
				return nil
			default:
			}

			activeConnections.Add(1)
			defer activeConnections.Add(-1)

			switch {
			case server.IsRecursive():
				if handled := r.handleRecursiveQuery(groupCtx, server, question, ecs, resultChan, cancel, &cidrFilterRefused); handled {
					return nil
				}

			default:
				// TCP/TLS/other: encrypted or single-response —
				// no hijacking possible, first-wins is fine.
				isSecure := zdnsutil.IsSecureProtocol(server.Protocol) &&
					server.Protocol != config.ProtoDNSCrypt &&
					server.Protocol != config.ProtoDNSCryptTCP
				msg := r.buildMsg(question, ecs, true, isSecure)
				queryResult := r.queryClient.ExecuteQuery(groupCtx, msg, server)
				pool.DefaultMessage.Put(msg)

				if queryResult.Error == nil && queryResult.Response != nil {
					if handled := r.processUpstreamResponse(queryResult, server, question, resultChan, &nxdomainResult, &activeConnections, cancel, groupCtx, &cidrFilterRefused, &lastUpstreamEDE); handled {
						return nil
					}
				}
			}
			return nil
		})
	}

	go func() {
		defer zdnsutil.HandlePanic("UPSTREAM errgroup wait")
		_ = g.Wait()
		if cidrFilterRefused.Load() {
			select {
			case resultChan <- QueryResult{Err: ErrCIDRFilterRefused}:
			default:
			}
		}
		close(resultChan)
	}()

	// First-wins: wait for the first successful result from any upstream.
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
		if nxRes := nxdomainResult.Load(); nxRes != nil && nxRes.Server != "" {
			return *nxRes
		}
		// Propagate any EDE code captured from upstream SERVFAIL.
		if opt := lastUpstreamEDE.Load(); opt != nil {
			log.Debugf("UPSTREAM: all %d servers failed for %s, propagating EDE %d", len(servers), question.Name, opt.InfoCode)
			return QueryResult{Err: dnssecEDEError(uint64(opt.InfoCode)), UpstreamEDE: opt}
		}
		log.Debugf("UPSTREAM: all %d servers failed for %s", len(servers), question.Name)
		return QueryResult{Err: errors.New("all upstream queries failed")}
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

func (r *Resolver) filterRecordsByCIDR(records []dns.RR, matchTags []string) ([]dns.RR, bool) {
	if r.crd == nil || len(matchTags) == 0 {
		return records, false
	}

	// Pre-filter tags: keep only those that have CIDR rules so we call
	// HasIPTag once per tag instead of once per record per tag.
	type tagKey struct {
		raw    string
		name   string
		negate bool
	}
	ipTags := make([]tagKey, 0, len(matchTags))
	for _, t := range matchTags {
		negate := t != "" && t[0] == '!'
		name := t
		if negate {
			name = t[1:]
		}
		if r.crd.HasIPTag(name) {
			ipTags = append(ipTags, tagKey{raw: t, name: name, negate: negate})
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
func (r *Resolver) processUpstreamResponse(queryResult *upstream.Result, server *config.UpstreamServer, question Question, resultChan chan<- QueryResult, nxdomainResult *atomic.Pointer[QueryResult], activeConnections *atomic.Int32, cancel context.CancelCauseFunc, groupCtx context.Context, cidrFilterRefused *atomic.Bool, lastEDE *atomic.Pointer[dns.EDE]) bool {
	rcode := queryResult.Response.Rcode
	serverDesc := server.Address
	if server.Protocol != "" && server.Protocol != config.ProtoUDP {
		serverDesc = server.Address + " (" + strings.ToUpper(server.Protocol) + ")"
	}

	upstreamEDE := captureUpstreamEDE(lastEDE, queryResult.Response, server.Address)

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

		select {
		case resultChan <- QueryResult{Answer: queryResult.Response.Answer, Authority: queryResult.Response.Ns, Additional: queryResult.Response.Extra, Validated: queryResult.Validated, Cacheable: !server.SkipCache, ECS: ecsResponse, Server: serverDesc, UpstreamEDE: upstreamEDE}:
			remaining := activeConnections.Load() - 1
			if remaining > 0 {
				log.Debugf("UPSTREAM: First win achieved, terminating %d remaining connections", remaining)
			}
			cancel(errors.New("successful result"))
			pool.DefaultMessage.Put(queryResult.Response)
			return true
		case <-groupCtx.Done():
			pool.DefaultMessage.Put(queryResult.Response)
			return true
		}
	case dns.RcodeNameError:
		nxdomainResult.CompareAndSwap(nil, &QueryResult{
			Answer:      queryResult.Response.Answer,
			Authority:   queryResult.Response.Ns,
			Additional:  queryResult.Response.Extra,
			Validated:   false,
			Cacheable:   !server.SkipCache,
			ECS:         r.edns.ParseFromDNS(queryResult.Response),
			Server:      serverDesc,
			UpstreamEDE: upstreamEDE,
		})
		pool.DefaultMessage.Put(queryResult.Response)
	default:
		pool.DefaultMessage.Put(queryResult.Response)
	}
	return false
}

// handleRecursiveQuery dispatches a single query to the built-in recursive
// resolver with CIDR filtering. Returns true if a successful result was sent.
func (r *Resolver) handleRecursiveQuery(groupCtx context.Context, server *config.UpstreamServer, question Question, ecs *edns.ECSOption, resultChan chan<- QueryResult, cancel context.CancelCauseFunc, cidrFilterRefused *atomic.Bool) bool {
	recursiveCtx, recursiveCancel := context.WithTimeout(groupCtx, config.DefaultRecursiveResolveTimeout)
	defer recursiveCancel()

	qr := r.cname.resolve(recursiveCtx, question, ecs)
	qr.Cacheable = !server.SkipCache
	if qr.Err != nil {
		return false
	}
	// NODATA / NXDOMAIN: authoritative returning empty Answer with
	// NSEC/NSEC3 denial-of-existence proof in Authority.
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

	select {
	case resultChan <- qr:
		cancel(errors.New("successful result"))
		return true
	case <-groupCtx.Done():
		return true
	}
}
