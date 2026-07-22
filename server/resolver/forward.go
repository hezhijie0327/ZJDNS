package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	"zjdns/server/defense"
	"zjdns/server/resolver/dnssec"
	"zjdns/server/upstream"

	"codeberg.org/miekg/dns"
	"golang.org/x/sync/errgroup"
)

// spoofEntry holds a QueryResult and its associated *dns.Msg for Tail voting.
// The message is kept alive until after voting; unused messages are returned
// to the pool by the collector.
type spoofEntry struct {
	qr  QueryResult
	msg *dns.Msg
}

func (r *Resolver) queryUpstream(ctx context.Context, question Question, ecs *edns.ECSOption, servers []*config.UpstreamServer) QueryResult {
	if len(servers) == 0 {
		return QueryResult{Err: errors.New("no upstream servers")}
	}

	// Clear any stale EDE from a previous query so it does not leak into
	// this query's response.
	r.lastUpstreamEDE.Store(nil)

	ShuffleSlice(servers)

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

	// Tail: when enabled, collect multiple UDP responses and trust the
	// chronologically last one (GFW fakes arrive before the real response).
	spoofActive := r.spoofEnabled

	resultChan := make(chan QueryResult, 1)
	var nxdomainResult atomic.Pointer[QueryResult]
	queryCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(errors.New("query completed"))

	g, groupCtx := errgroup.WithContext(queryCtx)
	g.SetLimit(concurrencyLimit(len(servers)))

	var activeConnections atomic.Int32

	// Tail voting: mutex-protected accumulator for (QueryResult, *dns.Msg) pairs.
	// Messages are kept alive until after voting; unused ones are returned to
	// the pool by the collector.
	var spoofMu sync.Mutex
	var spoofEntries []spoofEntry

	for _, srv := range servers {
		server := srv

		g.Go(func() error {
			select {
			case <-groupCtx.Done():
				return nil
			default:
			}

			activeConnections.Add(1)
			defer activeConnections.Add(-1)

			switch {
			case server.IsRecursive():
				if handled := r.handleRecursiveQuery(groupCtx, server, question, ecs, resultChan, cancel); handled {
					return nil
				}

			case spoofActive && (server.Protocol == config.ProtoUDP || server.Protocol == ""):
				// Tail + UDP: raw multi-read. GFW fakes arrive first,
				// real response always last — trust the tail.
				msg := r.buildMsg(question, ecs, true, false)
				if err := msg.Pack(); err == nil {
					r.executeUDPMultiRead(groupCtx, msg.Data, msg.ID, server, &spoofEntries, &spoofMu, &nxdomainResult)
				}
				pool.DefaultMessage.Put(msg)

			default:
				// TCP/TLS/other: encrypted or single-response —
				// no hijacking possible, first-wins is fine.
				isSecure := server.Protocol == config.ProtoTLS ||
					server.Protocol == config.ProtoQUIC ||
					server.Protocol == config.ProtoHTTPS ||
					server.Protocol == config.ProtoHTTP3 ||
					server.Protocol == config.ProtoDTLS ||
					server.Protocol == config.ProtoDTLCP ||
					server.Protocol == config.ProtoTLCP ||
					server.Protocol == config.ProtoHTTPTLCP
				msg := r.buildMsg(question, ecs, true, isSecure)
				queryResult := r.queryClient.ExecuteQuery(groupCtx, msg, server)
				pool.DefaultMessage.Put(msg)

				if queryResult.Error == nil && queryResult.Response != nil {
					if handled := r.processUpstreamResponse(queryResult, server, question, resultChan, &nxdomainResult, &activeConnections, cancel, groupCtx); handled {
						return nil
					}
				}
			}
			return nil
		})
	}

	go func() {
		if err := g.Wait(); err != nil {
			if errors.Is(err, ErrCIDRFilterRefused) {
				select {
				case resultChan <- QueryResult{Err: ErrCIDRFilterRefused}:
				default:
				}
			} else {
				log.Warnf("UPSTREAM: errgroup for %s: %v", question.Name, err)
			}
		}
		close(resultChan)
	}()

	if spoofActive {
		// Wait for the collection window, then drain and vote.
		tailTimer := time.NewTimer(config.DefaultSpoofguardCollectWindow)
		select {
		case <-tailTimer.C:
		case <-ctx.Done():
			if !tailTimer.Stop() {
				<-tailTimer.C
			}
		}

		spoofMu.Lock()
		entries := spoofEntries
		spoofEntries = nil
		spoofMu.Unlock()

		if len(entries) > 0 {
			// Build *dns.Msg slice for voting. Entries from recursive
			// queries have nil msg (their QueryResult already carries
			// the answer RRs).
			msgs := make([]*dns.Msg, len(entries))
			for i := range entries {
				if entries[i].msg != nil {
					msgs[i] = entries[i].msg
				}
			}
			winner := defense.LastResponse(msgs)
			if winner != nil {
				for i := range entries {
					if entries[i].msg == winner {
						// Put back non-winner messages.
						for j := range entries {
							if j != i && entries[j].msg != nil {
								pool.DefaultMessage.Put(entries[j].msg)
							}
						}
						qr := entries[i].qr
						pool.DefaultMessage.Put(entries[i].msg)
						return qr
					}
				}
			}
			// No majority: fallback to first response, put the rest.
			for i := range entries {
				if i > 0 && entries[i].msg != nil {
					pool.DefaultMessage.Put(entries[i].msg)
				}
			}
			qr := entries[0].qr
			if qr.Server != "" {
				return qr
			}
		}

		// Fallback: NXDOMAIN or error.
		if nxRes := nxdomainResult.Load(); nxRes != nil && nxRes.Server != "" {
			return *nxRes
		}
		if opt := r.lastUpstreamEDE.Load(); opt != nil {
			log.Debugf("UPSTREAM: all %d servers failed for %s, propagating EDE %d", len(servers), question.Name, opt.InfoCode)
			return QueryResult{Err: dnssecEDEError(uint64(opt.InfoCode))}
		}
		log.Debugf("UPSTREAM: all %d servers failed for %s", len(servers), question.Name)
		return QueryResult{Err: errors.New("all upstream queries failed")}
	}

	// Non-tail path: first-wins (existing behaviour).
	select {
	case res, ok := <-resultChan:
		if ok {
			if errors.Is(res.Err, ErrCIDRFilterRefused) {
				return QueryResult{Err: ErrCIDRFilterRefused}
			}
			if res.Server != "" {
				res.Fallback = false
				return res
			}
		}
		if nxRes := nxdomainResult.Load(); nxRes != nil && nxRes.Server != "" {
			return *nxRes
		}
		// Propagate any EDE code captured from upstream SERVFAIL.
		if opt := r.lastUpstreamEDE.Load(); opt != nil {
			log.Debugf("UPSTREAM: all %d servers failed for %s, propagating EDE %d", len(servers), question.Name, opt.InfoCode)
			return QueryResult{Err: dnssecEDEError(uint64(opt.InfoCode))}
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
					res.Fallback = false
					return res
				}
			}
		default:
		}
		// Check for captured EDE codes here too so they are
		// not lost to a "context canceled" error.
		if opt := r.lastUpstreamEDE.Load(); opt != nil {
			return QueryResult{Err: dnssecEDEError(uint64(opt.InfoCode))}
		}
		return QueryResult{Err: queryCtx.Err()}
	}
}

// captureUpstreamEDE extracts and stores the EDE option from an upstream
// response for passthrough to downstream clients. Upstream resolvers attach
// EDE codes (e.g. DNSSEC Bogus) to any rcode, so this is called once per
// response before rcode-specific handling.
func captureUpstreamEDE(r *Resolver, resp *dns.Msg, serverAddr string) {
	if resp == nil {
		return
	}
	for _, rr := range resp.Pseudo {
		if ede, ok := rr.(*dns.EDE); ok {
			r.lastUpstreamEDE.Store(ede)
			log.Debugf("UPSTREAM: captured EDE %d (%s) from %s (rcode=%s)",
				ede.InfoCode, dns.ExtendedErrorToString[ede.InfoCode], serverAddr, dns.RcodeToString[resp.Rcode])
			break
		}
	}
}

// executeUDPMultiRead sends a DNS query via raw UDP and reads multiple
// responses within the Tail collect window. Unlike miekg/dns.Client.Exchange
// which returns the first packet, this captures both GFW-injected fakes and
// the real server response so Tail voting can distinguish them.
func (r *Resolver) executeUDPMultiRead(ctx context.Context, wireQuery []byte, msgID uint16, server *config.UpstreamServer, spoofEntries *[]spoofEntry, mu *sync.Mutex, nxdomainResult *atomic.Pointer[QueryResult]) {
	conn, err := net.Dial("udp", server.Address)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write(wireQuery); err != nil {
		return
	}

	deadline := time.Now().Add(config.DefaultSpoofguardCollectWindow)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}

	buf := make([]byte, 4096)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, err := conn.Read(buf)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				if time.Now().After(deadline) {
					return
				}
				continue
			}
			return
		}

		// Quick ID check — skip packets not matching our query.
		if n < 12 || uint16(buf[0])<<8|uint16(buf[1]) != msgID {
			continue
		}

		raw := make([]byte, n)
		copy(raw, buf[:n])

		resp := pool.DefaultMessage.Get()
		resp.Data = raw
		if err := resp.Unpack(); err != nil {
			pool.DefaultMessage.Put(resp)
			continue
		}
		resp.Data = nil

		serverDesc := server.Address
		if server.Protocol != "" && server.Protocol != config.ProtoUDP {
			serverDesc = server.Address + " (" + strings.ToUpper(server.Protocol) + ")"
		}

		captureUpstreamEDE(r, resp, server.Address)

		rcode := resp.Rcode
		switch rcode {
		case dns.RcodeSuccess:
			validated := dnssec.IsResponseValid(resp, true)
			ecsResponse := r.edns.ParseFromDNS(resp)
			qr := QueryResult{
				Answer:     resp.Answer,
				Authority:  resp.Ns,
				Additional: resp.Extra,
				Validated:  validated,
				Cacheable:  !server.NoCache,
				ECS:        ecsResponse,
				Server:     serverDesc,
			}
			mu.Lock()
			*spoofEntries = append(*spoofEntries, spoofEntry{qr: qr, msg: resp})
			mu.Unlock()
			log.Debugf("UPSTREAM: UDP spoofguard collected response from %s, answer=%d", serverDesc, len(resp.Answer))

		case dns.RcodeNameError:
			nxdomainResult.CompareAndSwap(nil, &QueryResult{
				Answer:     resp.Answer,
				Authority:  resp.Ns,
				Additional: resp.Extra,
				Validated:  false,
				Cacheable:  !server.NoCache,
				ECS:        r.edns.ParseFromDNS(resp),
				Server:     serverDesc,
			})
			pool.DefaultMessage.Put(resp)

		default:
			pool.DefaultMessage.Put(resp)
		}
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

		accepted := false
		hasIPTag := false
		ipStr := ip.String()
		for _, t := range ipTags {
			hasIPTag = true
			matched, exists := r.crd.MatchIP(ipStr, t.raw)
			if !exists {
				return nil, true
			}
			if matched {
				accepted = true
				break
			}
		}
		if !hasIPTag {
			accepted = true
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
// Returns true if the goroutine should return (result sent or handled).
func (r *Resolver) processUpstreamResponse(queryResult *upstream.Result, server *config.UpstreamServer, question Question, resultChan chan<- QueryResult, nxdomainResult *atomic.Pointer[QueryResult], activeConnections *atomic.Int32, cancel context.CancelCauseFunc, groupCtx context.Context) bool {
	rcode := queryResult.Response.Rcode
	serverDesc := server.Address
	if server.Protocol != "" && server.Protocol != config.ProtoUDP {
		serverDesc = server.Address + " (" + strings.ToUpper(server.Protocol) + ")"
	}

	captureUpstreamEDE(r, queryResult.Response, server.Address)

	switch rcode {
	case dns.RcodeSuccess:
		if len(server.Match) > 0 {
			filteredAnswer, shouldRefuse := r.filterRecordsByCIDR(queryResult.Response.Answer, server.Match)
			if shouldRefuse {
				pool.DefaultMessage.Put(queryResult.Response)
				return false // errgroup will detect ErrCIDRFilterRefused
			}
			queryResult.Response.Answer = filteredAnswer
		}

		queryResult.Validated = dnssec.IsResponseValid(queryResult.Response, true)
		log.Debugf("UPSTREAM: DNSSEC validation result=%t for %s via %s", queryResult.Validated, question.Name, server.Address)
		ecsResponse := r.edns.ParseFromDNS(queryResult.Response)

		select {
		case resultChan <- QueryResult{Answer: queryResult.Response.Answer, Authority: queryResult.Response.Ns, Additional: queryResult.Response.Extra, Validated: queryResult.Validated, Cacheable: !server.NoCache, ECS: ecsResponse, Server: serverDesc}:
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
			Answer:     queryResult.Response.Answer,
			Authority:  queryResult.Response.Ns,
			Additional: queryResult.Response.Extra,
			Validated:  false,
			Cacheable:  !server.NoCache,
			ECS:        r.edns.ParseFromDNS(queryResult.Response),
			Server:     serverDesc,
		})
		pool.DefaultMessage.Put(queryResult.Response)
	default:
		pool.DefaultMessage.Put(queryResult.Response)
	}
	return false
}

// handleRecursiveQuery dispatches a single query to the built-in recursive
// resolver with CIDR filtering. Returns true if a successful result was sent.
func (r *Resolver) handleRecursiveQuery(groupCtx context.Context, server *config.UpstreamServer, question Question, ecs *edns.ECSOption, resultChan chan<- QueryResult, cancel context.CancelCauseFunc) bool {
	recursiveCtx, recursiveCancel := context.WithTimeout(groupCtx, config.DefaultRecursiveResolveTimeout)
	defer recursiveCancel()

	qr := r.cname.resolve(recursiveCtx, question, ecs)
	qr.Cacheable = !server.NoCache
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
			return false // errgroup will detect ErrCIDRFilterRefused
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
