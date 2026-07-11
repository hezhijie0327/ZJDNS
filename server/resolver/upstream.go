package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	"zjdns/server/client"
	"zjdns/server/security"

	"codeberg.org/miekg/dns"
	"golang.org/x/sync/errgroup"
)

func (r *Resolver) queryUpstream(ctx context.Context, question Question, ecs *edns.ECSOption, servers []*config.UpstreamServer) QueryResult {
	if len(servers) == 0 {
		return QueryResult{Err: errors.New("no upstream servers")}
	}

	// Clear any stale EDE from a previous query so it does not leak into
	// this query's response.
	r.lastUpstreamEDE.Store(nil)

	servers = ShuffleSlice(servers)

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

			if server.IsRecursive() {
				if handled := r.handleRecursiveQuery(groupCtx, server, question, ecs, resultChan, cancel); handled {
					return nil
				}
			} else {
				isSecure := server.Protocol == config.ProtoTLS || server.Protocol == config.ProtoQUIC || server.Protocol == config.ProtoHTTP || server.Protocol == config.ProtoHTTP3
				msg := r.buildMsg(question, ecs, true, isSecure)
				queryResult := r.client.ExecuteQuery(groupCtx, msg, server)
				pool.DefaultMessagePool.Put(msg)

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
		if err := g.Wait(); err != nil && errors.Is(err, ErrCIDRFilterRefused) {
			// All successful answers were filtered by CIDR rules —
			// propagate the specific error so callers can return REFUSED.
			select {
			case resultChan <- QueryResult{Err: ErrCIDRFilterRefused}:
			default:
			}
		}
		close(resultChan)
	}()

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
		// When all goroutines finish, errgroup cancels the derived
		// context, which can race with the channel-close goroutine.
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
	if ede := r.edns.ParseEDE(resp); ede != nil {
		r.lastUpstreamEDE.Store(ede)
		log.Debugf("UPSTREAM: captured EDE %d (%s) from %s (rcode=%s)",
			ede.InfoCode, edns.EDECodeString(ede.InfoCode), serverAddr, dns.RcodeToString[resp.Rcode])
	}
}

func (r *Resolver) filterRecordsByCIDR(records []dns.RR, matchTags []string) ([]dns.RR, bool) {
	if r.cidr == nil || len(matchTags) == 0 {
		return records, false
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
		for _, matchTag := range matchTags {
			matched, exists := r.cidr.MatchIP(ip, matchTag)
			if !exists {
				return nil, true
			}
			if matched {
				accepted = true
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
// Returns true if the goroutine should return (result sent or handled).
func (r *Resolver) processUpstreamResponse(queryResult *client.Result, server *config.UpstreamServer, question Question, resultChan chan<- QueryResult, nxdomainResult *atomic.Pointer[QueryResult], activeConnections *atomic.Int32, cancel context.CancelCauseFunc, groupCtx context.Context) bool {
	// 0x20 case-preservation check (draft-0x20 / RFC 6840 bis).
	// If the upstream server mangled the case pattern, retry without
	// perturbation — this server does not support 0x20.
	if queryResult.PerturbedName != "" && queryResult.Response != nil && len(queryResult.Response.Question) > 0 {
		respQname := queryResult.Response.Question[0].Header().Name
		if !edns.IsCasePreserved(queryResult.PerturbedName, respQname) {
			log.Debugf("UPSTREAM: 0x20 CAPSFAIL for %s via %s, retrying without case randomization", question.Name, server.Address)
			pool.DefaultMessagePool.Put(queryResult.Response)

			// Build a fresh message without perturbation.
			nocapsMsg := r.buildMsg(question, nil, true, false)
			// PerturbedName is left empty → no CAPSFAIL check on the retry.
			nocapsResult := r.client.ExecuteQuery(groupCtx, nocapsMsg, server)
			pool.DefaultMessagePool.Put(nocapsMsg)

			if nocapsResult.Error == nil && nocapsResult.Response != nil {
				queryResult = nocapsResult
				goto processResponse
			}
			// Nocaps retry failed — fall through to discard the original result.
			return false
		}
	}

processResponse:
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
				pool.DefaultMessagePool.Put(queryResult.Response)
				return false // errgroup will detect ErrCIDRFilterRefused
			}
			queryResult.Response.Answer = filteredAnswer
		}

		queryResult.Validated = security.IsResponseValid(queryResult.Response, true)
		log.Debugf("UPSTREAM: DNSSEC validation result=%t for %s via %s", queryResult.Validated, question.Name, server.Address)
		ecsResponse := r.edns.ParseFromDNS(queryResult.Response)

		select {
		case resultChan <- QueryResult{Answer: queryResult.Response.Answer, Authority: queryResult.Response.Ns, Additional: queryResult.Response.Extra, Validated: queryResult.Validated, Cacheable: !server.NoCache, ECS: ecsResponse, Server: serverDesc}:
			remaining := activeConnections.Load() - 1
			if remaining > 0 {
				log.Debugf("UPSTREAM: First win achieved, terminating %d remaining connections", remaining)
			}
			cancel(errors.New("successful result"))
			pool.DefaultMessagePool.Put(queryResult.Response)
			return true
		case <-groupCtx.Done():
			pool.DefaultMessagePool.Put(queryResult.Response)
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
		pool.DefaultMessagePool.Put(queryResult.Response)
	default:
		pool.DefaultMessagePool.Put(queryResult.Response)
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
	if qr.Err != nil || len(qr.Answer) == 0 {
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
