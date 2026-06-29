package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"

	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"

	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/log"
	"zjdns/internal/pool"
)

type result struct {
	Answer     []dns.RR
	Authority  []dns.RR
	Additional []dns.RR
	Validated  bool
	ECS        *edns.ECSOption
	Server     string
}

func (r *Resolver) queryUpstream(ctx context.Context, question dns.Question, ecs *edns.ECSOption, servers []*config.UpstreamServer) ([]dns.RR, []dns.RR, []dns.RR, bool, *edns.ECSOption, string, bool, error) {
	if len(servers) == 0 {
		return nil, nil, nil, false, nil, "", false, errors.New("no upstream servers")
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

	resultChan := make(chan result, 1)
	var nxdomainResult atomic.Pointer[result]
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
				recursiveCtx, recursiveCancel := context.WithTimeout(groupCtx, config.DefaultRecursiveResolveTimeout)
				defer recursiveCancel()

				answer, authority, additional, validated, ecsResponse, usedServer, _, err := r.cname.resolve(recursiveCtx, question, ecs)
				if err == nil && len(answer) > 0 {
					if len(server.Match) > 0 {
						filteredAnswer, shouldRefuse := r.filterRecordsByCIDR(answer, server.Match)
						if shouldRefuse {
							return ErrCIDRFilterRefused
						}
						answer = filteredAnswer
					}

					select {
					case resultChan <- result{Answer: answer, Authority: authority, Additional: additional, Validated: validated, ECS: ecsResponse, Server: usedServer}:
						cancel(errors.New("successful result"))
						return nil
					case <-groupCtx.Done():
						return nil
					}
				}
			} else {
				msg := r.buildMsg(question, ecs, true, false)
				queryResult := r.client.ExecuteQuery(groupCtx, msg, server)
				pool.DefaultMessagePool.Put(msg)

				if queryResult.Error == nil && queryResult.Response != nil {
					rcode := queryResult.Response.Rcode
					serverDesc := server.Address
					if server.Protocol != "" && server.Protocol != config.ProtoUDP {
						serverDesc = server.Address + " (" + strings.ToUpper(server.Protocol) + ")"
					}

					// Capture EDE from upstream response for passthrough.
					// Applies to all rcodes — upstream resolvers attach EDE
					// codes (e.g. DNSSEC Bogus) to NOERROR, NXDOMAIN, and
					// SERVFAIL responses alike.
					captureUpstreamEDE(r, queryResult.Response, server.Address)

					switch rcode {
					case dns.RcodeSuccess:
						if len(server.Match) > 0 {
							filteredAnswer, shouldRefuse := r.filterRecordsByCIDR(queryResult.Response.Answer, server.Match)
							if shouldRefuse {
								pool.DefaultMessagePool.Put(queryResult.Response)
								return ErrCIDRFilterRefused
							}
							queryResult.Response.Answer = filteredAnswer
						}

						// Trust the upstream resolver's AD flag for DNSSEC
						// validation in forwarding mode — the upstream
						// performed the cryptographic verification.
						queryResult.Validated = r.validator.DNSSEC.ValidateResponse(queryResult.Response, true)
						log.Debugf("UPSTREAM: DNSSEC validation result=%t for %s via %s", queryResult.Validated, question.Name, server.Address)
						ecsResponse := r.edns.ParseFromDNS(queryResult.Response)

						select {
						case resultChan <- result{Answer: queryResult.Response.Answer, Authority: queryResult.Response.Ns, Additional: queryResult.Response.Extra, Validated: queryResult.Validated, ECS: ecsResponse, Server: serverDesc}:
							remaining := activeConnections.Load() - 1
							if remaining > 0 {
								log.Debugf("UPSTREAM: First win achieved, terminating %d remaining connections", remaining)
							}
							cancel(errors.New("successful result"))
							pool.DefaultMessagePool.Put(queryResult.Response)
							return nil
						case <-groupCtx.Done():
							pool.DefaultMessagePool.Put(queryResult.Response)
							return nil
						}
					case dns.RcodeNameError:
						nxdomainResult.CompareAndSwap(nil, &result{
							Answer:     queryResult.Response.Answer,
							Authority:  queryResult.Response.Ns,
							Additional: queryResult.Response.Extra,
							Validated:  false,
							ECS:        r.edns.ParseFromDNS(queryResult.Response),
							Server:     serverDesc,
						})
						pool.DefaultMessagePool.Put(queryResult.Response)
					default:
						pool.DefaultMessagePool.Put(queryResult.Response)
					}
				}
			}
			return nil
		})
	}

	go func() {
		_ = g.Wait()
		close(resultChan)
	}()

	select {
	case res, ok := <-resultChan:
		if ok && res.Server != "" {
			return res.Answer, res.Authority, res.Additional, res.Validated, res.ECS, res.Server, false, nil
		}
		if nxRes := nxdomainResult.Load(); nxRes != nil && nxRes.Server != "" {
			return nxRes.Answer, nxRes.Authority, nxRes.Additional, nxRes.Validated, nxRes.ECS, nxRes.Server, false, nil
		}
		// Propagate any EDE code captured from upstream SERVFAIL.
		if opt := r.lastUpstreamEDE.Load(); opt != nil {
			log.Warnf("UPSTREAM: all %d servers failed for %s, propagating EDE %d", len(servers), question.Name, opt.InfoCode)
			return nil, nil, nil, false, nil, "", false, dnssecEDEError(uint64(opt.InfoCode))
		}
		log.Warnf("UPSTREAM: all %d servers failed for %s", len(servers), question.Name)
		return nil, nil, nil, false, nil, "", false, errors.New("all upstream queries failed")
	case <-queryCtx.Done():
		// When all goroutines finish, errgroup cancels the derived
		// context, which can race with the channel-close goroutine.
		// Check for captured EDE codes here too so they are
		// not lost to a "context canceled" error.
		if opt := r.lastUpstreamEDE.Load(); opt != nil {
			return nil, nil, nil, false, nil, "", false, dnssecEDEError(uint64(opt.InfoCode))
		}
		return nil, nil, nil, false, nil, "", false, queryCtx.Err()
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
			ip = record.A
		case *dns.AAAA:
			ip = record.AAAA
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
