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

func (r *Resolver) queryUpstream(question dns.Question, ecs *edns.ECSOption, servers []*config.UpstreamServer) ([]dns.RR, []dns.RR, []dns.RR, bool, *edns.ECSOption, string, bool, error) {
	if len(servers) == 0 {
		return nil, nil, nil, false, nil, "", false, errors.New("no upstream servers")
	}

	servers = ShuffleSlice(servers)

	if log.Default.Level() >= log.Debug {
		serverAddrs := make([]string, 0, len(servers))
		for _, s := range servers {
			proto := s.Protocol
			if proto == "" {
				proto = "udp"
			}
			serverAddrs = append(serverAddrs, fmt.Sprintf("%s(%s)", s.Address, proto))
		}
		log.Debugf("UPSTREAM: querying %d servers for %s: %v", len(servers), question.Name, serverAddrs)
	}

	resultChan := make(chan result, 1)
	nxdomainChan := make(chan result, 1)
	queryCtx, cancel := context.WithCancelCause(context.Background())
	defer cancel(errors.New("query completed"))

	g, queryCtx := errgroup.WithContext(queryCtx)
	g.SetLimit(ConcurrencyLimit(len(servers)))

	var activeConnections atomic.Int32
	var lastUpstreamDNSSECEDE atomic.Uint64 // EDE code from upstream SERVFAIL (DNSSEC-related)

	for _, srv := range servers {
		server := srv

		g.Go(func() error {
			select {
			case <-queryCtx.Done():
				return nil
			default:
			}

			activeConnections.Add(1)
			defer activeConnections.Add(-1)

			if server.IsRecursive() {
				recursiveCtx, recursiveCancel := context.WithTimeout(queryCtx, config.IdleTimeout)
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
					case <-queryCtx.Done():
						return nil
					}
				}
			} else {
				msg := r.buildMsg(question, ecs, true, false)
				queryResult := r.client.ExecuteQuery(queryCtx, msg, server)
				pool.DefaultMessagePool.Put(msg)

				if queryResult.Error == nil && queryResult.Response != nil {
					rcode := queryResult.Response.Rcode
					serverDesc := server.Address
					if server.Protocol != "" && server.Protocol != "udp" {
						serverDesc = fmt.Sprintf("%s (%s)", server.Address, strings.ToUpper(server.Protocol))
					}

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

						queryResult.Validated = r.validator.DNSSEC.ValidateResponse(queryResult.Response, true)
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
						case <-queryCtx.Done():
							pool.DefaultMessagePool.Put(queryResult.Response)
							return nil
						}
					case dns.RcodeNameError:
						select {
						case nxdomainChan <- result{Answer: queryResult.Response.Answer, Authority: queryResult.Response.Ns, Additional: queryResult.Response.Extra, Validated: false, ECS: r.edns.ParseFromDNS(queryResult.Response), Server: serverDesc}:
						default:
						}
						pool.DefaultMessagePool.Put(queryResult.Response)
					default:
						// Capture DNSSEC-related EDE codes from upstream
						// SERVFAIL so the client gets a meaningful error
						// instead of a generic "Network Error".
						if rcode == dns.RcodeServerFailure {
							if ede := r.edns.ParseEDE(queryResult.Response); ede != nil {
								if ede.InfoCode >= 1 && ede.InfoCode <= 12 {
									lastUpstreamDNSSECEDE.Store(uint64(ede.InfoCode))
									log.Debugf("UPSTREAM: captured DNSSEC EDE %d (%s) from %s", ede.InfoCode, edns.EDECodeString(ede.InfoCode), server.Address)
								}
							}
						}
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
		close(nxdomainChan)
	}()

	select {
	case res, ok := <-resultChan:
		if ok && res.Server != "" {
			return res.Answer, res.Authority, res.Additional, res.Validated, res.ECS, res.Server, false, nil
		}
		select {
		case nxRes, nxOk := <-nxdomainChan:
			if nxOk && nxRes.Server != "" {
				return nxRes.Answer, nxRes.Authority, nxRes.Additional, nxRes.Validated, nxRes.ECS, nxRes.Server, false, nil
			}
		default:
		}
		// Check if any upstream returned a DNSSEC-related EDE code
		// (e.g. EDE 9 "DNSKEY Missing" from a validating resolver).
		if edeCode := lastUpstreamDNSSECEDE.Load(); edeCode != 0 {
			return nil, nil, nil, false, nil, "", false, dnssecEDEError(edeCode)
		}
		return nil, nil, nil, false, nil, "", false, errors.New("all upstream queries failed")
	case <-queryCtx.Done():
		// When all goroutines finish, errgroup cancels the derived
		// context, which can race with the channel-close goroutine.
		// Check for captured DNSSEC EDE codes here too so they are
		// not lost to a "context canceled" error.
		if edeCode := lastUpstreamDNSSECEDE.Load(); edeCode != 0 {
			return nil, nil, nil, false, nil, "", false, dnssecEDEError(edeCode)
		}
		return nil, nil, nil, false, nil, "", false, queryCtx.Err()
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
