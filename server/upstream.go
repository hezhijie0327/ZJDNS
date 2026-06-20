package server

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

// UpstreamHandler manages querying upstream name servers, including primary and fallback lists.
type UpstreamHandler struct {
	servers atomic.Pointer[[]*config.UpstreamServer]
}

// getServers returns the list of configured upstream servers.
func (uh *UpstreamHandler) getServers() []*config.UpstreamServer {
	serversPtr := uh.servers.Load()
	if serversPtr == nil {
		return []*config.UpstreamServer{}
	}
	return *serversPtr
}

// queryUpstream performs concurrent queries to upstream DNS servers.
// It implements the "first win" strategy where the first successful response
// is returned immediately, canceling any pending queries.
func (qm *QueryManager) queryUpstream(question dns.Question, ecs *edns.ECSOption, servers []*config.UpstreamServer) ([]dns.RR, []dns.RR, []dns.RR, bool, *edns.ECSOption, string, bool, error) {
	if len(servers) == 0 {
		return nil, nil, nil, false, nil, "", false, errors.New("no upstream servers")
	}

	servers = shuffleSlice(servers)

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

	resultChan := make(chan UpstreamQueryResult, 1)
	nxdomainChan := make(chan UpstreamQueryResult, 1) // Fallback for NXDOMAIN
	queryCtx, cancel := context.WithCancelCause(context.Background())
	defer cancel(errors.New("query completed"))

	g, queryCtx := errgroup.WithContext(queryCtx)
	g.SetLimit(calculateConcurrencyLimit(len(servers)))

	var activeConnections atomic.Int32

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

				answer, authority, additional, validated, ecsResponse, usedServer, _, err := qm.cname.resolveWithCNAME(recursiveCtx, question, ecs)

				if err == nil && len(answer) > 0 {
					if len(server.Match) > 0 {
						filteredAnswer, shouldRefuse := qm.filterRecordsByCIDR(answer, server.Match)
						if shouldRefuse {
							log.Debugf("UPSTREAM: CIDR filter refused all records for %s from recursive", question.Name)
							return ErrCIDRFilterRefused
						}
						answer = filteredAnswer
					}

					select {
					case resultChan <- UpstreamQueryResult{
						answer:     answer,
						authority:  authority,
						additional: additional,
						validated:  validated,
						ecs:        ecsResponse,
						server:     usedServer,
					}:
						cancel(errors.New("successful result obtained from recursive resolution"))
						return nil
					case <-queryCtx.Done():
						return nil
					}
				}
			} else {
				msg := qm.server.buildQueryMessage(question, ecs, true, false)
				queryResult := qm.server.queryClient.ExecuteQuery(queryCtx, msg, server)
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
							filteredAnswer, shouldRefuse := qm.filterRecordsByCIDR(queryResult.Response.Answer, server.Match)
							if shouldRefuse {
								pool.DefaultMessagePool.Put(queryResult.Response)
								log.Debugf("UPSTREAM: CIDR filter refused all records for %s from %s", question.Name, serverDesc)
								return ErrCIDRFilterRefused
							}
							queryResult.Response.Answer = filteredAnswer
						}

						queryResult.Validated = qm.validator.dnssecValidator.ValidateResponse(queryResult.Response, true)
						ecsResponse := qm.server.ednsMgr.ParseFromDNS(queryResult.Response)

						select {
						case resultChan <- UpstreamQueryResult{
							answer:     queryResult.Response.Answer,
							authority:  queryResult.Response.Ns,
							additional: queryResult.Response.Extra,
							validated:  queryResult.Validated,
							ecs:        ecsResponse,
							server:     serverDesc,
						}:
							log.Debugf("UPSTREAM: NOERROR from %s for %s, validated=%t, answer=%d, authority=%d", serverDesc, question.Name, queryResult.Validated, len(queryResult.Response.Answer), len(queryResult.Response.Ns))
							remaining := activeConnections.Load() - 1
							if remaining > 0 {
								log.Debugf("UPSTREAM: First win achieved, terminating %d remaining connections", remaining)
							}
							cancel(errors.New("successful result obtained from upstream"))
							pool.DefaultMessagePool.Put(queryResult.Response)
							return nil
						case <-queryCtx.Done():
							pool.DefaultMessagePool.Put(queryResult.Response)
							return nil
						}
					case dns.RcodeNameError:
						log.Debugf("UPSTREAM: NXDOMAIN from %s for %s, storing as fallback", serverDesc, question.Name)
						// NXDOMAIN - store as fallback, continue querying other servers
						select {
						case nxdomainChan <- UpstreamQueryResult{
							answer:     queryResult.Response.Answer,
							authority:  queryResult.Response.Ns,
							additional: queryResult.Response.Extra,
							validated:  false,
							ecs:        qm.server.ednsMgr.ParseFromDNS(queryResult.Response),
							server:     serverDesc,
						}:
						default:
						}
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
		close(nxdomainChan)
	}()

	select {
	case res, ok := <-resultChan:
		if ok && res.server != "" {
			return res.answer, res.authority, res.additional, res.validated, res.ecs, res.server, false, nil
		}
		// No NOERROR response, check for NXDOMAIN fallback
		select {
		case nxRes, nxOk := <-nxdomainChan:
			if nxOk && nxRes.server != "" {
				log.Debugf("UPSTREAM: Returning NXDOMAIN fallback after no successful response")
				return nxRes.answer, nxRes.authority, nxRes.additional, nxRes.validated, nxRes.ecs, nxRes.server, false, nil
			}
		default:
		}
		log.Debugf("UPSTREAM: all upstream queries failed for %s after %d attempts", question.Name, len(servers))
		return nil, nil, nil, false, nil, "", false, errors.New("all upstream queries failed")
	case <-queryCtx.Done():
		return nil, nil, nil, false, nil, "", false, queryCtx.Err()
	}
}

// filterRecordsByCIDR filters DNS records based on CIDR match tags.
// It returns the filtered records and a boolean indicating if the response
// should be refused (all records filtered).
func (qm *QueryManager) filterRecordsByCIDR(records []dns.RR, matchTags []string) ([]dns.RR, bool) {
	if qm.server.cidrMgr == nil || len(matchTags) == 0 {
		return records, false
	}

	filtered := make([]dns.RR, 0, len(records))
	refusedCount := 0

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
			matched, exists := qm.server.cidrMgr.MatchIP(ip, matchTag)
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
		} else {
			refusedCount++
		}
	}

	if len(filtered) == 0 {
		return nil, true
	}

	return filtered, false
}
