package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"

	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"
)

var DefaultRootServers = []string{
	"198.41.0.4:53", "[2001:503:ba3e::2:30]:53",
	"170.247.170.2:53", "[2801:1b8:10::b]:53",
	"192.33.4.12:53", "[2001:500:2::c]:53",
	"199.7.91.13:53", "[2001:500:2d::d]:53",
	"192.203.230.10:53", "[2001:500:a8::e]:53",
	"192.5.5.241:53", "[2001:500:2f::f]:53",
	"192.112.36.4:53", "[2001:500:12::d0d]:53",
	"198.97.190.53:53", "[2001:500:1::53]:53",
	"192.36.148.17:53", "[2001:7fe::53]:53",
	"192.58.128.30:53", "[2001:503:c27::2:30]:53",
	"193.0.14.129:53", "[2001:7fd::1]:53",
	"199.7.83.42:53", "[2001:500:9f::42]:53",
	"202.12.27.33:53", "[2001:dc3::35]:53",
}

// config.UpstreamServer represents a configured upstream DNS server with optional client filters.
type RecursiveResolver struct {
	server *DNSServer
}

// recursiveQuery performs recursive DNS resolution starting from root servers.
// It follows the DNS resolution algorithm: query root servers, follow referrals
// to TLD servers, then to authoritative servers until an answer is found.
func (rr *RecursiveResolver) recursiveQuery(ctx context.Context, question dns.Question, ecs *edns.ECSOption, depth int, forceTCP bool) ([]dns.RR, []dns.RR, []dns.RR, bool, *edns.ECSOption, string, bool, error) {
	log.Debugf("RECURSION: depth=%d, querying %s (type=%s, tcp=%t)", depth, question.Name, dns.TypeToString[question.Qtype], forceTCP)
	if depth > MaxRecursionDep {
		log.Warnf("RECURSION: depth exceeded (depth=%d, max=%d) for %s", depth, MaxRecursionDep, question.Name)
		return nil, nil, nil, false, nil, "", false, fmt.Errorf("recursion depth exceeded: %d", depth)
	}

	qname := dns.Fqdn(question.Name)
	question.Name = qname
	nameservers := shuffleSlice(DefaultRootServers)
	currentDomain := "."
	normalizedQname := dnsutil.NormalizeDomain(qname)
	var hijackDetected bool

	log.Debugf("RECURSION: root domain query, %d nameservers", len(nameservers))
	if normalizedQname == "" {
		response, err := rr.queryNameserversConcurrent(ctx, nameservers, question, ecs, forceTCP)
		if err != nil {
			return nil, nil, nil, false, nil, "", false, fmt.Errorf("root domain query: %w", err)
		}

		if rr.server.securityMgr.hijack.IsEnabled() {
			if valid, reason := rr.server.securityMgr.hijack.CheckResponse(currentDomain, normalizedQname, response); !valid {
				pool.DefaultMessagePool.Put(response)
				return rr.handleSuspiciousResponse(reason, forceTCP, ctx, question, ecs, depth)
			}
		}

		validated := rr.server.securityMgr.dnssec.ValidateResponse(response, true)
		ecsResponse := rr.server.ednsMgr.ParseFromDNS(response)

		answer := response.Answer
		authority := response.Ns
		additional := response.Extra
		valid := validated
		ecsResp := ecsResponse
		server := config.RecursiveIndicator
		err = nil
		pool.DefaultMessagePool.Put(response)
		log.Debugf("RECURSION: root domain resolved, validated=%t, answer=%d, authority=%d", validated, len(answer), len(authority))
		return answer, authority, additional, valid, ecsResp, server, false, err
	}

	for {
		select {
		case <-ctx.Done():
			return nil, nil, nil, false, nil, "", false, ctx.Err()
		default:
		}

		response, err := rr.queryNameserversConcurrent(ctx, nameservers, question, ecs, forceTCP)
		if err != nil {
			if !forceTCP && strings.HasPrefix(err.Error(), "DNS_HIJACK_DETECTED") {
				log.Debugf("SECURITY: query error indicates hijack, retrying with TCP for %s", question.Name)
				return rr.recursiveQuery(ctx, question, ecs, depth, true)
			}
			return nil, nil, nil, false, nil, "", false, fmt.Errorf("query %s: %w", currentDomain, err)
		}

		if rr.server.securityMgr.hijack.IsEnabled() {
			if valid, reason := rr.server.securityMgr.hijack.CheckResponse(currentDomain, normalizedQname, response); !valid {
				pool.DefaultMessagePool.Put(response)
				answer, authority, additional, validated, ecsResponse, server, hijackDetectedNow, err := rr.handleSuspiciousResponse(reason, forceTCP, ctx, question, ecs, depth)
				if hijackDetectedNow {
					hijackDetected = true
				}
				if !forceTCP && strings.HasPrefix(err.Error(), "DNS_HIJACK_DETECTED") {
					return rr.recursiveQuery(ctx, question, ecs, depth, true)
				}
				return answer, authority, additional, validated, ecsResponse, server, hijackDetected, err
			}
		}

		validated := rr.server.securityMgr.dnssec.ValidateResponse(response, true)
		ecsResponse := rr.server.ednsMgr.ParseFromDNS(response)

		log.Debugf("RECURSION: query %s from %d nameservers (domain=%s), validated=%t, answer=%d", question.Name, len(nameservers), currentDomain, validated, len(response.Answer))
		if len(response.Answer) > 0 {
			answer, authority, additional := response.Answer, response.Ns, response.Extra
			pool.DefaultMessagePool.Put(response)
			return answer, authority, additional, validated, ecsResponse, config.RecursiveIndicator, false, nil
		}

		bestMatch := ""
		var bestNSRecords []*dns.NS

		for _, rrec := range response.Ns {
			if ns, ok := rrec.(*dns.NS); ok {
				nsName := dnsutil.NormalizeDomain(rrec.Header().Name)

				isMatch := normalizedQname == nsName ||
					(nsName != "" && strings.HasSuffix(normalizedQname, "."+nsName)) ||
					(nsName == "" && normalizedQname != "")

				if isMatch && len(nsName) >= len(bestMatch) {
					if len(nsName) > len(bestMatch) {
						bestMatch = nsName
						bestNSRecords = []*dns.NS{ns}
					} else {
						bestNSRecords = append(bestNSRecords, ns)
					}
				}
			}
		}

		if len(bestNSRecords) == 0 {
			nsSlice, extraSlice := response.Ns, response.Extra
			pool.DefaultMessagePool.Put(response)
			return nil, nsSlice, extraSlice, validated, ecsResponse, config.RecursiveIndicator, false, nil
		}

		currentDomainNormalized := dnsutil.NormalizeDomain(currentDomain)
		if bestMatch == currentDomainNormalized && currentDomainNormalized != "" {
			nsSlice, extraSlice := response.Ns, response.Extra
			pool.DefaultMessagePool.Put(response)
			return nil, nsSlice, extraSlice, validated, ecsResponse, config.RecursiveIndicator, false, nil
		}

		currentDomain = bestMatch + "."

		var nextNS []string
		for _, ns := range bestNSRecords {
			for _, rrec := range response.Extra {
				switch a := rrec.(type) {
				case *dns.A:
					if strings.EqualFold(a.Header().Name, ns.Ns) {
						nextNS = append(nextNS, net.JoinHostPort(a.A.String(), config.DefaultDNSPort))
					}
				case *dns.AAAA:
					if strings.EqualFold(a.Header().Name, ns.Ns) {
						nextNS = append(nextNS, net.JoinHostPort(a.AAAA.String(), config.DefaultDNSPort))
					}
				}
			}
		}

		if len(nextNS) == 0 {
			nextNS = rr.resolveNSAddressesConcurrent(ctx, bestNSRecords, qname, depth, forceTCP)
		}

		log.Debugf("RECURSION: following delegation to %s, %d NS records, %d glue addresses", currentDomain, len(bestNSRecords), len(nextNS))
		if len(nextNS) == 0 {
			nsSlice, extraSlice := response.Ns, response.Extra
			pool.DefaultMessagePool.Put(response)
			return nil, nsSlice, extraSlice, validated, ecsResponse, config.RecursiveIndicator, false, nil
		}

		nextNS = shuffleSlice(nextNS)

		pool.DefaultMessagePool.Put(response)
		nameservers = nextNS
	}
}

// handleSuspiciousResponse handles potentially hijacked DNS responses.
// It returns an error that triggers TCP fallback if not already using TCP.
func (rr *RecursiveResolver) handleSuspiciousResponse(reason string, currentlyTCP bool, _ context.Context, _ dns.Question, _ *edns.ECSOption, _ int) ([]dns.RR, []dns.RR, []dns.RR, bool, *edns.ECSOption, string, bool, error) {
	if !currentlyTCP {
		log.Debugf("SECURITY: UDP response suspicious, switching to TCP retry, reason=%s", reason)
		return nil, nil, nil, false, nil, "", true, fmt.Errorf("DNS_HIJACK_DETECTED: %s", reason)
	}
	log.Debugf("SECURITY: TCP response still suspicious, rejecting completely, reason=%s", reason)
	return nil, nil, nil, false, nil, "", true, fmt.Errorf("DNS hijacking detected (TCP): %s", reason)
}

// queryNameserversConcurrent performs concurrent queries to multiple nameservers
// using the "first win" strategy for optimal performance.
func (rr *RecursiveResolver) queryNameserversConcurrent(ctx context.Context, nameservers []string, question dns.Question, ecs *edns.ECSOption, forceTCP bool) (*dns.Msg, error) {
	if len(nameservers) == 0 {
		return nil, errors.New("no nameservers")
	}

	nameservers = shuffleSlice(nameservers)

	queryCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(errors.New("query resolution completed"))

	resultChan := make(chan *dns.Msg, 1)

	g, queryCtx := errgroup.WithContext(queryCtx)
	g.SetLimit(calculateConcurrencyLimit(len(nameservers)))

	// Track active connections for immediate termination
	var activeConnections atomic.Int32

	for _, ns := range nameservers {
		nsAddr := ns
		protocol := "udp"
		if forceTCP {
			protocol = "tcp"
		}
		server := &config.UpstreamServer{Address: nsAddr, Protocol: protocol}

		g.Go(func() error {
			defer dnsutil.HandlePanic("Query nameserver")
			activeConnections.Add(1)
			defer activeConnections.Add(-1)

			select {
			case <-queryCtx.Done():
				return queryCtx.Err()
			default:
			}

			msg := rr.server.buildQueryMessage(question, ecs, true, false)
			defer pool.DefaultMessagePool.Put(msg)

			// Create a sub-context with shorter timeout for individual queries
			subCtx, subCancel := context.WithTimeout(queryCtx, DefaultTimeout/2)
			defer subCancel()

			result := rr.server.queryClient.ExecuteQuery(subCtx, msg, server)

			if result.Error == nil && result.Response != nil {
				rcode := result.Response.Rcode

				if rcode == dns.RcodeSuccess || rcode == dns.RcodeNameError {
					result.Validated = rr.server.securityMgr.dnssec.ValidateResponse(result.Response, true)
					select {
					case resultChan <- result.Response:
						// First win - immediately cancel all other connections
						cancel(errors.New("first win successful query completed"))
						return nil
					case <-queryCtx.Done():
						pool.DefaultMessagePool.Put(result.Response)
						return queryCtx.Err()
					}
				}
				pool.DefaultMessagePool.Put(result.Response)
			}
			return nil
		})
	}

	// Monitor for first success and terminate remaining connections
	go func() {
		_ = g.Wait()
		close(resultChan)
	}()

	select {
	case result, ok := <-resultChan:
		if ok && result != nil {
			// Log connection termination stats
			remaining := activeConnections.Load()
			if remaining > 0 {
				log.Debugf("RECURSION: First win achieved, terminating %d remaining connections", remaining)
			}
			return result, nil
		}
		return nil, errors.New("no successful response")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// resolveNSAddressesConcurrent resolves NS record hostnames to IP addresses
// using concurrent A and AAAA queries with first-win optimization.
func (rr *RecursiveResolver) resolveNSAddressesConcurrent(ctx context.Context, nsRecords []*dns.NS, qname string, depth int, forceTCP bool) []string {
	if len(nsRecords) == 0 {
		return nil
	}

	nsRecords = shuffleSlice(nsRecords)

	resolveCtx, resolveCancel := context.WithTimeout(ctx, DefaultTimeout)
	defer resolveCancel()

	g, queryCtx := errgroup.WithContext(resolveCtx)
	g.SetLimit(calculateConcurrencyLimit(len(nsRecords)))

	var allMu sync.Mutex
	var allAddresses []string

	// For first-win optimization: cancel when we get sufficient addresses
	addressCtx, addressCancel := context.WithCancelCause(queryCtx)
	defer addressCancel(errors.New("NS address resolution completed"))

	var foundAddresses atomic.Int32
	var activeResolutions atomic.Int32

	for _, ns := range nsRecords {
		nsRecord := ns

		g.Go(func() error {
			defer dnsutil.HandlePanic("Resolve NS addresses")
			activeResolutions.Add(1)
			defer activeResolutions.Add(-1)

			select {
			case <-queryCtx.Done():
				return nil
			default:
			}

			if strings.EqualFold(strings.TrimSuffix(nsRecord.Ns, "."), strings.TrimSuffix(qname, ".")) {
				return nil
			}

			var nsAddresses atomic.Value
			nsAddresses.Store([]string{})

			// Use first-win for IPv4/IPv6 resolution (A and AAAA records)
			queryGroup, subCtx := errgroup.WithContext(addressCtx)
			queryGroup.SetLimit(calculateConcurrencyLimit(2)) // IPv4 + IPv6 queries

			// IPv4 resolution
			queryGroup.Go(func() error {
				defer dnsutil.HandlePanic("Resolve NS IPv4")

				nsQuestion := dns.Question{
					Name:   dns.Fqdn(nsRecord.Ns),
					Qtype:  dns.TypeA,
					Qclass: dns.ClassINET,
				}

				// Create sub-context with shorter timeout
				ipv4Ctx, ipv4Cancel := context.WithTimeout(subCtx, DefaultTimeout/3)
				defer ipv4Cancel()

				var ipv4Addresses []string
				if nsAnswer, _, _, _, _, _, _, err := rr.recursiveQuery(ipv4Ctx, nsQuestion, nil, depth+1, forceTCP); err == nil {
					for _, rrec := range nsAnswer {
						if a, ok := rrec.(*dns.A); ok {
							ipv4Addresses = append(ipv4Addresses, net.JoinHostPort(a.A.String(), config.DefaultDNSPort))
						}
					}
				}

				if len(ipv4Addresses) > 0 {
					if existing := nsAddresses.Load().([]string); len(existing) > 0 {
						combined := append(existing, ipv4Addresses...)
						nsAddresses.Store(combined)
					} else {
						nsAddresses.Store(ipv4Addresses)
					}
					// First win - cancel IPv6 resolution
					addressCancel(errors.New("IPv4 addresses resolved - first win"))
				}
				return nil
			})

			// IPv6 resolution
			queryGroup.Go(func() error {
				defer dnsutil.HandlePanic("Resolve NS IPv6")

				nsQuestionV6 := dns.Question{
					Name:   dns.Fqdn(nsRecord.Ns),
					Qtype:  dns.TypeAAAA,
					Qclass: dns.ClassINET,
				}

				// Create sub-context with shorter timeout
				ipv6Ctx, ipv6Cancel := context.WithTimeout(subCtx, DefaultTimeout/3)
				defer ipv6Cancel()

				var ipv6Addresses []string
				if nsAnswerV6, _, _, _, _, _, _, err := rr.recursiveQuery(ipv6Ctx, nsQuestionV6, nil, depth+1, forceTCP); err == nil {
					for _, rrec := range nsAnswerV6 {
						if aaaa, ok := rrec.(*dns.AAAA); ok {
							ipv6Addresses = append(ipv6Addresses, net.JoinHostPort(aaaa.AAAA.String(), config.DefaultDNSPort))
						}
					}
				}

				if len(ipv6Addresses) > 0 {
					if existing := nsAddresses.Load().([]string); len(existing) > 0 {
						combined := append(existing, ipv6Addresses...)
						nsAddresses.Store(combined)
					} else {
						nsAddresses.Store(ipv6Addresses)
					}
					// First win - cancel IPv4 resolution
					addressCancel(errors.New("IPv6 addresses resolved - first win"))
				}
				return nil
			})

			_ = queryGroup.Wait()

			if nsAddrs := nsAddresses.Load().([]string); len(nsAddrs) > 0 {
				allMu.Lock()
				allAddresses = append(allAddresses, nsAddrs...)
				allMu.Unlock()

				// First win optimization: if we have enough addresses, cancel remaining NS resolutions
				if foundAddresses.Add(1) >= int32(calculateConcurrencyLimit(len(nsRecords))) {
					resolveCancel()
					log.Debugf("RECURSION: First win NS resolution - canceling %d remaining NS lookups", activeResolutions.Load())
				}
			}

			return nil
		})
	}

	_ = g.Wait()

	allMu.Lock()
	finalAddresses := allAddresses
	allMu.Unlock()
	return finalAddresses
}
