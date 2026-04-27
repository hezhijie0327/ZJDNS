// Package main implements ZJDNS - High Performance DNS Server
// This file contains DNS resolution functionality including query management,
// upstream handling, recursive resolution, and CNAME chain resolution.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"

	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"
)

const (
	RecursiveIndicator = "builtin_recursive" // Indicator for responses obtained from the built-in recursive resolver

	MaxCNAMEChain      = 16                  // Maximum number of CNAME redirections to follow to prevent loops
	MaxRecursionDep    = 16                  // Maximum recursion depth for resolving queries to prevent infinite loops
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

// QueryManager orchestrates DNS query resolution, managing upstream servers,
type QueryManager struct {
	upstream  *UpstreamHandler
	fallback  *UpstreamHandler
	recursive *RecursiveResolver
	cname     *CNAMEHandler
	validator *ResponseValidator
	server    *DNSServer
}

// UpstreamHandler manages querying upstream name servers, including primary and fallback lists.
type UpstreamHandler struct {
	servers atomic.Pointer[[]*UpstreamServer]
}

// UpstreamServer represents a configured upstream DNS server with optional client filters.
type RecursiveResolver struct {
	server *DNSServer
}

// CNAMEHandler manages CNAME resolution logic, including multi-level chains and loop detection.
type CNAMEHandler struct {
	server *DNSServer
}

// ResponseValidator coordinates DNSSEC validation and hijack prevention checks for DNS responses.
type ResponseValidator struct {
	hijackPrevention *HijackPrevention
	dnssecValidator  *DNSSECValidator
}

// NewQueryManager creates a new QueryManager instance with initialized handlers.
func NewQueryManager(server *DNSServer) *QueryManager {
	upstream := &UpstreamHandler{}
	fallback := &UpstreamHandler{}
	emptyServers := make([]*UpstreamServer, 0)
	upstream.servers.Store(&emptyServers)
	fallback.servers.Store(&emptyServers)

	return &QueryManager{
		upstream: upstream,
		fallback: fallback,
		recursive: &RecursiveResolver{
			server: server,
		},
		cname: &CNAMEHandler{server: server},
		validator: &ResponseValidator{
			hijackPrevention: server.securityMgr.hijack,
			dnssecValidator:  server.securityMgr.dnssec,
		},
		server: server,
	}
}

// shuffleSlice shuffles a slice randomly.
func shuffleSlice[T any](slice []T) []T {
	if len(slice) <= 1 {
		return slice
	}

	shuffled := make([]T, len(slice))
	copy(shuffled, slice)

	for i := len(shuffled) - 1; i > 0; i-- {
		j := globalRNG.Intn(i + 1)
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	}

	return shuffled
}

// calculateConcurrencyLimit calculates the concurrency limit based on server count.
func calculateConcurrencyLimit(serverCount int) int {
	if serverCount <= 0 {
		return 1
	}

	switch {
	case serverCount <= 4:
		return serverCount
	case serverCount <= 12:
		return (serverCount*2 + 2) / 3
	case serverCount <= 20:
		return (serverCount + 1) / 2
	default:
		limit := serverCount / 3
		if limit < 8 {
			return 8
		}
		return limit
	}
}

// Initialize initializes the QueryManager with upstream and fallback server configurations.
// It processes the server lists and sets default protocols where needed.
func (qm *QueryManager) Initialize(servers []UpstreamServer, fallback []UpstreamServer) error {
	activeServers := make([]*UpstreamServer, 0, len(servers))
	for i := range servers {
		server := &servers[i]
		if server.Protocol == "" {
			server.Protocol = "udp"
		}
		activeServers = append(activeServers, server)
	}
	qm.upstream.servers.Store(&activeServers)

	fallbackServers := make([]*UpstreamServer, 0, len(fallback))
	for i := range fallback {
		server := &fallback[i]
		if server.Protocol == "" {
			server.Protocol = "udp"
		}
		fallbackServers = append(fallbackServers, server)
	}
	qm.fallback.servers.Store(&fallbackServers)

	return nil
}

// Query routes DNS queries between upstream servers, fallback servers, and recursive resolution.
// If primary upstream servers are configured, it queries them first and falls back if they fail.
func (qm *QueryManager) Query(question dns.Question, ecs *ECSOption) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, string, bool, error) {
	servers := qm.upstream.getServers()
	fallbackServers := qm.fallback.getServers()

	if len(servers) > 0 {
		answer, authority, additional, validated, ecsResponse, server, fallbackUsed, err := qm.queryUpstream(question, ecs, servers)
		if err == nil {
			return answer, authority, additional, validated, ecsResponse, server, fallbackUsed, nil
		}

		if len(fallbackServers) > 0 {
			LogDebug("UPSTREAM: primary upstream failed, querying fallback servers")
			answer, authority, additional, validated, ecsResponse, server, _, err = qm.queryUpstream(question, ecs, fallbackServers)
			if err == nil {
				return answer, authority, additional, validated, ecsResponse, server, true, nil
			}
		}

		return nil, nil, nil, false, nil, "", false, err
	}

	if len(fallbackServers) > 0 {
		answer, authority, additional, validated, ecsResponse, server, _, err := qm.queryUpstream(question, ecs, fallbackServers)
		return answer, authority, additional, validated, ecsResponse, server, true, err
	}

	ctx, cancel := context.WithTimeout(qm.server.ctx, IdleTimeout)
	defer cancel()

	answer, authority, additional, validated, ecsResponse, server, hijackDetected, err := qm.cname.resolveWithCNAME(ctx, question, ecs)
	return answer, authority, additional, validated, ecsResponse, server, hijackDetected, err
}

// getServers returns the list of configured upstream servers.
func (uh *UpstreamHandler) getServers() []*UpstreamServer {
	serversPtr := uh.servers.Load()
	if serversPtr == nil {
		return []*UpstreamServer{}
	}
	return *serversPtr
}

// queryUpstream performs concurrent queries to upstream DNS servers.
// It implements the "first win" strategy where the first successful response
// is returned immediately, canceling any pending queries.
func (qm *QueryManager) queryUpstream(question dns.Question, ecs *ECSOption, servers []*UpstreamServer) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, string, bool, error) {
	if len(servers) == 0 {
		return nil, nil, nil, false, nil, "", false, errors.New("no upstream servers")
	}

	servers = shuffleSlice(servers)

	serverAddrs := make([]string, 0, len(servers))
	for _, s := range servers {
		proto := s.Protocol
		if proto == "" {
			proto = "udp"
		}
		serverAddrs = append(serverAddrs, fmt.Sprintf("%s(%s)", s.Address, proto))
	}
	LogDebug("UPSTREAM: querying %d servers for %s: %v", len(servers), question.Name, serverAddrs)

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
				recursiveCtx, recursiveCancel := context.WithTimeout(queryCtx, IdleTimeout)
				defer recursiveCancel()

				answer, authority, additional, validated, ecsResponse, usedServer, _, err := qm.cname.resolveWithCNAME(recursiveCtx, question, ecs)

				if err == nil && len(answer) > 0 {
					if len(server.Match) > 0 {
						filteredAnswer, shouldRefuse := qm.filterRecordsByCIDR(answer, server.Match)
						if shouldRefuse {
							LogDebug("UPSTREAM: CIDR filter refused all records for %s from recursive", question.Name)
							return errors.New("cidr_filter_refused")
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
				messagePool.Put(msg)

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
								messagePool.Put(queryResult.Response)
								LogDebug("UPSTREAM: CIDR filter refused all records for %s from %s", question.Name, serverDesc)
								return errors.New("cidr_filter_refused")
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
							LogDebug("UPSTREAM: NOERROR from %s for %s, validated=%t, answer=%d, authority=%d", serverDesc, question.Name, queryResult.Validated, len(queryResult.Response.Answer), len(queryResult.Response.Ns))
							remaining := activeConnections.Load() - 1
							if remaining > 0 {
								LogDebug("UPSTREAM: First win achieved, terminating %d remaining connections", remaining)
							}
							cancel(errors.New("successful result obtained from upstream"))
							messagePool.Put(queryResult.Response)
							return nil
						case <-queryCtx.Done():
							messagePool.Put(queryResult.Response)
							return nil
						}
					case dns.RcodeNameError:
						LogDebug("UPSTREAM: NXDOMAIN from %s for %s, storing as fallback", serverDesc, question.Name)
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
						messagePool.Put(queryResult.Response)
					default:
						messagePool.Put(queryResult.Response)
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
				LogDebug("UPSTREAM: Returning NXDOMAIN fallback after no successful response")
				return nxRes.answer, nxRes.authority, nxRes.additional, nxRes.validated, nxRes.ecs, nxRes.server, false, nil
			}
		default:
		}
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

	if refusedCount > 0 {
		return nil, true
	}

	return filtered, false
}

// resolveWithCNAME resolves a DNS question while following CNAME chains.
// It handles multi-level CNAME resolution and detects circular references.
func (ch *CNAMEHandler) resolveWithCNAME(ctx context.Context, question dns.Question, ecs *ECSOption) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, string, bool, error) {
	var allAnswers []dns.RR
	var finalAuthority, finalAdditional []dns.RR
	var finalECSResponse *ECSOption
	var usedServer string
	var hijackOccurred bool
	allValidated := true

	currentQuestion := question
	visitedCNAMEs := make(map[string]bool)

	for range MaxCNAMEChain {
		select {
		case <-ctx.Done():
			return nil, nil, nil, false, nil, "", false, ctx.Err()
		default:
		}

		currentName := NormalizeDomain(currentQuestion.Name)
		if visitedCNAMEs[currentName] {
			return nil, nil, nil, false, nil, "", false, fmt.Errorf("CNAME loop detected: %s", currentName)
		}
		visitedCNAMEs[currentName] = true

		answer, authority, additional, validated, ecsResponse, server, hijackDetectedNow, err := ch.server.queryMgr.recursive.recursiveQuery(ctx, currentQuestion, ecs, 0, false)
		if err != nil {
			return nil, nil, nil, false, nil, "", false, err
		}

		if usedServer == "" {
			usedServer = server
		}

		if hijackDetectedNow {
			hijackOccurred = true
		}

		if !validated {
			allValidated = false
		}

		if ecsResponse != nil {
			finalECSResponse = ecsResponse
		}

		allAnswers = append(allAnswers, answer...)
		finalAuthority = authority
		finalAdditional = additional

		var nextCNAME *dns.CNAME
		hasTargetType := false

		for _, rr := range answer {
			if cname, ok := rr.(*dns.CNAME); ok {
				if strings.EqualFold(rr.Header().Name, currentQuestion.Name) {
					nextCNAME = cname
				}
			} else if rr.Header().Rrtype == currentQuestion.Qtype {
				hasTargetType = true
			}
		}

		if hasTargetType || currentQuestion.Qtype == dns.TypeCNAME || nextCNAME == nil {
			break
		}

		currentQuestion = dns.Question{
			Name:   nextCNAME.Target,
			Qtype:  question.Qtype,
			Qclass: question.Qclass,
		}
	}

	return allAnswers, finalAuthority, finalAdditional, allValidated, finalECSResponse, usedServer, hijackOccurred, nil
}

// recursiveQuery performs recursive DNS resolution starting from root servers.
// It follows the DNS resolution algorithm: query root servers, follow referrals
// to TLD servers, then to authoritative servers until an answer is found.
func (rr *RecursiveResolver) recursiveQuery(ctx context.Context, question dns.Question, ecs *ECSOption, depth int, forceTCP bool) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, string, bool, error) {
	LogDebug("RECURSION: depth=%d, querying %s (type=%s, tcp=%t)", depth, question.Name, dns.TypeToString[question.Qtype], forceTCP)
	if depth > MaxRecursionDep {
		return nil, nil, nil, false, nil, "", false, fmt.Errorf("recursion depth exceeded: %d", depth)
	}

	qname := dns.Fqdn(question.Name)
	question.Name = qname
	nameservers := shuffleSlice(DefaultRootServers)
	currentDomain := "."
	normalizedQname := NormalizeDomain(qname)
	var hijackDetected bool

	LogDebug("RECURSION: root domain query, %d nameservers", len(nameservers))
	if normalizedQname == "" {
		response, err := rr.queryNameserversConcurrent(ctx, nameservers, question, ecs, forceTCP)
		if err != nil {
			return nil, nil, nil, false, nil, "", false, fmt.Errorf("root domain query: %w", err)
		}

		if rr.server.securityMgr.hijack.IsEnabled() {
			if valid, reason := rr.server.securityMgr.hijack.CheckResponse(currentDomain, normalizedQname, response); !valid {
				messagePool.Put(response)
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
		server := RecursiveIndicator
		err = nil
		messagePool.Put(response)
		LogDebug("RECURSION: root domain resolved, validated=%t, answer=%d, authority=%d", validated, len(answer), len(authority))
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
				LogDebug("HIJACK: query error indicates hijack, retrying with TCP for %s", question.Name)
				return rr.recursiveQuery(ctx, question, ecs, depth, true)
			}
			return nil, nil, nil, false, nil, "", false, fmt.Errorf("query %s: %w", currentDomain, err)
		}

		if rr.server.securityMgr.hijack.IsEnabled() {
			if valid, reason := rr.server.securityMgr.hijack.CheckResponse(currentDomain, normalizedQname, response); !valid {
				messagePool.Put(response)
				answer, authority, additional, validated, ecsResponse, server, hijackDetectedNow, err := rr.handleSuspiciousResponse(reason, forceTCP, ctx, question, ecs, depth)
				if hijackDetectedNow {
					hijackDetected = true
				}
				if err != nil && !forceTCP && strings.HasPrefix(err.Error(), "DNS_HIJACK_DETECTED") {
					return rr.recursiveQuery(ctx, question, ecs, depth, true)
				}
				return answer, authority, additional, validated, ecsResponse, server, hijackDetected, err
			}
		}

		validated := rr.server.securityMgr.dnssec.ValidateResponse(response, true)
		ecsResponse := rr.server.ednsMgr.ParseFromDNS(response)

		LogDebug("RECURSION: query %s from %d nameservers (domain=%s), validated=%t, answer=%d", question.Name, len(nameservers), currentDomain, validated, len(response.Answer))
		if len(response.Answer) > 0 {
			answer, authority, additional := response.Answer, response.Ns, response.Extra
			messagePool.Put(response)
			return answer, authority, additional, validated, ecsResponse, RecursiveIndicator, false, nil
		}

		bestMatch := ""
		var bestNSRecords []*dns.NS

		for _, rrec := range response.Ns {
			if ns, ok := rrec.(*dns.NS); ok {
				nsName := NormalizeDomain(rrec.Header().Name)

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
			messagePool.Put(response)
			return nil, nsSlice, extraSlice, validated, ecsResponse, RecursiveIndicator, false, nil
		}

		currentDomainNormalized := NormalizeDomain(currentDomain)
		if bestMatch == currentDomainNormalized && currentDomainNormalized != "" {
			nsSlice, extraSlice := response.Ns, response.Extra
			messagePool.Put(response)
			return nil, nsSlice, extraSlice, validated, ecsResponse, RecursiveIndicator, false, nil
		}

		currentDomain = bestMatch + "."

		var nextNS []string
		for _, ns := range bestNSRecords {
			for _, rrec := range response.Extra {
				switch a := rrec.(type) {
				case *dns.A:
					if strings.EqualFold(a.Header().Name, ns.Ns) {
						nextNS = append(nextNS, net.JoinHostPort(a.A.String(), DefaultDNSPort))
					}
				case *dns.AAAA:
					if strings.EqualFold(a.Header().Name, ns.Ns) {
						nextNS = append(nextNS, net.JoinHostPort(a.AAAA.String(), DefaultDNSPort))
					}
				}
			}
		}

		if len(nextNS) == 0 {
			nextNS = rr.resolveNSAddressesConcurrent(ctx, bestNSRecords, qname, depth, forceTCP)
		}

		LogDebug("RECURSION: following delegation to %s, %d NS records, %d glue addresses", currentDomain, len(bestNSRecords), len(nextNS))
		if len(nextNS) == 0 {
			nsSlice, extraSlice := response.Ns, response.Extra
			messagePool.Put(response)
			return nil, nsSlice, extraSlice, validated, ecsResponse, RecursiveIndicator, false, nil
		}

		nextNS = shuffleSlice(nextNS)

		messagePool.Put(response)
		nameservers = nextNS
	}
}

// handleSuspiciousResponse handles potentially hijacked DNS responses.
// It returns an error that triggers TCP fallback if not already using TCP.
func (rr *RecursiveResolver) handleSuspiciousResponse(reason string, currentlyTCP bool, _ context.Context, _ dns.Question, _ *ECSOption, _ int) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, string, bool, error) {
	if !currentlyTCP {
		LogDebug("HIJACK: UDP response suspicious, switching to TCP retry, reason=%s", reason)
		return nil, nil, nil, false, nil, "", true, fmt.Errorf("DNS_HIJACK_DETECTED: %s", reason)
	}
	LogDebug("HIJACK: TCP response still suspicious, rejecting completely, reason=%s", reason)
	return nil, nil, nil, false, nil, "", true, fmt.Errorf("DNS hijacking detected (TCP): %s", reason)
}

// queryNameserversConcurrent performs concurrent queries to multiple nameservers
// using the "first win" strategy for optimal performance.
func (rr *RecursiveResolver) queryNameserversConcurrent(ctx context.Context, nameservers []string, question dns.Question, ecs *ECSOption, forceTCP bool) (*dns.Msg, error) {
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
		server := &UpstreamServer{Address: nsAddr, Protocol: protocol}
		msg := rr.server.buildQueryMessage(question, ecs, true, false)

		g.Go(func() error {
			defer HandlePanic("Query nameserver")
			activeConnections.Add(1)
			defer activeConnections.Add(-1)

			select {
			case <-queryCtx.Done():
				messagePool.Put(msg)
				return queryCtx.Err()
			default:
			}

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
						messagePool.Put(msg)
						return nil
					case <-queryCtx.Done():
						messagePool.Put(msg)
						messagePool.Put(result.Response)
						return queryCtx.Err()
					}
				}
				messagePool.Put(result.Response)
			}
			messagePool.Put(msg)
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
				LogDebug("RECURSION: First win achieved, terminating %d remaining connections", remaining)
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

	var allAddresses atomic.Pointer[[]string]
	empty := []string{}
	allAddresses.Store(&empty)

	// For first-win optimization: cancel when we get sufficient addresses
	addressCtx, addressCancel := context.WithCancelCause(queryCtx)
	defer addressCancel(errors.New("NS address resolution completed"))

	var foundAddresses atomic.Int32
	var activeResolutions atomic.Int32

	for _, ns := range nsRecords {
		nsRecord := ns

		g.Go(func() error {
			defer HandlePanic("Resolve NS addresses")
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
				defer HandlePanic("Resolve NS IPv4")

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
							ipv4Addresses = append(ipv4Addresses, net.JoinHostPort(a.A.String(), DefaultDNSPort))
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
				defer HandlePanic("Resolve NS IPv6")

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
							ipv6Addresses = append(ipv6Addresses, net.JoinHostPort(aaaa.AAAA.String(), DefaultDNSPort))
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
				current := allAddresses.Load()
				newAddresses := append(*current, nsAddrs...)
				allAddresses.Store(&newAddresses)

				// First win optimization: if we have enough addresses, cancel remaining NS resolutions
				if foundAddresses.Add(1) >= int32(calculateConcurrencyLimit(len(nsRecords))) {
					resolveCancel()
					LogDebug("RECURSION: First win NS resolution - canceling %d remaining NS lookups", activeResolutions.Load())
				}
			}

			return nil
		})
	}

	_ = g.Wait()

	if finalAddresses := allAddresses.Load(); finalAddresses != nil {
		return *finalAddresses
	}

	return nil
}

// IsRecursive returns true if this server is configured for recursive resolution.
func (s *UpstreamServer) IsRecursive() bool {
	if s == nil {
		return false
	}
	return s.Address == RecursiveIndicator
}
