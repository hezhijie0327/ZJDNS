// Package main implements ZJDNS - High Performance DNS Server
// This file contains query orchestration: QueryManager, CNAME resolution,
// and shared helpers used by both upstream and recursive resolution paths.
package server

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"

	"github.com/miekg/dns"

	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
)

// Sentinel errors for query results.
var (
	ErrCIDRFilterRefused = errors.New("cidr_filter_refused")
	ErrAllUpstreamFailed = errors.New("all upstream queries failed")
)

const (
	MaxCNAMEChain   = 16 // Maximum number of CNAME redirections to follow to prevent loops
	MaxRecursionDep = 16 // Maximum recursion depth for resolving queries to prevent infinite loops
)

// QueryManager orchestrates DNS query resolution, managing upstream servers,
type QueryManager struct {
	upstream  *UpstreamHandler
	fallback  *UpstreamHandler
	recursive *RecursiveResolver
	cname     *CNAMEHandler
	validator *ResponseValidator
	server    *DNSServer
}

// CNAMEHandler manages CNAME resolution logic, including multi-level chains and loop detection.
type CNAMEHandler struct {
	server *DNSServer
}

// ResponseValidator coordinates DNSSEC validation and hijack prevention checks for DNS responses.
type ResponseValidator struct {
	hijackPrevention *HijackPrevention
	dnssecValidator  *DNSSECIndicator
}

// NewQueryManager creates a new QueryManager instance with initialized handlers.
func NewQueryManager(server *DNSServer) *QueryManager {
	upstream := &UpstreamHandler{}
	fallback := &UpstreamHandler{}
	emptyServers := make([]*config.UpstreamServer, 0)
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
		j := rand.IntN(i + 1)
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
func (qm *QueryManager) Initialize(servers []config.UpstreamServer, fallback []config.UpstreamServer) error {
	activeServers := make([]*config.UpstreamServer, 0, len(servers))
	for i := range servers {
		server := &servers[i]
		if server.Protocol == "" {
			server.Protocol = "udp"
		}
		activeServers = append(activeServers, server)
	}
	qm.upstream.servers.Store(&activeServers)

	fallbackServers := make([]*config.UpstreamServer, 0, len(fallback))
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
func (qm *QueryManager) Query(question dns.Question, ecs *edns.ECSOption) ([]dns.RR, []dns.RR, []dns.RR, bool, *edns.ECSOption, string, bool, error) {
	servers := qm.upstream.getServers()
	fallbackServers := qm.fallback.getServers()

	if len(servers) > 0 {
		answer, authority, additional, validated, ecsResponse, server, fallbackUsed, err := qm.queryUpstream(question, ecs, servers)
		if err == nil {
			return answer, authority, additional, validated, ecsResponse, server, fallbackUsed, nil
		}

		if len(fallbackServers) > 0 {
			log.Debugf("UPSTREAM: primary upstream failed, querying fallback servers")
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

	ctx, cancel := context.WithTimeout(qm.server.ctx, config.IdleTimeout)
	defer cancel()

	answer, authority, additional, validated, ecsResponse, server, hijackDetected, err := qm.cname.resolveWithCNAME(ctx, question, ecs)
	return answer, authority, additional, validated, ecsResponse, server, hijackDetected, err
}

// It returns the filtered records and a boolean indicating if the response

// resolveWithCNAME resolves a DNS question while following CNAME chains.
// It handles multi-level CNAME resolution and detects circular references.
func (ch *CNAMEHandler) resolveWithCNAME(ctx context.Context, question dns.Question, ecs *edns.ECSOption) ([]dns.RR, []dns.RR, []dns.RR, bool, *edns.ECSOption, string, bool, error) {
	var allAnswers []dns.RR
	var finalAuthority, finalAdditional []dns.RR
	var finalECSResponse *edns.ECSOption
	var usedServer string
	var hijackOccurred bool
	allValidated := true

	currentQuestion := question
	visitedCNAMEs := make(map[string]bool)

	cnameDepth := 0
	for cnameDepth = range MaxCNAMEChain {
		select {
		case <-ctx.Done():
			return nil, nil, nil, false, nil, "", false, ctx.Err()
		default:
		}

		currentName := dnsutil.NormalizeDomain(currentQuestion.Name)
		if visitedCNAMEs[currentName] {
			log.Warnf("RECURSION: CNAME loop detected for %s", currentName)
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

	if cnameDepth >= MaxCNAMEChain-1 {
		log.Warnf("RECURSION: CNAME chain exhausted (max=%d) for %s", MaxCNAMEChain, dnsutil.NormalizeDomain(question.Name))
	}
	return allAnswers, finalAuthority, finalAdditional, allValidated, finalECSResponse, usedServer, hijackOccurred, nil
}
