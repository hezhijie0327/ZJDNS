// Package resolver implements DNS query resolution through upstream servers or
// built-in recursive resolution with CNAME chasing and DNSSEC validation.
package resolver

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"sync/atomic"

	"github.com/miekg/dns"

	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/log"
	"zjdns/server/client"
	"zjdns/server/security"
)

const (
	// MaxCNAMEChain is the maximum number of CNAME redirections to follow.
	MaxCNAMEChain = 16

	// MaxRecursionDep is the maximum recursion depth for iterative resolution.
	MaxRecursionDep = 16
)

var (
	// ErrCIDRFilterRefused is returned when all A/AAAA records are filtered by
	// CIDR rules.
	ErrCIDRFilterRefused = errors.New("cidr_filter_refused")

	// ErrAllUpstreamFailed is returned when no upstream server responds
	// successfully.
	ErrAllUpstreamFailed = errors.New("all upstream queries failed")
)

// BuildQueryFunc is a function type that constructs a DNS query message from a
// question, ECS option, and connection parameters.
type BuildQueryFunc func(question dns.Question, ecs *edns.ECSOption, recursionDesired bool, isSecureConnection bool) *dns.Msg

// CIDRMatcher is the interface for matching IP addresses against CIDR rules
// with optional tags.
type CIDRMatcher interface {
	MatchIP(ip net.IP, tag string) (matched, exists bool)
}

type upstreamSet struct {
	servers atomic.Pointer[[]*config.UpstreamServer]
}

// Resolver handles DNS query resolution by dispatching to upstream servers,
// recursive resolution, or fallback servers as configured.
type Resolver struct {
	client    *client.Client
	edns      *edns.Handler
	cidr      CIDRMatcher
	buildMsg  BuildQueryFunc
	upstream  *upstreamSet
	fallback  *upstreamSet
	recursive *Recursive
	cname     *CNAME
	validator *Validator
}

// Validator holds the DNSSEC and hijack detection components for response
// validation.
type Validator struct {
	DNSSEC *security.Validator
	Hijack *security.Detector
}

func (us *upstreamSet) list() []*config.UpstreamServer {
	p := us.servers.Load()
	if p == nil {
		return nil
	}
	return *p
}

func (us *upstreamSet) store(s []*config.UpstreamServer) {
	us.servers.Store(&s)
}

// New creates a new Resolver with the given client, security guard, EDNS
// handler, CIDR matcher, and query builder function.
func New(c *client.Client, g *security.Guard, e *edns.Handler, cidr CIDRMatcher, buildMsg BuildQueryFunc) *Resolver {
	r := &Resolver{
		client:   c,
		edns:     e,
		cidr:     cidr,
		buildMsg: buildMsg,
		upstream: &upstreamSet{},
		fallback: &upstreamSet{},
	}
	r.recursive = &Recursive{resolver: r}
	r.cname = &CNAME{resolver: r}
	r.validator = &Validator{DNSSEC: g.Validator, Hijack: g.Detector}
	return r
}

// InitServers initializes the primary and fallback upstream server lists.
func (r *Resolver) InitServers(servers, fallback []config.UpstreamServer) {
	active := make([]*config.UpstreamServer, 0, len(servers))
	for i := range servers {
		s := &servers[i]
		if s.Protocol == "" {
			s.Protocol = "udp"
		}
		active = append(active, s)
	}
	r.upstream.store(active)

	fb := make([]*config.UpstreamServer, 0, len(fallback))
	for i := range fallback {
		s := &fallback[i]
		if s.Protocol == "" {
			s.Protocol = "udp"
		}
		fb = append(fb, s)
	}
	r.fallback.store(fb)
}

// UpstreamServers returns the current list of primary upstream servers.
func (r *Resolver) UpstreamServers() []*config.UpstreamServer {
	return r.upstream.list()
}

// Query resolves a DNS question by querying upstream servers, falling back to
// recursive resolution if no upstream is configured.
func (r *Resolver) Query(question dns.Question, ecs *edns.ECSOption) ([]dns.RR, []dns.RR, []dns.RR, bool, *edns.ECSOption, string, bool, error) {
	servers := r.upstream.list()
	fallbackServers := r.fallback.list()

	if len(servers) > 0 {
		answer, authority, additional, validated, ecsResponse, server, fallbackUsed, err :=
			r.queryUpstream(question, ecs, servers)
		if err == nil {
			return answer, authority, additional, validated, ecsResponse, server, fallbackUsed, nil
		}
		if len(fallbackServers) > 0 {
			log.Debugf("UPSTREAM: primary upstream failed, querying fallback servers")
			a, au, ad, v, e, s, _, err2 := r.queryUpstream(question, ecs, fallbackServers)
			if err2 == nil {
				return a, au, ad, v, e, s, true, nil
			}
		}
		return nil, nil, nil, false, nil, "", false, err
	}

	if len(fallbackServers) > 0 {
		a, au, ad, v, e, s, _, err := r.queryUpstream(question, ecs, fallbackServers)
		return a, au, ad, v, e, s, true, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), config.IdleTimeout)
	defer cancel()
	return r.cname.resolve(ctx, question, ecs)
}

// ShuffleSlice returns a shuffled copy of the input slice using a modern
// Fisher-Yates algorithm.
func ShuffleSlice[T any](slice []T) []T {
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

// ConcurrencyLimit returns an adaptive concurrency limit based on the number of
// servers to query simultaneously.
func ConcurrencyLimit(serverCount int) int {
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
