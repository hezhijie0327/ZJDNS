// Package resolver implements DNS query resolution through upstream servers or
// built-in recursive resolution with CNAME chasing and DNSSEC validation.
package resolver

import (
	"context"
	"errors"
	"fmt"

	"math/rand/v2"
	"net"
	"sync/atomic"

	"codeberg.org/miekg/dns"

	"zjdns/cache"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/log"
	"zjdns/server/client"
	"zjdns/server/security"
)

// Question is a DNS question compatible with both v1 and v2 dns packages.
type Question struct {
	Name   string
	Qtype  uint16
	Qclass uint16
}

var (
	// ErrCIDRFilterRefused is returned when all A/AAAA records are filtered by
	// CIDR rules.
	ErrCIDRFilterRefused = errors.New("cidr_filter_refused")
)

// concurrencyTier1/2/3 define server-count thresholds for adaptive concurrency
// limits. concurrencyDiv2/3 are divisor constants used in the tier formulas:
//
//	Tier 1 (≤4 servers): 2 × serverCount
//	Tier 2 (5–12 servers): (2×serverCount + 2) / 3
//	Tier 3 (13–20 servers): (serverCount + 1) / 2
//	Tier 4 (>20 servers): serverCount / 3
const (
	concurrencyTier1 = 4
	concurrencyTier2 = 12
	concurrencyTier3 = 20
	concurrencyDiv2  = 2
	concurrencyDiv3  = 3
)

// DNSSECError wraps a DNSSEC validation failure with the RFC 8914 EDE code.
type DNSSECError struct {
	EDECode uint16
	Message string
}

func (e *DNSSECError) Error() string {
	return fmt.Sprintf("DNSSEC validation failed [EDE %d]: %s", e.EDECode, e.Message)
}

// dnssecEDEError builds a DNSSECError from an EDE code stored as uint64
// (matching atomic.Uint64.Load()), shared between upstream query result
// handlers to keep EDE construction in one place.
func dnssecEDEError(edeCode uint64) *DNSSECError {
	return &DNSSECError{
		EDECode: uint16(edeCode),
		Message: fmt.Sprintf("upstream rejected response (EDE %d: %s)", uint16(edeCode), edns.EDECodeString(uint16(edeCode))),
	}
}

// QueryResult bundles the return values of a DNS resolution query, replacing
// the previous 8-return-value tuple at the public API boundary.
type QueryResult struct {
	Answer     []dns.RR
	Authority  []dns.RR
	Additional []dns.RR
	Validated  bool
	ECS        *edns.ECSOption
	Server     string
	Fallback   bool
	Hijack     bool
	Err        error
}

// BuildQueryFunc is a function type that constructs a DNS query message from a
// question, ECS option, and connection parameters.
type BuildQueryFunc func(question Question, ecs *edns.ECSOption, recursionDesired bool, isSecureConnection bool) *dns.Msg

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
	client          *client.Client
	edns            *edns.Handler
	cidr            CIDRMatcher
	buildMsg        BuildQueryFunc
	upstream        *upstreamSet
	fallback        *upstreamSet
	recursive       *Recursive
	cname           *CNAME
	validator       *Validator
	DNSSECEnforce   bool
	lastUpstreamEDE atomic.Pointer[edns.EDEOption] // EDE from upstream response for passthrough
	cache           cache.Store                    // DNS response cache for NS A/AAAA lookups

	recursiveProxyURL string // proxy for recursive mode (from builtin_recursive upstream)
}

// Validator holds the DNSSEC and hijack detection components for response
// validation. Lightweight record-presence checking is provided by the
// package-level security.IsResponseValid function.
type Validator struct {
	Crypto *security.CryptoValidator // Full cryptographic DNSSEC validation
	Hijack *security.Detector        // DNS hijack detection
}

func (u *upstreamSet) list() []*config.UpstreamServer {
	p := u.servers.Load()
	if p == nil {
		return nil
	}
	return *p
}

func (u *upstreamSet) store(s []*config.UpstreamServer) {
	u.servers.Store(&s)
}

// New creates a new Resolver with the given client, security guard, EDNS
// handler, CIDR matcher, and query builder function.
func New(c *client.Client, g *security.Guard, e *edns.Handler, cidr CIDRMatcher, buildMsg BuildQueryFunc, cacheStore cache.Store) *Resolver {
	r := &Resolver{
		client:   c,
		edns:     e,
		cidr:     cidr,
		buildMsg: buildMsg,
		upstream: &upstreamSet{},
		fallback: &upstreamSet{},
		cache:    cacheStore,
	}
	r.recursive = &Recursive{resolver: r, cache: cacheStore}
	r.cname = &CNAME{resolver: r}
	r.validator = &Validator{Crypto: g.Crypto, Hijack: g.Detector}
	return r
}

// ConfigureServers initializes the primary and fallback upstream server lists.
func (r *Resolver) ConfigureServers(servers, fallback []config.UpstreamServer) {
	active := make([]*config.UpstreamServer, 0, len(servers))
	for i := range servers {
		s := &servers[i]
		if s.Protocol == "" {
			s.Protocol = config.ProtoUDP
		}
		if s.IsRecursive() && s.Proxy != "" {
			r.recursiveProxyURL = s.Proxy
		}
		active = append(active, s)
	}
	r.upstream.store(active)

	fb := make([]*config.UpstreamServer, 0, len(fallback))
	for i := range fallback {
		s := &fallback[i]
		if s.Protocol == "" {
			s.Protocol = config.ProtoUDP
		}
		if s.IsRecursive() && s.Proxy != "" && r.recursiveProxyURL == "" {
			r.recursiveProxyURL = s.Proxy
		}
		fb = append(fb, s)
	}
	r.fallback.store(fb)
}

// Recursive returns the built-in recursive resolver, or nil if not initialized.
func (r *Resolver) Recursive() *Recursive {
	if r == nil {
		return nil
	}
	return r.recursive
}

// UpstreamEDEOption returns the EDE option parsed from the last upstream
// response (any rcode). Returns nil when no EDE was present or the resolver
// used recursive mode. Callers should pass this through to downstream clients
// so upstream DNSSEC bogus and other diagnostic EDE codes are not dropped.
func (r *Resolver) UpstreamEDEOption() *edns.EDEOption {
	if r == nil {
		return nil
	}
	return r.lastUpstreamEDE.Load()
}

// UpstreamServers returns the current list of primary upstream servers.
func (r *Resolver) UpstreamServers() []*config.UpstreamServer {
	return r.upstream.list()
}

// Query resolves a DNS question by querying upstream servers, falling back to
// recursive resolution if no upstream is configured.
//
// When both upstream and fallback servers are configured, they are queried
// concurrently. The upstream result is preferred; if upstream fails, the
// fallback result is immediately available without waiting for a sequential
// retry. Fallback results are cacheable — the concurrent model ensures they
// are fresh, not stale second-attempt data.
func (r *Resolver) Query(ctx context.Context, question Question, ecs *edns.ECSOption) *QueryResult {
	servers := r.upstream.list()
	fallbackServers := r.fallback.list()

	// No servers configured — use built-in recursive resolver.
	if len(servers) == 0 && len(fallbackServers) == 0 {
		resolveCtx, cancel := context.WithTimeout(ctx, config.DefaultRecursiveResolveTimeout)
		defer cancel()
		a, au, ad, v, e, s, _, err := r.cname.resolve(resolveCtx, question, ecs)
		return &QueryResult{Answer: a, Authority: au, Additional: ad, Validated: v, ECS: e, Server: s, Fallback: false, Err: err}
	}

	// Only one set of servers — query directly without coordination overhead.
	// Do not fall back to recursive resolution when no fallback servers are
	// configured; return the upstream error so the client receives a clear
	// failure signal instead of silently switching to recursive mode.
	if len(fallbackServers) == 0 {
		a, au, ad, v, e, s, f, h, err := r.queryUpstream(ctx, question, ecs, servers)
		return &QueryResult{Answer: a, Authority: au, Additional: ad, Validated: v, ECS: e, Server: s, Fallback: f, Hijack: h, Err: err}
	}

	if len(servers) == 0 {
		a, au, ad, v, e, s, _, h, err := r.queryUpstream(ctx, question, ecs, fallbackServers)
		return &QueryResult{Answer: a, Authority: au, Additional: ad, Validated: v, ECS: e, Server: s, Fallback: true, Hijack: h, Err: err}
	}

	// Both upstream and fallback configured — query concurrently so the
	// fallback answer is already ready if upstream fails.

	upstreamCh := make(chan result, 1)
	fallbackCh := make(chan result, 1)
	queryCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(errors.New("query completed"))

	go func() {
		a, au, ad, v, e, s, _, h, err := r.queryUpstream(queryCtx, question, ecs, servers)
		select {
		case upstreamCh <- result{Answer: a, Authority: au, Additional: ad, Validated: v, ECS: e, Server: s, Hijack: h, Err: err}:
		case <-queryCtx.Done():
		}
	}()

	go func() {
		a, au, ad, v, e, s, _, h, err := r.queryUpstream(queryCtx, question, ecs, fallbackServers)
		select {
		case fallbackCh <- result{Answer: a, Authority: au, Additional: ad, Validated: v, ECS: e, Server: s, Hijack: h, Err: err}:
		case <-queryCtx.Done():
		}
	}()

	// Prefer upstream; if it fails, the concurrent fallback is already
	// available (or nearly so) instead of starting a fresh sequential query.
	select {
	case up := <-upstreamCh:
		if up.Err == nil {
			return &QueryResult{Answer: up.Answer, Authority: up.Authority, Additional: up.Additional, Validated: up.Validated, ECS: up.ECS, Server: up.Server, Fallback: false, Hijack: up.Hijack}
		}
		log.Debugf("UPSTREAM: primary upstream failed for %s, waiting for concurrent fallback", question.Name)
		select {
		case fb := <-fallbackCh:
			if fb.Err == nil {
				return &QueryResult{Answer: fb.Answer, Authority: fb.Authority, Additional: fb.Additional, Validated: fb.Validated, ECS: fb.ECS, Server: fb.Server, Fallback: true, Hijack: fb.Hijack}
			}
			return &QueryResult{Err: fb.Err}
		case <-ctx.Done():
			return &QueryResult{Err: ctx.Err()}
		}
	case <-ctx.Done():
		return &QueryResult{Err: ctx.Err()}
	}
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

// concurrencyLimit returns an adaptive concurrency limit based on the number of
// servers to query simultaneously.
func concurrencyLimit(serverCount int) int {
	if serverCount <= 0 {
		return 1
	}
	switch {
	case serverCount <= concurrencyTier1:
		return serverCount
	case serverCount <= concurrencyTier2:
		return (serverCount*concurrencyDiv2 + concurrencyDiv2) / concurrencyDiv3
	case serverCount <= concurrencyTier3:
		return (serverCount + 1) / concurrencyDiv2
	default:
		limit := serverCount / concurrencyDiv3
		if limit < config.DefaultMinConcurrencyLimit {
			return config.DefaultMinConcurrencyLimit
		}
		return limit
	}
}
