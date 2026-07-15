// Package resolver implements DNS query resolution through upstream servers or
// built-in recursive resolution with CNAME chasing and DNSSEC validation.
package resolver

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync/atomic"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/log"
	"zjdns/server/resolver/dnssec"
	"zjdns/server/resolver/hijack"
	"zjdns/server/upstream"

	"codeberg.org/miekg/dns"
)

// Question is a DNS question decoupled from the underlying DNS library's representation.
type Question struct {
	Name   string
	Qtype  uint16
	Qclass uint16
}

// DNSSECError wraps a DNSSEC validation failure with the RFC 8914 EDE code.
type DNSSECError struct {
	EDECode uint16
	Message string
}

// QueryResult bundles the return values of a DNS resolution query, replacing
// the previous 8-return-value tuple at the public API boundary.
type QueryResult struct {
	Answer     []dns.RR
	Authority  []dns.RR
	Additional []dns.RR
	Validated  bool
	Cacheable  bool
	ECS        *edns.ECSOption
	Server     string
	Fallback   bool
	Hijack     bool
	Err        error
}

// BuildQueryFunc is a function type that constructs a DNS query message from a
// question, ECS option, and connection parameters.
type BuildQueryFunc func(question Question, ecs *edns.ECSOption, recursionDesired, isSecureConnection bool) *dns.Msg

// CIDRMatcher is the interface for matching IP addresses against ruleset tags
// with optional tags.
type CIDRMatcher interface {
	MatchIP(ip, tag string) (matched, exists bool)
	HasIPTag(tag string) bool
}

type upstreamSet struct {
	servers atomic.Pointer[[]*config.UpstreamServer]
}

// Resolver handles DNS query resolution by dispatching to upstream servers,
// recursive resolution, or fallback servers as configured.
type Resolver struct {
	queryClient     *upstream.Client
	edns            *edns.Handler
	crd             CIDRMatcher
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
// package-level dnssec.IsResponseValid function.
type Validator struct {
	Crypto *dnssec.CryptoValidator // Full cryptographic DNSSEC validation
	Hijack *hijack.Detector        // DNS hijack detection
}

// Config bundles the dependencies needed to construct a Resolver.
type Config struct {
	QueryClient   *upstream.Client
	Crypto        *dnssec.CryptoValidator
	Hijack        *hijack.Detector
	EDNS          *edns.Handler
	CIDRMatcher   CIDRMatcher
	BuildMsg      BuildQueryFunc
	Cache         cache.Store
	DNSSECEnforce bool
}

// concurrencyTier1/2/3 define server-count thresholds for adaptive concurrency
// limits. concurrencyDiv2/3 are divisor constants used in the tier formulas:
//
//	Tier 1 (≤4 servers): serverCount
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

// ErrCIDRFilterRefused is returned when all A/AAAA records are filtered by
// CIDR rules.
var ErrCIDRFilterRefused = errors.New("cidr_filter_refused")

func (e *DNSSECError) Error() string {
	return fmt.Sprintf("DNSSEC validation failed [EDE %d]: %s", e.EDECode, e.Message)
}

// dnssecEDEError builds a DNSSECError from an EDE code stored as uint64
// (matching atomic.Uint64.Load()), shared between upstream query result
// handlers to keep EDE construction in one place.
func dnssecEDEError(edeCode uint64) *DNSSECError {
	return &DNSSECError{
		EDECode: uint16(edeCode),                                                                                              //nolint:gosec // G115: EDE code — protocol-bounded uint16
		Message: fmt.Sprintf("upstream rejected response (EDE %d: %s)", uint16(edeCode), edns.EDECodeString(uint16(edeCode))), //nolint:gosec // G115: EDE code — protocol-bounded uint16
	}
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

// New creates a new Resolver from the given Config.
func New(cfg *Config) *Resolver {
	r := &Resolver{
		queryClient:   cfg.QueryClient,
		edns:          cfg.EDNS,
		crd:           cfg.CIDRMatcher,
		buildMsg:      cfg.BuildMsg,
		DNSSECEnforce: cfg.DNSSECEnforce,
		upstream:      &upstreamSet{},
		fallback:      &upstreamSet{},
		cache:         cfg.Cache,
	}
	r.recursive = &Recursive{resolver: r, cache: cfg.Cache}
	r.cname = &CNAME{resolver: r}
	r.validator = &Validator{Crypto: cfg.Crypto, Hijack: cfg.Hijack}
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

// DNSSECEDECode returns the DNSSEC EDE code from the recursive resolver,
// or 0 if no recursive resolution was performed or no failure occurred.
func (r *Resolver) DNSSECEDECode() uint16 {
	if r == nil || r.recursive == nil {
		return 0
	}
	return r.recursive.DNSSECEDECode()
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
		qr := r.cname.resolve(resolveCtx, question, ecs)
		return &qr
	}

	// Only one set of servers — query directly without coordination overhead.
	// Do not fall back to recursive resolution when no fallback servers are
	// configured; return the upstream error so the client receives a clear
	// failure signal instead of silently switching to recursive mode.
	if len(fallbackServers) == 0 {
		qr := r.queryUpstream(ctx, question, ecs, servers)
		return &qr
	}

	if len(servers) == 0 {
		qr := r.queryUpstream(ctx, question, ecs, fallbackServers)
		qr.Fallback = true
		return &qr
	}

	// Both upstream and fallback configured — query concurrently so the
	// fallback answer is already ready if upstream fails.

	upstreamCh := make(chan QueryResult, 1)
	fallbackCh := make(chan QueryResult, 1)
	queryCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(errors.New("query completed"))

	go func() {
		qr := r.queryUpstream(queryCtx, question, ecs, servers)
		select {
		case upstreamCh <- qr:
		case <-queryCtx.Done():
		}
	}()

	go func() {
		qr := r.queryUpstream(queryCtx, question, ecs, fallbackServers)
		select {
		case fallbackCh <- qr:
		case <-queryCtx.Done():
		}
	}()

	// Prefer upstream; if it fails, the concurrent fallback is already
	// available (or nearly so) instead of starting a fresh sequential query.
	select {
	case up := <-upstreamCh:
		if up.Err == nil {
			return &up
		}
		log.Debugf("UPSTREAM: primary upstream failed for %s, waiting for concurrent fallback", question.Name)
		select {
		case fb := <-fallbackCh:
			if fb.Err == nil {
				fb.Fallback = true
				return &fb
			}
			return &QueryResult{Err: fb.Err}
		case <-ctx.Done():
			return &QueryResult{Err: ctx.Err()}
		}
	case <-ctx.Done():
		return &QueryResult{Err: ctx.Err()}
	}
}

// ShuffleSlice shuffles the input slice in-place using the Fisher-Yates
// algorithm. The caller must own the slice exclusively — the backing array is
// mutated.
func ShuffleSlice[T any](slice []T) []T {
	if len(slice) <= 1 {
		return slice
	}
	for i := len(slice) - 1; i > 0; i-- {
		j := rand.IntN(i + 1) //nolint:gosec // G404: Fisher-Yates shuffle — not cryptographic
		slice[i], slice[j] = slice[j], slice[i]
	}
	return slice
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
