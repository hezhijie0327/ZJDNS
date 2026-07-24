// Package resolver implements DNS query resolution through upstream servers or
// built-in recursive resolution with CNAME chasing and DNSSEC validation.
package resolver

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync/atomic"
	"time"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/edns"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/server/defense"
	"zjdns/server/resolver/dnssec"
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
	Poisoned   bool
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
	queryClient     UpstreamClient
	edns            *edns.Handler
	crd             CIDRMatcher
	buildMsg        BuildQueryFunc
	upstream        *upstreamSet
	fallback        *upstreamSet
	recursive       *Recursive
	cname           *CNAME
	validator       *Validator
	DNSSECEnforce   bool
	lastUpstreamEDE atomic.Pointer[dns.EDE] // EDE from upstream response for passthrough
	cache           cache.Store             // DNS response cache for NS A/AAAA lookups

	recursiveProxyURL string // proxy for recursive mode (from builtin_recursive upstream)
}

// Validator holds the DNSSEC and poison detection components for response
// validation. Lightweight record-presence checking is provided by the
// package-level dnssec.IsResponseValid function.
type Validator struct {
	Crypto      *dnssec.CryptoValidator // Full cryptographic DNSSEC validation
	Poisonguard defense.Detector        // DNS poison detection
}

// UpstreamClient is the interface for sending DNS queries to upstream servers,
// defined in the consumer package so the resolver depends on an abstraction.
type UpstreamClient interface {
	ExecuteQuery(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer) *upstream.Result
}

// Config bundles the dependencies needed to construct a Resolver.
type Config struct {
	QueryClient    UpstreamClient
	Crypto         *dnssec.CryptoValidator
	PoisonDetector defense.Detector // gated per-query by Recursive.poisonguard
	EDNS           *edns.Handler
	CIDRMatcher    CIDRMatcher
	BuildMsg       BuildQueryFunc
	Cache          cache.Store
	DNSSECEnforce  bool
	Ctx            context.Context // lifecycle context propagated to Recursive for probes
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
		EDECode: uint16(edeCode),                                                                                                     //nolint:gosec // G115: EDE code — protocol-bounded uint16
		Message: fmt.Sprintf("upstream rejected response (EDE %d: %s)", uint16(edeCode), dns.ExtendedErrorToString[uint16(edeCode)]), //nolint:gosec // G115: EDE code — protocol-bounded uint16
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
	r.recursive = &Recursive{
		resolver: r,
		cache:    cfg.Cache,
		ctx:      cfg.Ctx,
	}
	r.cname = &CNAME{resolver: r}
	r.validator = &Validator{Crypto: cfg.Crypto, Poisonguard: cfg.PoisonDetector}
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
		if s.IsRecursive() {
			if s.Proxy != "" {
				r.recursiveProxyURL = s.Proxy
			}
			r.recursive.spoofguard = r.recursive.spoofguard || s.Spoofguard
			r.recursive.splitguard = r.recursive.splitguard || s.Splitguard
			r.recursive.poisonguard = r.recursive.poisonguard || s.Poisonguard
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
		if s.IsRecursive() {
			if s.Proxy != "" && r.recursiveProxyURL == "" {
				r.recursiveProxyURL = s.Proxy
			}
			r.recursive.spoofguard = r.recursive.spoofguard || s.Spoofguard
			r.recursive.splitguard = r.recursive.splitguard || s.Splitguard
			r.recursive.poisonguard = r.recursive.poisonguard || s.Poisonguard
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
func (r *Resolver) UpstreamEDEOption() *dns.EDE {
	if r == nil {
		return nil
	}
	return r.lastUpstreamEDE.Load()
}

// UpstreamServers returns the current list of primary upstream servers.
func (r *Resolver) UpstreamServers() []*config.UpstreamServer {
	return r.upstream.list()
}

// FallbackServers returns the current list of fallback servers.
func (r *Resolver) FallbackServers() []*config.UpstreamServer {
	return r.fallback.list()
}

// Query resolves a DNS question by querying upstream servers, falling back to
// recursive resolution if no upstream is configured.
//
// When both upstream and fallback servers are configured, they are queried
// concurrently. Upstream is given DefaultFallbackTimeout to respond; if it
// succeeds within the deadline, it is always preferred. After the deadline
// expires (or if the fallback responds first with a successful answer), the
// fallback result is used. If the fallback also failed, the resolver waits
// for the upstream. Fallback results are cacheable — the concurrent model
// ensures they are fresh, not stale second-attempt data.
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

	// Both upstream and fallback configured — query concurrently. A deadline
	// timer prevents a slow primary upstream from delaying the fallback:
	// upstream gets DefaultFallbackTimeout to respond; after that the
	// concurrent fallback result is preferred if it succeeded. If the
	// fallback also failed, the resolver waits for the upstream.

	upstreamCh := make(chan QueryResult, 1)
	fallbackCh := make(chan QueryResult, 1)
	queryCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(errors.New("query completed"))

	go func() {
		defer zdnsutil.HandlePanic("UPSTREAM primary query")
		qr := r.queryUpstream(queryCtx, question, ecs, servers)
		select {
		case upstreamCh <- qr:
		case <-queryCtx.Done():
		}
	}()

	go func() {
		defer zdnsutil.HandlePanic("UPSTREAM fallback query")
		qr := r.queryUpstream(queryCtx, question, ecs, fallbackServers)
		select {
		case fallbackCh <- qr:
		case <-queryCtx.Done():
		}
	}()

	deadline := time.NewTimer(config.DefaultFallbackTimeout)
	defer deadline.Stop()

	select {
	case up := <-upstreamCh:
		// Upstream responded within the deadline — prefer it.
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

	case fb := <-fallbackCh:
		// Fallback responded first.
		if fb.Err == nil {
			// Give upstream until the deadline to also respond.
			select {
			case up := <-upstreamCh:
				if up.Err == nil {
					return &up
				}
			case <-deadline.C:
			case <-ctx.Done():
				return &QueryResult{Err: ctx.Err()}
			}
			fb.Fallback = true
			return &fb
		}
		// Fallback failed — must wait for upstream.
		select {
		case up := <-upstreamCh:
			if up.Err == nil {
				return &up
			}
			return &QueryResult{Err: up.Err}
		case <-ctx.Done():
			return &QueryResult{Err: ctx.Err()}
		}

	case <-deadline.C:
		// Deadline expired — prefer fallback if it succeeded, otherwise
		// wait for whichever responds first.
		select {
		case fb := <-fallbackCh:
			if fb.Err == nil {
				fb.Fallback = true
				return &fb
			}
			// Fallback failed — wait for upstream.
			select {
			case up := <-upstreamCh:
				if up.Err == nil {
					return &up
				}
				return &QueryResult{Err: up.Err}
			case <-ctx.Done():
				return &QueryResult{Err: ctx.Err()}
			}
		case up := <-upstreamCh:
			if up.Err == nil {
				return &up
			}
			// Upstream failed — wait for fallback.
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

	case <-ctx.Done():
		return &QueryResult{Err: ctx.Err()}
	}
}

// ShuffleSlice shuffles the input slice in-place using the Fisher-Yates
// algorithm. The caller must own the slice exclusively — the backing array is
// mutated.
func ShuffleSlice[T any](slice []T) {
	if len(slice) <= 1 {
		return
	}
	for i := len(slice) - 1; i > 0; i-- {
		j := rand.IntN(i + 1) //nolint:gosec // G404: Fisher-Yates shuffle — not cryptographic
		slice[i], slice[j] = slice[j], slice[i]
	}
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
