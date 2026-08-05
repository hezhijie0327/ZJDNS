// Package resolver implements DNS query resolution through upstream servers or
// built-in recursive resolution with CNAME chasing and DNSSEC validation.
package resolver

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/edns"
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
	Answer      []dns.RR
	Authority   []dns.RR
	Additional  []dns.RR
	Rcode       uint16 // response rcode (e.g. NXDOMAIN) — default NOERROR
	Validated   bool
	Cacheable   bool
	ECS         *edns.ECSOption
	Server      string
	Poisoned    bool
	UpstreamEDE *dns.EDE // EDE code captured from upstream response (per-query, no data race)
	DNSSECEDE   uint16   // DNSSEC EDE from recursive validation (per-query, no cross-query race)
	Err         error
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

// upstreamSet holds the configured upstream server list. It is written
// exactly once at startup (ConfigureServers) and read-only afterwards — the
// old atomic.Pointer implied reload support that does not exist.
type upstreamSet struct {
	servers []*config.UpstreamServer
}

// Resolver handles DNS query resolution by dispatching to upstream servers or
// built-in recursive resolution.
type Resolver struct {
	queryClient   UpstreamClient
	edns          *edns.Handler
	crd           CIDRMatcher
	buildMsg      BuildQueryFunc
	upstream      *upstreamSet
	recursive     *Recursive
	cname         *CNAME
	validator     *Validator
	DNSSECEnforce bool
	cache         cache.Store // DNS response cache for NS A/AAAA lookups

	recursiveProxyURL string // proxy for recursive mode (from protocol=recursive upstream)
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
	return u.servers
}

func (u *upstreamSet) store(s []*config.UpstreamServer) {
	u.servers = s
}

// New creates a new Resolver from the given Config.
func New(cfg *Config) (*Resolver, error) {
	if cfg == nil {
		return nil, errors.New("resolver: nil config")
	}
	if cfg.EDNS == nil {
		return nil, errors.New("resolver: EDNS handler is required")
	}
	if cfg.BuildMsg == nil {
		return nil, errors.New("resolver: BuildMsg function is required")
	}
	if cfg.QueryClient == nil {
		return nil, errors.New("resolver: QueryClient is required")
	}
	if cfg.Cache == nil {
		return nil, errors.New("resolver: Cache is required")
	}
	r := &Resolver{
		queryClient:   cfg.QueryClient,
		edns:          cfg.EDNS,
		crd:           cfg.CIDRMatcher,
		buildMsg:      cfg.BuildMsg,
		DNSSECEnforce: cfg.DNSSECEnforce,
		upstream:      &upstreamSet{},
		cache:         cfg.Cache,
	}
	r.recursive = &Recursive{
		resolver: r,
		cache:    cfg.Cache,
		ctx:      cfg.Ctx,
	}
	r.cname = &CNAME{resolver: r}
	r.validator = &Validator{Crypto: cfg.Crypto, Poisonguard: cfg.PoisonDetector}
	return r, nil
}

// ConfigureServers initializes the upstream server list.
func (r *Resolver) ConfigureServers(servers []config.UpstreamServer) {
	active := make([]*config.UpstreamServer, 0, len(servers))
	for i := range servers {
		s := &servers[i]
		if s.Protocol == "" {
			s.Protocol = config.ProtoUDP
		}
		// Normalize the protocol string once at registration — the client
		// lowercases it per query on the upstream hot path (strings.ToLower
		// scan per request).  Config values are lowercase (config.Proto*),
		// so this is a no-op in practice and a safety net for hand-built
		// configs.
		s.Protocol = strings.ToLower(s.Protocol)
		if s.IsRecursive() {
			if s.Proxy != "" {
				r.recursiveProxyURL = s.Proxy
			}
			r.recursive.spoofguard = r.recursive.spoofguard || s.Spoofguard
			r.recursive.splitguard = r.recursive.splitguard || s.Splitguard
			r.recursive.poisonguard = r.recursive.poisonguard || s.Poisonguard
			r.recursive.hopguard = r.recursive.hopguard || s.HopGuard
		}
		active = append(active, s)
	}
	r.upstream.store(active)
}

// UpstreamServers returns the current list of primary upstream servers.
func (r *Resolver) UpstreamServers() []*config.UpstreamServer {
	return r.upstream.list()
}

// Query resolves a DNS question by querying upstream servers, or falling back to
// built-in recursive resolution if no upstream servers are configured.
func (r *Resolver) Query(ctx context.Context, question Question, ecs *edns.ECSOption) *QueryResult {
	servers := r.upstream.list()

	// No servers configured — use built-in recursive resolver.
	if len(servers) == 0 {
		resolveCtx, cancel := context.WithTimeout(ctx, config.DefaultRecursiveResolveTimeout)
		defer cancel()
		qr := r.cname.resolve(resolveCtx, question, ecs)
		return &qr
	}

	qr := r.queryUpstream(ctx, question, ecs, servers)
	return &qr
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
// servers to query simultaneously. The limit is monotonic: each tier formula
// is floored at the previous tier's value, so adding a server never reduces
// the fan-out (e.g. 12 and 13 servers both yield 8; 20 and 21 both yield 10).
func concurrencyLimit(serverCount int) int {
	if serverCount <= 0 {
		return 1
	}
	switch {
	case serverCount <= concurrencyTier1:
		return serverCount
	case serverCount <= concurrencyTier2:
		return max((serverCount*concurrencyDiv2+concurrencyDiv2)/concurrencyDiv3, concurrencyTier1)
	case serverCount <= concurrencyTier3:
		return max((serverCount+1)/concurrencyDiv2, (concurrencyTier2*concurrencyDiv2+concurrencyDiv2)/concurrencyDiv3)
	default:
		limit := serverCount / concurrencyDiv3
		if limit < config.DefaultMinConcurrencyLimit {
			return max(config.DefaultMinConcurrencyLimit, (concurrencyTier3+1)/concurrencyDiv2)
		}
		return limit
	}
}
