// Upstream response processing: the per-server result funnel (first-win
// race, NXDOMAIN secondary fallback, CIDR filtering, EDE capture) and the
// recursive-mode hand-off.

package resolver

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"zjdns/config"
	"zjdns/edns"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	"zjdns/server/resolver/dnssec"
	"zjdns/server/upstream"

	"codeberg.org/miekg/dns"
)

// captureUpstreamEDE extracts the EDE option from an upstream response for
// passthrough to downstream clients. Upstream resolvers attach EDE codes
// (e.g. DNSSEC Bogus) to any rcode. The copied EDE is RETURNED so the caller
// carries it per-goroutine into its own result — reloading the shared atomic
// at send time can attribute a DIFFERENT upstream's EDE to the winning
// response (a slower SERVFAIL/DNSSEC-bogus responder could Store after this
// one captured). The atomic is still updated for the all-servers-failed
// fallback path.
func captureUpstreamEDE(lastEDE *atomic.Pointer[dns.EDE], resp *dns.Msg, serverAddr string) *dns.EDE {
	if resp == nil {
		return nil
	}
	for _, rr := range resp.Pseudo {
		if ede, ok := rr.(*dns.EDE); ok {
			// Copy the EDE out of the pooled response — the source server
			// stays in the Debug log, not in client-facing ExtraText
			// (RFC 8914 §3: forwarding is implementation dependent).
			copied := &dns.EDE{InfoCode: ede.InfoCode, ExtraText: ede.ExtraText}
			lastEDE.Store(copied)
			log.Debugf("UPSTREAM: captured EDE %d (%s) from %s (rcode=%s)",
				ede.InfoCode, dns.ExtendedErrorToString[ede.InfoCode], serverAddr, dns.RcodeToString[resp.Rcode])
			return copied
		}
	}
	return nil
}

// isSecureUpstream reports whether an upstream uses an encrypted transport
// where hijacking is impossible and first-wins needs no defense gating.
// DNSCrypt carries its own crypto on the DNS layer — not a TLS transport.
func isSecureUpstream(server *config.UpstreamServer) bool {
	return zdnsutil.IsSecureProtocol(server.Protocol) &&
		server.Protocol != config.ProtoDNSCrypt &&
		server.Protocol != config.ProtoDNSCryptTCP
}

func (r *Resolver) filterRecordsByCIDR(records []dns.RR, matchTags []string) ([]dns.RR, bool) {
	if r.crd == nil || len(matchTags) == 0 {
		return records, false
	}

	// Pre-filter tags: keep only those that have CIDR rules so we call
	// HasIPTag once per tag instead of once per record per tag.
	type tagKey struct {
		raw string
	}
	ipTags := make([]tagKey, 0, len(matchTags))
	for _, t := range matchTags {
		name := t
		if t != "" && t[0] == '!' {
			name = t[1:]
		}
		if r.crd.HasIPTag(name) {
			ipTags = append(ipTags, tagKey{raw: t})
		}
	}

	filtered := make([]dns.RR, 0, len(records))
	for _, rr := range records {
		var ip net.IP
		switch record := rr.(type) {
		case *dns.A:
			ip = net.IP(record.Addr.AsSlice())
		case *dns.AAAA:
			ip = net.IP(record.Addr.AsSlice())
		default:
			filtered = append(filtered, rr)
			continue
		}

		// AND semantics: every pre-filtered tag must be satisfied —
		// accept-on-first-match would let a record inside tagB but outside
		// tagA bypass a negated '!tagA' rule.
		accepted := len(ipTags) == 0
		ipStr := ip.String()
		for _, t := range ipTags {
			matched, exists := r.crd.MatchIP(ipStr, t.raw)
			if !exists {
				return nil, true
			}
			if !matched {
				accepted = false
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

// processUpstreamResponse handles the response from a forwarding upstream server.
//
// RFC 8767 §4 note: the AA-bit check for stale refresh applies only to authoritative
// answers. ZJDNS in forwarding mode queries recursive resolvers (always AA=0), so the
// check is intentionally skipped — it would incorrectly reject all recursive responses.
// Returns true if the goroutine should return (result sent or handled).
func (r *Resolver) processUpstreamResponse(queryResult *upstream.Result, server *config.UpstreamServer, question Question, resultChan chan<- QueryResult, nxdomainResult *atomic.Pointer[QueryResult], nxdomainCh chan<- struct{}, activeConnections *atomic.Int32, cancel context.CancelCauseFunc, groupCtx context.Context, cidrFilterRefused *atomic.Bool, lastEDE *atomic.Pointer[dns.EDE], coord *fallbackCoord) bool {
	// RFC 5452 §9.3: reject responses that do not echo the query's question.
	// The forwarding path already checks the response ID (spoofguard); the
	// question echo closes the cross-name replay variant (R3-H1).
	if !responseEchoesQuestion(queryResult.Response, question) {
		log.Debugf("UPSTREAM: %s question echo mismatch for %s %s", server.Address, question.Name, dns.TypeToString[question.Qtype])
		pool.DefaultMessage.Put(queryResult.Response)
		return false
	}
	rcode := queryResult.Response.Rcode

	upstreamEDE := captureUpstreamEDE(lastEDE, queryResult.Response, server.Address)
	// A cascaded ZJDNS marks fallback-served responses with its private EDE
	// — adopt them as ordinary first-wins results but never cache them (the
	// marker keeps propagating to our own clients).
	fallbackMarked := edns.IsFallbackEDE(upstreamEDE)

	// RFC 10029: the configured mqtype list warms the cache with the
	// upstream's merged records and strips them from the client-facing
	// response.  Client-sent MQTYPE-Query options never reach here — the
	// server-side MQTYPE middleware merges locally.
	mqr, mqInvalid := parseMQResponse(queryResult.Response)

	switch rcode {
	case dns.RcodeSuccess:
		if len(server.Match) > 0 {
			filteredAnswer, shouldRefuse := r.filterRecordsByCIDR(queryResult.Response.Answer, server.Match)
			if shouldRefuse {
				cidrFilterRefused.Store(true)
				pool.DefaultMessage.Put(queryResult.Response)
				return false
			}
			queryResult.Response.Answer = filteredAnswer
		}

		queryResult.Validated = dnssec.IsResponseValid(queryResult.Response, true)
		log.Debugf("UPSTREAM: DNSSEC validation result=%t for %s via %s", queryResult.Validated, question.Name, server.Address)
		ecsResponse := r.edns.ParseFromDNS(queryResult.Response)

		// RFC 9824 §5.1: the upstream may answer with a compact NODATA
		// (NOERROR + NSEC/NSEC3 NXNAME signal) for a nonexistent name — we
		// set the CO bit on upstream queries, so restore the NXDOMAIN
		// semantic before serving.
		rcode := uint16(dns.RcodeSuccess)
		if dnssec.HasCompactNXNAME(queryResult.Response) {
			log.Debugf("UPSTREAM: compact NODATA with NXNAME signal for %s via %s — restoring NXDOMAIN", question.Name, server.Address)
			rcode = dns.RcodeNameError
		}

		// Fallback upstreams never win the race directly: their result is
		// stashed and only adopted after the fallback timeout.  Never
		// cacheable, always marked with the ZJDNS fallback EDE.
		if server.Fallback {
			coord.stash(&QueryResult{
				Answer:        queryResult.Response.Answer,
				Authority:     queryResult.Response.Ns,
				Additional:    queryResult.Response.Extra,
				Validated:     queryResult.Validated,
				Authoritative: queryResult.Response.Authoritative,
				Cacheable:     false,
				ECS:           ecsResponse,
				Server:        server.Address,
				UpstreamEDE:   fallbackMarkEDE(),
				Truncated:     queryResult.Response.Truncated,
				Rcode:         rcode,
			})
			pool.DefaultMessage.Put(queryResult.Response)
			return true
		}

		// RFC 10029: warm the merged types and strip them from the answer —
		// the strip uses the completed list, never server.MQType, which
		// would remove the primary records.  A fallback-marked response
		// (65280 from a cascaded ZJDNS) must not warm the cache either.
		if len(server.MQType) > 0 && mqr != nil && !mqInvalid && r.cache != nil && !server.SkipCache && !fallbackMarked {
			r.warmFromMQResponse(queryResult.Response, question.Name, question.Qclass, mqr, ecsResponse, queryResult.Validated)
			queryResult.Response.Answer = stripMQBundled(queryResult.Response.Answer, mqr.Types)
		}

		res := QueryResult{Answer: queryResult.Response.Answer, Authority: queryResult.Response.Ns, Additional: queryResult.Response.Extra, Validated: queryResult.Validated, Authoritative: queryResult.Response.Authoritative, Cacheable: !server.SkipCache && !fallbackMarked, ECS: ecsResponse, Server: server.Address, UpstreamEDE: upstreamEDE, Truncated: queryResult.Response.Truncated, Rcode: rcode}
		select {
		case resultChan <- res:
			remaining := activeConnections.Load() - 1
			if remaining > 0 {
				log.Debugf("UPSTREAM: First win achieved, terminating %d remaining connections", remaining)
			}
			cancel(errors.New("successful result"))
			// A fallback may have been adopted while this result was in
			// flight — fill the cache directly instead of racing for a
			// client the wait loop already answered.
			coord.maybeBackfill(func() { r.fillCacheFromResult(coord, &res) })
			pool.DefaultMessage.Put(queryResult.Response)
			return true
		case <-groupCtx.Done():
			pool.DefaultMessage.Put(queryResult.Response)
			return true
		}
	case dns.RcodeNameError:
		// Fallback NXDOMAIN is stashed like a fallback NOERROR — adopted
		// only after the timeout, never cached, and it must not arm the
		// NXDOMAIN deferral window (that machinery is primary-only).
		if server.Fallback {
			coord.stash(&QueryResult{
				Answer:        queryResult.Response.Answer,
				Authority:     queryResult.Response.Ns,
				Additional:    queryResult.Response.Extra,
				Validated:     false,
				Authoritative: queryResult.Response.Authoritative,
				Cacheable:     false,
				Rcode:         dns.RcodeNameError,
				ECS:           r.edns.ParseFromDNS(queryResult.Response),
				Server:        server.Address,
				UpstreamEDE:   fallbackMarkEDE(),
			})
			pool.DefaultMessage.Put(queryResult.Response)
			return true
		}
		nxRes := QueryResult{
			Answer:        queryResult.Response.Answer,
			Authority:     queryResult.Response.Ns,
			Additional:    queryResult.Response.Extra,
			Validated:     false,
			Authoritative: queryResult.Response.Authoritative,
			Cacheable:     !server.SkipCache && !fallbackMarked,
			Rcode:         dns.RcodeNameError,
			ECS:           r.edns.ParseFromDNS(queryResult.Response),
			Server:        server.Address,
			UpstreamEDE:   upstreamEDE,
		}
		if nxdomainResult.CompareAndSwap(nil, &nxRes) {
			// First NXDOMAIN collected — arm the deferral window in the
			// wait loop (first-wins; same principle as the recursive walk).
			select {
			case nxdomainCh <- struct{}{}:
			default:
			}
			// A fallback may have been adopted between this CAS and now —
			// fill the negative cache directly (mirrors the NOERROR path).
			coord.maybeBackfill(func() { r.fillCacheFromResult(coord, &nxRes) })
		}
		pool.DefaultMessage.Put(queryResult.Response)
	default:
		pool.DefaultMessage.Put(queryResult.Response)
	}
	return false
}

// handleRecursiveQuery dispatches a single query to the built-in recursive
// resolver with CIDR filtering. Returns true if a successful result was sent.
func (r *Resolver) handleRecursiveQuery(recursiveParentCtx context.Context, server *config.UpstreamServer, question Question, ecs *edns.ECSOption, resultChan chan<- QueryResult, cancel context.CancelCauseFunc, cidrFilterRefused *atomic.Bool, coord *fallbackCoord) bool {
	recursiveCtx, recursiveCancel := context.WithTimeout(recursiveParentCtx, config.DefaultRecursiveResolveTimeout)
	defer recursiveCancel()

	qr := r.cname.resolve(recursiveCtx, question, ecs)
	qr.Cacheable = !server.SkipCache
	if qr.Err != nil {
		return false
	}
	// Empty response (no Answer AND no Authority): nothing to forward as a
	// first-win — the query is dropped here.  Note this only matches fully
	// empty responses: real denials carry the SOA/NSEC/NSEC3 proof in
	// Authority, so they ARE forwarded as first-wins — consistent with the
	// forwarding fan-out, where a collected NXDOMAIN is served after the
	// (default zero) deferral window without waiting for the slowest
	// upstream.
	if len(qr.Answer) == 0 && len(qr.Authority) == 0 {
		return false
	}

	if len(server.Match) > 0 {
		filteredAnswer, shouldRefuse := r.filterRecordsByCIDR(qr.Answer, server.Match)
		if shouldRefuse {
			cidrFilterRefused.Store(true)
			return false
		}
		qr.Answer = filteredAnswer
	}

	// Recursive fallback upstreams follow the same delayed-adoption rule as
	// forwarding fallbacks: stash, never cache, mark with the fallback EDE.
	if server.Fallback {
		qr.Cacheable = false
		qr.UpstreamEDE = fallbackMarkEDE()
		coord.stash(&qr)
		return true
	}

	select {
	case resultChan <- qr:
		cancel(errors.New("successful result"))
		return true
	case <-recursiveCtx.Done():
		return true
	}
}
