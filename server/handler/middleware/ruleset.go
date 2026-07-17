package middleware

import (
	"context"
	"zjdns/server/handler"
	"zjdns/server/resolver"

	"codeberg.org/miekg/dns"
)

// Ruleset filters A/AAAA records in the resolved answer based on
// CIDR- and tag-based rules.  If all A/AAAA records are filtered out and no
// other answer records remain, the query is refused (ErrCIDRFilterRefused).
//
// Ruleset wraps the DNS64 and Resolution middlewares — it calls
// next first to get the resolution result, then filters before returning.
type Ruleset struct {
	cidrMatcher resolver.CIDRMatcher
}

// Wrap implements Middleware.
func (m *Ruleset) Wrap(next handler.QueryHandler) handler.QueryHandler {
	return handler.QueryHandlerFunc(func(ctx context.Context, qctx *handler.QueryContext) error {
		// Let the inner chain (DNS64 → Resolution) complete first.
		err := next.ServeDNS(ctx, qctx)

		// Only filter after successful resolution.
		if m.cidrMatcher == nil || !qctx.Resolved || qctx.ResolutionResult == nil {
			return err
		}

		qr := qctx.ResolutionResult
		if qr.Err != nil {
			return err
		}

		// Filter A/AAAA records in the answer.
		filtered := m.filterRecords(qr.Answer)
		if filtered {
			qr.Err = resolver.ErrCIDRFilterRefused
			qctx.ResolutionError = true
		}

		return err
	})
}

func (m *Ruleset) filterRecords(records []dns.RR) bool {
	hasAOrAAAA := false
	allFiltered := true
	for _, rr := range records {
		rtype := dns.RRToType(rr)
		if rtype == dns.TypeA || rtype == dns.TypeAAAA {
			hasAOrAAAA = true
			if !m.cidrMatcher.HasIPTag("A") && !m.cidrMatcher.HasIPTag("AAAA") {
				allFiltered = false
			}
		}
	}

	// Only refuse when all A/AAAA records are blocked.
	return hasAOrAAAA && allFiltered
}
