package middleware

import (
	"context"
	"errors"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/internal/stats"
	"zjdns/server/handler"
	"zjdns/server/resolver"

	"codeberg.org/miekg/dns"
)

// Stats materialises the request journal record after the chain returns.
// It is the ONLY recording site: middleware classify their outcome by
// setting qctx.Result, and this layer turns the classification (plus the
// final response) into a single RequestRecord.  Rejected-before-classified
// queries (qctx.Result empty, no error) are not journaled — mirroring the
// FORMERR gates, which predate the refactor and stayed invisible to stats.
//
// Recording happens once, at the outermost layer, so ResponseTime covers
// the full chain including EDNS finalisation.
type Stats struct {
	store cache.Store
}

// Wrap implements Wrapper.
func (m *Stats) Wrap(next handler.QueryHandler) handler.QueryHandler {
	return handler.QueryHandlerFunc(func(ctx context.Context, qctx *handler.QueryContext) error {
		err := next.ServeDNS(ctx, qctx)

		result := qctx.Result
		if result == "" && err != nil {
			// The chain broke before any middleware built a response —
			// ServeDNS turns this into a SERVFAIL after we return.
			result = "error"
		}
		if result == "" {
			return err
		}

		rcode := int(dns.RcodeServerFailure)
		if qctx.Res != nil {
			rcode = int(qctx.Res.Rcode)
		}

		rec := stats.AcquireRequestRecord()
		rec.Qname = qctx.Qname
		rec.Qtype = qctx.Qtype
		rec.Qclass = qctx.Qclass
		rec.Protocol = qctx.Protocol
		rec.Result = result
		rec.Rcode = rcode
		rec.ResponseTime = handler.ElapsedMS(qctx.StartTime)
		if qr := qctx.ResolutionResult; qr != nil {
			switch result {
			case "miss":
				// Resolution metadata, exactly as the miss path always
				// journalled it (refresh-completed serves count as misses).
				rec.Server = qr.Server
				rec.Poisoned = qr.Poisoned
				rec.DNSSECStatus = dnssecStatusFor(qr)
			case "error":
				// DNSSEC failures are marked bogus; other errors carry no
				// DNSSEC classification (network failures are not
				// validation verdicts).
				rec.DNSSECStatus = dnssecBogusFor(qr)
			}
		}
		m.store.RecordRequest(rec)
		stats.ReleaseRequestRecord(rec)
		return err
	})
}

// dnssecStatusFor derives the journal's DNSSEC classification from a
// successfully resolved result: secure when validated, bogus when the result
// carries a DNSSEC EDE, insecure otherwise.
func dnssecStatusFor(qr *resolver.QueryResult) string {
	switch {
	case qr.Validated:
		return config.DNSSECStatusSecure
	case qr.DNSSECEDE != 0:
		return config.DNSSECStatusBogus
	default:
		return config.DNSSECStatusInsecure
	}
}

// dnssecBogusFor reports "bogus" when a failed resolution is a DNSSEC
// failure (EDE on the result, or the error itself is a DNSSECError), ""
// otherwise.
func dnssecBogusFor(qr *resolver.QueryResult) string {
	if qr.DNSSECEDE != 0 {
		return config.DNSSECStatusBogus
	}
	if _, ok := errors.AsType[*resolver.DNSSECError](qr.Err); ok {
		return config.DNSSECStatusBogus
	}
	return ""
}
