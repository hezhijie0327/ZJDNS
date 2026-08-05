package middleware

import (
	"context"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/log"
	"zjdns/server/handler"
	"zjdns/server/resolver"

	"codeberg.org/miekg/dns"
)

// MQTYPE implements RFC 10029 server-side MQTYPE-Query handling: a client may
// request additional RR types alongside the primary question via the
// MQTYPE-Query EDNS option (20); the server merges the responses for each
// additional type into a single reply and reports the completed types in the
// MQTYPE-Response option (21).
//
// The middleware runs after CacheStore (the primary response exists) but
// before Response (EDNS finalisation).  In forwarding mode the MQTYPE-Query
// is passed through to the upstream instead (Resolution middleware) — the
// upstream merges and echoes MQTYPE-Response, which buildSuccess forwards.
type MQTYPE struct {
	store    cache.Store
	resolver handler.Resolver
	pending  *handler.PendingRequests
}

type mqtypeError string

// mqtypeMetaTypes are the QTYPEs that must not appear in an MQTYPE-Query list
// (RFC 6895 §3.1 data types only — Meta-TYPEs and QTYPEs are excluded).
var mqtypeMetaTypes = map[uint16]struct{}{
	dns.TypeANY: {}, dns.TypeAXFR: {}, dns.TypeIXFR: {},
	dns.TypeMAILA: {}, dns.TypeMAILB: {},
	dns.TypeOPT: {}, dns.TypeTSIG: {}, dns.TypeTKEY: {},
	dns.TypeNXNAME: {}, dns.TypeReserved: {},
}

var (
	errMQTypeOpcode      = mqtypeError("MQTYPE-Query with non-QUERY opcode")
	errMQTypeNoQuestion  = mqtypeError("MQTYPE-Query without a question")
	errMQTypeEmpty       = mqtypeError("MQTYPE-Query with empty type list")
	errMQTypePrimaryMeta = mqtypeError("MQTYPE-Query with non-data primary type")
	errMQTypeMeta        = mqtypeError("MQTYPE-Query with a Meta/QTYPE in the list")
	errMQTypeDuplicate   = mqtypeError("MQTYPE-Query with duplicate type")
)

func (e mqtypeError) Error() string { return string(e) }

// Wrap implements Wrapper.
func (m *MQTYPE) Wrap(next handler.QueryHandler) handler.QueryHandler {
	return handler.QueryHandlerFunc(func(ctx context.Context, qctx *handler.QueryContext) error {
		mqQuery, hasMQ, invalid := findMQQUERY(qctx.Req.Pseudo)
		// RFC 10029 §3.3: a second MQTYPE-Query or an inbound
		// MQTYPE-Response → FORMERR, without resolving.
		if invalid {
			log.Debugf("MQTYPE: rejecting invalid MQTYPE option: mq=%v", mqQuery)
			msg := handler.BuildResponseMsg(qctx.Req)
			msg.Rcode = dns.RcodeFormatError
			qctx.Res = msg
			return nil
		}
		if !hasMQ {
			return next.ServeDNS(ctx, qctx)
		}
		if qerr := m.validate(qctx, mqQuery); qerr != nil {
			log.Debugf("MQTYPE: rejecting invalid MQTYPE-Query: %v", qerr)
			msg := handler.BuildResponseMsg(qctx.Req)
			msg.Rcode = dns.RcodeFormatError
			qctx.Res = msg
			return nil
		}

		err := next.ServeDNS(ctx, qctx)
		if qctx.Res == nil {
			return err
		}

		// Forwarding mode: the upstream handles the merge (Resolution passes
		// the option through); the upstream's MQTYPE-Response is forwarded by
		// CacheStore.buildSuccess.  Local merging applies to recursive mode
		// only.
		if len(m.resolver.UpstreamServers()) > 0 {
			return err
		}

		m.merge(ctx, qctx, mqQuery)
		return err
	})
}

// validate applies RFC 10029 §3.3: the server MUST return FORMERR for
// malformed MQTYPE-Query options.
func (m *MQTYPE) validate(qctx *handler.QueryContext, mq *dns.MQQUERY) error {
	if qctx.Req.Opcode != dns.OpcodeQuery {
		return errMQTypeOpcode
	}
	if len(qctx.Req.Question) == 0 {
		return errMQTypeNoQuestion
	}
	if len(mq.Types) == 0 {
		return errMQTypeEmpty
	}
	primary := dns.RRToType(qctx.Req.Question[0])
	if _, meta := mqtypeMetaTypes[primary]; meta {
		return errMQTypePrimaryMeta
	}
	seen := make(map[uint16]struct{}, len(mq.Types)+1)
	seen[primary] = struct{}{}
	for _, qt := range mq.Types {
		if _, meta := mqtypeMetaTypes[qt]; meta {
			return errMQTypeMeta
		}
		if _, dup := seen[qt]; dup {
			return errMQTypeDuplicate
		}
		seen[qt] = struct{}{}
	}
	return nil
}

// merge resolves each additional QTYPE (cache first, then singleflight
// resolution) and combines the RRsets into the primary response per
// RFC 10029 §3.4: same RCODE/flags, deduplicated RRs, size-capped.
func (m *MQTYPE) merge(ctx context.Context, qctx *handler.QueryContext, mq *dns.MQQUERY) {
	msg := qctx.Res
	qd := qctx.Req.Question[0]
	qname := qd.Header().Name
	qclass := qd.Header().Class
	ecsOpt := qctx.ECSOpt
	dnssecOK := qctx.ClientRequestedDNSSEC
	primaryRcode := msg.Rcode

	// §3.4: RCODE and flags are determined by the primary response.  The
	// AA-bit comparison is omitted — QueryResult does not carry the
	// authoritative flag through the recursive walk (NS/DS at a zone cut is
	// the RFC's example; the AD and RCODE checks cover the common cases).
	primaryAD := msg.AuthenticatedData

	// Budget for merged RRs: the remaining space below the RFC 9715 UDP
	// cap, minus the primary response size and EDNS overhead.
	budget := config.DefaultMaxUDPResponseSize - msg.Len() - 64

	completed := make([]uint16, 0, len(mq.Types))
	for _, qt := range mq.Types {
		qr := m.resolve(ctx, qname, qt, qclass, ecsOpt, dnssecOK)
		if qr == nil || qr.Err != nil {
			log.Debugf("MQTYPE: skipping %s %s — resolution failed", qname, dns.TypeToString[qt])
			continue
		}
		// §3.4: mismatching RCODE or flags — the additional response MUST
		// NOT be included.
		if qr.Rcode != primaryRcode || qr.Validated != primaryAD {
			log.Debugf("MQTYPE: skipping %s %s — RCODE/flags mismatch (rcode=%d validated=%t)", qname, dns.TypeToString[qt], qr.Rcode, qr.Validated)
			continue
		}

		// Estimate the added wire size before merging.
		added := 0
		for _, rr := range qr.Answer {
			added += rr.Len()
		}
		for _, rr := range qr.Authority {
			added += rr.Len()
		}
		for _, rr := range qr.Additional {
			added += rr.Len()
		}
		if added > budget {
			log.Debugf("MQTYPE: skipping %s %s — response size budget exceeded", qname, dns.TypeToString[qt])
			continue
		}
		budget -= added

		// §3.4: merge into the same sections a standalone query would use,
		// deduplicating RRs.
		msg.Answer = mergeRRs(msg.Answer, qr.Answer)
		msg.Ns = mergeRRs(msg.Ns, qr.Authority)
		msg.Extra = mergeRRs(msg.Extra, qr.Additional)
		completed = append(completed, qt)

		// Cache the additional response so future requests (including
		// CacheLookup for the same QTYPE) hit the warm cache.
		if qr.Cacheable {
			m.store.Set(qname, qt, qclass, ecsOpt, dnssecOK, qr.Answer, qr.Authority, qr.Additional, qr.Validated, qr.Rcode)
		}
	}

	if len(completed) > 0 || len(mq.Types) > 0 {
		// §3.4: the MQTYPE-Response option MUST be returned (even with an
		// empty list) to signal support.
		msg.Pseudo = append(msg.Pseudo, &dns.MQRESPONSE{Types: completed})
	}
	log.Debugf("MQTYPE: merged %d/%d types for %s", len(completed), len(mq.Types), qname)
}

// resolve performs the secondary lookup for one QTYPE: cache first, then
// singleflight resolution — the same pattern as the DNS64 middleware.
func (m *MQTYPE) resolve(ctx context.Context, qname string, qt, qclass uint16, ecsOpt *edns.ECSOption, dnssecOK bool) *resolver.QueryResult {
	if m.store != nil {
		if entry, found, _ := m.store.Get(qname, qt, qclass, ecsOpt, dnssecOK); found && entry.Unpack() == nil {
			return &resolver.QueryResult{
				Answer: entry.Answer, Authority: entry.Authority, Additional: entry.Additional,
				Validated: entry.Validated, Rcode: entryRcode(entry),
				Cacheable: true,
			}
		}
	}
	if m.pending != nil {
		return m.pending.DoJoin(qname, qt, qclass, ecsOpt, dnssecOK, func() *resolver.QueryResult {
			return m.resolver.Query(ctx, handler.Question{Name: qname, Qtype: qt, Qclass: qclass}, ecsOpt)
		})
	}
	return m.resolver.Query(ctx, handler.Question{Name: qname, Qtype: qt, Qclass: qclass}, ecsOpt)
}

// findMQQUERY returns the single MQTYPE-Query option from Pseudo.  present
// reports whether a MQTYPE-Query exists at all; invalid reports a second
// MQTYPE-Query or an inbound MQTYPE-Response — both are RFC 10029 §3.3
// FORMERR conditions and the caller must not proceed.
func findMQQUERY(pseudo []dns.RR) (mq *dns.MQQUERY, present, invalid bool) {
	for _, rr := range pseudo {
		switch opt := rr.(type) {
		case *dns.MQQUERY:
			if mq != nil {
				invalid = true // more than one MQTYPE-Query
			}
			mq = opt
		case *dns.MQRESPONSE:
			invalid = true // MQTYPE-Response in an inbound message
		}
	}
	return mq, mq != nil, invalid
}

// mergeRRs appends src RRs that are not already present in dst (RFC 10029
// §3.4: keep only a single copy of each RR).
func mergeRRs(dst, src []dns.RR) []dns.RR {
	if len(src) == 0 {
		return dst
	}
	for _, rr := range src {
		dup := false
		for _, existing := range dst {
			if existing == rr || equalRR(existing, rr) {
				dup = true
				break
			}
		}
		if !dup {
			dst = append(dst, rr)
		}
	}
	return dst
}

// equalRR compares two RRs by presentation form — wire-equivalent records
// (e.g. the SOA shared by multiple NODATA answers) merge to one copy.
func equalRR(a, b dns.RR) bool {
	return a.String() == b.String()
}

// entryRcode extracts the rcode from a pre-packed entry's wire header.
func entryRcode(entry *cache.Entry) uint16 {
	if len(entry.ResponseWire) >= 4 {
		return uint16(entry.ResponseWire[3] & 0x0F) //nolint:gosec // G115: DNS rcode — protocol-bounded byte
	}
	return 0
}
