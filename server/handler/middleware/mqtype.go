package middleware

import (
	"context"
	"zjdns/cache"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
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
// before Response (EDNS finalisation).  The merge is local in every mode
// (forwarding included) — each QTx resolves through the server's own
// upstreams, so the response supports MQTYPE regardless of upstream
// support.  The option is never passed through.
// qtResult is one prefetched additional-QTYPE resolution.
type qtResult struct {
	qt uint16
	qr *resolver.QueryResult
}

type MQTYPE struct {
	store     cache.Store
	secondary *handler.Secondary
}

type mqtypeError string

// mqtypeEDNSOverhead is the worst-case EDNS/MQTYPE-Response option overhead
// reserved in the merge budget so the post-merge wire cannot exceed the
// client's UDP size (RFC 10029 §3.4).
const mqtypeEDNSOverhead = 64

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
			if log.IsDebug() {
				log.Debugf("MQTYPE: rejecting invalid MQTYPE option: mq=%v", mqQuery)
			}
			msg := handler.BuildResponseMsg(qctx.Req)
			msg.Rcode = dns.RcodeFormatError
			qctx.Res = msg
			return nil
		}
		if !hasMQ {
			return next.ServeDNS(ctx, qctx)
		}
		if qerr := m.validate(qctx, mqQuery); qerr != nil {
			if log.IsDebug() {
				log.Debugf("MQTYPE: rejecting invalid MQTYPE-Query: %v", qerr)
			}
			msg := handler.BuildResponseMsg(qctx.Req)
			msg.Rcode = dns.RcodeFormatError
			qctx.Res = msg
			return nil
		}

		// RFC 10029 §3.4: resolve the additional QTx types CONCURRENTLY
		// with the primary — a sequential resolve-then-merge doubled the
		// end-to-end latency of every MQTYPE query (the AAAA QTx paid its
		// own full upstream round trip after the primary finished).  Each
		// QTx is detached from the request lifecycle and bounded by its
		// own timeout (§4 amplification bound); on a failed primary the
		// buffered results are simply discarded (bounded by the QTx cap).
		qtTypes := mqQuery.Types
		if len(qtTypes) > config.DefaultMQTypeMaxQTx {
			qtTypes = qtTypes[:config.DefaultMQTypeMaxQTx]
		}
		qtResults := make(chan qtResult, len(qtTypes))
		for _, qt := range qtTypes {
			go func() { //nolint:gosec // G118: QTx must detach from the request lifecycle (RFC 10029 §4) — a near-deadline request ctx must not abort the fresh QTx budget
				defer zdnsutil.HandlePanic("MQTYPE QTx prefetch")
				qtCtx, qtCancel := context.WithTimeout(context.WithoutCancel(ctx), config.DefaultMQTypeResolveTimeout)
				defer qtCancel()
				qtResults <- qtResult{
					qt: qt,
					qr: m.secondary.Lookup(qtCtx, qctx.Qname, qt, qctx.Qclass, qctx.ECSOpt, qctx.ClientRequestedDNSSEC),
				}
			}()
		}

		err := next.ServeDNS(ctx, qctx)
		if qctx.Res == nil {
			return err
		}

		// Merge locally in every mode — forwarding too.  ZJDNS is a full
		// resolver: each QTx is resolved through its own upstreams
		// (m.resolver.Query), so the response supports MQTYPE even when
		// no hop in the chain does.  The option is never passed through.
		m.merge(qctx, mqQuery, qtResults)
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
	if _, meta := config.MQTypeMetaTypes[primary]; meta {
		return errMQTypePrimaryMeta
	}
	seen := make(map[uint16]struct{}, len(mq.Types)+1)
	seen[primary] = struct{}{}
	for _, qt := range mq.Types {
		if _, meta := config.MQTypeMetaTypes[qt]; meta {
			return errMQTypeMeta
		}
		if _, dup := seen[qt]; dup {
			return errMQTypeDuplicate
		}
		seen[qt] = struct{}{}
	}
	return nil
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
