package resolver

import (
	"context"
	"slices"

	"codeberg.org/miekg/dns"
)

type mqtypeCtxKey struct{}

// captureMQResponse extracts the RFC 10029 MQTYPE-Response option from an
// upstream response for forwarding pass-through to the client.
func captureMQResponse(resp *dns.Msg) *dns.MQRESPONSE {
	if resp == nil {
		return nil
	}
	for _, rr := range resp.Pseudo {
		if mqr, ok := rr.(*dns.MQRESPONSE); ok {
			return &dns.MQRESPONSE{Types: slices.Clone(mqr.Types)}
		}
	}
	return nil
}

// ── MQTYPE forwarding pass-through ─────────────────────────────────────────
// When a client query carries an MQTYPE-Query option (RFC 10029), the
// Resolution middleware stores it in the context; the forwarding path reads
// it and attaches it to the upstream query.  This has nothing to do with
// recursive resolution — it is pure stub→recursive forwarder protocol.

func WithMQType(ctx context.Context, mq *dns.MQQUERY) context.Context {
	return context.WithValue(ctx, mqtypeCtxKey{}, mq)
}

// MQTypeFromContext returns the MQTYPE-Query option attached by the
// Resolution middleware, or nil.
func MQTypeFromContext(ctx context.Context) *dns.MQQUERY {
	mq, _ := ctx.Value(mqtypeCtxKey{}).(*dns.MQQUERY)
	return mq
}
