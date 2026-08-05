package resolver

import (
	"context"

	"codeberg.org/miekg/dns"
)

// mqtypeCtxKey carries the client's RFC 10029 MQTYPE-Query option from the
// Resolution middleware to the forwarding path (queryUpstream), which
// attaches it to the upstream request.  Defined here (not in handler) so the
// resolver package can read it without an import cycle.
type mqtypeCtxKey struct{}

// WithMQType returns a context carrying the client's MQTYPE-Query option for
// upstream pass-through (RFC 10029).
func WithMQType(ctx context.Context, mq *dns.MQQUERY) context.Context {
	return context.WithValue(ctx, mqtypeCtxKey{}, mq)
}

// MQTypeFromContext returns the MQTYPE-Query option attached by the
// Resolution middleware, or nil.
func MQTypeFromContext(ctx context.Context) *dns.MQQUERY {
	mq, _ := ctx.Value(mqtypeCtxKey{}).(*dns.MQQUERY)
	return mq
}
