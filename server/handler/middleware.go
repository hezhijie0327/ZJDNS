// Package handler provides the DNS query processing pipeline: cache lookup,
// zone evaluation, upstream/recursive resolution, and DNSSEC validation.
package handler

import (
	"context"
	"errors"
)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// QueryHandler resolves a DNS query carried in the QueryContext.
// Implementations may short-circuit the chain by setting qctx.Res and
// returning nil, or delegate to the next handler.  Returning ErrDrop
// discards the query silently.  Any other error produces a SERVFAIL.
//
// NOTE: Renamed from Handler to avoid collision with the existing Handler
// struct.  Will be renamed back to Handler in Phase 3 when the old struct
// is removed.
type QueryHandler interface {
	ServeDNS(ctx context.Context, qctx *QueryContext) error
}

// QueryHandlerFunc adapts a plain function to the QueryHandler interface.
type QueryHandlerFunc func(ctx context.Context, qctx *QueryContext) error

// Middleware wraps a QueryHandler, returning a new QueryHandler that adds
// pre- or post-processing logic.  Implementations should delegate to
// next.ServeDNS when they choose not to short-circuit.
type Middleware interface {
	Wrap(next QueryHandler) QueryHandler
}

// ---------------------------------------------------------------------------
// Sentinel errors
// ---------------------------------------------------------------------------

// ErrDrop is returned by a Handler to signal that no response should be sent
// to the client (e.g. rate-limit or hijack detection drops the query silently).
var ErrDrop = errors.New("drop: no response")

// ErrSuspense is returned by a Handler when processing is intentionally
// deferred (e.g. follower waiting on a singleflight leader).
var ErrSuspense = errors.New("suspense: result pending")

// ---------------------------------------------------------------------------
// QueryHandlerFunc method
// ---------------------------------------------------------------------------

// ServeDNS implements QueryHandler.
func (f QueryHandlerFunc) ServeDNS(ctx context.Context, qctx *QueryContext) error {
	return f(ctx, qctx)
}
