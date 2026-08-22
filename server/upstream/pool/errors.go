package pool

import "errors"

// Sentinel errors returned by the pooled connection/exchange hot paths.
// Callers classify failures with errors.Is instead of formatting — the
// per-query fmt.Errorf sites were ~700M allocations on a loaded server
// (every closed-conn, collision and saturated-pool error built a formatted
// string nobody consumed).  Dial-time errors keep fmt.Errorf("%w") wraps:
// the dynamic address context is worth keeping there, and dials are cold.
var (
	ErrConnClosed        = errors.New("pool: connection closed")
	ErrKeyCollision      = errors.New("pool: match key collision")
	ErrNoAvailableSocket = errors.New("pool: no available socket")
	ErrPoolShutdown      = errors.New("pool: pool shut down")
	ErrMaxConnsReached   = errors.New("pool: max conns reached for key")
	ErrWriteFailed       = errors.New("pool: write failed")
)
