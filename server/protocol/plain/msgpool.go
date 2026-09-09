package plain

import (
	"context"

	"codeberg.org/miekg/dns"
)

type datagramPool struct {
	free chan []byte
	size int
}

// recyclingHandler returns the query wire to the MsgPool once the handler
// chain returns: the fork recycles buffers only on its reject/error paths and
// drops every accepted query's buffer to the GC (~1.2 KiB/query).  Safe to
// pool because the chain is synchronous and nothing retains req.Data past
// ServeDNS; the nil-out keeps a future fork-side recycling of the accept path
// from double-returning the same buffer.
type recyclingHandler struct {
	next dns.Handler
	p    *datagramPool
}

const datagramPoolDepth = 256

func newDatagramPool(size int) *datagramPool {
	return &datagramPool{free: make(chan []byte, datagramPoolDepth), size: size}
}

func (p *datagramPool) Get() []byte {
	select {
	case b := <-p.free:
		return b
	default:
		return make([]byte, p.size)
	}
}

func (p *datagramPool) Put(b []byte) {
	if cap(b) < p.size {
		return
	}
	select {
	case p.free <- b[:p.size]:
	default:
	}
}

func (h recyclingHandler) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
	h.next.ServeDNS(ctx, w, r)
	h.p.Put(r.Data)
	r.Data = nil
}
