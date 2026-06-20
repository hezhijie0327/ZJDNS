// Package pool provides sync.Pool-based object pools for dns.Msg and byte slices
// to reduce GC pressure in the hot query path.
package pool

import (
	"sync"

	"github.com/miekg/dns"
)

// Buffer size constants.
const (
	UDPBufferSize    = 1232 // Optimal UDP payload size for DNS to avoid fragmentation.
	TCPBufferSize    = 4096 // Buffer size for TCP DNS messages.
	SecureBufferSize = 8192 // Buffer size for secure DNS messages (DoT, DoH, DoQ).
)

// DefaultMessagePool is the shared pool for dns.Msg objects.
var DefaultMessagePool = NewMessagePool()

// DefaultBufferPool is the shared pool for byte buffers.
var DefaultBufferPool = NewBufferPool(SecureBufferSize, 256)

// MessagePool manages reusable dns.Msg objects.
type MessagePool struct {
	pool sync.Pool
}

// BufferPool manages reusable byte buffers.
type BufferPool struct {
	pool sync.Pool
	size int
}

// NewMessagePool creates a new pool for dns.Msg objects.
func NewMessagePool() *MessagePool {
	return &MessagePool{
		pool: sync.Pool{
			New: func() any {
				return &dns.Msg{}
			},
		},
	}
}

// Get retrieves a zeroed dns.Msg from the pool.
func (mp *MessagePool) Get() *dns.Msg {
	msg := mp.pool.Get().(*dns.Msg)
	*msg = dns.Msg{}
	return msg
}

// Put returns a dns.Msg to the pool after zeroing it.
func (mp *MessagePool) Put(msg *dns.Msg) {
	if msg != nil {
		*msg = dns.Msg{}
		mp.pool.Put(msg)
	}
}

// NewBufferPool creates a new pool for byte buffers of the given size.
func NewBufferPool(size, poolSize int) *BufferPool {
	bp := &BufferPool{
		size: size,
		pool: sync.Pool{},
	}
	for range poolSize {
		buf := make([]byte, size)
		bp.pool.Put(&buf)
	}
	return bp
}

// Get retrieves a buffer from the pool.
func (bp *BufferPool) Get() []byte {
	bufPtr := bp.pool.Get()
	if bufPtr == nil {
		return make([]byte, bp.size)
	}
	buf := bufPtr.(*[]byte)
	return *buf
}

// Put returns a buffer to the pool after zeroing it.
// The entire buffer is zeroed to prevent stale DNS data leakage
// from callers that extended the buffer beyond bp.size.
func (bp *BufferPool) Put(buf []byte) {
	if buf != nil && cap(buf) >= bp.size {
		clear(buf[:cap(buf)])
		bp.pool.Put(&buf)
	}
}
