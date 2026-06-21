// Package pool provides sync.Pool-based message and buffer pools.
package pool

import (
	"sync"

	"github.com/miekg/dns"
)

// UDPBufferSize is the standard size for UDP DNS messages.
// TCPBufferSize is the recommended size for TCP DNS message buffers.
// SecureBufferSize is the recommended size for secure DNS message buffers.
const (
	UDPBufferSize    = 1232
	TCPBufferSize    = 4096
	SecureBufferSize = 8192
)

// DefaultMessagePool is the package-level default MessagePool.
var DefaultMessagePool = NewMessagePool()

// DefaultBufferPool is the package-level default BufferPool.
var DefaultBufferPool = NewBufferPool(SecureBufferSize, 256)

// MessagePool is a pooled allocator for dns.Msg values.
type MessagePool struct {
	pool sync.Pool
}

// BufferPool is a pooled allocator for byte slices.
type BufferPool struct {
	pool sync.Pool
	size int
}

// NewMessagePool creates a new MessagePool.
func NewMessagePool() *MessagePool {
	return &MessagePool{
		pool: sync.Pool{
			New: func() any {
				return &dns.Msg{}
			},
		},
	}
}

// Get acquires a zeroed dns.Msg from the pool.
func (mp *MessagePool) Get() *dns.Msg {
	msg := mp.pool.Get().(*dns.Msg)
	*msg = dns.Msg{}
	return msg
}

// Put returns a dns.Msg to the pool.
func (mp *MessagePool) Put(msg *dns.Msg) {
	if msg != nil {
		*msg = dns.Msg{}
		mp.pool.Put(msg)
	}
}

// NewBufferPool creates a new BufferPool pre-populated with the given number
// of buffers. Buffers are stored as *[]byte pointers to avoid interface-boxing
// allocations on every Put (see staticcheck SA6002).
func NewBufferPool(size, poolSize int) *BufferPool {
	bp := &BufferPool{
		size: size,
		pool: sync.Pool{
			New: func() any {
				b := make([]byte, size)
				return &b
			},
		},
	}
	for range poolSize {
		b := make([]byte, size)
		bp.pool.Put(&b)
	}
	return bp
}

// Get acquires a byte slice from the pool.
func (bp *BufferPool) Get() []byte {
	bufPtr := bp.pool.Get()
	if bufPtr == nil {
		b := make([]byte, bp.size)
		return b
	}
	return *(bufPtr.(*[]byte))
}

// Put returns a byte slice to the pool.
func (bp *BufferPool) Put(buf []byte) {
	if buf != nil && cap(buf) >= bp.size {
		clear(buf[:cap(buf)])
		bp.pool.Put(&buf)
	}
}
