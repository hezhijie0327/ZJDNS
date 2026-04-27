// Package main implements ZJDNS - High Performance DNS Server
package main

import (
	"sync"

	"github.com/miekg/dns"
)

const (
	UDPBufferSize    = 1232 // Optimal UDP payload size for DNS to avoid fragmentation
	TCPBufferSize    = 4096 // Buffer size for TCP DNS messages
	SecureBufferSize = 8192 // Buffer size for secure DNS messages (DoT, DoH, DoQ)

	MessagePoolSize  = 512  // Number of pre-allocated dns.Msg objects in the pool
	BufferPoolSize   = 256  // Number of pre-allocated byte buffers in the pool
)

var (
	messagePool *MessagePool // Pool for dns.Msg objects to reduce GC overhead
	bufferPool  *BufferPool  // Pool for byte buffers to reduce GC overhead
)

// MessagePool manages reusable dns.Msg objects to reduce GC overhead and improve performance.
type MessagePool struct {
	pool sync.Pool
}

// BufferPool manages reusable byte buffers to reduce GC overhead and improve performance.
type BufferPool struct {
	pool sync.Pool
	size int
}

// Initialization
func init() {
	messagePool = NewMessagePool()
	bufferPool = NewBufferPool(SecureBufferSize, BufferPoolSize)
}

// NewMessagePool creates a new pool for dns.Msg objects
func NewMessagePool() *MessagePool {
	return &MessagePool{
		pool: sync.Pool{
			New: func() any {
				return &dns.Msg{}
			},
		},
	}
}

// Get retrieves a dns.Msg from the pool
func (mp *MessagePool) Get() *dns.Msg {
	msg := mp.pool.Get().(*dns.Msg)
	*msg = dns.Msg{}
	return msg
}

// Put returns a dns.Msg to the pool
func (mp *MessagePool) Put(msg *dns.Msg) {
	if msg != nil {
		*msg = dns.Msg{}
		mp.pool.Put(msg)
	}
}

// NewBufferPool creates a new pool for byte buffers
func NewBufferPool(size int, poolSize int) *BufferPool {
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

// Get retrieves a buffer from the pool
func (bp *BufferPool) Get() []byte {
	bufPtr := bp.pool.Get()
	if bufPtr == nil {
		return make([]byte, bp.size)
	}
	buf := bufPtr.(*[]byte)
	return *buf
}

// Put returns a buffer to the pool
func (bp *BufferPool) Put(buf []byte) {
	if buf != nil && cap(buf) >= bp.size {
		// Zero out the buffer before returning to pool to prevent data leakage
		clear(buf[:bp.size])
		bp.pool.Put(&buf)
	}
}
