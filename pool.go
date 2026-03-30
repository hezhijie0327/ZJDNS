// Package main implements ZJDNS - High Performance DNS Server
package main

import (
	"sync"

	"github.com/miekg/dns"
)

// =============================================================================
// Global Pool Variables
// =============================================================================

var (
	messagePool *MessagePool
	bufferPool  *BufferPool
)

// =============================================================================
// Initialization
// =============================================================================

func init() {
	messagePool = NewMessagePool()
	bufferPool = NewBufferPool(SecureBufferSize, BufferPoolSize)
}

// =============================================================================
// MessagePool Implementation
// =============================================================================

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

// =============================================================================
// BufferPool Implementation
// =============================================================================

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
		bufCopy := make([]byte, bp.size)
		copy(bufCopy, buf[:bp.size])
		bp.pool.Put(&bufCopy)
	}
}
