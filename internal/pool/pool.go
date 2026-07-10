// Package pool provides sync.Pool-based message and buffer pools.
package pool

import (
	"sync"

	"codeberg.org/miekg/dns"
	"github.com/quic-go/quic-go"
)

// UDPBufferSize is the EDNS0 UDP payload size for standard upstream queries per
// DNS Flag Day 2020: 1232 bytes avoids IP fragmentation on any path.
// RecursiveUDPBufferSize is used for recursive (root/TLD) queries where
// DNSSEC-signed referrals commonly exceed 1232 bytes.
const (
	UDPBufferSize          = 1232
	RecursiveUDPBufferSize = 4096
	SecureBufferSize       = 8192
	defaultBufferPoolSize  = 256
)

// DefaultMessagePool is the package-level default MessagePool.
var DefaultMessagePool = NewMessagePool()

// DefaultBufferPool is the package-level default BufferPool.
var DefaultBufferPool = NewBufferPool(SecureBufferSize, defaultBufferPoolSize)

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

// Get acquires a dns.Msg from the pool. The message is already zeroed by Put(),
// so callers that need a clean slate are covered; callers that pre-populate
// fields before use can rely on the zero state.
func (m *MessagePool) Get() *dns.Msg {
	return m.pool.Get().(*dns.Msg)
}

// Put returns a dns.Msg to the pool.
func (m *MessagePool) Put(msg *dns.Msg) {
	if msg != nil {
		*msg = dns.Msg{}
		m.pool.Put(msg)
	}
}

// NewBufferPool creates a new BufferPool pre-populated with the given number
// of buffers. Buffers are stored as *[]byte pointers to avoid interface-boxing
// allocations on every Put (see staticcheck SA6002).
func NewBufferPool(size, poolSize int) *BufferPool {
	bufPool := &BufferPool{
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
		bufPool.pool.Put(&b)
	}
	return bufPool
}

// Get acquires a byte slice from the pool.
func (b *BufferPool) Get() []byte {
	bufPtr := b.pool.Get()
	if bufPtr == nil {
		b := make([]byte, b.size)
		return b
	}
	return *bufPtr.(*[]byte)
}

// Put returns a byte slice to the pool. The slice is normalized to full
// capacity before clearing to ensure the next Get returns the full buffer.
func (b *BufferPool) Put(buf []byte) {
	if buf != nil && cap(buf) >= b.size {
		buf = buf[:cap(buf)]
		clear(buf[:cap(buf)])
		b.pool.Put(&buf)
	}
}

// QUIC application error codes shared across client and server packages.
const (
	// QUICCodeNoError is for normal connection closure.
	QUICCodeNoError quic.ApplicationErrorCode = 0

	// QUICCodeInternalError is for internal errors.
	QUICCodeInternalError quic.ApplicationErrorCode = 1

	// QUICCodeProtocolError is for protocol violations.
	QUICCodeProtocolError quic.ApplicationErrorCode = 2
)
