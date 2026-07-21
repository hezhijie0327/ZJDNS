// Package pool provides sync.Pool-based message and buffer pools.
package pool

import (
	"sync"

	"codeberg.org/miekg/dns"
	"github.com/quic-go/quic-go"
)

// Message is a pooled allocator for dns.Msg values.
type Message struct {
	pool sync.Pool
}

// Buffer is a pooled allocator for byte slices.
type Buffer struct {
	pool sync.Pool
	size int
}

// UDPBufferSize is the EDNS0 UDP payload size for standard upstream queries per
// DNS Flag Day 2020: 1232 bytes avoids IP fragmentation on any path.
// RecursiveUDPBufferSize is used for recursive (root/TLD) queries where
// DNSSEC-signed referrals commonly exceed 1232 bytes.
// SecureBufferSize is the default buffer pool size for TCP/DoT query framing.
const (
	UDPBufferSize          = 1232
	RecursiveUDPBufferSize = 4096
	SecureBufferSize       = 8192
	defaultBufferSize      = 256
)

// QUIC application error codes (RFC 9000 §20) shared across client and
// server packages.  Defined here because they are consumed by both
// server/protocol/tls and server/upstream/tls.
const (
	// QUICCodeNoError is for normal connection closure.
	QUICCodeNoError quic.ApplicationErrorCode = 0

	// QUICCodeInternalError is for internal errors.
	QUICCodeInternalError quic.ApplicationErrorCode = 1

	// QUICCodeProtocolError is for protocol violations.
	QUICCodeProtocolError quic.ApplicationErrorCode = 2
)

// DefaultMessage is the package-level default message pool, shared across the
// entire server for maximum reuse.  Package-level globals are intentional here:
// a sync.Pool is mechanically a shared free-list; splitting it into per-package
// instances would fragment the pool and increase allocations.
var DefaultMessage = NewMessage()

// DefaultBuffer is the package-level default byte-slice pool.  See the
// DefaultMessage comment for the rationale behind global pools.
var DefaultBuffer = NewBuffer(SecureBufferSize, defaultBufferSize)

// NewMessage creates a new Message.
func NewMessage() *Message {
	return &Message{
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
func (m *Message) Get() *dns.Msg {
	return m.pool.Get().(*dns.Msg)
}

// Put returns a dns.Msg to the pool.
func (m *Message) Put(msg *dns.Msg) {
	if msg != nil {
		*msg = dns.Msg{}
		m.pool.Put(msg)
	}
}

// NewBuffer creates a new Buffer pre-populated with the given number
// of buffers. Buffers are stored as *[]byte pointers to avoid interface-boxing
// allocations on every Put (see staticcheck SA6002).
func NewBuffer(size, poolSize int) *Buffer {
	bufPool := &Buffer{
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
func (b *Buffer) Get() []byte {
	bufPtr := b.pool.Get()
	if bufPtr == nil {
		b := make([]byte, b.size)
		return b
	}
	return *bufPtr.(*[]byte)
}

// Put returns a byte slice to the pool. The slice is normalized to full
// capacity before clearing to ensure the next Get returns the full buffer.
func (b *Buffer) Put(buf []byte) {
	if buf != nil && cap(buf) >= b.size {
		buf = buf[:cap(buf)]
		clear(buf[:cap(buf)])
		b.pool.Put(&buf)
	}
}
