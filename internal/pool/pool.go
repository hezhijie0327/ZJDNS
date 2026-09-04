// Package pool provides sync.Pool-based message and buffer pools.
package pool

import (
	"sync"

	"codeberg.org/miekg/dns"
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

	// wireBufferSize is the capacity class of the response-wire pool.
	// Deliberately distinct from every other pool class (packBufPool 1232,
	// DefaultBuffer 8192, packet tiers 512/1500/4096/16384) so Message.Put
	// can route a Data buffer back to its owning pool by capacity alone — no
	// ownership flags, no cross-pool contamination, no double-release window.
	wireBufferSize = 2048
)

// DefaultMessage is the package-level default message pool, shared across the
// entire server for maximum reuse.  Package-level globals are intentional here:
// a sync.Pool is mechanically a shared free-list; splitting it into per-package
// instances would fragment the pool and increase allocations.
var DefaultMessage = NewMessage()

// DefaultBuffer is the package-level default byte-slice pool.  See the
// DefaultMessage comment for the rationale behind global pools.
var DefaultBuffer = NewBuffer(SecureBufferSize, defaultBufferSize)

// wireBufPool backs AcquireWire: per-hit response-wire copies on the
// cache-hit fast path (the former per-hit slices.Clone).  Buffers up to 2048
// bytes come from the pool; larger responses allocate fresh and are GC'd on
// Put (cap mismatch) — response wires above 2 KB are rare (DNSKEY/RRSIG-heavy).
var wireBufPool = sync.Pool{New: func() any { b := make([]byte, wireBufferSize); return &b }}

// packBufPool reuses outbound query packing buffers.  Outbound DNS queries
// (header + question + EDNS) fit comfortably in UDPBufferSize (1232);
// msg.Pack reuses msg.Data's capacity, so pre-setting Data to a pooled
// buffer makes Pack allocation-free on the hot path — Message.Put zeroes
// Data, so without this pool every packed query allocated fresh.
var packBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, UDPBufferSize)
		return &b
	},
}

// AcquireWire returns a byte slice of length n backed by the pooled 2048-byte
// class when n fits, or a fresh allocation otherwise.
func AcquireWire(n int) []byte {
	if n > wireBufferSize || n < 0 {
		return make([]byte, n)
	}
	b := wireBufPool.Get().(*[]byte)
	return (*b)[:n]
}

// ReleaseWire returns a buffer to the wire pool; only exact-class capacities
// are accepted (grown or foreign buffers are dropped to the GC).
func ReleaseWire(buf []byte) {
	if cap(buf) == wireBufferSize {
		clear(buf[:wireBufferSize])
		b := buf[:wireBufferSize]
		wireBufPool.Put(&b)
	}
}

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
	// New always returns *dns.Msg, so Get never yields nil or a foreign
	// type — the assertion cannot fail.
	return m.pool.Get().(*dns.Msg)
}

// Put returns a dns.Msg to the pool.
func (m *Message) Put(msg *dns.Msg) {
	if msg != nil {
		// Zeroing the entire Msg struct ensures that callers who capture slices
		// (Answer, Ns, Extra) before Put retain valid references — the backing
		// arrays are not zeroed, only the slice headers. Callers who depend on
		// this (e.g. recursive_helpers.go processAnswerWithDNSSEC) must not
		// mutate the captured slices after Put.
		// Route the packed wire back to the wire pool.  Every protocol writer
		// ends a response's life with this Put — the single universal choke
		// point for wire recycling.  Capacity-class routing (see
		// wireBufferSize) accepts only wire-pool buffers; packBuf/DefaultBuffer
		// backing never matches and is dropped to the GC as before.  The
		// buffer must not be used past this point (same contract as the
		// struct zeroing below).
		if len(msg.Data) > 0 {
			ReleaseWire(msg.Data)
		}
		*msg = dns.Msg{}
		m.pool.Put(msg)
	}
}

// NewBuffer creates a new Buffer pre-populated with the given number
// of buffers. Buffers are stored as *[]byte pointers to avoid interface-boxing
// allocations on every Put (see staticcheck SA6002).
func NewBuffer(size, poolSize int) *Buffer {
	if size < 0 {
		size = 0
	}
	if poolSize < 0 {
		poolSize = 0
	}
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
		return make([]byte, b.size)
	}
	buf, ok := bufPtr.(*[]byte)
	if !ok {
		return make([]byte, b.size)
	}
	return *buf
}

// Put returns a byte slice to the pool. The slice must have exactly the
// expected capacity (b.size) — buffers that grew via append are discarded
// to maintain the pool's uniform-size invariant. The slice is normalized
// to full capacity and zeroed before returning.
func (b *Buffer) Put(buf []byte) {
	if buf != nil && cap(buf) == b.size {
		buf = buf[:b.size]
		clear(buf)
		b.pool.Put(&buf)
	}
}

// AcquirePackBuf returns a zero-length, UDPBufferSize-capacity packing
// buffer.  Set it as msg.Data before Pack: Pack reuses the capacity when
// the message fits, and callers release via ReleasePackBuf after the
// packed bytes have been consumed (the write/encrypt completes before the
// release).
func AcquirePackBuf() []byte {
	bp := packBufPool.Get().(*[]byte)
	return (*bp)[:0]
}

// ReleasePackBuf returns a packing buffer to the pool when its capacity
// matches the class.  Pack-grown buffers (an oversized message) are
// dropped.  No clear: Pack writes every byte of the serialized message.
func ReleasePackBuf(b []byte) {
	if cap(b) == UDPBufferSize {
		packBufPool.Put(&b)
	}
}
