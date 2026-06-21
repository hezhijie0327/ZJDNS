package pool

import (
	"testing"

	"github.com/miekg/dns"
)

func TestMessagePool_GetPut(t *testing.T) {
	mp := NewMessagePool()
	msg := mp.Get()
	if msg == nil {
		t.Fatal("Get returned nil")
	}
	if msg.Response {
		t.Error("new message should be zero-valued")
	}
	// Modify and put back
	msg.Response = true
	msg.Rcode = dns.RcodeServerFailure
	mp.Put(msg)

	// Get again — should be zeroed
	msg2 := mp.Get()
	if msg2.Response {
		t.Error("Put should zero the message before returning to pool")
	}
	if msg2.Rcode != dns.RcodeSuccess {
		t.Errorf("zeroed Rcode = %d, want %d", msg2.Rcode, dns.RcodeSuccess)
	}
}

func TestMessagePool_PutNil(t *testing.T) {
	mp := NewMessagePool()
	mp.Put(nil) // must not panic
}

func TestDefaultMessagePool(t *testing.T) {
	msg := DefaultMessagePool.Get()
	if msg == nil {
		t.Fatal("DefaultMessagePool.Get returned nil")
	}
	DefaultMessagePool.Put(msg)

	msg2 := DefaultMessagePool.Get()
	if msg2 == nil {
		t.Fatal("DefaultMessagePool.Get returned nil after Put")
	}
}

func TestBufferPool_Get(t *testing.T) {
	bp := NewBufferPool(512, 4)
	buf := bp.Get()
	if len(buf) != 512 {
		t.Errorf("buffer length = %d, want 512", len(buf))
	}
	if cap(buf) != 512 {
		t.Errorf("buffer capacity = %d, want 512", cap(buf))
	}
}

func TestBufferPool_PutAndReuse(t *testing.T) {
	bp := NewBufferPool(256, 4)
	buf1 := bp.Get()
	copy(buf1, []byte("hello"))

	bp.Put(buf1) // should zero buffer
	buf2 := bp.Get()
	if buf2[0] != 0 {
		t.Errorf("Put should clear buffer, got byte %d", buf2[0])
	}
}

func TestBufferPool_PutSmallBuffer(t *testing.T) {
	bp := NewBufferPool(512, 4)
	small := make([]byte, 128)
	bp.Put(small) // too small, should be discarded
	// Just verify no panic
	buf := bp.Get()
	if len(buf) < 512 {
		t.Errorf("Get should still return full-size buffer, got len=%d", len(buf))
	}
}

func TestBufferPool_PutNil(t *testing.T) {
	bp := NewBufferPool(256, 4)
	bp.Put(nil) // must not panic
}

func TestBufferPool_PrePopulated(t *testing.T) {
	bp := NewBufferPool(1024, 8)
	// First 8 Gets should come from the prepopulated pool
	for i := range 8 {
		buf := bp.Get()
		if len(buf) != 1024 {
			t.Errorf("prepopulated get %d: len=%d, want 1024", i, len(buf))
		}
		bp.Put(buf)
	}
}

func BenchmarkMessagePool_GetPut(b *testing.B) {
	mp := NewMessagePool()
	b.ResetTimer()
	for b.Loop() {
		msg := mp.Get()
		mp.Put(msg)
	}
}

func BenchmarkBufferPool_GetPut(b *testing.B) {
	bp := NewBufferPool(SecureBufferSize, 16)
	b.ResetTimer()
	for b.Loop() {
		buf := bp.Get()
		bp.Put(buf)
	}
}

func TestBufferPool_DrainAndRefill(t *testing.T) {
	bp := NewBufferPool(512, 2)
	// Drain the 2 prepopulated + a few more
	bufs := make([][]byte, 10)
	for i := range bufs {
		bufs[i] = bp.Get()
	}
	// Return them all
	for _, buf := range bufs {
		bp.Put(buf)
	}
	// Get again — should come from pool
	for range 5 {
		b := bp.Get()
		if len(b) != 512 {
			t.Errorf("buffer after drain/refill: len=%d, want 512", len(b))
		}
		bp.Put(b)
	}
}

func TestDefaultBufferPool(t *testing.T) {
	buf := DefaultBufferPool.Get()
	if len(buf) != SecureBufferSize {
		t.Errorf("DefaultBufferPool buffer len=%d, want %d", len(buf), SecureBufferSize)
	}
	DefaultBufferPool.Put(buf)
}

func BenchmarkDefaultMessagePool_GetPut(b *testing.B) {
	for b.Loop() {
		msg := DefaultMessagePool.Get()
		DefaultMessagePool.Put(msg)
	}
}
