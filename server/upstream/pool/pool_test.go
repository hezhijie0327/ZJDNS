package pool

import (
	"context"
	"io"
	"net"
	"testing"
)

func TestNewConnPool(t *testing.T) {
	pool := NewConnPool(10, 16, 0)
	if pool == nil {
		t.Fatal("NewConnPool returned nil")
	}
	pool.Shutdown()
}

func TestNewQUIC(t *testing.T) {
	pool := NewQUIC(10, 0)
	if pool == nil {
		t.Fatal("NewQUIC returned nil")
	}
	pool.Shutdown()
}

func TestConnPool_Shutdown_Double(t *testing.T) {
	pool := NewConnPool(10, 16, 0)
	pool.Shutdown()
	// Second shutdown should be safe
	pool.Shutdown()
}

func TestQUIC_Shutdown_Double(t *testing.T) {
	pool := NewQUIC(10, 0)
	pool.Shutdown()
	pool.Shutdown()
}

func TestConnPool_ZeroConns(t *testing.T) {
	pool := NewConnPool(0, 16, 0)
	if pool == nil {
		t.Fatal("NewConnPool(0) returned nil")
	}
	pool.Shutdown()
}

func TestQUIC_ZeroConns(t *testing.T) {
	pool := NewQUIC(0, 0)
	if pool == nil {
		t.Fatal("NewQUIC(0, 0) returned nil")
	}
	pool.Shutdown()
}

// countTracked sums every pooled connection across all keys — the ground
// truth p.total must match after any operation sequence.
func countTracked(p *ConnPool) int {
	n := 0
	for _, conns := range p.conns {
		n += len(conns)
	}
	return n
}

// TestConnPool_TotalAccounting: p.total must stay equal to the number of
// tracked connections across dead-filter (Acquire), dead-replacement
// (dialAndAdd) and eviction paths.  Before 2026-09 U1/U2 the dead filter
// forgot to decrement and the replace-dead append forgot to increment — the
// counter drifted in both directions, breaking the maxTotal cap (upward
// drift caused permanent eviction churn; downward drift disabled the cap).
func TestConnPool_TotalAccounting(t *testing.T) {
	p := NewConnPool(2, 4, 8)
	defer p.Shutdown()

	dial := func(context.Context, string) (net.Conn, error) {
		c1, c2 := net.Pipe()
		go func() { _, _ = io.Copy(io.Discard, c2) }() // keep pipes drainable
		return c1, nil
	}

	// Two conns under one key (WarmUp dials without reusing).
	if err := p.WarmUp(context.Background(), "k1", "a", dial); err != nil {
		t.Fatal(err)
	}
	if err := p.WarmUp(context.Background(), "k1", "a", dial); err != nil {
		t.Fatal(err)
	}
	if got := p.total; got != 2 {
		t.Fatalf("total = %d after 2 warmups, want 2", got)
	}

	// Kill both readLoops (mark dead without removing from the pool map).
	for _, c := range p.conns["k1"] {
		c.close()
	}

	// Acquire runs the dead filter: both dead conns are dropped and a fresh
	// one dialed.  total must equal the tracked count, not stay inflated
	// (U1) — the pre-fix counter kept the dead entries forever.
	_, err := p.Acquire(context.Background(), "k1", "a", dial)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.total; got != countTracked(p) {
		t.Fatalf("total = %d, tracked = %d after dead-filter Acquire (U1 drift)", got, countTracked(p))
	}

	// Dead-replacement: fill the key to maxConns, kill one, dial again —
	// the swap must be net-zero (U2).
	if err := p.WarmUp(context.Background(), "k1", "a", dial); err != nil {
		t.Fatal(err)
	}
	for _, c := range p.conns["k1"] {
		c.close()
	}
	if err := p.WarmUp(context.Background(), "k1", "a", dial); err != nil {
		t.Fatal(err)
	}
	if got := p.total; got != countTracked(p) {
		t.Fatalf("total = %d, tracked = %d after dead-replacement (U2 drift)", got, countTracked(p))
	}
	if got := p.total; got <= 0 || got > 2 {
		t.Fatalf("total = %d after replacements, want 1..2", got)
	}
}
