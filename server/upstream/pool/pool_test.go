package pool

import (
	"testing"
)

func TestNewConnPool(t *testing.T) {
	pool := NewConnPool(10, 16)
	if pool == nil {
		t.Fatal("NewConnPool returned nil")
	}
	pool.Shutdown()
}

func TestNewQUIC(t *testing.T) {
	pool := NewQUIC(10)
	if pool == nil {
		t.Fatal("NewQUIC returned nil")
	}
	pool.Shutdown()
}

func TestConnPool_Shutdown_Double(t *testing.T) {
	pool := NewConnPool(10, 16)
	pool.Shutdown()
	// Second shutdown should be safe
	pool.Shutdown()
}

func TestQUIC_Shutdown_Double(t *testing.T) {
	pool := NewQUIC(10)
	pool.Shutdown()
	pool.Shutdown()
}

func TestConnPool_ZeroConns(t *testing.T) {
	pool := NewConnPool(0, 16)
	if pool == nil {
		t.Fatal("NewConnPool(0) returned nil")
	}
	pool.Shutdown()
}

func TestQUIC_ZeroConns(t *testing.T) {
	pool := NewQUIC(0)
	if pool == nil {
		t.Fatal("NewQUIC(0) returned nil")
	}
	pool.Shutdown()
}
