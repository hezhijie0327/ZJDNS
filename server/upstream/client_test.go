package upstream

import (
	"testing"
)

func TestNew(t *testing.T) {
	c := New()
	if c == nil {
		t.Fatal("New returned nil")
	}
	if c.plainClient == nil {
		t.Error("plainClient is nil")
	}
	if c.tlsClient == nil {
		t.Error("tlsClient is nil")
	}
	if c.tlcpClient == nil {
		t.Error("tlcpClient is nil")
	}
	if c.dnscryptClient == nil {
		t.Error("dnscryptClient is nil")
	}
	c.Close()
}

func TestClose_Double(t *testing.T) {
	c := New()
	c.Close()
	c.Close()
}

func TestResult(t *testing.T) {
	r := &Result{
		Server:   "8.8.8.8",
		Protocol: "UDP",
	}
	if r.Server != "8.8.8.8" {
		t.Errorf("Server = %q, want 8.8.8.8", r.Server)
	}
}
