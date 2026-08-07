package upstream

import (
	"errors"
	"testing"
	"zjdns/config"

	"codeberg.org/miekg/dns"
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

func TestNeedsTCPFallback_Truncated(t *testing.T) {
	c := New()
	defer c.Close()
	r := &Result{
		Response: new(dns.Msg),
		Protocol: config.ProtoUDP,
	}
	r.Response.Response = true
	r.Response.Truncated = true
	if !c.needsTCPFallback(r, config.ProtoUDP) {
		t.Error("truncated UDP response should trigger TCP fallback")
	}
}

func TestNeedsTCPFallback_Error(t *testing.T) {
	c := New()
	defer c.Close()
	r := &Result{
		Protocol: config.ProtoUDP,
		Error:    errors.New("udp timeout"),
	}
	if !c.needsTCPFallback(r, config.ProtoUDP) {
		t.Error("UDP error should trigger TCP fallback")
	}
}

func TestNeedsTCPFallback_NoFallbackForTCP(t *testing.T) {
	c := New()
	defer c.Close()
	r := &Result{
		Response: new(dns.Msg),
		Protocol: config.ProtoTCP,
	}
	r.Response.Response = true
	r.Response.Truncated = true
	if c.needsTCPFallback(r, config.ProtoTCP) {
		t.Error("truncated TCP response should NOT trigger another fallback")
	}
}

func TestNeedsTCPFallback_Success(t *testing.T) {
	c := New()
	defer c.Close()
	r := &Result{
		Response: new(dns.Msg),
		Protocol: config.ProtoUDP,
	}
	r.Response.Response = true
	if c.needsTCPFallback(r, config.ProtoUDP) {
		t.Error("clean UDP response should NOT trigger fallback")
	}
}
