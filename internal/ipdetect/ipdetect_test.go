package ipdetect

import (
	"net"
	"testing"
)

func TestDefaultTraceURL(t *testing.T) {
	if DefaultTraceURL == "" {
		t.Error("DefaultTraceURL should not be empty")
	}
}

func TestDetector_DefaultURL(t *testing.T) {
	d := &Detector{}
	if d.TraceURL != "" {
		t.Error("zero-value Detector should have empty TraceURL")
	}
}

func TestDetector_CustomURL(t *testing.T) {
	d := &Detector{TraceURL: "https://custom.example.com/trace"}
	if d.TraceURL != "https://custom.example.com/trace" {
		t.Errorf("TraceURL = %q, want custom URL", d.TraceURL)
	}
}

func TestIPPattern_Match(t *testing.T) {
	body := "fl=123\nh=example.com\nip=192.0.2.1\nts=1234567890"
	matches := ipPattern.FindStringSubmatch(body)
	if len(matches) < 2 {
		t.Fatal("ipPattern should match")
	}
	if matches[1] != "192.0.2.1" {
		t.Errorf("ip = %q, want 192.0.2.1", matches[1])
	}
}

func TestIPPattern_IPv6Match(t *testing.T) {
	body := "ip=2001:db8::1\nother=value"
	matches := ipPattern.FindStringSubmatch(body)
	if len(matches) < 2 {
		t.Fatal("ipPattern should match IPv6")
	}
	if matches[1] != "2001:db8::1" {
		t.Errorf("ip = %q, want 2001:db8::1", matches[1])
	}
}

func TestIPPattern_NoMatch(t *testing.T) {
	body := "fl=123\nh=example.com"
	matches := ipPattern.FindStringSubmatch(body)
	if matches != nil {
		t.Error("ipPattern should not match body without ip=")
	}
}

func TestIPPattern_Whitespace(t *testing.T) {
	body := "ip=1.2.3.4"
	matches := ipPattern.FindStringSubmatch(body)
	if len(matches) < 2 {
		t.Fatal("ipPattern should match")
	}
	if matches[1] != "1.2.3.4" {
		t.Errorf("ip = %q, want 1.2.3.4", matches[1])
	}
}

func TestParseIP_Valid(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	if ip == nil {
		t.Error("net.ParseIP should return non-nil for valid IP")
	}
}

func TestParseIP_Invalid(t *testing.T) {
	ip := net.ParseIP("not-an-ip")
	if ip != nil {
		t.Error("net.ParseIP should return nil for invalid IP")
	}
}

func TestIPv4To4(t *testing.T) {
	v4 := net.ParseIP("192.0.2.1")
	if v4.To4() == nil {
		t.Error("IPv4.To4() should return non-nil")
	}
}

func TestIPv6To4(t *testing.T) {
	v6 := net.ParseIP("2001:db8::1")
	if v6.To4() != nil {
		t.Error("IPv6.To4() should return nil")
	}
}
