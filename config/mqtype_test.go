package config

import (
	"testing"

	"codeberg.org/miekg/dns"
)

// TestValidateMQType_Valid parses a numeric MQTYPE list.
func TestValidateMQType_Valid(t *testing.T) {
	s := &UpstreamServer{MQType: []uint16{dns.TypeA, dns.TypeAAAA}}
	if err := validateMQType(s); err != nil {
		t.Fatalf("valid list rejected: %v", err)
	}
}

// TestValidateMQType_EmptyIsDisabled reports no error and no parsed state.
func TestValidateMQType_EmptyIsDisabled(t *testing.T) {
	s := &UpstreamServer{}
	if err := validateMQType(s); err != nil {
		t.Fatalf("empty list rejected: %v", err)
	}
}

// TestValidateMQType_MetaType rejects Meta/QTYPEs (RFC 6895 §3.1).
func TestValidateMQType_MetaType(t *testing.T) {
	for _, meta := range []uint16{dns.TypeANY, dns.TypeAXFR, dns.TypeIXFR, dns.TypeOPT, dns.TypeTSIG, dns.TypeTKEY} {
		s := &UpstreamServer{MQType: []uint16{dns.TypeA, meta}}
		if err := validateMQType(s); err == nil {
			t.Errorf("meta type %d accepted", meta)
		}
	}
}

// TestValidateMQType_UnknownType rejects unregistered QTYPEs.
func TestValidateMQType_UnknownType(t *testing.T) {
	s := &UpstreamServer{MQType: []uint16{dns.TypeA, 60000}}
	if err := validateMQType(s); err == nil {
		t.Fatal("unknown type accepted")
	}
}

// TestValidateMQType_Duplicate rejects duplicated QTYPEs.
func TestValidateMQType_Duplicate(t *testing.T) {
	s := &UpstreamServer{MQType: []uint16{dns.TypeA, dns.TypeA}}
	if err := validateMQType(s); err == nil {
		t.Fatal("duplicate type accepted")
	}
}

// TestValidateMQType_QTxCap enforces the RFC 10029 §4 cap of 4 types.
func TestValidateMQType_QTxCap(t *testing.T) {
	s := &UpstreamServer{MQType: []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeHTTPS, dns.TypeTXT, dns.TypeMX}}
	if err := validateMQType(s); err == nil {
		t.Fatal("list over the §4 QTx cap accepted")
	}
}

// TestValidateMQType_ViaUpstreamServers runs the full upstream validation
// path, proving the check is wired into Validate.
func TestValidateMQType_ViaUpstreamServers(t *testing.T) {
	cfg := &ServerConfig{
		Upstream: []UpstreamServer{{MQType: []uint16{dns.TypeANY}}},
	}
	if err := validateUpstreamServers(cfg, map[string]bool{}); err == nil {
		t.Fatal("meta type accepted through full upstream validation")
	}
}
