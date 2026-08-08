package resolver

import (
	"context"
	"testing"

	"codeberg.org/miekg/dns"
)

func TestCaptureMQResponse_Nil(t *testing.T) {
	if got := captureMQResponse(nil); got != nil {
		t.Errorf("captureMQResponse(nil) = %v, want nil", got)
	}
}

func TestCaptureMQResponse_NoPseudo(t *testing.T) {
	resp := &dns.Msg{}
	if got := captureMQResponse(resp); got != nil {
		t.Errorf("captureMQResponse(no pseudo) = %v, want nil", got)
	}
}

func TestCaptureMQResponse_NoMQResponse(t *testing.T) {
	resp := &dns.Msg{
		Pseudo: []dns.RR{&dns.OPT{}},
	}
	if got := captureMQResponse(resp); got != nil {
		t.Errorf("captureMQResponse(no MQRESPONSE) = %v, want nil", got)
	}
}

func TestCaptureMQResponse_Found(t *testing.T) {
	types := []uint16{dns.TypeA, dns.TypeAAAA}
	resp := &dns.Msg{
		Pseudo: []dns.RR{&dns.MQRESPONSE{Types: types}},
	}
	got := captureMQResponse(resp)
	if got == nil {
		t.Fatal("captureMQResponse = nil, want MQRESPONSE")
	}
	if len(got.Types) != 2 || got.Types[0] != dns.TypeA || got.Types[1] != dns.TypeAAAA {
		t.Errorf("captureMQResponse types = %v, want [A AAAA]", got.Types)
	}
	// Verify clone: mutating the returned slice must not affect the original.
	got.Types[0] = dns.TypeMX
	if resp.Pseudo[0].(*dns.MQRESPONSE).Types[0] != dns.TypeA {
		t.Error("captureMQResponse must clone types (original mutated)")
	}
}

func TestCaptureMQResponse_AmongOtherPseudo(t *testing.T) {
	resp := &dns.Msg{
		Pseudo: []dns.RR{
			&dns.OPT{},
			&dns.MQRESPONSE{Types: []uint16{dns.TypeAAAA}},
			&dns.EDE{},
		},
	}
	got := captureMQResponse(resp)
	if got == nil {
		t.Fatal("captureMQResponse = nil, want MQRESPONSE among other Pseudo")
	}
	if len(got.Types) != 1 || got.Types[0] != dns.TypeAAAA {
		t.Errorf("captureMQResponse types = %v, want [AAAA]", got.Types)
	}
}

func TestWithMQType_RoundTrip(t *testing.T) {
	mq := &dns.MQQUERY{Types: []uint16{dns.TypeA, dns.TypeMX}}
	ctx := WithMQType(context.Background(), mq)
	got := MQTypeFromContext(ctx)
	if got == nil {
		t.Fatal("MQTypeFromContext = nil, want MQQUERY")
	}
	if len(got.Types) != 2 || got.Types[0] != dns.TypeA || got.Types[1] != dns.TypeMX {
		t.Errorf("MQTypeFromContext types = %v, want [A MX]", got.Types)
	}
}

func TestMQTypeFromContext_NotSet(t *testing.T) {
	if got := MQTypeFromContext(context.Background()); got != nil {
		t.Errorf("MQTypeFromContext(empty) = %v, want nil", got)
	}
}
