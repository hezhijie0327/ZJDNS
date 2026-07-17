package middleware

import (
	"context"
	"strings"
	"testing"
	"zjdns/server/handler"

	"codeberg.org/miekg/dns"
)

func newMsg(name string, rr dns.RR) *dns.Msg {
	msg := new(dns.Msg)
	msg.Question = []dns.RR{rr}
	return msg
}

func TestValidation_NilRequest(t *testing.T) {
	m := &Validation{}
	h := m.Wrap(handler.QueryHandlerFunc(func(_ context.Context, qctx *handler.QueryContext) error {
		return nil
	}))
	qctx := &handler.QueryContext{Req: nil}
	_ = h.ServeDNS(context.Background(), qctx)
	if qctx.Res == nil {
		t.Fatal("expected response for nil request")
	}
	if qctx.Res.Rcode != dns.RcodeFormatError {
		t.Errorf("rcode = %d, want RcodeFormatError", qctx.Res.Rcode)
	}
}

func TestValidation_NoQuestions(t *testing.T) {
	m := &Validation{}
	nextCalled := false
	h := m.Wrap(handler.QueryHandlerFunc(func(_ context.Context, qctx *handler.QueryContext) error {
		nextCalled = true
		return nil
	}))
	qctx := &handler.QueryContext{Req: new(dns.Msg)}
	_ = h.ServeDNS(context.Background(), qctx)
	if nextCalled {
		t.Error("next should not be called for empty questions")
	}
}

func TestValidation_ValidQuery(t *testing.T) {
	m := &Validation{}
	nextCalled := false
	h := m.Wrap(handler.QueryHandlerFunc(func(_ context.Context, qctx *handler.QueryContext) error {
		nextCalled = true
		return nil
	}))
	qctx := &handler.QueryContext{
		Req: newMsg("example.com.", &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}}),
	}
	_ = h.ServeDNS(context.Background(), qctx)
	if !nextCalled {
		t.Error("next should be called for valid query")
	}
}

func TestValidation_ANY_Rejected(t *testing.T) {
	m := &Validation{}
	nextCalled := false
	h := m.Wrap(handler.QueryHandlerFunc(func(_ context.Context, qctx *handler.QueryContext) error {
		nextCalled = true
		return nil
	}))
	qctx := &handler.QueryContext{
		Req: newMsg("example.com.", &dns.ANY{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}}),
	}
	_ = h.ServeDNS(context.Background(), qctx)
	if nextCalled {
		t.Error("next should not be called for ANY query")
	}
	if qctx.Res.Rcode != dns.RcodeRefused {
		t.Errorf("rcode = %d, want RcodeRefused", qctx.Res.Rcode)
	}
}

func TestValidation_LongDomain(t *testing.T) {
	m := &Validation{}
	nextCalled := false
	h := m.Wrap(handler.QueryHandlerFunc(func(_ context.Context, qctx *handler.QueryContext) error {
		nextCalled = true
		return nil
	}))
	longName := strings.Repeat("a", 260) + ".com."
	qctx := &handler.QueryContext{
		Req: newMsg(longName, &dns.A{Hdr: dns.Header{Name: longName, Class: dns.ClassINET}}),
	}
	_ = h.ServeDNS(context.Background(), qctx)
	if nextCalled {
		t.Error("long domain should be rejected")
	}
}
