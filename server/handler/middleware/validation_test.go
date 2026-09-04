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
	qctx := (&handler.QueryContext{Req: nil}).InitQuestion()
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
	qctx := (&handler.QueryContext{Req: new(dns.Msg)}).InitQuestion()
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
	qctx := (&handler.QueryContext{
		Req: newMsg("example.com.", &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}}),
	}).InitQuestion()
	_ = h.ServeDNS(context.Background(), qctx)
	if !nextCalled {
		t.Error("next should be called for valid query")
	}
}

// TestValidation_ANY_PassesThrough verifies that ANY queries are no longer
// rejected by Validation — RFC 8482 minimal responses are synthesized by the
// Any middleware further down the chain.
func TestValidation_ANY_PassesThrough(t *testing.T) {
	m := &Validation{}
	nextCalled := false
	h := m.Wrap(handler.QueryHandlerFunc(func(_ context.Context, qctx *handler.QueryContext) error {
		nextCalled = true
		return nil
	}))
	qctx := (&handler.QueryContext{
		Req: newMsg("example.com.", &dns.ANY{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}}),
	}).InitQuestion()
	_ = h.ServeDNS(context.Background(), qctx)
	if !nextCalled {
		t.Error("next should be called for ANY query (RFC 8482 minimal response)")
	}
}

// TestValidation_NXNAME_Rejected verifies that NXNAME (128) queries are
// rejected — RFC 9824 §3.5: a resolver MUST NOT forward or iterate NXNAME
// and MUST answer with FORMERR.
func TestValidation_NXNAME_Rejected(t *testing.T) {
	m := &Validation{}
	nextCalled := false
	h := m.Wrap(handler.QueryHandlerFunc(func(_ context.Context, qctx *handler.QueryContext) error {
		nextCalled = true
		return nil
	}))
	qctx := (&handler.QueryContext{
		Req: newMsg("example.com.", &dns.NXNAME{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}}),
	}).InitQuestion()
	_ = h.ServeDNS(context.Background(), qctx)
	if nextCalled {
		t.Error("next should not be called for NXNAME query")
	}
	if qctx.Res == nil || qctx.Res.Rcode != dns.RcodeFormatError {
		t.Errorf("rcode = %d, want RcodeFormatError (RFC 9824 §3.5 MUST)", qctx.Res.Rcode)
	}
	if qctx.EDE == nil || qctx.EDE.InfoCode != dns.ExtendedErrorInvalidQueryType {
		t.Errorf("EDE = %+v, want EDE 30 (Invalid Query Type)", qctx.EDE)
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
	qctx := (&handler.QueryContext{
		Req: newMsg(longName, &dns.A{Hdr: dns.Header{Name: longName, Class: dns.ClassINET}}),
	}).InitQuestion()
	_ = h.ServeDNS(context.Background(), qctx)
	if nextCalled {
		t.Error("long domain should be rejected")
	}
}
