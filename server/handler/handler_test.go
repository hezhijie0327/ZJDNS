package handler

import (
	"testing"

	"codeberg.org/miekg/dns"
)

// TestBuildQueryMsgUnknownType pins the RFC 8906 §8.1.2 forwarding
// requirement: a query for a type the library has no Go representation for
// must still produce an outbound message with a question section (the
// library's SetQuestion returns nil for unknown types — ignoring that left
// QDCOUNT=0 queries that every upstream silently drops).
func TestBuildQueryMsgUnknownType(t *testing.T) {
	for _, qtype := range []uint16{1000, 65280, 65535} {
		msg := BuildQueryMsg(nil, Question{Name: "example.com", Qtype: qtype, Qclass: dns.ClassINET}, nil, true, false)
		if len(msg.Question) != 1 {
			t.Fatalf("type %d: outbound question missing — QDCOUNT=0 queries are silently dropped by upstreams", qtype)
		}
		if got := dns.RRToType(msg.Question[0]); got != qtype {
			t.Fatalf("type %d: outbound question carries type %d", qtype, got)
		}
		if err := msg.Pack(); err != nil {
			t.Fatalf("type %d: pack: %v", qtype, err)
		}
	}
}
