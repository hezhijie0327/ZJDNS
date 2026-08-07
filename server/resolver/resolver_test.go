package resolver

import (
	"testing"
	"zjdns/edns"

	"codeberg.org/miekg/dns"
)

// TestQueryResult_TruncatedField verifies the TC bit propagation field exists
// and defaults to false (zero value).
func TestQueryResult_TruncatedField(t *testing.T) {
	qr := &QueryResult{}
	if qr.Truncated {
		t.Error("new QueryResult should have Truncated=false by default")
	}

	// Verify the field is settable and readable.
	qr.Truncated = true
	if !qr.Truncated {
		t.Error("Truncated should be settable to true")
	}

	// Verify the field is preserved alongside other fields.
	qr = &QueryResult{
		Answer:    []dns.RR{&dns.A{Hdr: dns.Header{Name: "example.com."}}},
		Rcode:     dns.RcodeSuccess,
		Cacheable: true,
		Truncated: true,
		Server:    "test",
		ECS:       &edns.ECSOption{Address: nil, SourcePrefix: 0},
	}
	if !qr.Truncated {
		t.Error("QueryResult with Truncated=true should keep the value")
	}
	if qr.Rcode != dns.RcodeSuccess {
		t.Error("other fields should be preserved alongside Truncated")
	}
}
