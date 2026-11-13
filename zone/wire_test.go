package zone

import (
	"testing"
	"zjdns/config"

	"codeberg.org/miekg/dns"
)

// TestBuildRecord_BadContentDropped pins the Round 6 D6 fix: when dns.New
// cannot parse a record, the RFC 3597 fallback only accepts content that can
// actually pack — a typo'd address used to become an RFC3597 RR whose
// serve-time pack failed on EVERY hit of the rule.  (Well-formed `\# <len>
// <hex>` content never reaches the fallback: the dns fork's parser accepts it
// for known types directly.)
func TestBuildRecord_BadContentDropped(t *testing.T) {
	domain := "example.com."
	for _, content := range []string{
		"999.999.999.999",  // typo'd A address
		"not-an-ip",        // known type, garbage rdata
		`\# 5 0a000001`,    // rdlength does not match the hex
		`\# four 0a000001`, // non-numeric rdlength
		`\# 4 0a0000zz`,    // non-hex payload
	} {
		rec := &config.ZoneRecord{Type: dns.TypeA, Content: content}
		if rr := buildRecord(domain, rec); rr != nil {
			t.Errorf("buildRecord(content %q) = %v, want the unpackable record dropped", content, rr)
		}
	}
}

// TestBuildRecord_RFC3597FallbackPacks verifies the accepted fallback (bare
// contiguous hex — Data is hex-decoded verbatim on pack) yields a record
// that packs cleanly instead of failing at serve time.
func TestBuildRecord_RFC3597FallbackPacks(t *testing.T) {
	domain := "example.com."
	rec := &config.ZoneRecord{Type: dns.TypeA, Content: "0a000001"}
	rr := buildRecord(domain, rec)
	if rr == nil {
		t.Fatal("buildRecord = nil, want the RFC 3597 fallback for bare hex content")
	}
	gen, ok := rr.(*dns.RFC3597)
	if !ok {
		t.Fatalf("buildRecord = %T, want *dns.RFC3597", rr)
	}
	if gen.RFC3597.Data != "0a000001" {
		t.Fatalf("RFC3597.Data = %q, want the bare hex payload", gen.RFC3597.Data)
	}
	m := new(dns.Msg)
	m.Answer = append(m.Answer, rr)
	if err := m.Pack(); err != nil {
		t.Fatalf("pack of the fallback record: %v", err)
	}
}
