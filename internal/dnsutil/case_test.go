package dnsutil

import (
	"net/netip"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"
)

func TestFoldCase(t *testing.T) {
	tests := []struct {
		name       string
		rr         dns.RR
		wantOwner  string
		wantString string
	}{
		{
			name:       "cname owner and target",
			rr:         &dns.CNAME{Hdr: dns.Header{Name: "Pvp.QQ.com.", Class: dns.ClassINET, TTL: 60}, Target: "Pvp.qq.com.TeGSEA.TC.Qq.CoM."},
			wantOwner:  "pvp.qq.com.",
			wantString: "pvp.qq.com.tegsea.tc.qq.com.",
		},
		{
			name:       "soa names",
			rr:         &dns.SOA{Hdr: dns.Header{Name: "NS1.EXAMPLE.com.", Class: dns.ClassINET, TTL: 300}, Ns: "NS1.EXAMPLE.com.", Mbox: "HOSTMASTER.EXAMPLE.com."},
			wantOwner:  "ns1.example.com.",
			wantString: "ns1.example.com. hostmaster.example.com.",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rrs := []dns.RR{tt.rr}
			FoldCase(rrs)
			if got := rrs[0].Header().Name; got != tt.wantOwner {
				t.Errorf("owner = %q, want %q", got, tt.wantOwner)
			}
			if got := rrs[0].String(); !strings.Contains(got, tt.wantString) {
				t.Errorf("rdata = %q, want it to contain %q", got, tt.wantString)
			}
		})
	}
}

func TestFoldCase_AlreadyLowercaseReturnsInput(t *testing.T) {
	rr := &dns.CNAME{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, Target: "target.example.com."}
	rrs := []dns.RR{rr}
	FoldCase(rrs)
	if rrs[0] != rr {
		t.Errorf("clean record was rebuilt (allocation churn): got %p, want %p", rrs[0], rr)
	}
}

func TestFoldCase_QuotedDataUntouched(t *testing.T) {
	rr := &dns.TXT{Hdr: dns.Header{Name: "EXAMPLE.com.", Class: dns.ClassINET, TTL: 300}, Txt: []string{"Hello WORLD. Mixed Case."}}
	rrs := []dns.RR{rr}
	FoldCase(rrs)

	txt, ok := rrs[0].(*dns.TXT)
	if !ok {
		t.Fatalf("unexpected type %T", rrs[0])
	}
	if txt.Txt[0] != "Hello WORLD. Mixed Case." {
		t.Errorf("TXT content mutated: %q", txt.Txt[0])
	}
	if txt.Hdr.Name != "example.com." {
		t.Errorf("owner not folded: %q", txt.Hdr.Name)
	}
}

func TestFoldCase_RRSIGSignatureUntouched(t *testing.T) {
	// Signature data contains uppercase base64; only the signer name may fold.
	rr := &dns.RRSIG{
		Hdr:         dns.Header{Name: "EXAMPLE.com.", Class: dns.ClassINET, TTL: 300},
		TypeCovered: dns.TypeA, Algorithm: 13, Labels: 2, OrigTTL: 300, KeyTag: 34505,
		SignerName: "EXAMPLE.com.", Signature: "abcDEF123+/=",
	}
	rrs := []dns.RR{rr}
	FoldCase(rrs)

	sig, ok := rrs[0].(*dns.RRSIG)
	if !ok {
		t.Fatalf("unexpected type %T", rrs[0])
	}
	if sig.SignerName != "example.com." {
		t.Errorf("signer name not folded: %q", sig.SignerName)
	}
	if sig.Signature != "abcDEF123+/=" {
		t.Errorf("signature mutated: %q", sig.Signature)
	}
}

func TestFoldCase_NonASCIIUntouched(t *testing.T) {
	// RFC 4343 §3 folds ASCII letters only — UTF-8 bytes must survive
	// byte-exact (upper- and lowercase multibyte runes alike), while ASCII
	// letters still fold.
	rr := &dns.A{Hdr: dns.Header{Name: "Café.Éxample.com.", Class: dns.ClassINET, TTL: 300}, Addr: netip.MustParseAddr("192.0.2.1")}
	rrs := []dns.RR{rr}
	FoldCase(rrs)

	if got := rrs[0].Header().Name; got != "café.Éxample.com." {
		t.Errorf("non-ASCII folding wrong: got %q, want %q", got, "café.Éxample.com.")
	}
}

func TestASCIIFold(t *testing.T) {
	if got := ASCIIFold("lowercase."); got != "lowercase." {
		t.Errorf("no-op fold changed input: %q", got)
	}
	if got := ASCIIFold("Mixed.CASE."); got != "mixed.case." {
		t.Errorf("fold = %q, want %q", got, "mixed.case.")
	}
}
