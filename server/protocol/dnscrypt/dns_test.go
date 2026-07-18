package dnscrypt

import (
	"strconv"
	"testing"
	dnscryptcrypto "zjdns/internal/dnscryptcrypto"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

func TestDNSize_UDP_DefaultMinMsgSize(t *testing.T) {
	req := new(dns.Msg)
	got := dnscryptcrypto.DNSSize("udp", req)
	if got != dns.MinMsgSize {
		t.Errorf("dnscryptcrypto.DNSSize(udp, no OPT) = %d, want %d (MinMsgSize)", got, dns.MinMsgSize)
	}
}

func TestDNSize_UDP_ExplicitUDPSize(t *testing.T) {
	req := new(dns.Msg)
	req.UDPSize = 1232
	got := dnscryptcrypto.DNSSize("udp", req)
	if got != 1232 {
		t.Errorf("dnscryptcrypto.DNSSize(udp, UDPSize=1232) = %d, want 1232", got)
	}
}

func TestDNSize_UDP_OPTInExtra(t *testing.T) {
	req := new(dns.Msg)
	req.UDPSize = 512
	opt := new(dns.OPT)
	opt.Hdr = dns.Header{Name: ".", Class: 4096}
	req.Extra = []dns.RR{opt}
	got := dnscryptcrypto.DNSSize("udp", req)
	if got != 4096 {
		t.Errorf("dnscryptcrypto.DNSSize(udp, OPT.Class=4096) = %d, want 4096", got)
	}
}

func TestDNSize_TCP_AlwaysMaxMsgSize(t *testing.T) {
	req := new(dns.Msg)
	req.UDPSize = 512
	got := dnscryptcrypto.DNSSize("tcp", req)
	if got != dns.MaxMsgSize {
		t.Errorf("dnscryptcrypto.DNSSize(tcp) = %d, want %d (MaxMsgSize)", got, dns.MaxMsgSize)
	}
}

// mkA is a shorthand for creating an A record via the zone parser.
func mkA(name string) dns.RR {
	rr, err := dns.New(name + " 300 IN A 1.2.3.4")
	if err != nil {
		panic(err)
	}
	return rr
}

// buildBulkResponse creates a packed response with n A records using unique
// names to defeat DNS name compression, ensuring the wire format is large.
func buildBulkResponse(n int) *dns.Msg {
	res := new(dns.Msg)
	for i := range n {
		name := "host" + strconv.Itoa(i) + ".example.com."
		res.Answer = append(res.Answer, mkA(name))
	}
	return res
}

func TestNormalize_UDP_Fits_NoTruncation(t *testing.T) {
	req := new(dns.Msg)
	req.UDPSize = 4096
	res := new(dns.Msg)
	res.Answer = []dns.RR{mkA("example.com.")}
	if err := res.Pack(); err != nil {
		t.Fatalf("Pack: %v", err)
	}

	dnscryptcrypto.Normalize("udp", req, res)

	if res.Truncated {
		t.Error("response should NOT be truncated when it fits in buffer")
	}
}

func TestNormalize_UDP_Exceeds_Truncates(t *testing.T) {
	req := new(dns.Msg)
	req.UDPSize = dns.MinMsgSize // 512
	res := buildBulkResponse(30) // 30 unique-host A records → well over 512
	if err := res.Pack(); err != nil {
		t.Fatalf("Pack: %v", err)
	}
	t.Logf("response size: %d bytes, limit: %d - %d = %d",
		res.Len(), dnscryptcrypto.DNSSize("udp", req), dnscryptcrypto.EDNSSize, dnscryptcrypto.DNSSize("udp", req)-dnscryptcrypto.EDNSSize)

	dnscryptcrypto.Normalize("udp", req, res)

	if !res.Truncated {
		t.Error("response SHOULD be truncated when exceeding buffer")
	}
	if len(res.Answer) != 0 {
		t.Errorf("truncated response should have 0 answer RRs, got %d", len(res.Answer))
	}
	if len(res.Ns) != 0 {
		t.Errorf("truncated response should have 0 authority RRs, got %d", len(res.Ns))
	}
	if len(res.Extra) != 0 {
		t.Errorf("truncated response should have 0 additional RRs, got %d", len(res.Extra))
	}
}

func TestNormalize_TCP_NeverTruncates(t *testing.T) {
	req := new(dns.Msg)
	req.UDPSize = dns.MinMsgSize
	res := buildBulkResponse(50)
	if err := res.Pack(); err != nil {
		t.Fatalf("Pack: %v", err)
	}

	dnscryptcrypto.Normalize("tcp", req, res)

	if res.Truncated {
		t.Error("TCP response should NEVER be truncated")
	}
	if len(res.Answer) == 0 {
		t.Error("TCP response should retain all answer RRs")
	}
}

func TestNormalize_UDP_SmallResponse_NoTruncation(t *testing.T) {
	req := new(dns.Msg)
	req.UDPSize = 512
	res := new(dns.Msg)
	res.Answer = []dns.RR{mkA("x.")}
	if err := res.Pack(); err != nil {
		t.Fatalf("Pack: %v", err)
	}

	dnscryptcrypto.Normalize("udp", req, res)

	if res.Truncated {
		t.Error("small response should NOT be truncated after EDNS overhead deduction")
	}
}

func TestNormalize_TruncatePreservesQuestion(t *testing.T) {
	req := new(dns.Msg)
	req.UDPSize = dns.MinMsgSize
	res := new(dns.Msg)
	dnsutil.SetQuestion(res, dnsutil.Fqdn("question.example.com"), dns.TypeA)
	res.Answer = buildBulkResponse(30).Answer
	if err := res.Pack(); err != nil {
		t.Fatalf("Pack: %v", err)
	}

	dnscryptcrypto.Normalize("udp", req, res)

	if len(res.Question) != 1 {
		t.Fatalf("question should be preserved after truncation, got %d", len(res.Question))
	}
	qname := res.Question[0].Header().Name
	if qname != "question.example.com." {
		t.Errorf("question name = %q, want question.example.com.", qname)
	}
}

func TestNormalize_TruncateRepackRoundTrip(t *testing.T) {
	// Verify that after normalize + Pack, the TC bit survives
	// a Pack/Unpack round-trip in wire format.
	req := new(dns.Msg)
	req.UDPSize = dns.MinMsgSize
	res := buildBulkResponse(30)

	dnscryptcrypto.Normalize("udp", req, res)

	if err := res.Pack(); err != nil {
		t.Fatalf("Pack after truncation: %v", err)
	}

	unpacked := new(dns.Msg)
	unpacked.Data = res.Data
	if err := unpacked.Unpack(); err != nil {
		t.Fatalf("Unpack after truncation: %v", err)
	}
	if !unpacked.Truncated {
		t.Error("TC bit should be set in wire format after truncation")
	}
}
