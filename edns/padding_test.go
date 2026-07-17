package edns

import (
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

func TestHasPaddingOption_NoPseudo_LegacyClient(t *testing.T) {
	req := &dns.Msg{}
	if !HasPaddingOption(req) {
		t.Error("legacy client (no EDNS) should default to padding")
	}
}

func TestHasPaddingOption_WithPadding(t *testing.T) {
	req := &dns.Msg{
		Pseudo: []dns.RR{&dns.PADDING{Padding: "00"}},
	}
	if !HasPaddingOption(req) {
		t.Error("client with PADDING option should be padded")
	}
}

func TestHasPaddingOption_WithoutPadding(t *testing.T) {
	req := &dns.Msg{
		Pseudo: []dns.RR{&dns.EDE{InfoCode: dns.ExtendedErrorBlocked}},
	}
	if HasPaddingOption(req) {
		t.Error("client with EDNS but no PADDING opted out — should NOT pad")
	}
}

// paddedMsg creates a message with a non-empty Pseudo section, simulating
// the production path where ECS/Cookie/EDE options are already present so
// the OPT record overhead is already accounted for in the initial Pack().
func paddedMsg(qname string) *dns.Msg {
	msg := new(dns.Msg)
	_ = dnsutil.SetQuestion(msg, qname, dns.TypeA)
	msg.Pseudo = append(msg.Pseudo, &dns.EDE{InfoCode: dns.ExtendedErrorOther})
	return msg
}

func TestAddPadding_NotSecure(t *testing.T) {
	msg := paddedMsg("example.com.")
	n := addPadding(msg, false, 128, true)
	if n != 0 {
		t.Errorf("insecure connection should not add padding, got %d bytes", n)
	}
}

func TestAddPadding_ClientOptOut(t *testing.T) {
	msg := paddedMsg("example.com.")
	n := addPadding(msg, true, 128, false)
	if n != 0 {
		t.Errorf("client opted out of padding, got %d bytes", n)
	}
}

func TestAddPadding_Secure_AddsPadding(t *testing.T) {
	msg := paddedMsg("example.com.")
	n := addPadding(msg, true, 128, true)
	if n == 0 {
		t.Error("secure connection with padding enabled should add padding")
	}

	hasPadding := false
	for _, o := range msg.Pseudo {
		if p, ok := o.(*dns.PADDING); ok && p.Padding != "" {
			hasPadding = true
			break
		}
	}
	if !hasPadding {
		t.Error("no PADDING pseudo-record found after addPadding")
	}

	_ = msg.Pack()
	if len(msg.Data)%128 != 0 {
		t.Errorf("repacked wire length %d not aligned to 128-byte block", len(msg.Data))
	}
}

func TestAddPadding_BlockAlignment(t *testing.T) {
	for _, blockSize := range []int{64, 128, 256, 512} {
		msg := paddedMsg("example.com.")

		addPadding(msg, true, blockSize, true)
		_ = msg.Pack()

		if len(msg.Data)%blockSize != 0 {
			t.Errorf("block=%d: repacked wire length %d not aligned", blockSize, len(msg.Data))
		}
	}
}

func TestAddPadding_PaddingBytesAreRandom(t *testing.T) {
	msg1 := paddedMsg("example.com.")
	addPadding(msg1, true, 128, true)

	msg2 := paddedMsg("example.com.")
	addPadding(msg2, true, 128, true)

	var p1, p2 string
	for _, o := range msg1.Pseudo {
		if p, ok := o.(*dns.PADDING); ok {
			p1 = p.Padding
		}
	}
	for _, o := range msg2.Pseudo {
		if p, ok := o.(*dns.PADDING); ok {
			p2 = p.Padding
		}
	}

	if p1 == "" || p2 == "" {
		t.Fatal("padding not found in message")
	}
	if p1 == p2 {
		t.Error("padding bytes should be random — two calls produced identical padding")
	}
}
