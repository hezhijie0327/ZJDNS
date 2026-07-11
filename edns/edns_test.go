package edns

import (
	"testing"
	"zjdns/config"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

func TestApplyToMessage_Keepalive(t *testing.T) {
	h, _ := NewHandler(config.ECSConfig{})
	msg := new(dns.Msg)
	dnsutil.SetQuestion(msg, "example.com.", dns.TypeA)

	// tcpKeepaliveTimeout=0 -> no keepalive option in response
	h.ApplyToMessage(msg, nil, false, "", nil, false, true, 0)
	for _, o := range msg.Pseudo {
		if _, ok := o.(*dns.TCPKEEPALIVE); ok {
			t.Error("unexpected keepalive option with timeout=0")
		}
	}

	// tcpKeepaliveTimeout=1200 -> keepalive option present in response
	msg2 := new(dns.Msg)
	dnsutil.SetQuestion(msg2, "example.com.", dns.TypeA)
	h.ApplyToMessage(msg2, nil, false, "", nil, false, true, 1200)
	var found bool
	for _, o := range msg2.Pseudo {
		if ka, ok := o.(*dns.TCPKEEPALIVE); ok {
			found = true
			if ka.Timeout != 1200 {
				t.Errorf("expected timeout=1200, got %d", ka.Timeout)
			}
		}
	}
	if !found {
		t.Error("expected keepalive option with timeout=1200")
	}

	// tcpKeepaliveTimeout=1200 but isRequest=true -> no keepalive (client-side)
	msg3 := new(dns.Msg)
	dnsutil.SetQuestion(msg3, "example.com.", dns.TypeA)
	h.ApplyToMessage(msg3, nil, false, "", nil, true, true, 1200)
	for _, o := range msg3.Pseudo {
		if _, ok := o.(*dns.TCPKEEPALIVE); ok {
			t.Error("keepalive should not be included in requests")
		}
	}
}

func TestBuildCookieResponse(t *testing.T) {
	client := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	server := []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20}

	result := BuildCookieResponse(client, server)
	if result == "" {
		t.Error("BuildCookieResponse should not return empty")
	}

	resultInvalid := BuildCookieResponse([]byte{0, 0}, server)
	if resultInvalid != "" {
		t.Error("BuildCookieResponse should return empty for invalid client cookie")
	}
}
