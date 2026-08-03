package cache

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
)

// ── Key codec ──────────────────────────────────────────────────────────────

func TestCodec_KeyRoundTrip(t *testing.T) {
	c := cacheCodec{}
	keys := []entryKey{
		{qname: "example.com.", qtype: dns.TypeA, qclass: 1},
		{qname: "ecs.com.", ecsAddr: "198.51.100.0", ecsPrefix: 24, dnssecOK: true, qtype: 1, qclass: 1},
		{qname: "v6.com.", ecsAddr: "2001:db8::", ecsPrefix: 56, dnssecOK: true, qtype: 28, qclass: 1},
		{qname: "aaaa.com.", qtype: 28, qclass: 3},
	}
	for _, want := range keys {
		got, err := c.DecodeKey(c.EncodeKey(want))
		if err != nil {
			t.Errorf("DecodeKey(%+v): %v", want, err)
			continue
		}
		if got != want {
			t.Errorf("round trip = %+v, want %+v", got, want)
		}
	}
}

func TestCodec_KeyTruncated_ReturnsError(t *testing.T) {
	c := cacheCodec{}
	if _, err := c.DecodeKey([]byte{0, 0, 0, 5, 'a'}); err == nil {
		t.Error("truncated key: want error, got nil")
	}
}

// ── Value codec ─────────────────────────────────────────────────────────────

func TestCodec_ValueRoundTrip(t *testing.T) {
	c := cacheCodec{}
	values := []cacheEntry{
		{value: []byte("wire-data"), ts: 100, expiresAt: log.NowUnix() + 3600, validated: true},
		{value: []byte{0xde, 0xad, 0xbe, 0xef}, expiresAt: 0},
	}
	for _, want := range values {
		got, include, err := c.DecodeValue(c.EncodeValue(want))
		if err != nil {
			t.Errorf("DecodeValue(%+v): %v", want, err)
			continue
		}
		if !include {
			t.Errorf("entry %+v should be included", want)
		}
		if !bytes.Equal(got.value, want.value) || got.expiresAt != want.expiresAt || got.validated != want.validated {
			t.Errorf("round trip = %+v, want %+v", got, want)
		}
	}
}

func TestCodec_ValueLarge(t *testing.T) {
	// 64KB — beyond uint16 length, exercises the u32 writer.
	c := cacheCodec{}
	big := make([]byte, 64<<10)
	for i := range big {
		big[i] = byte(i)
	}
	want := cacheEntry{value: big, expiresAt: log.NowUnix() + 3600, validated: true}
	got, include, err := c.DecodeValue(c.EncodeValue(want))
	if err != nil {
		t.Fatal(err)
	}
	if !include || !bytes.Equal(got.value, big) {
		t.Fatal("large value round trip failed")
	}
}

func TestCodec_ValueExpired_Skipped(t *testing.T) {
	c := cacheCodec{}
	e := cacheEntry{value: []byte("x"), expiresAt: log.NowUnix() - 1}
	_, include, err := c.DecodeValue(c.EncodeValue(e))
	if err != nil {
		t.Fatal(err)
	}
	if include {
		t.Error("expired entry should be skipped on load")
	}
}

func TestCodec_ValueTruncated_ReturnsError(t *testing.T) {
	c := cacheCodec{}
	if _, _, err := c.DecodeValue([]byte{0, 0, 0, 5, 'a'}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("truncated value: want ErrUnexpectedEOF, got %v", err)
	}
}
