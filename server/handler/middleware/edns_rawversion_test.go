package middleware

import (
	"context"
	"encoding/binary"
	"testing"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/server/handler"

	"codeberg.org/miekg/dns"
)

// rawQuery builds a wire query with full header control — the same shape an
// 8906-style conformance probe sends.
func rawQuery(id, flags, qtype uint16, name string, optRR []byte) []byte {
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], id)
	binary.BigEndian.PutUint16(hdr[2:4], flags)
	binary.BigEndian.PutUint16(hdr[4:6], 1)
	body := []byte{}
	for _, label := range []string{"example", "com"} {
		body = append(body, byte(len(label))) //nolint:gosec // G115: label length fits a byte by construction
		body = append(body, label...)
	}
	body = append(body, 0)
	body = binary.BigEndian.AppendUint16(body, qtype)
	body = binary.BigEndian.AppendUint16(body, 1)
	if optRR != nil {
		body = append(body, optRR...)
		binary.BigEndian.PutUint16(hdr[10:12], 1) // ARCOUNT
	}
	return append(append(make([]byte, 0, len(hdr)+len(body)), hdr...), body...) //nolint:makezero // test builder: hdr is fully written before this append
}

// optRRWire builds an OPT pseudo-record: bufsize in CLASS, version in TTL
// bits 23-16 (RFC 6891 §6.1.3).
func optRRWire(bufsize uint16, version uint8) []byte {
	rr := []byte{0}
	rr = binary.BigEndian.AppendUint16(rr, 41)
	rr = binary.BigEndian.AppendUint16(rr, bufsize)
	rr = binary.BigEndian.AppendUint32(rr, uint32(version)<<16)
	return binary.BigEndian.AppendUint16(rr, 0)
}

// TestEDNSMiddleware_RawVersionBADVERS pins the RFC 6891 §6.1.3 / RFC 8906
// §3.2.2 requirement end to end on the wire form: an OPT carrying version > 0
// must yield BADVERS.  The version arrives folded into the unpacked message
// (Pseudo holds only the OPT's options — empty here — so the pipeline's
// EnsureFullUnpack re-unpack must not lose it).
func TestEDNSMiddleware_RawVersionBADVERS(t *testing.T) {
	ednsH, err := edns.NewHandler(config.ECSConfig{})
	if err != nil {
		t.Fatal(err)
	}
	m := &EDNS{edns: ednsH}
	h := m.Wrap(handler.QueryHandlerFunc(func(_ context.Context, qctx *handler.QueryContext) error {
		t.Fatalf("version>0 must short-circuit, reached next handler (qtype=%d)", dns.RRToType(qctx.Req.Question[0]))
		return nil
	}))

	for _, v := range []uint8{1, 127} {
		raw := rawQuery(0x42, 0x0100, 1, "example.com", optRRWire(512, v))
		req := new(dns.Msg)
		req.Data = append(req.Data[:0], raw...)
		if err := req.Unpack(); err != nil {
			t.Fatalf("v=%d: unpack: %v", v, err)
		}
		if req.Version != v {
			t.Fatalf("v=%d: unpack produced Version=%d", v, req.Version)
		}
		// The pipeline re-unpacks when Pseudo is empty — mirror it.
		if err := handler.EnsureFullUnpack(req); err != nil {
			t.Fatalf("v=%d: ensure unpack: %v", v, err)
		}
		if req.Version != v {
			t.Fatalf("v=%d: EnsureFullUnpack lost Version (now %d)", v, req.Version)
		}
		qctx := (&handler.QueryContext{Req: req}).InitQuestion()
		if err := h.ServeDNS(context.Background(), qctx); err != nil {
			t.Fatalf("v=%d: serve: %v", v, err)
		}
		if qctx.Res == nil || qctx.Res.Rcode != dns.RcodeBadVers {
			got := "nil"
			if qctx.Res != nil {
				got = dns.RcodeToString[qctx.Res.Rcode]
			}
			t.Fatalf("v=%d: rcode=%s, want BADVERS", v, got)
		}
	}
}
