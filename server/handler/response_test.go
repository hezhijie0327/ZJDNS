package handler

import (
	"net/netip"
	"testing"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/internal/pool"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// newCachedEntry stores a canonical A response and returns the entry Get()
// hands to the serve path.
func newCachedEntry(t *testing.T, store cache.Store, name string, ttl uint32) *cache.Entry {
	t.Helper()
	store.Set(name, dns.TypeA, dns.ClassINET, nil, []dns.RR{&dns.A{
		Hdr:  dns.Header{Name: name, Class: dns.ClassINET, TTL: ttl},
		Addr: netip.MustParseAddr("192.0.2.1"),
	}}, nil, nil, false, 0)
	entry, found, _ := store.Get(name, dns.TypeA, dns.ClassINET, nil)
	if !found {
		t.Fatalf("cache entry for %s not found", name)
	}
	return entry
}

// unpackedQuestion unpacks a pre-packed response and returns its question
// name (case included).
func unpackedQuestion(t *testing.T, msg *dns.Msg) string {
	t.Helper()
	defer pool.DefaultMessage.Put(msg)
	got := new(dns.Msg)
	got.Data = msg.Data
	if err := got.Unpack(); err != nil {
		t.Fatalf("unpack pre-packed response: %v", err)
	}
	if len(got.Question) == 0 {
		t.Fatal("response has no question section")
	}
	return got.Question[0].Header().Name
}

func TestBuildCacheEntryResponse_EchoesClientCase(t *testing.T) {
	store := cache.New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	entry := newCachedEntry(t, store, "www.example.com.", 300)

	req := new(dns.Msg)
	dnsutil.SetQuestion(req, "wWw.ExAmPle.CoM.", dns.TypeA, dns.ClassINET)

	msg := BuildCacheEntryResponse(req, entry, false, false)
	if got := unpackedQuestion(t, msg); got != "wWw.ExAmPle.CoM." {
		t.Fatalf("fresh hit echoes %q, want client case %q", got, "wWw.ExAmPle.CoM.")
	}
}

func TestBuildCacheEntryResponse_StaleEchoesClientCase(t *testing.T) {
	store := cache.New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	entry := newCachedEntry(t, store, "www.example.com.", 300)

	req := new(dns.Msg)
	dnsutil.SetQuestion(req, "wWw.ExAmPle.CoM.", dns.TypeA, dns.ClassINET)

	msg := BuildCacheEntryResponse(req, entry, false, true)
	if got := unpackedQuestion(t, msg); got != "wWw.ExAmPle.CoM." {
		t.Fatalf("stale hit echoes %q, want client case %q", got, "wWw.ExAmPle.CoM.")
	}
}

func TestBuildCacheEntryResponse_NilReqServesCanonical(t *testing.T) {
	store := cache.New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	entry := newCachedEntry(t, store, "www.example.com.", 300)

	msg := BuildCacheEntryResponse(nil, entry, false, false)
	if got := unpackedQuestion(t, msg); got != "www.example.com." {
		t.Fatalf("nil req serves %q, want canonical %q", got, "www.example.com.")
	}
}

func TestBuildCacheEntryResponse_EmptyQuestionServesCanonical(t *testing.T) {
	store := cache.New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	entry := newCachedEntry(t, store, "www.example.com.", 300)

	msg := BuildCacheEntryResponse(new(dns.Msg), entry, false, false)
	if got := unpackedQuestion(t, msg); got != "www.example.com." {
		t.Fatalf("empty question serves %q, want canonical %q", got, "www.example.com.")
	}
}

func TestBuildCacheEntryResponse_DigitsLabel(t *testing.T) {
	// Digit labels are non-letter bytes that must byte-match the stored
	// canonical name; letters still adopt the client case.
	store := cache.New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	entry := newCachedEntry(t, store, "www.example.123.com.", 300)

	req := new(dns.Msg)
	dnsutil.SetQuestion(req, "wWw.ExAmPle.123.CoM.", dns.TypeA, dns.ClassINET)

	msg := BuildCacheEntryResponse(req, entry, false, false)
	if got := unpackedQuestion(t, msg); got != "wWw.ExAmPle.123.CoM." {
		t.Fatalf("digit-label name echoes %q, want client case %q", got, "wWw.ExAmPle.123.CoM.")
	}
}

func TestBuildCacheEntryResponse_RootServesCanonical(t *testing.T) {
	store := cache.New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	entry := newCachedEntry(t, store, ".", 300)

	msg := BuildCacheEntryResponse(new(dns.Msg), entry, false, false)
	if got := unpackedQuestion(t, msg); got != "." {
		t.Fatalf("root name serves %q, want canonical %q", got, ".")
	}
}

func TestBuildCacheEntryResponse_MismatchedCaseLengthServesCanonical(t *testing.T) {
	// A defensive case: a request whose packed question does not match the
	// stored wire's question length must leave the wire untouched (never
	// corrupt the response) — the canonical name is served.
	store := cache.New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	entry := newCachedEntry(t, store, "www.example.com.", 300)

	req := new(dns.Msg)
	dnsutil.SetQuestion(req, "www.other-example.com.", dns.TypeA, dns.ClassINET)

	msg := BuildCacheEntryResponse(req, entry, false, false)
	if got := unpackedQuestion(t, msg); got != "www.example.com." {
		t.Fatalf("length-mismatched question serves %q, want stored canonical %q", got, "www.example.com.")
	}
}
