package handler

import (
	"encoding/binary"
	"zjdns/cache"
	"zjdns/internal/pool"
	"zjdns/internal/ttl"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// BuildResponseMsg creates a basic DNS response message from a request.
// It sets the QR bit, copies the question section, and fills in
// Authoritative=false and RecursionAvailable=true.
func BuildResponseMsg(req *dns.Msg) *dns.Msg {
	msg := pool.DefaultMessage.Get()

	switch {
	case req != nil && len(req.Question) > 0:
		dnsutil.SetReply(msg, req)
	case req != nil:
		msg.Response = true
		msg.Rcode = dns.RcodeFormatError
	default:
		msg.Response = true
	}

	msg.Authoritative = false
	msg.RecursionAvailable = true
	return msg
}

// BuildCacheEntryResponse builds a DNS response from a cache entry, applying
// TTL deduction for fresh entries or cyclical stale-TTL for expired entries.
// When isExpired is true, the caller should set qctx.EDE after calling.
func BuildCacheEntryResponse(req *dns.Msg, entry *cache.Entry, dnssecOK, isExpired bool) *dns.Msg {
	return buildFromPrePacked(entry, isExpired)
}

// buildFromPrePacked adjusts TTLs in the pre-packed response wire and returns
// a dns.Msg with Data already populated — the Response middleware serves the
// wire directly when no EDNS modification is needed (bridge.go then skips
// packSafe for such messages).
func buildFromPrePacked(entry *cache.Entry, isExpired bool) *dns.Msg {
	// The entry is per-Get memory (never shared or re-read after this call) —
	// adjust TTLs in place instead of copying the wire.
	wire := entry.ResponseWire

	// Apply TTL deduction.
	if isExpired {
		staleTTL := entry.RemainingTTL()
		for _, off := range entry.TTLOffsets {
			binary.BigEndian.PutUint32(wire[off:], staleTTL)
		}
	} else {
		elapsed := ttl.Elapsed(entry.Timestamp)
		if elapsed > 0 {
			for _, off := range entry.TTLOffsets {
				oldTTL := int64(binary.BigEndian.Uint32(wire[off:]))
				newTTL := uint32(max(oldTTL-elapsed, 0)) //nolint:gosec // G115: DNS TTL subtraction, protocol-bounded uint32
				binary.BigEndian.PutUint32(wire[off:], newTTL)
			}
		}
	}
	// The TTL offsets are no longer needed — return them to the pool.
	cache.ReleaseTTLOffsets(entry.TTLOffsets)

	msg := pool.DefaultMessage.Get()
	msg.Data = wire
	msg.Response = true
	msg.Authoritative = false
	msg.RecursionAvailable = true

	// The pre-packed wire is served verbatim, so the msg fields are never
	// Unpacked.  Sync the rcode from the wire header (byte 3, low nibble)
	// so code reading msg.Rcode — the stats journal groups by it — sees the
	// cached entry's real rcode (negative-cache NXDOMAIN → 3) instead of 0.
	// Extended EDNS rcodes (>= 16) do not occur in cached responses.
	msg.Rcode = uint16(wire[3] & 0x0F) //nolint:gosec // G115: rcode < 16, wire format bounded

	if entry.Validated {
		msg.AuthenticatedData = true
	}

	return msg
}
