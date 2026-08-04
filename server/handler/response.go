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
// a dns.Msg with Data already populated — bridge.go skips packSafe() for such
// messages and serves the wire directly.
func buildFromPrePacked(entry *cache.Entry, isExpired bool) *dns.Msg {
	// Copy the wire so the cached entry is not mutated.
	wire := make([]byte, len(entry.ResponseWire))
	copy(wire, entry.ResponseWire)

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

	msg := pool.DefaultMessage.Get()
	msg.Data = wire
	msg.Response = true
	msg.Authoritative = false
	msg.RecursionAvailable = true

	if entry.Validated {
		msg.AuthenticatedData = true
	}

	return msg
}
