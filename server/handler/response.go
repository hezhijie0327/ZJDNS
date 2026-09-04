package handler

import (
	"encoding/binary"
	"zjdns/cache"
	zdnsutil "zjdns/internal/dnsutil"
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
	return buildFromPrePacked(req, entry, isExpired)
}

// buildFromPrePacked adjusts TTLs in the pre-packed response wire, restores
// the client's original question case, and returns a dns.Msg with Data
// already populated — the Response middleware serves the wire directly when
// no EDNS modification is needed (bridge.go then skips packSafe for such
// messages).
func buildFromPrePacked(req *dns.Msg, entry *cache.Entry, isExpired bool) *dns.Msg {
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

	// Echo the client's original 0x20 question case: the stored wire's
	// question was canonicalized at Set() time, and a response must copy the
	// question byte-for-byte (draft-vixie-dnsext-dns0x20-00 §5.2).  A case
	// flip never changes the wire length (RFC 4343 §3), so this is a
	// same-length in-place patch — TTL offsets above stay valid.
	patchQuestionCase(wire, req)

	// The TTL offsets are no longer needed — return them to the pool.
	entry.ReleaseOffsets()

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

// UnpackPrePackedForModify unpacks a pre-packed response (Data populated by
// BuildCacheEntryResponse) into its RR sections so middleware can modify it:
// patches in the client's message ID and RD bit (the cached wire carries the
// values from Set() time), filters DNSSEC proofs for DO=0 clients (RFC 3225
// §4.4), and clears Data so the response is re-packed on the way out.
// Returns false when the wire cannot be unpacked — the caller serves
// SERVFAIL or skips its modification.
func UnpackPrePackedForModify(qctx *QueryContext) bool {
	msg := qctx.Res
	if err := msg.Unpack(); err != nil {
		return false
	}
	msg.ID = qctx.Req.ID
	msg.RecursionDesired = qctx.Req.RecursionDesired
	if !qctx.ClientRequestedDNSSEC {
		msg.Answer = zdnsutil.ProcessRecords(msg.Answer, 0, false, false)
		msg.Ns = zdnsutil.ProcessRecords(msg.Ns, 0, false, false)
		msg.Extra = zdnsutil.ProcessRecords(msg.Extra, 0, false, false)
	}
	msg.Data = nil
	return true
}

// patchQuestionCase overwrites the question name bytes of a pre-packed
// response wire with the client's original case.  The cached wire stores the
// canonical (lowercased) qname from Set() — echoing it would strip the
// client's 0x20 randomization (draft-vixie-dnsext-dns0x20-00 §5.2: the
// response MUST copy the question bit for bit).
//
// The question section is the first name in the message (offset 12, never a
// compression pointer).  The client name (unpack output: FQDN, only '.' is
// escaped as \.) is walked in lockstep with the wire QNAME — label-length
// bytes are skipped — copying every byte: ASCII letters adopt the client's
// case, non-letters must byte-match the stored canonical (0x20 flips only
// letters, RFC 4343 §3, so they are identical otherwise).  Zero allocations:
// this runs on the cache-hit hot path whose direct-wire serve promises
// 0 B/op.  Any inconsistency (nil request, missing question, unparseable
// wire, name mismatch) aborts the patch and the canonical name is served.
func patchQuestionCase(wire []byte, req *dns.Msg) {
	if req == nil || len(req.Question) == 0 || len(wire) < 12 {
		return
	}
	nameEnd, ok := zdnsutil.SkipWireName(wire, 12)
	if !ok {
		return
	}

	name := req.Question[0].Header().Name

	// Single pass with a stack backup: the QNAME is patched in place, so a
	// mismatch mid-walk would leave partially written bytes — snapshot the
	// QNAME and restore it on failure (rare) instead of walking twice.  A
	// wire-format name is at most 255 octets (RFC 1035 §2.3.4), so the
	// stack array always fits; a longer wire (impossible for a valid name)
	// simply skips the restore and is served as patched.
	var backup [255]byte
	qlen := nameEnd - 12
	if qlen <= len(backup) {
		copy(backup[:], wire[12:nameEnd])
	}
	if !walkQuestionCase(wire, name, nameEnd) && qlen <= len(backup) {
		copy(wire[12:nameEnd], backup[:qlen])
	}
}

// walkQuestionCase walks name (unpack output: FQDN, only '.' is escaped as
// \.) in lockstep with the wire QNAME at offset 12 — label-length bytes are
// skipped — copying every byte: ASCII letters adopt the client's case,
// non-letter bytes must byte-match the stored canonical name (a mismatch
// means the names are not case variants).  Returns false when the name does
// not map onto the wire QNAME (length/label mismatch, non-FQDN, malformed
// escape); the caller restores its snapshot on failure.
//
// Zero allocations: this runs on the cache-hit hot path whose direct-wire
// serve promises 0 B/op.
func walkQuestionCase(wire []byte, name string, nameEnd int) bool {
	wi := 12 // QNAME starts at the header end (first label-length byte)
	for si := 0; si < len(name); {
		// At a label start the wire byte is the label length (or the
		// terminating 0x00 for the root — nothing to patch).
		if wi >= nameEnd || wire[wi] == 0 {
			return false
		}
		wi++ // skip the label length byte
		for si < len(name) && name[si] != '.' {
			c := name[si]
			si++
			if c == '\\' {
				// Escaped dot (\.) from unpack — a literal '.' inside the
				// label.  Note: miekg's Pack does not parse these escapes,
				// so a name with an escaped dot is stored with a WRONG wire
				// QNAME by Set() — the length check below then fails and the
				// canonical name is served (this branch is a correctness
				// defense, not a path real cache entries reach).
				if si >= len(name) || name[si] != '.' || wi >= nameEnd {
					return false
				}
				c = '.'
				si++
			}
			if wi >= nameEnd {
				return false
			}
			if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' {
				// ASCII letter: adopt the client's case.
				wire[wi] = c
			} else if wire[wi] != c {
				// Non-letter: must match the stored canonical name.
				return false
			}
			wi++
		}
		if si == len(name) {
			// Not an FQDN (unpack always produces one) — reject defensively.
			return false
		}
		si++ // consume the '.'
		// The wire byte after a label is the next label's length — or the
		// root's terminating 0x00, consumed here so the walk ends exactly
		// at nameEnd.
		if si == len(name) {
			if wi >= nameEnd || wire[wi] != 0 {
				return false
			}
			wi++
		}
	}
	return wi == nameEnd
}
