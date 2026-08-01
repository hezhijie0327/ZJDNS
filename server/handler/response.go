package handler

import (
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
		// Without SetReply the request's transaction ID is never copied and
		// the pooled (zeroed) message would be emitted with Id=0 — clients
		// correlate by ID and would discard the FORMERR.
		msg.ID = req.ID
		msg.Opcode = req.Opcode
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
	msg := BuildResponseMsg(req)
	// Restore the cached response's rcode — SetReply always leaves NOERROR,
	// so a cached NXDOMAIN would otherwise be served as NODATA.
	msg.Rcode = uint16(entry.Rcode) //nolint:gosec // G115: DNS rcode — protocol-bounded uint16

	if isExpired {
		responseTTL := entry.RemainingTTL()
		msg.Answer = cache.ProcessRecords(entry.Answer, int64(responseTTL), false, dnssecOK)
		msg.Ns = cache.ProcessRecords(entry.Authority, int64(responseTTL), false, dnssecOK)
		msg.Extra = cache.ProcessRecords(entry.Additional, int64(responseTTL), false, dnssecOK)
	} else {
		elapsed := ttl.Elapsed(entry.Timestamp)
		msg.Answer = cache.ProcessRecords(entry.Answer, elapsed, true, dnssecOK)
		msg.Ns = cache.ProcessRecords(entry.Authority, elapsed, true, dnssecOK)
		msg.Extra = cache.ProcessRecords(entry.Additional, elapsed, true, dnssecOK)
	}

	if entry.Validated {
		msg.AuthenticatedData = true
	}

	return msg
}
