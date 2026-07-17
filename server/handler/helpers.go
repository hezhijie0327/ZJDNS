package handler

import (
	"net"
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
	msg := pool.DefaultMessagePool.Get()

	if req != nil && len(req.Question) > 0 {
		dnsutil.SetReply(msg, req)
	} else if req != nil {
		msg.Response = true
		msg.Rcode = dns.RcodeFormatError
	}

	msg.Authoritative = false
	msg.RecursionAvailable = true
	return msg
}

// buildCacheEntryResponse builds a DNS response from a cache entry, applying
// TTL deduction for fresh entries or cyclical stale-TTL for expired entries.
// When isExpired is true, the caller should set qctx.EDE after calling.
func BuildCacheEntryResponse(req *dns.Msg, entry *cache.Entry, dnssecOK, isExpired bool) *dns.Msg {
	msg := BuildResponseMsg(req)

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

// copyIP returns a deep copy of ip, allocating a new backing array.
func CopyIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	return append(net.IP(nil), ip...)
}
