package middleware

import (
	"strings"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/server/handler"
	"zjdns/server/resolver"

	"codeberg.org/miekg/dns"
)

// This file implements the RFC 10029 §3.4 merge: combining additional-QTYPE
// RRsets into the primary response with RCODE/flag matching, wire-size
// budgeting, RR deduplication and cache warm-up.  The chain-facing policy
// (FORMERR validation, QTx prefetch) lives in mqtype.go.

// merge resolves each additional QTYPE (cache first, then singleflight
// resolution) and combines the RRsets into the primary response per
// RFC 10029 §3.4: same RCODE/flags, deduplicated RRs, size-capped.
func (m *MQTYPE) merge(qctx *handler.QueryContext, mq *dns.MQQUERY, qtResults <-chan qtResult) {
	msg := qctx.Res
	if msg.Data != nil {
		// Cache-hit primary responses are pre-packed: Data carries the full
		// wire and the RR sections are nil.  Unpack so the merged RRs and the
		// MQTYPE-Response option are added to real sections — the outer
		// Response middleware would otherwise Unpack the wire later and
		// rebuild the sections from it, silently discarding the merge.
		// This also makes msg.Len() report the true primary size for the
		// merge budget below.
		if !handler.UnpackPrePackedForModify(qctx) {
			if log.IsDebug() {
				log.Debugf("MQTYPE: unpack pre-packed primary response failed")
			}
			return
		}
	}

	// RFC 10029 §3.4: a truncated primary response MUST NOT be extended —
	// the additional queries are not processed.  The MQTYPE-Response option
	// is still returned (empty list) to signal support.
	if msg.Truncated {
		if log.IsDebug() {
			log.Debugf("MQTYPE: primary response truncated — skipping additional types for %s", qctx.Req.Question[0].Header().Name)
		}
		msg.Pseudo = append(msg.Pseudo, &dns.MQRESPONSE{})
		return
	}

	qname := qctx.Qname
	qclass := qctx.Qclass
	ecsOpt := qctx.ECSOpt
	dnssecOK := qctx.ClientRequestedDNSSEC
	primaryRcode := msg.Rcode

	// §3.4: RCODE and flags are determined by the primary response.  The AA
	// bit is included — a zone-rule primary (authoritative, RFC 9606) must
	// not merge recursively-resolved (AA=0) additional data, the RFC's own
	// NS/DS-at-a-zone-cut example.
	primaryAD := msg.AuthenticatedData
	primaryAA := msg.Authoritative

	// Budget for merged RRs: the remaining space below the client's
	// advertised UDP size (RFC 2181 §9 clamp, matching bridge.go's
	// truncation point), minus the primary response size and EDNS overhead.
	// Merging against the server-side cap alone could push the wire past
	// the client's limit and trigger a post-merge truncation that destroys
	// the merged RRsets (§3.4: MQTYPE handling MUST NOT itself cause TC).
	udpSize := min(max(qctx.Req.UDPSize, dns.MinMsgSize), config.DefaultMaxUDPResponseSize)
	budget := int(udpSize) - msg.Len() - mqtypeEDNSOverhead

	// §4 / §3.4: the fixed QTx cap bounds the amplification factor — the
	// server MAY stop processing further combinations, and unprocessed
	// types are simply absent from the MQTYPE-Response list.
	types := mq.Types
	if len(types) > config.DefaultMQTypeMaxQTx {
		types = types[:config.DefaultMQTypeMaxQTx]
	}
	completed := make([]uint16, 0, len(types))
	// Drain the prefetched QTx results (started before the primary — see
	// Wrap); the channel is buffered to the QTx count, so every prefetch
	// goroutine completes regardless of how far the merge gets.
	qtMap := make(map[uint16]*resolver.QueryResult, len(types))
	for range types {
		r := <-qtResults
		qtMap[r.qt] = r.qr
	}
	for _, qt := range types {
		qr := qtMap[qt]
		if qr == nil || qr.Err != nil {
			if log.IsDebug() {
				log.Debugf("MQTYPE: skipping %s %s — resolution failed", qname, dns.TypeToString[qt])
			}
			continue
		}
		// §3.4: mismatching RCODE or flags — the additional response MUST
		// NOT be included.
		if qr.Rcode != primaryRcode || qr.Validated != primaryAD || qr.Authoritative != primaryAA {
			if log.IsDebug() {
				log.Debugf("MQTYPE: skipping %s %s — RCODE/flags mismatch (rcode=%d validated=%t aa=%t)", qname, dns.TypeToString[qt], qr.Rcode, qr.Validated, qr.Authoritative)
			}
			continue
		}

		// Estimate the added wire size before merging.
		added := 0
		for _, rr := range qr.Answer {
			added += rr.Len()
		}
		for _, rr := range qr.Authority {
			added += rr.Len()
		}
		for _, rr := range qr.Additional {
			added += rr.Len()
		}
		if added > budget {
			if log.IsDebug() {
				log.Debugf("MQTYPE: skipping %s %s — response size budget exceeded", qname, dns.TypeToString[qt])
			}
			continue
		}
		budget -= added

		// §3.4: merge into the same sections a standalone query would use,
		// deduplicating RRs.
		// RFC 3225 §4.4 / §3.5: a DO=0 client must not receive DNSSEC
		// proofs — the additional RRsets are filtered exactly like the
		// primary (mirroring the unpack path above).  The unfiltered
		// originals still go to the cache below (raw records are stored
		// under both DO keys; filtering happens at serve time).
		mergeAnswer, mergeNs, mergeExtra := qr.Answer, qr.Authority, qr.Additional
		if !dnssecOK {
			mergeAnswer = zdnsutil.ProcessRecords(qr.Answer, 0, false, false)
			mergeNs = zdnsutil.ProcessRecords(qr.Authority, 0, false, false)
			mergeExtra = zdnsutil.ProcessRecords(qr.Additional, 0, false, false)
		}
		msg.Answer = mergeRRs(msg.Answer, mergeAnswer)
		msg.Ns = mergeRRs(msg.Ns, mergeNs)
		msg.Extra = mergeRRs(msg.Extra, mergeExtra)
		completed = append(completed, qt)

		// Cache the additional response so future requests (including
		// CacheLookup for the same QTYPE) hit the warm cache (single
		// cacheability gate, RFC 4035 §5.3.3 TTL cap included).
		handler.StoreIfCacheable(m.store, qname, qt, qclass, ecsOpt, qr)
	}

	if len(completed) > 0 || len(mq.Types) > 0 {
		// §3.4: the MQTYPE-Response option MUST be returned (even with an
		// empty list) to signal support.
		msg.Pseudo = append(msg.Pseudo, &dns.MQRESPONSE{Types: completed})
	}
	if log.IsDebug() {
		log.Debugf("MQTYPE: merged %d/%d types for %s", len(completed), len(types), qname)
	}
}

// mergeRRs appends src RRs that are not already present in dst (RFC 10029
// §3.4: keep only a single copy of each RR).
func mergeRRs(dst, src []dns.RR) []dns.RR {
	if len(src) == 0 {
		return dst
	}
	// Precompute each src RR's folded rdata once — the dup check must not
	// format both RRs (rr.String() allocates) for every (existing, candidate)
	// pair (H-L4).
	keys := make([]string, len(src))
	for i, rr := range src {
		if rr != nil {
			keys[i] = foldRRData(rr)
		}
	}
	for i, rr := range src {
		if rr == nil {
			continue
		}
		dup := false
		for _, existing := range dst {
			if existing == rr || (existing != nil &&
				dns.RRToType(existing) == dns.RRToType(rr) &&
				existing.Header().Class == rr.Header().Class &&
				dns.EqualName(existing.Header().Name, rr.Header().Name) &&
				foldRRData(existing) == keys[i]) {
				dup = true
				break
			}
		}
		if !dup {
			dst = append(dst, rr)
		}
	}
	return dst
}

// foldRRData returns the RR's rdata presentation form (TTL excluded) with
// embedded domain names folded to lowercase: whitespace-separated tokens
// ending in '.' are FQDN names and get ASCII-folded, everything else stays
// byte-exact (TXT content, addresses, numbers).  RFC 4343 §3 folds only
// ASCII letters, so a literal name is always distinguishable.
func foldRRData(rr dns.RR) string {
	fields := strings.Fields(rr.String())
	if len(fields) < 5 { // "owner TTL class type rdata"
		return rr.String()
	}
	rdata := fields[4:]
	for i, tok := range rdata {
		if strings.HasSuffix(tok, ".") {
			rdata[i] = strings.ToLower(tok)
		}
	}
	return strings.Join(rdata, " ")
}
