package middleware

import (
	"context"
	"encoding/binary"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/log"
	"zjdns/server/handler"
	"zjdns/server/resolver"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// MQTYPE implements RFC 10029 server-side MQTYPE-Query handling: a client may
// request additional RR types alongside the primary question via the
// MQTYPE-Query EDNS option (20); the server merges the responses for each
// additional type into a single reply and reports the completed types in the
// MQTYPE-Response option (21).
//
// The middleware runs after CacheStore (the primary response exists) but
// before Response (EDNS finalisation).  The merge is local in every mode
// (forwarding included) — each QTx resolves through the server's own
// upstreams, so the response supports MQTYPE regardless of upstream
// support.  The option is never passed through.
type MQTYPE struct {
	store    cache.Store
	resolver handler.Resolver
	pending  *handler.PendingRequests
}

type mqtypeError string

// mqtypeEDNSOverhead is the worst-case EDNS/MQTYPE-Response option overhead
// reserved in the merge budget so the post-merge wire cannot exceed the
// client's UDP size (RFC 10029 §3.4).
const mqtypeEDNSOverhead = 64

var (
	errMQTypeOpcode      = mqtypeError("MQTYPE-Query with non-QUERY opcode")
	errMQTypeNoQuestion  = mqtypeError("MQTYPE-Query without a question")
	errMQTypeEmpty       = mqtypeError("MQTYPE-Query with empty type list")
	errMQTypePrimaryMeta = mqtypeError("MQTYPE-Query with non-data primary type")
	errMQTypeMeta        = mqtypeError("MQTYPE-Query with a Meta/QTYPE in the list")
	errMQTypeDuplicate   = mqtypeError("MQTYPE-Query with duplicate type")
)

func (e mqtypeError) Error() string { return string(e) }

// Wrap implements Wrapper.
func (m *MQTYPE) Wrap(next handler.QueryHandler) handler.QueryHandler {
	return handler.QueryHandlerFunc(func(ctx context.Context, qctx *handler.QueryContext) error {
		mqQuery, hasMQ, invalid := findMQQUERY(qctx.Req.Pseudo)
		// RFC 10029 §3.3: a second MQTYPE-Query or an inbound
		// MQTYPE-Response → FORMERR, without resolving.
		if invalid {
			log.Debugf("MQTYPE: rejecting invalid MQTYPE option: mq=%v", mqQuery)
			msg := handler.BuildResponseMsg(qctx.Req)
			msg.Rcode = dns.RcodeFormatError
			qctx.Res = msg
			return nil
		}
		if !hasMQ {
			return next.ServeDNS(ctx, qctx)
		}
		if qerr := m.validate(qctx, mqQuery); qerr != nil {
			log.Debugf("MQTYPE: rejecting invalid MQTYPE-Query: %v", qerr)
			msg := handler.BuildResponseMsg(qctx.Req)
			msg.Rcode = dns.RcodeFormatError
			qctx.Res = msg
			return nil
		}

		err := next.ServeDNS(ctx, qctx)
		if qctx.Res == nil {
			return err
		}

		// Merge locally in every mode — forwarding too.  ZJDNS is a full
		// resolver: each QTx is resolved through its own upstreams
		// (m.resolver.Query), so the response supports MQTYPE even when
		// no hop in the chain does.  The option is never passed through.
		m.merge(qctx, mqQuery)
		return err
	})
}

// validate applies RFC 10029 §3.3: the server MUST return FORMERR for
// malformed MQTYPE-Query options.
func (m *MQTYPE) validate(qctx *handler.QueryContext, mq *dns.MQQUERY) error {
	if qctx.Req.Opcode != dns.OpcodeQuery {
		return errMQTypeOpcode
	}
	if len(qctx.Req.Question) == 0 {
		return errMQTypeNoQuestion
	}
	if len(mq.Types) == 0 {
		return errMQTypeEmpty
	}
	primary := dns.RRToType(qctx.Req.Question[0])
	if _, meta := config.MQTypeMetaTypes[primary]; meta {
		return errMQTypePrimaryMeta
	}
	seen := make(map[uint16]struct{}, len(mq.Types)+1)
	seen[primary] = struct{}{}
	for _, qt := range mq.Types {
		if _, meta := config.MQTypeMetaTypes[qt]; meta {
			return errMQTypeMeta
		}
		if _, dup := seen[qt]; dup {
			return errMQTypeDuplicate
		}
		seen[qt] = struct{}{}
	}
	return nil
}

// merge resolves each additional QTYPE (cache first, then singleflight
// resolution) and combines the RRsets into the primary response per
// RFC 10029 §3.4: same RCODE/flags, deduplicated RRs, size-capped.
func (m *MQTYPE) merge(qctx *handler.QueryContext, mq *dns.MQQUERY) {
	msg := qctx.Res
	if msg.Data != nil {
		// Cache-hit primary responses are pre-packed: Data carries the full
		// wire and the RR sections are nil.  Unpack so the merged RRs and the
		// MQTYPE-Response option are added to real sections — the outer
		// Response middleware would otherwise Unpack the wire later and
		// rebuild the sections from it, silently discarding the merge.
		// This also makes msg.Len() report the true primary size for the
		// merge budget below.
		if err := msg.Unpack(); err != nil {
			log.Debugf("MQTYPE: unpack pre-packed primary response: %v", err)
			return
		}
		msg.ID = qctx.Req.ID
		msg.RecursionDesired = qctx.Req.RecursionDesired
		// Filter DNSSEC proofs for DO=0 clients, mirroring the Response
		// middleware's unpack path.
		if !qctx.ClientRequestedDNSSEC {
			msg.Answer = cache.ProcessRecords(msg.Answer, 0, false, false)
			msg.Ns = cache.ProcessRecords(msg.Ns, 0, false, false)
			msg.Extra = cache.ProcessRecords(msg.Extra, 0, false, false)
		}
		msg.Data = nil
	}

	// RFC 10029 §3.4: a truncated primary response MUST NOT be extended —
	// the additional queries are not processed.  The MQTYPE-Response option
	// is still returned (empty list) to signal support.
	if msg.Truncated {
		log.Debugf("MQTYPE: primary response truncated — skipping additional types for %s", qctx.Req.Question[0].Header().Name)
		msg.Pseudo = append(msg.Pseudo, &dns.MQRESPONSE{})
		return
	}

	qd := qctx.Req.Question[0]
	qname := qd.Header().Name
	qclass := qd.Header().Class
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
	for _, qt := range types {
		// The merge runs after the primary response is built — the request
		// ctx may already be near its deadline or cancelled (client
		// disconnect, timeout).  A QTx fallback must be a fresh query:
		// detach from the request lifecycle, bounded only by its own
		// timeout (RFC 10029 §4 amplification bound).
		qtCtx, qtCancel := context.WithTimeout(context.Background(), config.DefaultMQTypeResolveTimeout)
		qr := m.resolve(qtCtx, qname, qt, qclass, ecsOpt, dnssecOK)
		qtCancel()
		if qr == nil || qr.Err != nil {
			log.Debugf("MQTYPE: skipping %s %s — resolution failed", qname, dns.TypeToString[qt])
			continue
		}
		// §3.4: mismatching RCODE or flags — the additional response MUST
		// NOT be included.
		if qr.Rcode != primaryRcode || qr.Validated != primaryAD || qr.Authoritative != primaryAA {
			log.Debugf("MQTYPE: skipping %s %s — RCODE/flags mismatch (rcode=%d validated=%t aa=%t)", qname, dns.TypeToString[qt], qr.Rcode, qr.Validated, qr.Authoritative)
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
			log.Debugf("MQTYPE: skipping %s %s — response size budget exceeded", qname, dns.TypeToString[qt])
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
			mergeAnswer = cache.ProcessRecords(qr.Answer, 0, false, false)
			mergeNs = cache.ProcessRecords(qr.Authority, 0, false, false)
			mergeExtra = cache.ProcessRecords(qr.Additional, 0, false, false)
		}
		msg.Answer = mergeRRs(msg.Answer, mergeAnswer)
		msg.Ns = mergeRRs(msg.Ns, mergeNs)
		msg.Extra = mergeRRs(msg.Extra, mergeExtra)
		completed = append(completed, qt)

		// Cache the additional response so future requests (including
		// CacheLookup for the same QTYPE) hit the warm cache.  Bogus
		// validation results are never cached (see dnssecCacheable).
		if qr.Cacheable && dnssecCacheable(qr.Validated, qr.DNSSECEDE) {
			m.store.Set(qname, qt, qclass, ecsOpt, qr.Answer, qr.Authority, qr.Additional, qr.Validated, qr.Rcode)
		}
	}

	if len(completed) > 0 || len(mq.Types) > 0 {
		// §3.4: the MQTYPE-Response option MUST be returned (even with an
		// empty list) to signal support.
		msg.Pseudo = append(msg.Pseudo, &dns.MQRESPONSE{Types: completed})
	}
	log.Debugf("MQTYPE: merged %d/%d types for %s", len(completed), len(types), qname)
}

// resolve performs the secondary lookup for one QTYPE: cache first, then
// singleflight resolution — the same pattern as the DNS64 middleware.  Each
// QTx is bounded by DefaultMQTypeResolveTimeout so a merge cannot blow the
// request budget through amplification (RFC 10029 §4).
func (m *MQTYPE) resolve(ctx context.Context, qname string, qt, qclass uint16, ecsOpt *edns.ECSOption, dnssecOK bool) *resolver.QueryResult {
	// Canonicalize: cache.Get requires the canonical qname (Set stores it) —
	// the merge entry passes the raw wire name, which can carry mixed case
	// (regression of the removed internal canonicalization).
	qname = dnsutil.Canonical(qname)
	if m.store != nil {
		// Skip expired entries: merging a stale answer with the full stored
		// TTL would serve data past its freshness window without the
		// stale-answer EDE the CacheLookup path applies (M-cache).
		if entry, found, isExpired := m.store.Get(qname, qt, qclass, ecsOpt); found && !isExpired {
			if entry.Unpack() == nil {
				cache.ReleaseTTLOffsets(entry.TTLOffsets)
				return &resolver.QueryResult{
					Answer: entry.Answer, Authority: entry.Authority, Additional: entry.Additional,
					Validated: entry.Validated, Rcode: entryRcode(entry), Authoritative: entryAuthoritative(entry),
					Cacheable: true,
				}
			}
			// Unpack failed — the entry is dropped; still return the
			// pool-owned TTL-offset slice (audit M-pool).
			cache.ReleaseTTLOffsets(entry.TTLOffsets)
		}
	}
	query := func() *resolver.QueryResult {
		return m.resolver.Query(ctx, handler.Question{Name: qname, Qtype: qt, Qclass: qclass}, ecsOpt)
	}
	if m.pending != nil {
		return m.pending.DoJoin(qname, qt, qclass, ecsOpt, dnssecOK, query)
	}
	return query()
}

// findMQQUERY returns the single MQTYPE-Query option from Pseudo.  present
// reports whether a MQTYPE-Query exists at all; invalid reports a second
// MQTYPE-Query or an inbound MQTYPE-Response — both are RFC 10029 §3.3
// FORMERR conditions and the caller must not proceed.
func findMQQUERY(pseudo []dns.RR) (mq *dns.MQQUERY, present, invalid bool) {
	for _, rr := range pseudo {
		switch opt := rr.(type) {
		case *dns.MQQUERY:
			if mq != nil {
				invalid = true // more than one MQTYPE-Query
			}
			mq = opt
		case *dns.MQRESPONSE:
			invalid = true // MQTYPE-Response in an inbound message
		}
	}
	return mq, mq != nil, invalid
}

// mergeRRs appends src RRs that are not already present in dst (RFC 10029
// §3.4: keep only a single copy of each RR).
func mergeRRs(dst, src []dns.RR) []dns.RR {
	if len(src) == 0 {
		return dst
	}
	for _, rr := range src {
		dup := false
		for _, existing := range dst {
			if existing == rr || equalRR(existing, rr) {
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

// equalRR compares two RRs by presentation form — wire-equivalent records
// (e.g. the SOA shared by multiple NODATA answers) merge to one copy.
func equalRR(a, b dns.RR) bool {
	return a.String() == b.String()
}

// entryAuthoritative reads the AA flag from a pre-packed entry's wire header
// (bit 2 of the flags byte) — the cached wire preserves the AA of the
// response as received, needed for the RFC 10029 §3.4 flag match.
func entryAuthoritative(entry *cache.Entry) bool {
	wire := entry.ResponseWire
	return len(wire) >= 4 && wire[2]&0x04 != 0
}

// entryRcode extracts the rcode from a pre-packed entry's wire header,
// including extended rcodes (>= 16): the low 4 bits live in the header flags
// byte, the extended bits in the OPT record's TTL high byte (RFC 6891
// §6.1.3).  Reading only the low nibble misclassified e.g. BADVERS (16) as
// NOERROR, breaking the RFC 10029 §3.4 RCODE-match check.
func entryRcode(entry *cache.Entry) uint16 {
	wire := entry.ResponseWire
	if len(wire) < 4 {
		return 0
	}
	rcode := uint16(wire[3] & 0x0F) //nolint:gosec // G115: DNS rcode — protocol-bounded byte
	// Scan the wire for the OPT record.  The cached wire's question section
	// is uncompressed (canonical qname built by Set), so a plain label walk
	// finds its end.
	pos := dns.MsgHeaderSize
	for pos < len(wire) {
		l := int(wire[pos])
		if l == 0 {
			pos += 1 + 4 // root label + QTYPE(2) + QCLASS(2)
			break
		}
		if l&0xC0 == 0xC0 {
			return rcode // compression pointer in the question — not the cache format
		}
		pos += l + 1
	}
	for pos+11 <= len(wire) {
		off := pos
		// Name: labels or a compression pointer.
		for off < len(wire) {
			b := wire[off]
			if b&0xC0 == 0xC0 {
				off += 2
				break
			}
			if b == 0 {
				off++
				break
			}
			off += int(b) + 1
		}
		if off+10 > len(wire) {
			break
		}
		typ := binary.BigEndian.Uint16(wire[off:])
		if typ == dns.TypeOPT {
			rcode |= uint16(wire[off+4]) << 4 // OPT TTL byte 0 = extended rcode (RFC 6891 §6.1.3)
			return rcode
		}
		pos = off + 10 + int(binary.BigEndian.Uint16(wire[off+8:]))
	}
	return rcode
}
