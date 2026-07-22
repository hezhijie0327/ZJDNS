// Package defense — UDP tail selection. In polluted networks, GFW-injected
// fakes arrive before the real server response on the same socket.
// LastResponse picks the chronologically last response; CollectAndVote
// provides majority-consensus voting for multi-source scenarios.
// Both strategies use semantic equivalence (ignoring TTL, RR order, and
// EDNS padding).
package defense

import (
	"encoding/binary"
	"hash/fnv"
	"sort"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// rdataKey is a (name, type, rdata) triple used for semantic equivalence
// comparison. Name is canonicalised (lowercase, FQDN). Rdata is the
// wire-format string of the record data.
type rdataKey struct {
	name  string
	rtype uint16
	rdata string
}

// semanticHash returns a hash of the DNS response that is stable across
// TTL changes, RR ordering, and EDNS padding. Two responses that differ
// only in TTL, RR order, or EDNS padding produce the same hash.
//
// Only the Answer section is hashed — Authority and Additional sections
// carry delegation/glue data whose ordering can vary legitimately.
// Rcode and the AA flag are included because they affect the semantic
// meaning of the response.
func semanticHash(msg *dns.Msg) uint64 {
	h := fnv.New64a()

	// Rcode + AA flag.
	var buf [8]byte
	binary.BigEndian.PutUint16(buf[:2], msg.Rcode)
	_, _ = h.Write(buf[:2])
	var flags [1]byte
	if msg.Authoritative {
		flags[0] = 1
	}
	_, _ = h.Write(flags[:])

	// Extract and sort answer records by (name, type, rdata).
	keys := make([]rdataKey, len(msg.Answer))
	for i, rr := range msg.Answer {
		keys[i] = rdataKey{
			name:  dnsutil.Canonical(rr.Header().Name),
			rtype: dns.RRToType(rr),
			rdata: rdataString(rr),
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].name != keys[j].name {
			return keys[i].name < keys[j].name
		}
		if keys[i].rtype != keys[j].rtype {
			return keys[i].rtype < keys[j].rtype
		}
		return keys[i].rdata < keys[j].rdata
	})

	for _, k := range keys {
		_, _ = h.Write([]byte(k.name))
		binary.BigEndian.PutUint16(buf[:2], k.rtype)
		_, _ = h.Write(buf[:2])
		_, _ = h.Write([]byte(k.rdata))
	}

	return h.Sum64()
}

// rdataString returns a stable string representation of an RR's rdata
// excluding TTL, for semantic equivalence comparison under TTL variation.
func rdataString(rr dns.RR) string {
	// Use the rdata portion only, dropping TTL and header fields.
	// dns.RR.String() includes TTL which breaks TTL-agnostic comparison.
	// We extract the rdata by taking everything after the 4th tab-separated
	// field (name, TTL, class, type → rdata follows).
	s := rr.String()
	for i, tabs := 0, 0; i < len(s); i++ {
		if s[i] == '\t' {
			tabs++
			if tabs == 4 {
				return s[i+1:]
			}
		}
	}
	return s // fallback: shouldn't happen for valid RRs
}

// DrainResponseChan reads all available messages from ch without blocking.
func DrainResponseChan(ch chan *dns.Msg) []*dns.Msg {
	var responses []*dns.Msg
	for {
		select {
		case resp := <-ch:
			if resp != nil {
				responses = append(responses, resp)
			}
		default:
			return responses
		}
	}
}

// CollectAndVote groups responses by semantic hash and returns the
// earliest response from the group that reaches the threshold. Returns
// nil if no group meets the threshold.
func CollectAndVote(responses []*dns.Msg, threshold int) *dns.Msg {
	if len(responses) == 0 {
		return nil
	}
	if threshold <= 1 {
		return responses[0] // threshold=1: first response wins (no voting needed)
	}

	type group struct {
		first *dns.Msg
		count int
	}
	groups := make(map[uint64]*group)

	for _, resp := range responses {
		h := semanticHash(resp)
		if g, ok := groups[h]; ok {
			g.count++
		} else {
			groups[h] = &group{first: resp, count: 1}
		}
	}

	for _, g := range groups {
		if g.count >= threshold {
			return g.first
		}
	}
	return nil // no majority
}

// LastResponse returns the last (chronologically latest) response from the
// slice. In polluted networks, GFW-injected fakes arrive before real server
// responses on the same UDP socket, so the tail of the response stream is
// more trustworthy than the head. Returns nil if the slice is empty.
func LastResponse(responses []*dns.Msg) *dns.Msg {
	if len(responses) == 0 {
		return nil
	}
	return responses[len(responses)-1]
}
