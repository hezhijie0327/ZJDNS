// The DNSCrypt certificate handshake (RFC/TBD dnscrypt protocol): parsing
// client queries, selecting the active cert, and building the encrypted
// response.

package dnscrypt

import (
	"errors"
	"fmt"
	"time"
	"zjdns/config"
	dnscryptcrypto "zjdns/internal/dnscryptcrypto"
	"zjdns/internal/log"
	"zjdns/internal/pool"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

func (s *Server) handleHandshake(b []byte, isUDP bool) (res []byte, err error) {
	m := pool.DefaultMessage.Get()
	defer func() {
		if m != nil {
			pool.DefaultMessage.Put(m)
		}
	}()
	m.Data = b
	err = m.Unpack()
	if err != nil {
		return nil, fmt.Errorf("unpacking handshake message: %w", err)
	}

	if len(m.Question) != 1 || m.Response {
		return nil, dnscryptcrypto.ErrInvalidQuery
	}

	q := m.Question[0]
	providerName := dnsutil.Fqdn(s.providerName)

	qName := dnsutil.Fqdn(q.Header().Name)
	if dns.RRToType(q) != dns.TypeTXT || qName != providerName {
		// Only the configured provider's TXT query is answered.  Everything
		// else is REFUSED explicitly, never silently dropped: a drop leaves
		// the client waiting out its own timeout (a perceived hang), while
		// an explicit REFUSED fails the fetch in one RTT.
		refused := pool.DefaultMessage.Get()
		dnsutil.SetReply(refused, m)
		refused.Rcode = dns.RcodeRefused
		// RA=1 like the cert path: this server is a recursive resolver, the
		// REFUSED is policy, not lack of recursion.  AA stays 0 — a refusal is
		// not an authoritative answer for the queried name.
		refused.RecursionAvailable = true
		if packErr := refused.Pack(); packErr != nil {
			pool.DefaultMessage.Put(refused)
			return nil, fmt.Errorf("packing refused handshake response: %w", packErr)
		}
		// Same copy discipline as the success path (M14): res must not alias
		// refused.Data — the pool zeroes it on Put.
		res = make([]byte, len(refused.Data))
		copy(res, refused.Data)
		pool.DefaultMessage.Put(refused)
		log.Debugf("DNSCRYPT: refusing non-cert query %s (qtype=%s)", qName, dns.TypeToString[dns.RRToType(q)])
		return res, nil
	}

	// Serve only the newest window's certificates (ref: serve_certificates
	// picks the cert with the highest ts_end).  Older windows remain in
	// s.keys only for decrypting client queries that still use them.
	s.mu.RLock()
	if len(s.keys) == 0 {
		s.mu.RUnlock()
		return nil, errors.New("dnscrypt: no active key pair")
	}
	newest := s.keys[0]
	s.mu.RUnlock()

	// Static TTL: the renewal interval (ref: DNSCRYPT_CERTS_RENEWAL).  The
	// cert's NotAfter is up to 24h away, so clients re-fetch well before the
	// certificate expires.
	ttl := uint32(config.DefaultDNSCryptCertificateRenewal / time.Second)

	// The PQ cert (~1.3 KB) is included over UDP only when the response fits
	// within the client query size (§10.3 anti-amplification); over TCP it is
	// always included.  When omitted, set TC so the PQ-capable client retries
	// over TCP.  The classical cert is always included.
	classicalTXT := newest.classicalTXT
	pqTXT := newest.pqTXT

	pqFits := true
	if isUDP {
		// Pack a temporary classical-only response to measure the wire size.
		// Use m (still alive — not yet returned to the pool) for SetReply.
		tmp := pool.DefaultMessage.Get()
		dnsutil.SetReply(tmp, m)
		tmp.Answer = append(tmp.Answer, &dns.TXT{
			Hdr: dns.Header{
				Name:  q.Header().Name,
				TTL:   ttl,
				Class: dns.ClassINET,
			},
			Txt: classicalTXT,
		})
		tmp.Authoritative = true
		tmp.RecursionAvailable = true
		if packErr := tmp.Pack(); packErr != nil {
			pool.DefaultMessage.Put(tmp)
			return nil, fmt.Errorf("packing handshake response: %w", packErr)
		}
		baseSize := len(tmp.Data)
		pool.DefaultMessage.Put(tmp)
		pqFits = baseSize+newest.pqWireSize <= len(b)
	}

	// Build the actual reply.
	reply := pool.DefaultMessage.Get()
	dnsutil.SetReply(reply, m)
	pool.DefaultMessage.Put(m)
	m = nil // prevent defer from double-Put

	reply.Answer = append(reply.Answer, &dns.TXT{
		Hdr: dns.Header{
			Name:  q.Header().Name,
			TTL:   ttl,
			Class: dns.ClassINET,
		},
		Txt: classicalTXT,
	})
	if pqFits {
		reply.Answer = append(reply.Answer, &dns.TXT{
			Hdr: dns.Header{
				Name:  q.Header().Name,
				TTL:   ttl,
				Class: dns.ClassINET,
			},
			Txt: pqTXT,
		})
	}

	reply.Authoritative = true
	reply.RecursionAvailable = true

	if !pqFits {
		reply.Truncated = true
	}

	log.Debugf("DNSCRYPT: handshake response — 1 cert window (%d TXT records, TC=%v)%s",
		len(reply.Answer), reply.Truncated, map[bool]string{true: " (UDP)", false: ""}[isUDP])

	err = reply.Pack()
	if err != nil {
		pool.DefaultMessage.Put(reply)
		return nil, fmt.Errorf("packing handshake response: %w", err)
	}
	// NOTE(M14): res must be a copy of reply.Data, not an alias.  After
	// pool.DefaultMessage.Put(reply), reply.Data's backing memory is zeroed
	// and available for reuse by another goroutine.
	res = make([]byte, len(reply.Data))
	copy(res, reply.Data)
	pool.DefaultMessage.Put(reply)
	return res, nil
}
