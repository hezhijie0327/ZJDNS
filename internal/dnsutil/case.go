package dnsutil

import (
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// FoldCase lowercases every record owner name and the embedded rdata names
// in place.  An upstream may echo a CapsGuard-randomized (DNS 0x20) question
// case into record owners and rdata names (draft-vixie-dnsext-dns0x20-00
// §5.4); that random case must not leak to clients or into the cache.
// Lowercasing rdata names also lets a packed wire compress them against the
// canonical question — a mixed-case target misses the case-sensitive
// compression map and stays fully encoded, showing a different case than the
// owner on cache hits.
//
// The rdata name fields are covered type-agnostically via the presentation
// form (RFC 4343 §3): a whitespace-separated token ending in '.' and not
// quoted is a domain name, so folding it cannot touch data (TXT/URI/CAA
// values are always quoted).
func FoldCase(rrs []dns.RR) {
	for i, rr := range rrs {
		if rr == nil {
			continue
		}
		rrs[i] = foldCaseRR(rr)
	}
}

// foldCaseRR folds the owner and every embedded rdata name of an RR to
// lowercase.  Every RR type carrying rdata names in the miekg library gets a
// field-wise path: plain ASCII scans with zero allocations (RFC 4343 §3) —
// the previous approach serialised every record to presentation form
// (rr.String(), several allocations per RR) just to discover there was
// nothing to fold.  Any other type falls back to the type-agnostic
// presentation reparse, so future and exotic RR types keep full coverage.
//
// FoldCase's contract is "lowercase in place": the RR is uniquely owned by
// the caller (fresh per-query unpack, or a cache clone), so fields are
// mutated directly.
func foldCaseRR(rr dns.RR) dns.RR {
	rr.Header().Name = ASCIIFold(rr.Header().Name)
	switch v := rr.(type) {
	case *dns.A, *dns.AAAA, *dns.TXT, *dns.DS, *dns.DNSKEY, *dns.NSEC3, *dns.OPT,
		*dns.TLSA, *dns.SMIMEA, *dns.URI, *dns.CAA, *dns.SSHFP, *dns.HINFO,
		*dns.OPENPGPKEY, *dns.RFC3597, *dns.ANY, *dns.NID, *dns.L32, *dns.L64:
		// No rdata names — the owner fold above is the whole job.
	case *dns.SOA:
		v.Ns = ASCIIFold(v.Ns)
		v.Mbox = ASCIIFold(v.Mbox)
	case *dns.NS:
		v.Ns = ASCIIFold(v.Ns)
	case *dns.CNAME:
		v.Target = ASCIIFold(v.Target)
	case *dns.DNAME:
		v.Target = ASCIIFold(v.Target)
	case *dns.PTR:
		v.Ptr = ASCIIFold(v.Ptr)
	case *dns.MX:
		v.Mx = ASCIIFold(v.Mx)
	case *dns.SRV:
		v.Target = ASCIIFold(v.Target)
	case *dns.NAPTR:
		v.Replacement = ASCIIFold(v.Replacement)
	case *dns.KX:
		v.Exchanger = ASCIIFold(v.Exchanger)
	case *dns.AFSDB:
		v.Hostname = ASCIIFold(v.Hostname)
	case *dns.RT:
		v.Host = ASCIIFold(v.Host)
	case *dns.PX:
		v.Map822 = ASCIIFold(v.Map822)
		v.Mapx400 = ASCIIFold(v.Mapx400)
	case *dns.MINFO:
		v.Rmail = ASCIIFold(v.Rmail)
		v.Email = ASCIIFold(v.Email)
	case *dns.TALINK:
		v.PreviousName = ASCIIFold(v.PreviousName)
		v.NextName = ASCIIFold(v.NextName)
	case *dns.SVCB:
		v.Target = ASCIIFold(v.Target)
	case *dns.HTTPS:
		v.Target = ASCIIFold(v.Target)
	case *dns.NSEC:
		v.NextDomain = ASCIIFold(v.NextDomain)
	case *dns.RRSIG:
		v.SignerName = ASCIIFold(v.SignerName)
	case *dns.SIG:
		v.SignerName = ASCIIFold(v.SignerName)
	case *dns.HIP:
		for i, s := range v.RendezvousServers {
			v.RendezvousServers[i] = ASCIIFold(s)
		}
	default:
		// Unknown or exotic type — the presentation reparse covers every
		// name it carries, including ones this switch will grow for.
		return presentationFoldCase(rr)
	}
	return rr
}

// presentationFoldCase is the type-agnostic fallback: rebuild the record
// from its folded presentation form via the zone parser — the same
// self-describing grammar — so any RR type, including future ones, is
// covered without enumerating it above.  Returns the input unchanged when
// there is nothing to fold or the reparse fails (defensive — serve the
// original; the owner may already have been folded in place, which is its
// correct canonical form).
func presentationFoldCase(rr dns.RR) dns.RR {
	folded, changed := foldPresentationNames(rr.String())
	if !changed {
		return rr
	}
	zp := dns.NewZoneParser(strings.NewReader(folded), ".", "")
	parsed, ok := zp.Next()
	if !ok || zp.Err() != nil {
		return rr // defensive — serve the original
	}
	return parsed
}

// foldPresentationNames folds every unquoted whitespace-delimited token
// ending in '.' — the presentation-form shape of a domain name — while
// copying quoted segments verbatim (TXT/URI/CAA data; their interior may
// contain whitespace and '.'-terminated words that are not names).
//
// Two-pass: the common case (nothing to fold — lowercase owners, no
// mixed-case rdata names) returns after a pure scan with zero allocations;
// the Builder only runs when a fold is actually needed.  FoldCase sits on
// the per-response funnel of every upstream answer, so the scan-only fast
// path keeps the no-op cost at one presentation serialisation.
func foldPresentationNames(s string) (string, bool) {
	if !presentationNeedsFold(s) {
		return s, false
	}
	return foldPresentationNamesBuild(s)
}

// presentationNeedsFold reports whether any unquoted '.'-suffixed token in
// the presentation form carries an ASCII uppercase letter.
func presentationNeedsFold(s string) bool {
	for i := 0; i < len(s); {
		switch s[i] {
		case ' ', '\t':
			i++
		case '"':
			i++
			for i < len(s) {
				if s[i] == '\\' && i+1 < len(s) {
					i += 2
					continue
				}
				if s[i] == '"' {
					i++
					break
				}
				i++
			}
		default:
			start := i
			for i < len(s) && s[i] != ' ' && s[i] != '\t' && s[i] != '"' {
				i++
			}
			tok := s[start:i]
			if strings.HasSuffix(tok, ".") && ASCIIFold(tok) != tok {
				return true
			}
		}
	}
	return false
}

func foldPresentationNamesBuild(s string) (string, bool) {
	var b strings.Builder
	changed := true // caller verified a fold exists
	for i := 0; i < len(s); {
		if s[i] == ' ' || s[i] == '\t' {
			b.WriteByte(s[i])
			i++
			continue
		}
		if s[i] == '"' {
			b.WriteByte('"')
			i++
			for i < len(s) {
				if s[i] == '\\' && i+1 < len(s) {
					b.WriteByte(s[i])
					b.WriteByte(s[i+1])
					i += 2
					continue
				}
				b.WriteByte(s[i])
				if s[i] == '"' {
					i++
					break
				}
				i++
			}
			continue
		}
		start := i
		for i < len(s) && s[i] != ' ' && s[i] != '\t' && s[i] != '"' {
			i++
		}
		tok := s[start:i]
		if strings.HasSuffix(tok, ".") {
			if low := ASCIIFold(tok); low != tok {
				tok = low
				changed = true
			}
		}
		b.WriteString(tok)
	}
	return b.String(), changed
}

// Canonical lowercases the ASCII letters of an FQDN (RFC 4343 §3 fold),
// appending the trailing dot when missing.  Drop-in replacement for miekg
// dnsutil.Canonical on hot paths: that one is a strings.Map closure which
// allocates even for an already-canonical name, while this scans first and
// returns the input unchanged (zero-alloc) when nothing needs folding.
func Canonical(s string) string {
	if !dnsutil.IsFqdn(s) {
		s += "."
	}
	return ASCIIFold(s)
}

// ASCIIFold lowercases only ASCII letters — RFC 4343 §3 folds exactly the
// 0x20 bit of A-Z; non-ASCII bytes are case-sensitive in DNS and must stay
// untouched.  Returns the input unchanged (no allocation) when there is
// nothing to fold.
func ASCIIFold(name string) string {
	needsFold := false
	for i := 0; i < len(name); i++ {
		if name[i] >= 'A' && name[i] <= 'Z' {
			needsFold = true
			break
		}
	}
	if !needsFold {
		return name
	}
	b := []byte(name)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 0x20
		}
	}
	return string(b)
}
