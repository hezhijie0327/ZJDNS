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
// lowercase by rebuilding it via the zone parser — the same self-describing
// grammar — so any RR type, including future ones, is covered without a
// per-type field table.  Returns the input unchanged when there is nothing
// to fold.
func foldCaseRR(rr dns.RR) dns.RR {
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
