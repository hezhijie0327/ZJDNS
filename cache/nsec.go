package cache

import (
	"encoding/binary"
	"slices"
	"strings"
	"zjdns/config"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"

	zdnsutil "zjdns/internal/dnsutil"
)

// NsecResult is the outcome of an aggressive NSEC negative cache lookup.
type NsecResult struct {
	Rcode int      // dns.RcodeSuccess for NODATA, dns.RcodeNameError for NXDOMAIN
	Types []uint16 // type bitmap from matching NSEC (for NODATA: proves qtype absent)
}

// toWireName converts a presentation-format domain name to TLD-first wire
// format (labels reversed, root-terminated). Byte comparison on this encoding
// matches DNS canonical order (RFC 4034 §6.1).
func toWireName(name string) []byte {
	s := toLower(name)
	if s != "" && s[len(s)-1] == '.' {
		s = s[:len(s)-1]
	}
	if s == "" {
		return []byte{0}
	}
	labels := splitLabels(s)
	buf := make([]byte, 0, len(s)+2)
	for i := len(labels) - 1; i >= 0; i-- {
		buf = append(buf, byte(len(labels[i]))) //nolint:gosec // G115: DNS label length — protocol-bounded to 63
		buf = append(buf, labels[i]...)
	}
	buf = append(buf, 0)
	return buf
}

func splitLabels(name string) []string {
	if name == "" {
		return nil
	}
	labels := make([]string, 0, 4)
	start := 0
	for i := range len(name) {
		if name[i] == '.' {
			labels = append(labels, name[start:i])
			start = i + 1
		}
	}
	if start < len(name) {
		labels = append(labels, name[start:])
	}
	return labels
}

func toLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// IndexNsecRecords extracts NSEC/NSEC3 records from a validated response and
// indexes them into nsec_chain.
func (s *SQLiteCache) IndexNsecRecords(qname string, qtype, qclass uint16, ecs *config.ECSOption, dnssecOK, validated bool, authority []dns.RR) {
	if s.db.IsClosed() {
		return
	}
	if !validated {
		return
	}

	zoneWire := toWireName(qname)
	for _, rr := range authority {
		if soa, ok := rr.(*dns.SOA); ok {
			zoneWire = toWireName(soa.Header().Name)
			break
		}
	}

	ecsAddr, ecsPrefix := ecsParams(ecs)
	dnssec := zdnsutil.BoolToInt(dnssecOK)
	entryID := s.db.EnsureEntry(qname, int(qtype), int(qclass), ecsAddr, ecsPrefix, dnssec)

	for _, rr := range authority {
		if rec, ok := rr.(*dns.NSEC); ok {
			s.indexNsec(entryID, zoneWire, rec)
		}
	}
}

func (s *SQLiteCache) indexNsec(entryID int64, zoneWire []byte, nsec *dns.NSEC) {
	ownerWire := toWireName(nsec.Header().Name)
	nextWire := toWireName(nsec.NextDomain)
	types := marshalTypeBitmap(nsec.TypeBitMap)
	if _, err := s.db.StmtNsecInsert.Exec(zoneWire, ownerWire, nextWire, types, entryID); err != nil {
		log.Debugf("NSEC: insert failed for %s: %v", nsec.Header().Name, err)
	}
}

// LookupNsecNeg checks whether a query is covered by an NSEC/NSEC3 record
// in the negative cache. Returns nil if no covering record is found.
func (s *SQLiteCache) LookupNsecNeg(qname string, qtype uint16) *NsecResult {
	if s.db.IsClosed() {
		return nil
	}

	for zone := qname; zone != "."; zone = parentName(zone) {
		// NSEC records from zone Z only prove non-existence of direct
		// children of Z (exactly 1 label deeper). Skip zones where the
		// qname is deeper — e.g. edu.cn NSEC records cannot prove
		// non-existence of mirrors.cernet.edu.cn (a grandchild).
		if labelDepth(qname)-labelDepth(zone) > 1 {
			continue
		}
		rows, err := s.db.StmtNsecLookup.Query(toWireName(zone))
		if err != nil {
			return nil
		}

		var bestOwner, bestNext []byte
		var bestTypes []uint16
		for rows.Next() {
			var ownerWire, nextWire, typeBuf []byte
			if err := rows.Scan(&ownerWire, &nextWire, &typeBuf); err != nil {
				continue
			}
			ownerName := wireToName(ownerWire)
			if dnameCanonicalCompare(ownerName, qname) <= 0 &&
				(bestOwner == nil || dnameCanonicalCompare(wireToName(bestOwner), ownerName) < 0) {
				bestOwner = ownerWire
				bestNext = nextWire
				bestTypes = unmarshalTypeBitmap(typeBuf)
			}
		}
		_ = rows.Close()

		if bestOwner != nil {
			bestOwnerName := wireToName(bestOwner)
			if strings.EqualFold(bestOwnerName, qname) {
				if !slices.Contains(bestTypes, qtype) {
					return &NsecResult{Rcode: dns.RcodeSuccess, Types: bestTypes}
				}
			} else {
				bestNextName := wireToName(bestNext)
				// NXDOMAIN if qname falls strictly between owner and next (canonical order).
				// Handle wrap-around: if next <= owner, the interval wraps.
				wrapped := dnameCanonicalCompare(bestNextName, bestOwnerName) <= 0
				covered := dnameCanonicalCompare(qname, bestNextName) < 0
				if wrapped {
					covered = dnameCanonicalCompare(qname, bestNextName) < 0 ||
						dnameCanonicalCompare(bestOwnerName, qname) < 0
				}
				if covered {
					return &NsecResult{Rcode: dns.RcodeNameError}
				}
			}
		}
	}
	return nil
}

// wireToName converts TLD-first wire-format bytes back to normal (presentation)
// order, so that wireToName(toWireName(x)) == x.
func wireToName(wire []byte) string {
	var labels []string
	pos := 0
	for pos < len(wire)-1 {
		l := int(wire[pos])
		if l == 0 {
			break
		}
		labels = append(labels, string(wire[pos+1:pos+1+l]))
		pos += 1 + l
	}
	// Reverse labels: wire is TLD-first, presentation is TLD-last.
	var s string
	for i := len(labels) - 1; i >= 0; i-- {
		if s != "" {
			s += "."
		}
		s += labels[i]
	}
	if s != "" {
		s += "."
	}
	return s
}

// parentName strips the leftmost label from a domain name.
func parentName(name string) string {
	n := toLower(name)
	n = strings.TrimSuffix(n, ".")
	dot := strings.IndexByte(n, '.')
	if dot < 0 {
		return "."
	}
	return n[dot+1:] + "."
}

// labelDepth returns the number of labels in a domain name.
// "." returns 0, "cn." returns 1, "cernet.edu.cn." returns 3.
func labelDepth(name string) int {
	s := toLower(name)
	if s == "." || s == "" {
		return 0
	}
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return 0
	}
	return strings.Count(s, ".") + 1
}

// dnameCanonicalCompare compares two domain names in DNS canonical order
// (RFC 4034 §6.1): labels compared right-to-left, case-insensitively,
// shorter names sort before longer names with the same suffix.
func dnameCanonicalCompare(a, b string) int {
	a = toLower(a)
	b = toLower(b)
	a = strings.TrimSuffix(a, ".")
	b = strings.TrimSuffix(b, ".")
	if a == b {
		return 0
	}
	aLabels := splitLabels(a)
	bLabels := splitLabels(b)
	i, j := len(aLabels)-1, len(bLabels)-1
	for i >= 0 && j >= 0 {
		if aLabels[i] < bLabels[j] {
			return -1
		}
		if aLabels[i] > bLabels[j] {
			return 1
		}
		i--
		j--
	}
	if len(aLabels) < len(bLabels) {
		return -1
	}
	return 1
}

func marshalTypeBitmap(types []uint16) []byte {
	buf := make([]byte, len(types)*2)
	for i, t := range types {
		binary.BigEndian.PutUint16(buf[i*2:], t)
	}
	return buf
}

func unmarshalTypeBitmap(raw []byte) []uint16 {
	if len(raw)%2 != 0 {
		return nil
	}
	types := make([]uint16, len(raw)/2)
	for i := range types {
		types[i] = binary.BigEndian.Uint16(raw[i*2:])
	}
	return types
}
