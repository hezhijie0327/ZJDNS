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
func (s *SQLiteCache) IndexNsecRecords(qname string, qtype, qclass uint16, ecs *config.ECSOption, dnssecOK bool, authority []dns.RR) {
	if s.db.IsClosed() {
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
		switch rec := rr.(type) {
		case *dns.NSEC:
			s.indexNsec(entryID, zoneWire, rec)
		case *dns.NSEC3:
			s.indexNsec3(entryID, zoneWire, rec)
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

func (s *SQLiteCache) indexNsec3(entryID int64, zoneWire []byte, nsec3 *dns.NSEC3) {
	ownerWire := toWireName(nsec3.Header().Name)
	nextWire := toWireName(nsec3.NextDomain)
	types := marshalTypeBitmap(nsec3.TypeBitMap)
	if _, err := s.db.StmtNsecInsert.Exec(zoneWire, ownerWire, nextWire, types, entryID); err != nil {
		log.Debugf("NSEC: nsec3 insert failed for %s: %v", nsec3.Header().Name, err)
	}
}

// LookupNsecNeg checks whether a query is covered by an NSEC/NSEC3 record
// in the negative cache. Returns nil if no covering record is found.
func (s *SQLiteCache) LookupNsecNeg(qname string, qtype uint16) *NsecResult {
	if s.db.IsClosed() {
		return nil
	}

	for zone := qname; zone != "."; zone = parentName(zone) {
		rows, err := s.db.SQ.Query(
			"SELECT owner_name, next_name, types FROM nsec_chain WHERE zone_name = ? ORDER BY owner_name ASC",
			toWireName(zone))
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

// parentWire strips the leftmost (original-first) label from a TLD-first
// wire-format name.
// wireToName converts wire-format bytes back to presentation format.
func wireToName(wire []byte) string {
	s := ""
	pos := 0
	for pos < len(wire)-1 {
		l := int(wire[pos])
		if l == 0 {
			break
		}
		if s != "" {
			s += "."
		}
		s += string(wire[pos+1 : pos+1+l])
		pos += 1 + l
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

func parentWire(wire []byte) []byte {
	if len(wire) <= 1 {
		return wire
	}
	pos := 0
	labels := 0
	for pos < len(wire)-1 {
		labels++
		l := int(wire[pos])
		if l == 0 {
			break
		}
		pos += 1 + l
	}
	if labels <= 1 {
		return []byte{0}
	}
	pos = 0
	for i := 0; i < labels-1; i++ {
		l := int(wire[pos])
		pos += 1 + l
	}
	b := make([]byte, pos+1)
	copy(b, wire[:pos])
	b[pos] = 0
	return b
}

func bytesLT(a, b []byte) bool {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := range n {
		if a[i] < b[i] {
			return true
		}
		if a[i] > b[i] {
			return false
		}
	}
	return len(a) < len(b)
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

func bytesLE(a, b []byte) bool {
	return bytesLT(a, b) || slices.Equal(a, b)
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

func init() {
	_ = zdnsutil.NormalizeDomain
	_ = strings.ToLower
}
