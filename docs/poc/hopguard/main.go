// HopGuard POC — IP TTL Fingerprinting for DNS Pollution Detection
//
// Run with: go run .
//
// Concept:
//   Real DNS responses travel a consistent network path → stable TTL (±2).
//   GFW-injected responses come from a different network location → different TTL.
//   HopGuard learns the real server's TTL fingerprint, then rejects mismatches.
//
// Comparison:
//   Scenario A — Google directly (no warm-up): HopGuard starts cold, needs 32
//               samples to arm. GFW fakes slip through during learning.
//   Scenario B — Baidu warm-up → Google: HopGuard arms on clean Baidu traffic,
//               then immediately rejects GFW fakes when querying Google.
//
// Algorithm mirror (server/defense/hopguard.go)

package main

import (
	"flag"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"slices"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// ── Types ─────────────────────────────────────────────────────────

type hgState struct {
	hist    map[uint8]int
	trusted map[uint8]int
	samples int
	armed   bool
}

type queryRow struct {
	id     int
	domain string
	ttl    uint8
	gfw    bool
	armed  bool
	accept bool
}

type ttlCount struct {
	ttl   uint8
	count int
}

type realRow struct {
	id       int
	domain   string
	ipTTL    int // -1 = unavailable (Windows); the fingerprint source when present
	recTTL   uint32
	answers  []string
	polluted bool
	armed    bool
	accept   bool
	err      string
}

// realPkt is one datagram received for a real query: answer IPs plus the
// IP-layer TTL from the control message (hopguard's fingerprint).
type realPkt struct {
	ips    []string
	ipTTL  int
	recTTL uint32
}

// ttlCapture mirrors internal/ipttl: the x/net control-message API enables
// IP TTL (IPv4) / HopLimit (IPv6) capture on a UDP connection, resolving the
// platform socket option internally (Linux/Darwin/FreeBSD). Windows yields
// nil here, degrading hopguard to TTL-less operation.
type ttlCapture struct {
	pc4 *ipv4.PacketConn
	pc6 *ipv6.PacketConn
}

// ── Constants ─────────────────────────────────────────────────────

const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	dim    = "\033[2m"
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	cyan   = "\033[36m"
)

const (
	fluctuation = 2
	minSamples  = 32
)

// ── Helpers ───────────────────────────────────────────────────────

// ttl returns the IP-layer TTL when available, else the record TTL.
func (r *realRow) ttl() uint32 {
	if r.ipTTL >= 0 {
		return uint32(r.ipTTL) //nolint:gosec // G115: IP TTL is 1–255
	}
	return r.recTTL
}

func rpad(s string, w int) string {
	vis := len(s)
	for i := 0; i < len(s); i++ {
		if s[i] == '\033' {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			vis -= 2
		}
	}
	if vis >= w {
		return s
	}
	return s + strings.Repeat(" ", w-vis)
}

// ── HopGuard Core ──────────────────────────────────────────────────

func newHGState() *hgState {
	return &hgState{hist: map[uint8]int{}, trusted: map[uint8]int{}}
}

func (s *hgState) feed(ttl uint8) {
	s.hist[ttl]++
	s.samples++
	if s.samples >= minSamples && s.samples%minSamples == 0 {
		s.rebuild()
		if len(s.trusted) > 0 {
			s.armed = true
		}
	}
}

func (s *hgState) validate(ttl uint8) bool {
	if !s.armed {
		return true
	}
	for t := range s.trusted {
		lo, hi := int(t)-fluctuation, int(t)+fluctuation
		if lo < 1 {
			lo = 1
		}
		if hi > 255 {
			hi = 255
		}
		if int(ttl) >= lo && int(ttl) <= hi {
			return true
		}
	}
	return false
}

func (s *hgState) rebuild() {
	for t, c := range s.hist {
		if nc := c * 3 / 4; nc <= 0 {
			delete(s.hist, t)
		} else {
			s.hist[t] = nc
		}
	}
	var mode uint8
	maxC := 0
	for t, c := range s.hist {
		if c > maxC || (c == maxC && t < mode) {
			mode, maxC = t, c
		}
	}
	thresh := max(maxC/4, 4)
	clear(s.trusted)
	if mode > 0 {
		s.trusted[mode] = s.hist[mode]
	}
	for t, c := range s.hist {
		if t != mode && c >= thresh && c >= s.hist[mode]/2 {
			s.trusted[t] = c
		}
	}
}

// ── Simulation ────────────────────────────────────────────────────

// ── Real-network mode ─────────────────────────────────────────────

func newTTLCapture(conn *net.UDPConn) *ttlCapture {
	c := &ttlCapture{}
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil
	}
	if addr.IP.To4() != nil {
		c.pc4 = ipv4.NewPacketConn(conn)
		if err := c.pc4.SetControlMessage(ipv4.FlagTTL, true); err != nil {
			return nil
		}
		return c
	}
	if addr.IP.IsUnspecified() {
		// Dual-stack wildcard: try IPv4 first; fall back to IPv6.
		c.pc4 = ipv4.NewPacketConn(conn)
		if err := c.pc4.SetControlMessage(ipv4.FlagTTL, true); err == nil {
			return c
		}
		c.pc4 = nil
	}
	c.pc6 = ipv6.NewPacketConn(conn)
	if err := c.pc6.SetControlMessage(ipv6.FlagHopLimit, true); err != nil {
		return nil
	}
	return c
}

// readFrom reads one datagram; ttl is -1 when no control message arrived.
func (c *ttlCapture) readFrom(buf []byte) (n, ttl int, err error) {
	if c.pc4 != nil {
		n, cm, _, err := c.pc4.ReadFrom(buf)
		if cm != nil {
			return n, cm.TTL, nil
		}
		return n, -1, err
	}
	n, cm, _, err := c.pc6.ReadFrom(buf)
	if cm != nil {
		return n, cm.HopLimit, nil
	}
	return n, -1, err
}

// hasIPRecvTTL probes whether the platform delivers the received IP TTL.
func hasIPRecvTTL() bool {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	return newTTLCapture(conn) != nil
}

// realQuery sends one UDP DNS query and collects every datagram in a 500ms
// window (GFW fakes arrive first, the real answer later), returning each
// packet's answers and IP-layer TTL.
func realQuery(server, qname string, recvTTL bool) ([]realPkt, error) {
	conn, err := net.DialTimeout("udp", server, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	uc := conn.(*net.UDPConn) //nolint:forcetypeassert // DialTimeout("udp") always yields *UDPConn

	var tc *ttlCapture
	if recvTTL {
		tc = newTTLCapture(uc)
	}

	msg := new(dns.Msg)
	dnsutil.SetQuestion(msg, dnsutil.Fqdn(qname), dns.TypeA)
	msg.UDPSize = 1232
	if err := msg.Pack(); err != nil {
		return nil, err
	}
	if _, err := uc.Write(msg.Data); err != nil {
		return nil, err
	}
	_ = uc.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

	var out []realPkt
	buf := make([]byte, 4096)
	first := time.Now()
	for {
		var n int
		pktTTL := -1
		if tc != nil {
			n, pktTTL, err = tc.readFrom(buf)
		} else {
			n, err = uc.Read(buf)
		}
		if err != nil {
			return out, nil // deadline — window closed
		}
		resp := new(dns.Msg)
		resp.Data = buf[:n]
		if err := resp.Unpack(); err != nil {
			continue
		}
		pkt := realPkt{ipTTL: pktTTL}
		for _, rr := range resp.Answer {
			if a, ok := rr.(*dns.A); ok {
				pkt.ips = append(pkt.ips, a.Addr.String())
				if pkt.recTTL == 0 {
					pkt.recTTL = a.Hdr.TTL
				}
			}
		}
		out = append(out, pkt)
		if len(out) == 1 {
			// First packet seen — allow up to 200ms total for peers (GFW
			// fakes first, the real answer at ~65–180ms).
			_ = uc.SetReadDeadline(first.Add(200 * time.Millisecond))
		}
		if len(out) >= 2 && time.Since(first) > 150*time.Millisecond {
			return out, nil // fakes present and the real-answer window covered
		}
	}
}

// isPolluted reports whether the first answer IP is outside the known clean
// segments for the queried domain (real-network heuristic: GFW fakes come
// from Facebook/SoftLayer segments, the real answer is 142.251.x/172.217.x/74.125.x).
func isPolluted(domain string, ips []string) bool {
	if len(ips) == 0 {
		return false
	}
	if domain == "www.google.com" {
		ip := ips[0]
		return !strings.HasPrefix(ip, "142.251.") && !strings.HasPrefix(ip, "172.217.") &&
			!strings.HasPrefix(ip, "74.125.")
	}
	return false
}

// collectRows runs n live queries, feeding clean packets into st (the
// hgState learning loop) and rendering each received datagram as a row.
func collectRows(server, domain string, startID, n int, recvTTL bool, st *hgState) []realRow {
	var rows []realRow
	id := startID
	for range n {
		pkts, err := realQuery(server, domain, recvTTL)
		if err != nil {
			rows = append(rows, realRow{id: id, domain: domain, ipTTL: -1, err: err.Error()})
			id++
			continue
		}
		for _, p := range pkts {
			r := realRow{
				id: id, domain: domain, ipTTL: p.ipTTL, recTTL: p.recTTL,
				answers: p.ips, polluted: isPolluted(domain, p.ips), armed: st.armed,
			}
			if r.ipTTL > 0 {
				ttl := uint8(r.ipTTL) //nolint:gosec // G115: IP TTL is 1–255
				r.accept = st.validate(ttl)
				if !r.polluted {
					st.feed(ttl) // learn only from clean (non-polluted) packets
				}
			}
			rows = append(rows, r)
			id++
		}
	}
	return rows
}

// shortAnswers renders up to two IPs plus a count ellipsis (34-char column).
func shortAnswers(ips []string) string {
	switch len(ips) {
	case 0:
		return dim + "no A record" + reset
	case 1:
		return ips[0]
	case 2:
		return strings.Join(ips, ", ")
	default:
		return strings.Join(ips[:2], ", ") + fmt.Sprintf(" …(%d)", len(ips))
	}
}

func renderRealHeader() {
	fmt.Println("  ┌──────┬─────────────────┬───────┬────────┬────────────┬──────────────────────────────────┐")
	fmt.Println("  │  #   │ Domain          │ TTL   │ Source │ Verdict    │ Answers                  │")
	fmt.Println("  ├──────┼─────────────────┼───────┼────────┼────────────┼──────────────────────────────────┤")
}

func renderRealFooter() {
	fmt.Println("  └──────┴─────────────────┴───────┴────────┴────────────┴──────────────────────────────────┘")
}

func renderRealRow(r *realRow) {
	src := green + "REAL" + reset
	if r.polluted {
		src = red + "GFW " + reset
	}
	var verdict string
	switch {
	case r.err != "":
		verdict = red + "FAILED" + reset
	case !r.armed:
		verdict = dim + "LEARN" + reset
	case r.accept:
		verdict = green + "PASS ✓" + reset
	default:
		verdict = red + "REJECT ✗" + reset
	}
	ans := shortAnswers(r.answers)
	fmt.Printf("  │ %-4d │ %-15s │ %-5d │ %s │ %s │ %s │\n",
		r.id, r.domain, r.ttl(), rpad(src, 8), rpad(verdict, 12), rpad(ans, 32))
}

func renderRealTable(rows []realRow) {
	renderRealHeader()
	for i := range rows {
		renderRealRow(&rows[i])
	}
	renderRealFooter()
}

// trustedTTLs returns the armed TTL set sorted ascending.
func trustedTTLs(s *hgState) []int {
	var out []int
	for t := range s.trusted {
		out = append(out, int(t))
	}
	slices.Sort(out)
	return out
}

func realTest(server string) {
	recvTTL := hasIPRecvTTL() // macOS/Linux deliver IP TTL; Windows does not

	fmt.Println(bold + "HopGuard Real-Network Mode — Live Queries" + reset)
	if recvTTL {
		fmt.Printf("  Upstream: %s    Tolerance: ±%d    Learning: %d samples    IP-TTL fingerprint: %sACTIVE%s\n\n",
			server, fluctuation, minSamples, green, reset)
	} else {
		fmt.Printf("  Upstream: %s    Tolerance: ±%d    Learning: %d samples    IP-TTL fingerprint: %sUNAVAILABLE%s\n",
			server, fluctuation, minSamples, red, reset)
		fmt.Println("  (Windows sockets expose no IP TTL — showing DNS-layer signals: pollution IPs + record TTLs)")
		fmt.Println()
	}

	// ── Scenario A: Google directly (cold) ─────────────────────
	fmt.Printf("  %s━━━ Scenario A: Google directly (no warm-up) ━━━%s\n\n", red, reset)
	cold := newHGState()
	rowsA := collectRows(server, "www.google.com", 1, 3, recvTTL, cold)
	fmt.Printf("  HopGuard state: %sNOT ARMED%s (%d clean samples, need %d)\n\n", red, reset, cold.samples, minSamples)
	renderRealTable(rowsA)
	pollutedA, rejectedA := 0, 0
	for _, r := range rowsA {
		if r.polluted {
			pollutedA++
			if !r.accept && r.armed {
				rejectedA++
			}
		}
	}
	fmt.Printf("  %sResult: %d/%d GFW fakes PASSED — still learning, can't reject yet%s\n",
		red, pollutedA-rejectedA, pollutedA, reset)

	// ── Scenario B: Baidu warm-up → Google ─────────────────────
	fmt.Println()
	fmt.Println()
	fmt.Printf("  %s━━━ Scenario B: Baidu warm-up → Google ━━━%s\n\n", green, reset)
	warm := newHGState()
	baiduRows := collectRows(server, "www.baidu.com", 1, minSamples, recvTTL, warm)
	rowsB := collectRows(server, "www.google.com", 4, 3, recvTTL, warm)
	renderRealHeader()
	for i := range baiduRows[:3] {
		renderRealRow(&baiduRows[i])
	}
	fmt.Printf("  │ %-4s │ %-15s │ %-5s │ %-8s │ %-12s │ %-32s │\n", "···", "···", "···", "···", "···", "···")
	fmt.Println("  ├──────┴─────────────────┴───────┴────────┴────────────┴──────────────────────────────────┤")
	fmt.Printf("  %s▲ ARMED after %d Baidu queries — trusted TTLs: %v (±%d)%s\n",
		yellow, warm.samples, trustedTTLs(warm), fluctuation, reset)
	fmt.Println("  ├──────┬─────────────────┬───────┬────────┬────────────┬──────────────────────────────────┤")
	for i := range rowsB {
		renderRealRow(&rowsB[i])
	}
	renderRealFooter()
	pollutedB, rejectedB := 0, 0
	for _, r := range rowsB {
		if r.polluted {
			pollutedB++
			if !r.accept && r.armed {
				rejectedB++
			}
		}
	}
	fmt.Printf("  %sResult: %d/%d GFW fakes REJECTED — armed from Baidu warm-up%s\n",
		green, rejectedB, pollutedB, reset)

	fmt.Println("\n  GFW injections come from a different network location and cannot match")
	fmt.Println("  the real server's IP-layer TTL (±2 trusted window); baidu shares the")
	fmt.Println("  same path to 8.8.8.8, so its clean traffic arms the fingerprint.")
}

func main() {
	realMode := flag.Bool("real", false, "real-network mode: query a live upstream")
	server := flag.String("server", "8.8.8.8:53", "upstream address for -real")
	flag.Parse()

	if len(os.Args) > 1 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
		fmt.Println("HopGuard POC — IP TTL Fingerprinting for DNS Pollution Detection")
		fmt.Println("\nUsage: go run . [-real -server 8.8.8.8:53]")
		fmt.Println("\nCompares: Google directly (cold) vs Baidu warm-up → Google (armed).")
		return
	}

	fmt.Print("\033[2J\033[H")
	fmt.Println()
	fmt.Println(bold + cyan + "  ╔══════════════════════════════════════════════════════════════╗" + reset)
	fmt.Println(bold + cyan + "  ║       HopGuard — IP TTL Fingerprinting Anti-Pollution        ║" + reset)
	fmt.Println(bold + cyan + "  ╚══════════════════════════════════════════════════════════════╝" + reset)
	fmt.Println()

	if *realMode {
		realTest(*server)
		return
	}

	realBaseTTL := uint8(52)

	// GFW injection pattern for Google queries (same for both scenarios).
	// 8 fakes out of 20 queries at these positions.
	gfwSet := map[int]bool{2: true, 4: true, 7: true, 9: true, 12: true, 14: true, 17: true, 19: true}

	// ── Scenario A: Google directly (no warm-up) ─────────────────
	// HopGuard starts with zero samples. During 20 Google queries,
	// only ~12 real responses are fed. 12 < 32 → never arms.
	// All 20 responses (including 8 GFW fakes) are accepted.

	cold := newHGState()
	var coldRows []queryRow
	for i := 1; i <= 20; i++ {
		isGFW := gfwSet[i]
		ttl := realBaseTTL + uint8(rand.IntN(3)) - 1 //nolint:gosec // G404: demo simulation — not cryptographic
		if isGFW {
			if rand.IntN(2) == 0 { //nolint:gosec // G404: demo simulation — not cryptographic
				ttl = uint8(rand.IntN(16) + 32) //nolint:gosec // 32–47
			} else {
				ttl = uint8(rand.IntN(16) + 58) //nolint:gosec // 58–73
			}
		}
		wasArmed := cold.armed
		accept := cold.validate(ttl)
		if !isGFW {
			cold.feed(ttl)
		}
		coldRows = append(coldRows, queryRow{id: i, domain: "www.google.com", ttl: ttl, gfw: isGFW, armed: wasArmed, accept: accept})
	}

	// ── Scenario B: Baidu warm-up → Google ──────────────────────
	// Phase B1: 32 Baidu queries (all real) → arms HopGuard.
	// Phase B2: 20 Google queries → already armed, GFW fakes rejected.

	warm := newHGState()
	var warmRows []queryRow

	// B1: Baidu warm-up.
	for i := 1; i <= 32; i++ {
		ttl := realBaseTTL + uint8(rand.IntN(3)) - 1 //nolint:gosec // G404: demo simulation — not cryptographic
		warm.feed(ttl)                               // all real
		warmRows = append(warmRows, queryRow{id: i, domain: "www.baidu.com", ttl: ttl, gfw: false, armed: warm.armed, accept: warm.validate(ttl)})
	}

	// B2: Google queries.
	for i := 1; i <= 20; i++ {
		id := 32 + i
		isGFW := gfwSet[i]                           // same GFW pattern
		ttl := realBaseTTL + uint8(rand.IntN(3)) - 1 //nolint:gosec // G404: demo simulation — not cryptographic
		if isGFW {
			if rand.IntN(2) == 0 { //nolint:gosec // G404: demo simulation — not cryptographic
				ttl = uint8(rand.IntN(16) + 32) //nolint:gosec // 32–47
			} else {
				ttl = uint8(rand.IntN(16) + 58) //nolint:gosec // 58–73
			}
		}
		wasArmed := warm.armed
		accept := warm.validate(ttl)
		if !isGFW {
			warm.feed(ttl)
		}
		warmRows = append(warmRows, queryRow{id: id, domain: "www.google.com", ttl: ttl, gfw: isGFW, armed: wasArmed, accept: accept})
	}

	// ── Stats ───────────────────────────────────────────────────

	coldGFWTotal, coldGFWPassed := 0, 0
	for _, r := range coldRows {
		if r.gfw {
			coldGFWTotal++
			if r.accept {
				coldGFWPassed++
			}
		}
	}

	warmGoogleStart := 32 // rows 33-52 are Google
	warmGFWTotal, warmGFWPassed, warmGFWRejected := 0, 0, 0
	for _, r := range warmRows[warmGoogleStart:] {
		if r.gfw {
			warmGFWTotal++
			if r.accept {
				warmGFWPassed++
			} else {
				warmGFWRejected++
			}
		}
	}

	// ── Render ──────────────────────────────────────────────────

	fmt.Printf("  Upstream: 8.8.8.8    Real TTL: %d±1    Tolerance: ±%d    Learning: %d samples\n\n",
		realBaseTTL, fluctuation, minSamples)

	// ── Scenario A: Cold start ──────────────────────────────────

	fmt.Printf("  %s━━━ Scenario A: Google directly (no warm-up) ━━━%s\n", red, reset)
	fmt.Println()
	fmt.Printf("  HopGuard state: %sNOT ARMED%s (only %d real samples, need %d)\n\n",
		red, reset, cold.samples, minSamples)

	fmt.Println("  ┌──────┬─────────────────┬─────┬────────┬──────────┐")
	fmt.Println("  │  #   │ Domain          │ TTL │ Source │ Verdict  │")
	fmt.Println("  ├──────┼─────────────────┼─────┼────────┼──────────┤")

	for _, r := range coldRows {
		src := green + "REAL" + reset
		if r.gfw {
			src = red + "GFW " + reset
		}
		fmt.Printf("  │ %-4d │ %-15s │ %-3d │ %s │ %s │\n",
			r.id, r.domain, r.ttl, rpad(src, 8), rpad(dim+"LEARN"+reset, 12))
	}
	fmt.Println("  └──────┴─────────────────┴─────┴────────┴──────────┘")
	fmt.Printf("  %sResult: %d/%d GFW fakes PASSED — still learning, can't reject yet%s\n",
		red, coldGFWPassed, coldGFWTotal, reset)

	// ── Scenario B: Warm start ──────────────────────────────────

	fmt.Println()
	fmt.Println()
	fmt.Printf("  %s━━━ Scenario B: Baidu warm-up → Google ━━━%s\n", green, reset)
	fmt.Println()

	fmt.Println("  ┌──────┬─────────────────┬─────┬────────┬──────────┐")
	fmt.Println("  │  #   │ Domain          │ TTL │ Source │ Verdict  │")
	fmt.Println("  ├──────┼─────────────────┼─────┼────────┼──────────┤")

	for _, r := range warmRows[:3] {
		fmt.Printf("  │ %-4d │ %-15s │ %-3d │ %s │ %s │\n",
			r.id, r.domain, r.ttl, green+"REAL"+reset, dim+"LEARN"+reset)
	}
	fmt.Printf("  │ %-4s │ %-15s │ %-3s │ %-8s │ %-12s │\n", "···", "···", "···", "···", "···")
	for _, r := range warmRows[29:32] {
		verdict := dim + "LEARN" + reset
		if r.armed {
			verdict = green + "PASS ✓" + reset
		}
		fmt.Printf("  │ %-4d │ %-15s │ %-3d │ %s │ %s │\n",
			r.id, r.domain, r.ttl, green+"REAL"+reset, verdict)
	}

	fmt.Println("  ├──────┴─────────────────┴─────┴────────┴──────────┤")
	fmt.Println(yellow + "  │  ▲ ARMED after 32 Baidu queries — trusted TTLs: 51,52,53 (±2)" + reset + " │")
	fmt.Println("  ├──────┬─────────────────┬─────┬────────┬──────────┤")

	for _, r := range warmRows[32:] {
		src := green + "REAL" + reset
		if r.gfw {
			src = red + "GFW " + reset
		}
		var verdict string
		if r.accept {
			verdict = green + "PASS ✓" + reset
		} else {
			verdict = red + "REJECT ✗" + reset
		}
		fmt.Printf("  │ %-4d │ %-15s │ %-3d │ %s │ %s │\n",
			r.id, r.domain, r.ttl, rpad(src, 8), rpad(verdict, 12))
	}
	fmt.Println("  └──────┴─────────────────┴─────┴────────┴──────────┘")
	fmt.Printf("  %sResult: %d/%d GFW fakes REJECTED — already armed from Baidu warm-up%s\n",
		green, warmGFWRejected, warmGFWTotal, reset)

	// ── Comparison Table ───────────────────────────────────────

	fmt.Println()
	fmt.Println()
	fmt.Println(bold + "  ╔══════════════════════════════════════════════════════════╗" + reset)
	fmt.Println(bold + "  ║   Google directly (cold)  vs  Baidu → Google (warm)     ║" + reset)
	fmt.Println(bold + "  ╚══════════════════════════════════════════════════════════╝" + reset)
	fmt.Println()

	hr := dim + "  ├──────────────────────────────┼──────────────┼──────────────┤" + reset
	fmt.Println(dim + "  ┌──────────────────────────────┬──────────────┬──────────────┐" + reset)
	fmt.Printf(dim+"  │ %-28s │ %-12s │ %-12s │"+reset+"\n", "Metric", "Cold (A)", "Warm (B)")
	fmt.Println(hr)

	coldWarmupStr := fmt.Sprintf(red+"%-12s"+reset, "0 (none)")
	warmWarmupStr := fmt.Sprintf(green+"%-12s"+reset, "32 (Baidu)")
	fmt.Printf(dim+"  │ %-28s │ %s │ %s │"+reset+"\n", "Warm-up queries", coldWarmupStr, warmWarmupStr)

	coldArmedStr := fmt.Sprintf(red+"%-12s"+reset, "NO")
	warmArmedStr := fmt.Sprintf(green+"%-12s"+reset, "YES")
	fmt.Printf(dim+"  │ %-28s │ %s │ %s │"+reset+"\n", "Armed before Google?", coldArmedStr, warmArmedStr)

	fmt.Printf(dim+"  │ %-28s │ %-12d │ %-12d │"+reset+"\n", "Google queries", 20, 20)
	fmt.Println(hr)

	coldGFWStr := fmt.Sprintf(red+"%-12d"+reset, coldGFWTotal)
	warmGFWStr := fmt.Sprintf(red+"%-12d"+reset, warmGFWTotal)
	fmt.Printf(dim+"  │ %-28s │ %s │ %s │"+reset+"\n", "GFW fakes injected", coldGFWStr, warmGFWStr)

	coldPassedStr := fmt.Sprintf(red+"%-12d"+reset, coldGFWPassed)
	warmPassedStr := fmt.Sprintf(red+"%-12d"+reset, warmGFWPassed)
	fmt.Printf(dim+"  │ %-28s │ %s │ %s │"+reset+"\n", "GFW fakes accepted", coldPassedStr, warmPassedStr)

	coldRejStr := fmt.Sprintf(dim+"%-12d"+reset, 0)
	warmRejStr := fmt.Sprintf(green+"%-12d"+reset, warmGFWRejected)
	fmt.Printf(dim+"  │ %-28s │ %s │ %s │"+reset+"\n", "GFW fakes rejected", coldRejStr, warmRejStr)

	coldRealStr := fmt.Sprintf(green+"%-12d"+reset, 20-coldGFWTotal)
	warmRealStr := fmt.Sprintf(green+"%-12d"+reset, 20-warmGFWTotal)
	fmt.Printf(dim+"  │ %-28s │ %s │ %s │"+reset+"\n", "Real responses OK", coldRealStr, warmRealStr)

	fmt.Println(hr)

	coldResultStr := fmt.Sprintf(red+"%-12s"+reset, fmt.Sprintf("%d%% poisoned", coldGFWPassed*100/20))
	warmResultStr := fmt.Sprintf(green+"%-12s"+reset, fmt.Sprintf("%d%% clean", (20-warmGFWPassed)*100/20))
	fmt.Printf(dim+"  │ %-28s │ %s │ %s │"+reset+"\n", "Google query quality", coldResultStr, warmResultStr)

	fmt.Println(dim + "  └──────────────────────────────┴──────────────┴──────────────┘" + reset)

	// ── TTL Distribution ───────────────────────────────────────

	fmt.Println()
	fmt.Println(bold + "  ═══════════ TTL Distribution (Scenario B, after warm-up) ═══════════" + reset)
	fmt.Println()

	var hist []ttlCount
	maxC := 0
	for t, c := range warm.hist {
		hist = append(hist, ttlCount{t, c})
		if c > maxC {
			maxC = c
		}
	}
	slices.SortStableFunc(hist, func(a, b ttlCount) int { return int(a.ttl) - int(b.ttl) })

	barW := 36
	for _, h := range hist {
		trusted := warm.trusted[h.ttl] > 0
		mark := "  "
		if trusted {
			mark = green + "✓ " + reset
		}
		filled := h.count * barW / max(maxC, 1)
		b := green + strings.Repeat("█", filled) + dim + strings.Repeat("░", barW-filled) + reset
		extra := ""
		if trusted {
			extra = green + fmt.Sprintf(" TRUSTED [%d–%d]", int(h.ttl)-fluctuation, int(h.ttl)+fluctuation) + reset
		}
		fmt.Printf("  %sTTL %-3d %s %s%d%s\n", mark, h.ttl, b, dim, h.count, extra)
	}

	fmt.Println()
	fmt.Println(bold + "  Key insight:" + reset)
	fmt.Println("  HopGuard needs 32 clean samples to arm. Querying a censored")
	fmt.Println("  domain directly means learning from mixed real+GFW traffic —")
	fmt.Println("  the GFW fakes arrive before the baseline is established.")
	fmt.Println()
	fmt.Println("  " + green + "Solution:" + reset + " warm up on any clean domain (Baidu, GitHub, etc.)")
	fmt.Println("  first. The TTL baseline is per-upstream-server, shared across")
	fmt.Println("  all domains. Once armed, even censored domains are protected.")
	fmt.Println()
}
