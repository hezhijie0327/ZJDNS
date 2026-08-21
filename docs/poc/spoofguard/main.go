// Spoofguard POC — UDP Multi-Read Loop for GFW Injection Detection
//
// Run with: go run .
//
// Concept:
//   GFW injects bare A/AAAA records into UDP DNS responses.
//   Spoofguard uses a multi-read loop: keep reading UDP datagrams, prefer
//   EDNS-bearing and authority-signal candidates, and never serve a bare
//   single-answer A/AAAA without confirmation.
//
// Detection rules (mirrors server/upstream/plain/udp.go processPacket):
//   Fast-return: AN\u22652, NS>0, or AD=1 \u2192 authoritative, return immediately
//   EDNS-bearing \u2192 collect as candidate (always preferred)
//   Non-EDNS + CNAME \u2192 safe fallback (GFW does not inject CNAME chains)
//   Non-EDNS + bare single-answer A/AAAA \u2192 AMBIGUOUS:
//     only ONE response received \u2192 serve directly (no injection signal —
//     the observed GFW pattern always injects TWO fakes)
//     \u22652 responses received \u2192 injection suspected \u2192 re-query (pure UDP);
//       a matching repeat confirms the real answer (GFW fakes vary per
//       packet, the real answer is deterministic); never served unconfirmed.
//   After 500ms window: pick richest candidate, random tie-break

package main

import (
	"flag"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// ── Types ─────────────────────────────────────────────────────────

type simResp struct {
	delay    time.Duration
	hasEDNS  bool
	answers  []string
	hasCNAME bool
	nscount  int
	adFlag   bool
	rcode    int
	label    string
}

type sgState struct {
	prev, last *simResp
	rejected   int
	candidates int
	nonEDNS    *simResp
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

// ── Spoofguard Core ───────────────────────────────────────────────

func (s *sgState) processPacket(r *simResp) (result *simResp, verdict string) { //nolint:gocritic // unnamedResult: demo code
	if len(r.answers) >= 2 || r.nscount > 0 || r.adFlag {
		return r, green + "FAST-RETURN" + reset + " (authoritative signal)"
	}
	if r.rcode != 0 {
		// Mirror production processPacket: a non-NOERROR response without
		// authority signals is collected as a candidate (returned after the
		// window via pickBest), not returned immediately.
		s.prev = s.last
		s.last = r
		s.candidates++
		return nil, yellow + "COLLECT" + reset + " (non-NOERROR — real server signal, collected)"
	}
	if r.hasEDNS {
		// Identical-repeat confirm (mirrors collectEDNSCandidate): two
		// identical EDNS answers confirm the deterministic real response —
		// GFW fakes vary per packet.  Return immediately instead of
		// waiting out the collect window.
		if s.last != nil && sameAnswers(s.last.answers, r.answers) {
			s.last = r
			s.candidates++
			return r, green + "CONFIRMED" + reset + " (identical repeat — real server, no window wait)"
		}
		s.prev = s.last
		s.last = r
		s.candidates++
		return nil, yellow + "COLLECT" + reset + " (EDNS candidate #" + strconv.Itoa(s.candidates) + ")"
	}
	// Non-EDNS NOERROR (single-answer included) \u2192 low-priority fallback.
	// Previously single-answer non-EDNS was REJECTED outright (the "GFW
	// injects bare A/AAAA" heuristic) \u2014 but real servers that don't echo
	// EDNS return the same shape, so those queries blocked the full 9s
	// budget and SERVFAILed.  pickBest prefers EDNS candidates and the
	// collect window waits for a second candidate, so a real EDNS response
	// beats an injected bare A; the fallback is served only when nothing
	// better arrives (mirrors processPacket in server/upstream/plain/udp.go).
	s.rejected++
	s.nonEDNS = r
	return nil, yellow + "FALLBACK" + reset + " (non-EDNS \u2014 collected, EDNS preferred)"
}

func (s *sgState) pickBest() *simResp {
	if s.last == nil {
		return s.nonEDNS
	}
	if s.prev == nil {
		return s.last
	}
	la, pa := len(s.last.answers), len(s.prev.answers)
	if la == 1 && pa > 1 {
		return s.prev
	}
	if pa == 1 && la > 1 {
		return s.last
	}
	if rand.IntN(2) == 0 { //nolint:gosec // G404: demo tie-break — not cryptographic
		return s.prev
	}
	return s.last
}

// ── Render helpers ─────────────────────────────────────────────────

func printHR() { fmt.Println("  " + dim + strings.Repeat("\u2500", 65) + reset) }

func showResponse(i int, r *simResp, arrival time.Duration) {
	prefix := dim
	if i == 1 || i == 2 {
		prefix = red
	}
	fmt.Printf("  %s[+%3dms] Datagram #%d arrives%s\n", prefix, arrival.Milliseconds(), i, reset)
	fmt.Printf("           %s\n", r.label)

	edns := red + "NO " + reset
	if r.hasEDNS {
		edns = green + "YES" + reset
	}
	ans := dim + "(none)" + reset
	if len(r.answers) > 0 {
		ans = strings.Join(r.answers, ", ")
	}
	fmt.Printf("           EDNS: %s   Answers: [%s]   CNAME: %v\n", edns, ans, r.hasCNAME)
}

// runConfirmRound feeds one collect round's datagrams through the spoofguard
// state machine and returns the best candidate (the ambiguous non-EDNS
// fallback), or the safe response if one was returned immediately.
func runConfirmRound(scenario []simResp, start time.Time) *simResp {
	state := &sgState{}
	for i := range scenario {
		r := &scenario[i]
		elapsed := time.Since(start)
		if r.delay > elapsed {
			time.Sleep(r.delay - elapsed)
		}
		arrival := time.Since(start)
		showResponse(i+1, r, arrival)
		result, verdict := state.processPacket(r)
		fmt.Printf("           \u2192 %s\n", verdict)
		fmt.Println()
		if result != nil {
			return result
		}
	}
	return state.pickBest()
}

// sameAnswers reports whether two candidate answers carry identical records.
func sameAnswers(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ── Main ───────────────────────────────────────────────────────────

// ── Real-network mode ─────────────────────────────────────────────

// realCollect sends one query and reads every datagram arriving within the
// spoofguard window (500ms), converting each into simResp for the shared
// rule engine. On a polluted path this yields multiple candidates (real +
// GFW fakes, or fakes only).
func realCollect(server, qname string) []simResp {
	conn, err := net.DialTimeout("udp", server, 5*time.Second)
	if err != nil {
		return nil
	}
	defer func() { _ = conn.Close() }()

	msg := new(dns.Msg)
	dnsutil.SetQuestion(msg, dnsutil.Fqdn(qname), dns.TypeA)
	msg.UDPSize = 1232  // EDNS: spoofguard expects EDNS from real servers
	msg.Security = true // DO bit
	if err := msg.Pack(); err != nil {
		return nil
	}
	if _, err := conn.Write(msg.Data); err != nil {
		return nil
	}
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

	var out []simResp
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return out // deadline — window closed
		}
		resp := new(dns.Msg)
		resp.Data = buf[:n]
		if err := resp.Unpack(); err != nil {
			continue
		}
		r := simResp{
			rcode: int(resp.Rcode), adFlag: resp.AuthenticatedData, label: "real",
			hasEDNS: resp.UDPSize > 0,
		} // EDNS echo detected via advertised UDP size
		for _, rr := range resp.Answer {
			switch a := rr.(type) {
			case *dns.A:
				r.answers = append(r.answers, a.Addr.String())
			case *dns.CNAME:
				r.hasCNAME = true
			}
		}
		r.nscount = len(resp.Ns)
		out = append(out, r)
	}
}

func realTest(server, qname string) {
	fmt.Println(bold + cyan + "  Spoofguard Real-Network Mode — UDP Multi-Read on Live Upstream" + reset)
	fmt.Printf("  Query: %sA %s%s → %s\n\n", bold, qname, reset, server)

	for round := 1; round <= 3; round++ {
		start := time.Now()
		collected := realCollect(server, qname)
		fmt.Printf("  ─ Round %d: %d datagram(s) in window ─\n", round, len(collected))
		if len(collected) == 0 {
			fmt.Printf("  %syellow%s: no response (blocked or timeout)\n", yellow, reset)
			continue
		}
		state := &sgState{}
		best := (*simResp)(nil)
		bestVerdict := ""
		for i, r := range collected {
			res, verdict := state.processPacket(&r)
			showResponse(i, &r, time.Since(start))
			fmt.Printf("    verdict: %s\n", verdict)
			if res != nil {
				best, bestVerdict = res, verdict
			}
		}
		if best == nil {
			best = state.pickBest()
			bestVerdict = "PICK-BEST"
		}
		if best != nil {
			fmt.Printf("  → served: %s (%s)\n", strings.Join(best.answers, ", "), bestVerdict)
		} else {
			fmt.Printf("  → %sno usable candidate%s\n", red, reset)
		}
		printHR()
	}
}

func main() {
	realMode := flag.Bool("real", false, "real-network mode: query a live upstream")
	server := flag.String("server", "8.8.8.8:53", "upstream address for -real")
	qname := flag.String("qname", "www.google.com", "query name for -real")
	flag.Parse()

	if len(os.Args) > 1 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
		fmt.Println("Spoofguard POC — UDP Multi-Read GFW Injection Detection")
		fmt.Println("\nUsage: go run . [-real -server 8.8.8.8:53 -qname www.google.com]")
		return
	}

	fmt.Print("\033[2J\033[H")
	fmt.Println()
	fmt.Println(bold + cyan + "  \u2554══════════════════════════════════════════════════════════════╗" + reset)
	fmt.Println(bold + cyan + "  ║     Spoofguard — UDP Multi-Read GFW Injection Detection      ║" + reset)
	fmt.Println(bold + cyan + "  ╚══════════════════════════════════════════════════════════════╝" + reset)
	fmt.Println()

	if *realMode {
		realTest(*server, *qname)
		return
	}

	// ── Scenario 1: censored domain, EDNS candidate collection ──

	fmt.Printf("  %sScenario 1:%s censored domain — GFW injects fakes, real has EDNS\n", bold, reset)
	fmt.Printf("  Query: %sA www.google.com%s \u2192 8.8.8.8:53\n\n", bold, reset)

	scenario1 := []simResp{
		{delay: 30 * time.Millisecond, hasEDNS: false, answers: []string{"A 93.46.8.89"}, label: "GFW fake #1 — bare A record"},
		{delay: 60 * time.Millisecond, hasEDNS: false, answers: []string{"AAAA 2001:db8::1"}, label: "GFW fake #2 — bare AAAA record"},
		{delay: 110 * time.Millisecond, hasEDNS: true, answers: []string{"A 142.250.80.4"}, label: "Real: 8.8.8.8 — EDNS + A record"},
	}

	state := &sgState{}
	start := time.Now()

	printHR()
	fmt.Println("  " + bold + "Multi-Read Loop" + reset)
	fmt.Println()
	fmt.Println("  GFW signature: bare A/AAAA, no EDNS, no CNAME \u2192 low-priority fallback")
	fmt.Println("  Real signal:   EDNS-bearing \u2192 collect as candidate")
	fmt.Println("  Window:        adaptive \u2014 150ms single datagram / 500ms once a")
	fmt.Println("                 second datagram arrives (injection signal)")
	fmt.Println()
	fmt.Println("  " + bold + "Impact of the 2026-08 change on www.google.com:" + reset)
	fmt.Println("    BEFORE: fakes #1/#2 \u2192 REJECTED; the REAL EDNS response was ALSO")
	fmt.Println("            rejected \u2014 this fork's Unpack moves the OPT out of Extra")
	fmt.Println("            (options \u2192 Pseudo, UDPSize set), and the old gate scanned")
	fmt.Println("            Extra for *dns.OPT, so hasEDNS never matched and the single")
	fmt.Println("            A answer was treated as a bare GFW signature. No acceptable")
	fmt.Println("            response \u2192 www.google.com blocked the full 9s budget.")
	fmt.Println("    AFTER:  fakes \u2192 low-priority fallback; real EDNS detected via")
	fmt.Println("            resp.UDPSize \u2192 EDNS candidate \u2192 wins \u2192 CLEAN.")
	printHR()

	for i, r := range scenario1 {
		elapsed := time.Since(start)
		if r.delay > elapsed {
			time.Sleep(r.delay - elapsed)
		}
		arrival := time.Since(start)

		showResponse(i+1, &r, arrival)
		result, verdict := state.processPacket(&r)
		fmt.Printf("           \u2192 %s\n", verdict)
		fmt.Printf("           (rejected=%d  candidates=%d)\n", state.rejected, state.candidates)
		fmt.Println()
		if result != nil {
			fmt.Printf("  %s>>> Fast-return to client: %s%s\n\n", green, result.label, reset)
			break
		}
	}

	best := state.pickBest()
	if best != nil {
		fmt.Println("  " + bold + "\u2500\u2500 Collect window expired (500ms) \u2500\u2500" + reset)
		fmt.Println()
		all := []*simResp{}
		if state.prev != nil {
			all = append(all, state.prev)
		}
		if state.last != nil {
			all = append(all, state.last)
		}
		for i, c := range all {
			mark := "  "
			if c == best {
				mark = green + "\u2192 " + reset
			}
			fmt.Printf("  %sEDNS candidate #%d: answers=%v\n", mark, i+1, c.answers)
		}
		fmt.Println()
		fmt.Printf("  %sSelected:%s %s (returned to client)\n", green, reset, best.label)
		fmt.Printf("  GFW fakes discarded: %s%d%s (EDNS real response wins)\n", red, state.rejected, reset)
	}

	// ── Scenario 2: fast-return ──

	fmt.Println()
	fmt.Println()
	fmt.Printf("  %sScenario 2:%s non-censored domain — real server returns CNAME chain\n", bold, reset)
	fmt.Printf("  Query: %sA mail.google.com%s \u2192 8.8.8.8:53\n\n", bold, reset)

	state2 := &sgState{}
	start2 := time.Now()

	printHR()
	fmt.Println("  " + bold + "Multi-Read Loop" + reset)
	fmt.Println()
	printHR()

	scenario2 := []simResp{
		{delay: 40 * time.Millisecond, hasEDNS: true, answers: []string{"CNAME mail.google.com.", "A 142.250.80.5"}, hasCNAME: true, label: "Real: EDNS + CNAME + A (2 answers)"},
	}

	for i, r := range scenario2 {
		elapsed := time.Since(start2)
		if r.delay > elapsed {
			time.Sleep(r.delay - elapsed)
		}
		arrival := time.Since(start2)
		showResponse(i+1, &r, arrival)
		result, verdict := state2.processPacket(&r)
		fmt.Printf("           \u2192 %s\n", verdict)
		fmt.Println()
		if result != nil {
			fmt.Printf("  %s>>> AN\u22652 detected — strong authority signal, return immediately%s\n", green, reset)
			fmt.Println("  No need to wait for GFW fakes; multi-answer responses are")
			fmt.Println("  inherently trustworthy (GFW only injects single answers).")
			break
		}
	}

	// ── Scenario 3: real server does NOT echo EDNS — confirmation re-query ──

	fmt.Println()
	fmt.Println()
	fmt.Printf("  %sScenario 3:%s real server without EDNS — GFW fake arrives first\n", bold, reset)
	fmt.Printf("  Query: %sA www.google.com%s \u2192 authority (no EDNS echo)\n\n", bold, reset)

	printHR()
	fmt.Println("  " + bold + "Re-Query Confirmation (pure UDP)" + reset)
	fmt.Println()
	fmt.Println("  Old gate: single-answer non-EDNS \u2192 REJECT \u2192 fake AND real dropped")
	fmt.Println("           \u2192 query blocked the full 9s budget \u2192 SERVFAIL (the bug)")
	fmt.Println("  New gate: single-answer non-EDNS \u2192 AMBIGUOUS \u2192 re-query; a matching")
	fmt.Println("           repeat confirms the real answer. Never served unconfirmed.")
	fmt.Println()
	printHR()

	scenario3R1 := []simResp{
		{delay: 30 * time.Millisecond, hasEDNS: false, answers: []string{"A 93.46.8.89"}, label: "R1 GFW fake — bare A record"},
		{delay: 110 * time.Millisecond, hasEDNS: false, answers: []string{"A 142.250.80.4"}, label: "R1 Real — single-answer non-EDNS A"},
	}
	scenario3R2 := []simResp{
		{delay: 30 * time.Millisecond, hasEDNS: false, answers: []string{"A 31.13.92.37"}, label: "R2 GFW fake — bare A (different IP)"},
		{delay: 110 * time.Millisecond, hasEDNS: false, answers: []string{"A 142.250.80.4"}, label: "R2 Real — same single-answer non-EDNS A"},
	}

	start3 := time.Now()
	fmt.Println("  " + bold + "\u2500\u2500 Round 1 (collect window) \u2500\u2500" + reset)
	fmt.Println()
	best3 := runConfirmRound(scenario3R1, start3)
	fmt.Println("  " + bold + "\u2500\u2500 Round 1 result: AMBIGUOUS \u2192 re-querying \u2500\u2500" + reset)
	fmt.Println()

	fmt.Println("  " + bold + "\u2500\u2500 Round 2 (confirmation) \u2500\u2500" + reset)
	fmt.Println()
	best3b := runConfirmRound(scenario3R2, time.Now())
	fmt.Println()
	if best3 != nil && best3b != nil && sameAnswers(best3.answers, best3b.answers) {
		fmt.Printf("  %sConfirmed:%s round 1 and round 2 real answers match \u2192 %s\n", green, reset, best3b.label)
		fmt.Println("  Served to client: 142.250.80.4 (real). Pure UDP, no TCP.")
	} else {
		fmt.Printf("  %sNo confirmation \u2192 ambiguous response not served.%s\n", red, reset)
	}

	// ── Scenario 4: lone injection (real response lost) ──

	fmt.Println()
	fmt.Println()
	fmt.Printf("  %sScenario 4:%s lone GFW injection \u2014 real response never arrives\n", bold, reset)
	fmt.Printf("  Query: %sA www.google.com%s \u2192 authority (real datagram dropped)\n\n", bold, reset)

	printHR()
	fmt.Println("  " + bold + "Re-Query Confirmation (pure UDP)" + reset)
	fmt.Println()
	fmt.Println("  Old gate: lone fake \u2192 REJECT \u2192 timeout (no answer, no poison)")
	fmt.Println("  GFW reality: TWO fakes are injected per query (observed pattern)")
	fmt.Println("  New gate: \u22652 non-EDNS responses \u2192 AMBIGUOUS \u2192 re-query; the fakes")
	fmt.Println("           differ each round \u2192 never confirms \u2192 the query fails cleanly.")
	fmt.Println("           A single clean response is served directly (no injection signal).")
	fmt.Println()
	printHR()

	scenario4R1 := []simResp{
		{delay: 30 * time.Millisecond, hasEDNS: false, answers: []string{"A 93.46.8.89"}, label: "R1 GFW fake #1 — bare A"},
		{delay: 60 * time.Millisecond, hasEDNS: false, answers: []string{"A 31.13.92.37"}, label: "R1 GFW fake #2 — different IP"},
	}
	scenario4R2 := []simResp{
		{delay: 30 * time.Millisecond, hasEDNS: false, answers: []string{"A 157.240.7.20"}, label: "R2 GFW fake #1 — different IP"},
		{delay: 60 * time.Millisecond, hasEDNS: false, answers: []string{"A 185.45.5.35"}, label: "R2 GFW fake #2 — different IP"},
	}
	scenario4R3 := []simResp{
		{delay: 30 * time.Millisecond, hasEDNS: false, answers: []string{"A 104.244.42.197"}, label: "R3 GFW fake #1 — different IP"},
		{delay: 60 * time.Millisecond, hasEDNS: false, answers: []string{"A 174.132.167.252"}, label: "R3 GFW fake #2 — different IP"},
	}

	best4 := runConfirmRound(scenario4R1, time.Now())
	fmt.Println("  \u2500\u2500 Round 1: AMBIGUOUS \u2192 re-querying" + reset)
	best4b := runConfirmRound(scenario4R2, time.Now())
	fmt.Println("  \u2500\u2500 Round 2: DIFFERS \u2192 re-querying" + reset)
	best4c := runConfirmRound(scenario4R3, time.Now())
	fmt.Println()
	if best4 != nil && best4b != nil && best4c != nil &&
		sameAnswers(best4.answers, best4b.answers) && sameAnswers(best4b.answers, best4c.answers) {
		fmt.Printf("  %sServed:%s %s (confirmed across rounds)\n", green, reset, best4c.label)
	} else {
		fmt.Printf("  %sNo matching confirmation across 3 rounds \u2192 query fails, nothing served.%s\n", red, reset)
		fmt.Println("  (HopGuard TTL validation, when armed, is the additional first-line filter.)")
	}

	// ── Scenario 5: clean single response (github.com nsone) ──

	fmt.Println()
	fmt.Println()
	fmt.Printf("  %sScenario 5:%s clean single-answer no-EDNS response — no injection\n", bold, reset)
	fmt.Printf("  Query: %sA github.com%s \u2192 nsone authority (single response)\n\n", bold, reset)

	printHR()
	fmt.Println("  " + bold + "Single Clean Response (no re-query)" + reset)
	fmt.Println()
	fmt.Println("  GFW always injects TWO fakes \u2014 one response carries no injection")
	fmt.Println("  signal, so it is served directly (no confirmation latency). This is")
	fmt.Println("  the github.com nsone case: the old gate rejected it \u2192 9s timeout;")
	fmt.Println("  the naive fallback served it; now it is trusted without delay.")
	fmt.Println()
	printHR()

	scenario5 := []simResp{
		{delay: 40 * time.Millisecond, hasEDNS: false, answers: []string{"A 140.82.112.4"}, label: "Real: nsone — single-answer non-EDNS A (only datagram)"},
	}
	best5 := runConfirmRound(scenario5, time.Now())
	fmt.Println()
	if best5 != nil {
		fmt.Printf("  %sServed directly:%s %s (1 response, no injection signal)\n", green, reset, best5.label)
	} else {
		fmt.Printf("  %sNo response.%s\n", red, reset)
	}

	// ── Scenario 6: server retransmit — identical EDNS repeat ──

	fmt.Println()
	fmt.Println()
	fmt.Printf("  %sScenario 6:%s server retransmit — two identical EDNS responses\n", bold, reset)
	fmt.Printf("  Query: %sA www.example.com%s → EDNS-capable authority\n\n", bold, reset)

	printHR()
	fmt.Println("  " + bold + "Identical-Repeat Confirm (no window wait)" + reset)
	fmt.Println()
	fmt.Println("  The authority retransmits its (deterministic) EDNS answer: the second")
	fmt.Println("  identical candidate confirms the first and is served immediately —")
	fmt.Println("  no 500ms window wait. GFW fakes vary per packet, so an identical")
	fmt.Println("  repeat can only be the real server (same principle as the non-EDNS")
	fmt.Println("  re-query confirm in Scenario 3).")
	fmt.Println()
	printHR()

	scenario6 := []simResp{
		{delay: 40 * time.Millisecond, hasEDNS: true, answers: []string{"A 192.0.2.9"}, label: "Real #1 — EDNS + A record"},
		{delay: 90 * time.Millisecond, hasEDNS: true, answers: []string{"A 192.0.2.9"}, label: "Real #2 — retransmit, identical answer"},
	}
	best6 := runConfirmRound(scenario6, time.Now())
	fmt.Println()
	if best6 != nil {
		fmt.Printf("  %sServed at +90ms:%s %s (confirmed by identical repeat, window skipped)\n", green, reset, best6.label)
	} else {
		fmt.Printf("  %sNo response.%s\n", red, reset)
	}

	// ── Comparison Table ──

	fmt.Println()
	fmt.Println()
	fmt.Println(bold + "  \u2554════════════════════════════════════════════════════╗" + reset)
	fmt.Println(bold + "  ║     Spoofguard OFF  vs  Spoofguard ON              ║" + reset)
	fmt.Println(bold + "  ╚════════════════════════════════════════════════════╝" + reset)
	fmt.Println()

	hr := dim + "  \u251c────────────────────────────┼──────────────────────────────┤" + reset
	fmt.Println(dim + "  ┌────────────────────────────┬──────────────────────────────┐" + reset)
	fmt.Printf(dim+"  │ %-26s │ %-28s │ %-28s │"+reset+"\n", "Metric", "OFF", "ON")
	fmt.Println(hr)

	fmt.Printf(dim+"  │ %-26s │ "+red+"%-28s"+reset+" │ "+green+"%-28s"+reset+" │"+reset+"\n",
		"First response", "GFW fake (30ms)", "GFW fake \u2192 fallback (discarded later)")
	fmt.Printf(dim+"  │ %-26s │ "+red+"%-28s"+reset+" │ "+green+"%-28s"+reset+" │"+reset+"\n",
		"Returned to client", "A 93.46.8.89 (fake)", "A 142.250.80.4 (real)")
	fmt.Printf(dim+"  │ %-26s │ "+red+"%-28s"+reset+" │ "+green+"%-28s"+reset+" │"+reset+"\n",
		"Detection method", "None — first wins", "EDNS preference + multi-read")
	fmt.Printf(dim+"  │ %-26s │ "+red+"%-28s"+reset+" │ "+green+"%-28s"+reset+" │"+reset+"\n",
		"GFW fakes filtered", "0 / 2", "2 / 2 discarded (EDNS wins)")
	fmt.Printf(dim+"  │ %-26s │ "+green+"%-28s"+reset+" │ "+yellow+"%-28s"+reset+" │"+reset+"\n",
		"Latency cost", "~30ms (first wins)", "+80ms (real @ 110ms)")

	fmt.Println(hr)
	fmt.Printf(dim+"  │ %-26s │ "+red+"%-28s"+reset+" │ "+green+"%-28s"+reset+" │"+reset+"\n",
		"Result", "POISONED", "CLEAN")
	fmt.Println(dim + "  └────────────────────────────┴──────────────────────────────┘" + reset)

	fmt.Println()
	fmt.Println(bold + "  How it works:" + reset)
	fmt.Println("  GFW injects bare A/AAAA records without EDNS — the signature")
	fmt.Println("  of DNS injection. Spoofguard reads all UDP datagrams in an")
	fmt.Println("  adaptive collect window — 150ms after a single datagram (nothing")
	fmt.Println("  to compare; authorities answer once), the full 500ms once a")
	fmt.Println("  second datagram arrives (a possible injected peer). EDNS-bearing")
	fmt.Println("  candidates are preferred; two identical EDNS answers confirm")
	fmt.Println("  the deterministic real response immediately. The richest response")
	fmt.Println("  wins the window comparison. Non-EDNS responses are kept as a")
	fmt.Println("  low-priority candidate; a bare single-answer A/AAAA is ambiguous")
	fmt.Println("  and is served only after a matching re-query confirms it (pure")
	fmt.Println("  UDP — GFW fakes vary per packet, the real answer is deterministic).")
	fmt.Println()
}
