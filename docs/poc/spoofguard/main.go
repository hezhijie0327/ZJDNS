// Spoofguard POC — UDP Multi-Read Loop for GFW Injection Detection
//
// Run with: go run .
//
// Concept:
//   GFW injects bare A/AAAA records into UDP DNS responses.
//   Real DNS servers include EDNS (OPT pseudo-record) per RFC 6891.
//   Spoofguard uses a multi-read loop: keep reading UDP datagrams,
//   reject GFW signatures (non-EDNS + single-answer), collect EDNS
//   candidates, then pick the richest after a collect window.
//
// Detection rules (mirrors server/upstream/plain/udp.go processPacket):
//   Fast-return: AN\u22652, NS>0, or AD=1 \u2192 authoritative, return immediately
//   EDNS-bearing \u2192 collect as candidate
//   Non-EDNS + single-answer \u2192 REJECT (canonical GFW signature)
//   Non-EDNS + CNAME/multi-answer \u2192 fallback (real server w/o EDNS)
//   After 500ms window: pick richest candidate, random tie-break

package main

import (
	"fmt"
	"math/rand/v2"
	"os"
	"strconv"
	"strings"
	"time"
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
		return r, green + "ACCEPT" + reset + " (non-NOERROR from real server)"
	}
	if r.hasEDNS {
		s.prev = s.last
		s.last = r
		s.candidates++
		return nil, yellow + "COLLECT" + reset + " (EDNS candidate #" + strconv.Itoa(s.candidates) + ")"
	}
	if r.hasCNAME || len(r.answers) >= 2 {
		s.nonEDNS = r
		return nil, yellow + "COLLECT" + reset + " (non-EDNS fallback)"
	}
	s.rejected++
	return nil, red + "REJECT" + reset + " (GFW: bare record, no EDNS, no CNAME)"
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

// ── Main ───────────────────────────────────────────────────────────

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
		fmt.Println("Spoofguard POC — UDP Multi-Read GFW Injection Detection")
		fmt.Println("\nUsage: go run .")
		return
	}

	fmt.Print("\033[2J\033[H")
	fmt.Println()
	fmt.Println(bold + cyan + "  \u2554══════════════════════════════════════════════════════════════╗" + reset)
	fmt.Println(bold + cyan + "  ║     Spoofguard — UDP Multi-Read GFW Injection Detection      ║" + reset)
	fmt.Println(bold + cyan + "  ╚══════════════════════════════════════════════════════════════╝" + reset)
	fmt.Println()

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
	fmt.Println("  GFW signature: bare A/AAAA, no EDNS, no CNAME \u2192 auto-reject")
	fmt.Println("  Real signal:   EDNS-bearing \u2192 collect as candidate")
	fmt.Println("  After 500ms:   compare candidates, pick richest")
	fmt.Println()
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
		fmt.Printf("  GFW fakes rejected: %s%d%s\n", red, state.rejected, reset)
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
		"First response", "GFW fake (30ms)", "GFW fake \u2192 REJECTED")
	fmt.Printf(dim+"  │ %-26s │ "+red+"%-28s"+reset+" │ "+green+"%-28s"+reset+" │"+reset+"\n",
		"Returned to client", "A 93.46.8.89 (fake)", "A 142.250.80.4 (real)")
	fmt.Printf(dim+"  │ %-26s │ "+red+"%-28s"+reset+" │ "+green+"%-28s"+reset+" │"+reset+"\n",
		"Detection method", "None — first wins", "EDNS gate + multi-read")
	fmt.Printf(dim+"  │ %-26s │ "+red+"%-28s"+reset+" │ "+green+"%-28s"+reset+" │"+reset+"\n",
		"GFW fakes filtered", "0 / 2", "2 / 2 rejected")
	fmt.Printf(dim+"  │ %-26s │ "+green+"%-28s"+reset+" │ "+yellow+"%-28s"+reset+" │"+reset+"\n",
		"Latency cost", "~30ms (first wins)", "+80ms (real @ 110ms)")

	fmt.Println(hr)
	fmt.Printf(dim+"  │ %-26s │ "+red+"%-28s"+reset+" │ "+green+"%-28s"+reset+" │"+reset+"\n",
		"Result", "POISONED", "CLEAN")
	fmt.Println(dim + "  └────────────────────────────┴──────────────────────────────┘" + reset)

	fmt.Println()
	fmt.Println(bold + "  How it works:" + reset)
	fmt.Println("  GFW injects bare A/AAAA records without EDNS — the signature")
	fmt.Println("  of DNS injection. Spoofguard reads all UDP datagrams in a")
	fmt.Println("  500ms window, filters by EDNS gate, and picks the richest")
	fmt.Println("  response. Real servers always include EDNS (RFC 6891).")
	fmt.Println()
}
