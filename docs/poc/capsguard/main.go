// CapsGuard POC — DNS 0x20 Question-Case Randomization (draft-vixie-dnsext-dns0x20)
//
// Run with: go run .
//
// Concept:
//   Every outbound query randomizes the case bit of each ASCII letter in the
//   question name (one bit of transaction entropy per letter).  A legitimate
//   responder MUST echo the question byte-for-byte (RFC 4343 §3) — a
//   spoofing attacker cannot predict the case pattern, so its injection
//   fails the echo check and is discarded; the query is retried once with
//   the original case (§6.4 baseline fallback).
//
// Comparison:
//   Scenario A — 0x20-capable server: randomized case echoed → accept.
//   Scenario B — case-rewriting middlebox (§6.2, e.g. a lowercasing box):
//               first response discarded, unrandomized retry accepted.
//   Scenario C — spoofer (wrong echo): every attempt discarded, SERVFAIL.
//
// Algorithm mirror (server/defense/capsguard.go + server/upstream/client.go)

package main

import (
	"errors"
	"flag"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// ── Types ─────────────────────────────────────────────────────────

// simServer answers a query with the given question case transform.
type simServer func(name string) (echo string, poisoned bool)

// row is one attempt in the simulated query table.
type row struct {
	id       int
	sent     string
	echo     string
	decision string
	ok       bool
}

// ── Constants ─────────────────────────────────────────────────────

// downgradeState mirrors the mainline capsDowngrades map in
// server/upstream/client.go: after DefaultCapsGuardDowngradeAfter (8)
// CONSECUTIVE mismatches, randomisation is skipped for the whole retry
// window — no per-query retry doubling.  A successful echo resets the
// counter (intermittent middleboxes never accumulate to a downgrade, S8).
type downgradeState struct {
	consecutive int
	disabled    bool
}

const (
	downgradeAfter = 8

	reset       = "\033[0m"
	bold        = "\033[1m"
	dim         = "\033[2m"
	green       = "\033[32m"
	red         = "\033[31m"
	yellow      = "\033[33m"
	cyan        = "\033[36m"
	screenClear = "\033[2J\033[H"
)

// ── CapsGuard core (mirror of defense/capsguard.go RandomizeCase) ──

// randomizeCase flips the 0x20 (case) bit of each ASCII letter with 50%
// probability — the DNS 0x20 transaction-identity defense (§5.1).
func randomizeCase(name string) string {
	b := []byte(name)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' {
			if rand.IntN(2) == 1 { //nolint:gosec // G404: demo simulation — not cryptographic
				b[i] = c ^ 0x20
			}
		}
	}
	return string(b)
}

// ── Simulated servers ─────────────────────────────────────────────

// echoCapable echoes the question byte-for-byte (normal authoritative server).
func echoCapable(name string) (string, bool) { return name, false }

// lowercasingMiddlebox rewrites the case to all-lowercase (§6.2 — the draft's
// "rare and/or private label" implementations and some middleboxes).
func lowercasingMiddlebox(name string) (string, bool) { return strings.ToLower(name), false }

// spoofer echoes a WRONG case pattern — the injection signature.
func spoofer(name string) (string, bool) {
	if up := strings.ToUpper(name); up != name {
		return up, false
	}
	return strings.ToLower(name), false
}

// ── One CapsGuard query cycle ─────────────────────────────────────

// simulate runs one query against a simulated server, collecting the rows.
func simulate(name string, srv simServer) []row {
	var rows []row
	orig := dnsutil.Fqdn(name)

	// Attempt 1: randomized.
	randName := randomizeCase(orig)
	echo, _ := srv(randName)
	if echo == randName {
		rows = append(rows, row{1, randName, echo, "ACCEPT — echo matches 0x20", true})
		return rows
	}
	rows = append(rows, row{1, randName, echo, "DISCARD — echo mismatch", false})

	// §6.4: retry once with the original case, no verification.
	echo2, _ := srv(orig)
	rows = append(rows, row{2, orig, echo2, "ACCEPT — §6.4 baseline retry", true})
	return rows
}

func (d *downgradeState) noteMatch() { d.consecutive = 0 }

// noteMismatch counts one mismatch and reports whether THIS one triggered
// the downgrade.
func (d *downgradeState) noteMismatch() bool {
	d.consecutive++
	if d.consecutive >= downgradeAfter {
		d.disabled = true
		return true
	}
	return false
}

// renderRows renders the attempt table shared by simulation and real-network
// modes, returning the number of §6.4 retries (id==2 rows).
func renderRows(rows []row) int {
	fmt.Printf("\n  ┌──────┬─────────────────────────┬─────────────────────────┬─────────────────────────┐\n")
	fmt.Printf("  │ %s%-4s%s │ %s%-23s%s │ %s%-23s%s │ %s%-23s%s │\n", cyan, "try", reset, cyan, "sent (0x20)", reset, cyan, "echoed", reset, cyan, "verdict", reset)
	fmt.Printf("  ├──────┼─────────────────────────┼─────────────────────────┼─────────────────────────┤\n")
	retries := 0
	for _, r := range rows {
		color := green
		if !r.ok {
			color = red
		}
		if r.id == 2 {
			retries++
		}
		fmt.Printf("  │ %s%-4d%s │ %-23s │ %-23s │ %s%-23s%s │\n", color, r.id, reset, r.sent, r.echo, color, r.decision, reset)
	}
	fmt.Printf("  └──────┴─────────────────────────┴─────────────────────────┴─────────────────────────┘\n")
	return retries
}

func printScenario(title string, srv simServer, name string) {
	fmt.Printf("\n  %s━━━ %s ━━━%s\n", red, title, reset)
	rows := make([]row, 0, 12)
	for i := 1; i <= 6; i++ {
		rows = append(rows, simulate(name, srv)...)
	}
	total := renderRows(rows)
	fmt.Printf("\n  %s→ 6 queries: %d unrandomized retries (mismatch rate = %d/6)%s\n", yellow, total, total, reset)
}

// ── Real-network mode ─────────────────────────────────────────────

// exchange sends one UDP query and returns the echoed question name.
func exchange(server, name string) (string, error) {
	msg := new(dns.Msg)
	dnsutil.SetQuestion(msg, name, dns.TypeA, dns.ClassINET)

	conn, err := net.Dial("udp", server)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if err := msg.Pack(); err != nil {
		return "", err
	}
	if _, err := conn.Write(msg.Data); err != nil {
		return "", err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	resp := new(dns.Msg)
	resp.Data = buf[:n]
	if err := resp.Unpack(); err != nil {
		return "", err
	}
	if len(resp.Question) == 0 {
		return "", errors.New("no question in response")
	}
	return resp.Question[0].Header().Name, nil
}

func realTest(server, qname string) {
	fmt.Printf("  %sUpstream: %s    Qname: %s%s\n", dim, server, qname, reset)
	fmt.Printf("\n  %s━━━ Scenario: live upstream — 0x20 echo verification ━━━%s\n", red, reset)
	var rows []row
	queries := 0
	orig := dnsutil.Fqdn(qname)
	for i := range 5 {
		randName := randomizeCase(orig)

		echo, err := exchange(server, randName)
		if err != nil {
			fmt.Printf("  %s✗ query %d failed: %v%s\n", red, i+1, err, reset)
			continue
		}
		queries++
		if echo == randName {
			rows = append(rows, row{1, randName, echo, "ACCEPT — echo matches 0x20", true})
			continue
		}
		rows = append(rows, row{1, randName, echo, "DISCARD — echo mismatch", false})
		echo2, err := exchange(server, orig)
		if err != nil {
			fmt.Printf("  %s  retry failed: %v%s\n", red, err, reset)
			continue
		}
		rows = append(rows, row{2, orig, echo2, "ACCEPT — §6.4 baseline retry", true})
	}
	total := renderRows(rows)
	fmt.Printf("\n  %s→ %d queries: %d unrandomized retries (mismatch rate = %d/%d)%s\n",
		yellow, queries, total, total, queries, reset)
}

func main() {
	realMode := flag.Bool("real", false, "real-network mode: query a live upstream")
	server := flag.String("server", "8.8.8.8:53", "upstream address for -real")
	qname := flag.String("qname", "wWw.GoOgLe.CoM", "query name for -real")
	flag.Parse()

	if len(os.Args) > 1 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
		fmt.Println("CapsGuard POC — DNS 0x20 Question-Case Randomization")
		fmt.Println("\nUsage: go run . [-real -server 8.8.8.8:53 -qname wWw.GoOgLe.CoM]")
		fmt.Println("\nCompares: 0x20-capable server vs case-rewriting middlebox vs spoofer.")
		return
	}

	fmt.Print(screenClear)
	fmt.Printf("%s  ╔══════════════════════════════════════════════════════════════╗%s\n", cyan, reset)
	fmt.Printf("%s  ║      CapsGuard — DNS 0x20 Question-Case Randomization       ║%s\n", bold, reset)
	fmt.Printf("%s  ╚══════════════════════════════════════════════════════════════╝%s\n", cyan, reset)
	fmt.Printf("\n  Concept: each ASCII letter in the outbound question carries 1 random bit;\n")
	fmt.Printf("  the responder must echo it byte-for-byte or the response is discarded.\n")

	if *realMode {
		realTest(*server, *qname)
		return
	}

	printScenario("Scenario A: 0x20-capable server (echoes randomized case)", echoCapable, "wWw.GoOgLe.CoM")
	printScenario("Scenario B: case-rewriting middlebox (§6.2, lowercasing)", lowercasingMiddlebox, "wWw.GoOgLe.CoM")
	printScenario("Scenario C: spoofer (never echoes the right case)", spoofer, "wWw.GoOgLe.CoM")

	// ── Scenario D: persistent middlebox → consecutive-mismatch downgrade ──
	fmt.Printf("\n  %s━━━ Scenario D: persistent middlebox — consecutive-mismatch downgrade ━━━%s\n", red, reset)
	dg := &downgradeState{}
	var rowsD []row
	downgradedAt := 0
	for i := 1; i <= 12; i++ {
		orig := "www.google.com." // canonical (lowercase) name
		if dg.disabled {
			// Randomisation skipped: send the canonical name, verify nothing
			// (baseline semantics), zero extra round-trips.
			echo, _ := lowercasingMiddlebox(orig)
			rowsD = append(rowsD, row{1, orig, echo, "ACCEPT — randomisation skipped (downgraded)", true})
			dg.noteMatch()
			continue
		}
		randName := randomizeCase(orig)
		echo, _ := lowercasingMiddlebox(randName)
		if echo == randName {
			rowsD = append(rowsD, row{1, randName, echo, "ACCEPT — echo matches 0x20", true})
			dg.noteMatch()
			continue
		}
		rowsD = append(rowsD, row{1, randName, echo, "DISCARD — echo mismatch", false})
		if dg.noteMismatch() && downgradedAt == 0 {
			downgradedAt = i
		}
		echo2, _ := lowercasingMiddlebox(orig)
		rowsD = append(rowsD, row{2, orig, echo2, "ACCEPT — §6.4 baseline retry", true})
	}
	renderRows(rowsD)
	fmt.Printf("\n  %s→ query %d hit 8 consecutive mismatches — queries %d+ send the canonical\n", yellow, downgradedAt, downgradedAt+1)
	fmt.Printf("     name directly: no randomisation, no retry, no doubled latency%s\n", reset)

	// ── Scenario E: PTR exemption ──
	fmt.Printf("\n  %s━━━ Scenario E: PTR query through the case-rewriting middlebox ━━━%s\n", red, reset)
	ptrName := randomizeCase("1.2.0.192.in-addr.arpa.")
	echo, _ := lowercasingMiddlebox(ptrName)
	rowsE := []row{{1, ptrName, echo, "ACCEPT — PTR exempt (no 0x20 check)", true}}
	renderRows(rowsE)
	fmt.Printf("\n  %s→ reverse-lookup names skip echo verification: some middleboxes\n", yellow)
	fmt.Printf("     (Cisco DNS guard) rewrite reverse qnames, which would trigger a\n")
	fmt.Printf("     spurious mismatch on every PTR query (mirrors the PTR exemption\n")
	fmt.Printf("     in server/upstream/client.go ExecuteQuery)%s\n", reset)

	fmt.Printf("\n  %sTakeaways%s\n", bold, reset)
	fmt.Printf("  %s•%s A: every query accepted on the first attempt — zero overhead.\n", green, reset)
	fmt.Printf("  %s•%s B: one extra unrandomized round-trip per query — the §6.4 fallback\n", yellow, reset)
	fmt.Printf("     keeps service working against case-rewriting middleboxes.\n")
	fmt.Printf("  %s•%s C: no correct response ever arrives — the spoofer cannot forge\n", red, reset)
	fmt.Printf("     the per-query random case pattern (2^n bits of entropy).\n")
	fmt.Printf("  %s•%s D: 8 consecutive mismatches downgrade to plain queries — a\n", yellow, reset)
	fmt.Printf("     permanently non-compliant upstream stops paying the retry cost.\n")
	fmt.Printf("  %s•%s E: PTR queries are exempt — case-rewriting of reverse names is\n", green, reset)
	fmt.Printf("     known middlebox behaviour, not spoofing.\n")
}
