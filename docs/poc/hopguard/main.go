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
	"fmt"
	"math/rand/v2"
	"os"
	"slices"
	"strings"
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

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
		fmt.Println("HopGuard POC — IP TTL Fingerprinting for DNS Pollution Detection")
		fmt.Println("\nUsage: go run .")
		fmt.Println("\nCompares: Google directly (cold) vs Baidu warm-up → Google (armed).")
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

	fmt.Print("\033[2J\033[H")
	fmt.Println()
	fmt.Println(bold + cyan + "  ╔══════════════════════════════════════════════════════════════╗" + reset)
	fmt.Println(bold + cyan + "  ║       HopGuard — IP TTL Fingerprinting Anti-Pollution        ║" + reset)
	fmt.Println(bold + cyan + "  ╚══════════════════════════════════════════════════════════════╝" + reset)
	fmt.Println()
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
