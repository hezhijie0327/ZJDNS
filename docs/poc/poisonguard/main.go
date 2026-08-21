// Poisonguard POC — Root/TLD Hijack Detection for the Recursive Walk
//
// Run with: go run .
//
// Concept:
//   GFW injects bare A/AAAA records into UDP DNS responses — including
//   responses from root and TLD servers, which would NEVER legitimately
//   return data records for a subdomain.  Poisonguard validates that a
//   server claiming authority for a zone does not answer outside its
//   delegated authority, and forces a UDP→TCP retry on detection (GFW
//   cannot forge TCP responses).
//
// Algorithm mirror (server/defense/poisonguard.go):
//   classifyRoot:  root-servers.net glue, TLD NS/DS + DNSSEC proofs → clean;
//                  any other data record for a subdomain → POISONED
//   classifyTLD:   TLD apex → clean; child delegation/proof → clean;
//                  data records for a child name → POISONED
//   authoritative: content cannot distinguish real from injected → UNCERTAIN
//                  (the blind spot — spoofguard's re-query confirmation
//                   covers it)
//   TLD probe (IsPoisonedByTLD): full qname to a TLD server; A/AAAA for the
//                  qname → POISONED → force the whole walk over TCP
//   RRSIG exemption: an answer carrying a matching RRSIG cannot be forged
//                  (DNSSEC-signed data is not GFW-injectable)

package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// ── Types ─────────────────────────────────────────────────────────

type verdict int

type simRR struct {
	name  string
	rtype string // "A", "AAAA", "NS", "DS", "RRSIG", "NSEC", "NSEC3", ...
}

type simResp struct {
	answer []simRR
}

type detector struct{}

const (
	clean verdict = iota
	poisoned
	uncertain
)

const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	dim    = "\033[2m"
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	cyan   = "\033[36m"
)

const rootServersDomain = "root-servers.net"

func (v verdict) String() string {
	switch v {
	case clean:
		return "CLEAN"
	case poisoned:
		return "POISONED"
	default:
		return "UNCERTAIN"
	}
}

// ── Poisonguard Core (mirrors server/defense/poisonguard.go) ───────

func delegationOrProof(rtype string) bool {
	switch rtype {
	case "NS", "DS", "RRSIG", "NSEC", "NSEC3":
		return true
	}
	return false
}

func isTLD(domain string) bool {
	domain = strings.TrimSuffix(domain, ".")
	return domain != "" && !strings.Contains(domain, ".")
}

func isRootServerDomain(domain string) bool {
	return domain == rootServersDomain || strings.HasSuffix(domain, "."+rootServersDomain)
}

// classifyRoot: root servers only answer with glue for their own hostnames,
// TLD delegations (NS/DS), and DNSSEC proofs.
func (d *detector) classifyRoot(name, rtype string) verdict {
	if isRootServerDomain(name) {
		return clean
	}
	if delegationOrProof(rtype) && isTLD(name) {
		return clean
	}
	if name != "." {
		return poisoned
	}
	return clean
}

// classifyTLD: TLD servers answer for their own apex, delegations, and
// DNSSEC proofs — never data records for a child name.
func (d *detector) classifyTLD(zone, name, rtype string) verdict {
	if name != zone {
		if delegationOrProof(rtype) && (name == zone+"." || strings.HasSuffix(name, "."+zone)) {
			return clean
		}
		return poisoned
	}
	return clean
}

// validate mirrors Detector.Validate: only Answer records matching the query
// name are inspected; a matching RRSIG exempts a poison candidate.
func (d *detector) validate(zone, qname string, resp *simResp) verdict {
	qname = strings.ToLower(strings.TrimSuffix(qname, "."))
	hasSig := false
	for _, rr := range resp.answer {
		if rr.rtype == "RRSIG" && strings.TrimSuffix(strings.ToLower(rr.name), ".") == qname {
			hasSig = true
			break
		}
	}
	for _, rr := range resp.answer {
		if strings.TrimSuffix(strings.ToLower(rr.name), ".") != qname {
			continue
		}
		var v verdict
		switch {
		case zone == ".":
			v = d.classifyRoot(rr.name, rr.rtype)
		case isTLD(zone):
			v = d.classifyTLD(strings.TrimSuffix(zone, "."), strings.TrimSuffix(rr.name, "."), rr.rtype)
		default:
			v = uncertain
		}
		if v != clean {
			if v == poisoned && hasSig {
				return clean // RRSIG-bearing — DNSSEC-signed, cannot be forged
			}
			return v
		}
	}
	return clean
}

// isPoisonedByTLD mirrors Detector.IsPoisonedByTLD.
func (d *detector) isPoisonedByTLD(resp *simResp, qname string) bool {
	n := strings.TrimSuffix(strings.ToLower(qname), ".")
	if isRootServerDomain(n) || isTLD(n) {
		return false
	}
	for _, rr := range resp.answer {
		if strings.TrimSuffix(strings.ToLower(rr.name), ".") != n {
			continue
		}
		if rr.rtype == "A" || rr.rtype == "AAAA" {
			return true
		}
	}
	return false
}

// ── Render helpers ─────────────────────────────────────────────────

func printHR() { fmt.Println("  " + dim + strings.Repeat("\u2500", 66) + reset) }

func verdictColor(v verdict) string {
	switch v {
	case clean:
		return green
	case poisoned:
		return red
	default:
		return yellow
	}
}

// ── Main ───────────────────────────────────────────────────────────

// ── Real-network mode ─────────────────────────────────────────────

// realQuery sends a non-recursive query (RD=0) to a root/TLD server and
// converts the answer section into simRR for the shared detector. A root or
// TLD server must never return data records for a subdomain — if it does
// (GFW injection), the detector flags it poisoned.
func realQuery(server, qname string) ([]simRR, error) {
	conn, err := net.DialTimeout("udp", server, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	msg := new(dns.Msg)
	dnsutil.SetQuestion(msg, dnsutil.Fqdn(qname), dns.TypeA)
	msg.RecursionDesired = false // TLD/root servers only answer authoritatively
	msg.UDPSize = 1232
	if err := msg.Pack(); err != nil {
		return nil, err
	}
	if _, err := conn.Write(msg.Data); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	resp := new(dns.Msg)
	resp.Data = buf[:n]
	if err := resp.Unpack(); err != nil {
		return nil, err
	}
	var out []simRR
	for _, rr := range resp.Answer {
		out = append(out, simRR{name: rr.Header().Name, rtype: dns.TypeToString[dns.RRToType(rr)]})
	}
	return out, nil
}

func realTest(qname string) {
	fmt.Println(bold + "Poisonguard Real-Network Mode — Root/TLD Responses on Live Servers" + reset)
	fmt.Printf("  Query: A %s (RD=0) — data records from root/TLD = injected\n\n", qname)

	d := &detector{}
	for _, target := range []struct{ label, addr string }{
		{"root server (a.root-servers.net)", "198.41.0.4:53"},
		{"TLD server (a.gtld-servers.net)", "192.5.6.30:53"},
	} {
		fmt.Printf("  ─ %s ─\n", target.label)
		rrset, err := realQuery(target.addr, qname)
		if err != nil {
			fmt.Printf("  %squery failed: %v%s\n", red, err, reset)
			continue
		}
		if len(rrset) == 0 {
			fmt.Printf("  no answer records (referral/empty) — %sclean%s\n", green, reset)
			continue
		}
		for _, rr := range rrset {
			v := d.validate(".", qname, &simResp{answer: []simRR{rr}})
			mark := green + "clean" + reset
			if v == poisoned {
				mark = red + "POISONED" + reset
			}
			fmt.Printf("  %-12s %-6s → %s\n", rr.name, rr.rtype, mark)
		}
	}
	fmt.Println("\n  Note: an A record in a root/TLD response for a subdomain is")
	fmt.Println("  GFW injection — legitimately it can only be a referral (NS/glue).")
}

func main() {
	realMode := flag.Bool("real", false, "real-network mode: query root/TLD servers")
	qname := flag.String("qname", "www.google.com", "query name for -real")
	flag.Parse()

	if len(os.Args) > 1 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
		fmt.Println("Poisonguard POC — Root/TLD Hijack Detection")
		fmt.Println("\nUsage: go run . [-real -qname www.google.com]")
		return
	}

	if *realMode {
		realTest(*qname)
		return
	}

	d := &detector{}

	fmt.Print("\033[2J\033[H")
	fmt.Println()
	fmt.Println(bold + cyan + "  \u2554══════════════════════════════════════════════════════════════╗" + reset)
	fmt.Println(bold + cyan + "  ║    Poisonguard — Root/TLD Hijack Detection (recursive walk)  ║" + reset)
	fmt.Println(bold + cyan + "  ╚══════════════════════════════════════════════════════════════╝" + reset)
	fmt.Println()
	fmt.Println("  GFW pattern (measured): bare A/AAAA injected at root, TLD, and")
	fmt.Println("  authoritative levels; root/TLD levels never legitimately return")
	fmt.Println("  data records for a subdomain — so injection there is unambiguous.")
	fmt.Println()

	// ── Scenario 1: root-level fake ──

	fmt.Printf("  %sScenario 1:%s root server returns a fake A for a subdomain\n", bold, reset)
	fmt.Printf("  Query: %sA www.google.com%s \u2192 root server\n\n", bold, reset)
	fake := &simResp{answer: []simRR{{name: "www.google.com.", rtype: "A"}}}
	v := d.validate(".", "www.google.com.", fake)
	fmt.Printf("  %sVerdict: %s%s%s \u2192 restart the walk over TCP%s\n",
		bold, verdictColor(v), v, reset, reset)
	fmt.Println()

	// ── Scenario 2: TLD-level fake ──

	fmt.Printf("  %sScenario 2:%s TLD (com) server returns a fake A for a subdomain\n", bold, reset)
	fmt.Printf("  Query: %sA www.google.com%s \u2192 com server\n\n", bold, reset)
	v = d.validate("com.", "www.google.com.", fake)
	fmt.Printf("  %sVerdict: %s%s%s \u2192 restart the walk over TCP%s\n",
		bold, verdictColor(v), v, reset, reset)
	fmt.Println()

	// ── Scenario 3: legitimate root delegation (no false positive) ──

	fmt.Printf("  %sScenario 3:%s legitimate root delegations stay clean\n", bold, reset)
	rootOK := &simResp{answer: []simRR{
		{name: "com.", rtype: "NS"},
		{name: "com.", rtype: "RRSIG"},
		{name: "a.root-servers.net.", rtype: "A"}, // glue for a root hostname
	}}
	v = d.validate(".", "com.", rootOK)
	fmt.Printf("  %sVerdict: %s%s%s (NS delegation + RRSIG + root glue — legitimate)%s\n",
		bold, verdictColor(v), v, reset, reset)
	fmt.Println()

	// ── Scenario 4: legitimate TLD DS delegation (no false positive) ──

	fmt.Printf("  %sScenario 4:%s TLD returns DS for a signed child\n", bold, reset)
	tldOK := &simResp{answer: []simRR{{name: "google.com.", rtype: "DS"}}}
	v = d.validate("com.", "google.com.", tldOK)
	fmt.Printf("  %sVerdict: %s%s%s (child DS delegation — legitimate)%s\n",
		bold, verdictColor(v), v, reset, reset)
	fmt.Println()

	// ── Scenario 5: authoritative-level blind spot ──

	fmt.Printf("  %sScenario 5:%s authoritative server returns a fake A — the blind spot\n", bold, reset)
	v = d.validate("google.com.", "www.google.com.", fake)
	fmt.Printf("  %sVerdict: %s%s%s \u2192 content cannot distinguish real from injected;\n", bold, verdictColor(v), v, reset)
	fmt.Println("           covered by spoofguard's re-query confirmation (pure UDP).")
	fmt.Println()

	// ── Scenario 6: RRSIG exemption ──

	fmt.Printf("  %sScenario 6:%s signed answer — not GFW-forgeable\n", bold, reset)
	signed := &simResp{answer: []simRR{
		{name: "www.google.com.", rtype: "A"},
		{name: "www.google.com.", rtype: "RRSIG"},
	}}
	v = d.validate("com.", "www.google.com.", signed)
	fmt.Printf("  %sVerdict: %s%s%s (matching RRSIG exempts the candidate)%s\n",
		bold, verdictColor(v), v, reset, reset)
	fmt.Println()

	// ── Scenario 7: TLD probe ──

	fmt.Printf("  %sScenario 7:%s TLD probe — full qname sent to the TLD server\n", bold, reset)
	probeHit := d.isPoisonedByTLD(fake, "www.google.com.")
	probeClean := d.isPoisonedByTLD(rootOK, "www.google.com.")
	probeColor := func(b bool) string {
		if b {
			return red
		}
		return green
	}
	fmt.Printf("  Injected A for the qname \u2192 force TCP: %s%v%s\n", probeColor(probeHit), probeHit, reset)
	fmt.Printf("  Legitimate referral       \u2192 no flag:     %s%v%s\n", probeColor(probeClean), probeClean, reset)
	fmt.Println()

	// ── Summary Table ──

	fmt.Println()
	fmt.Println(bold + "  \u2554════════════════════════════════════════════════════╗" + reset)
	fmt.Println(bold + "  ║     Poisonguard — Detection Summary                ║" + reset)
	fmt.Println(bold + "  ╚════════════════════════════════════════════════════╝" + reset)
	fmt.Println()
	printHR()
	fmt.Printf(dim+"  │ %-42s │ %-20s │"+reset+"\n", "Case", "Verdict")
	printHR()
	fmt.Printf(dim+"  │ %-42s │ "+red+"%-20s"+reset+" │"+reset+"\n", "Root server A for subdomain", "POISONED")
	fmt.Printf(dim+"  │ %-42s │ "+red+"%-20s"+reset+" │"+reset+"\n", "TLD server A/AAAA/CNAME for child", "POISONED")
	fmt.Printf(dim+"  │ %-42s │ "+green+"%-20s"+reset+" │"+reset+"\n", "Root NS/DS delegation + proofs", "CLEAN")
	fmt.Printf(dim+"  │ %-42s │ "+green+"%-20s"+reset+" │"+reset+"\n", "TLD DS for signed child", "CLEAN")
	fmt.Printf(dim+"  │ %-42s │ "+green+"%-20s"+reset+" │"+reset+"\n", "Signed answer (RRSIG present)", "CLEAN")
	fmt.Printf(dim+"  │ %-42s │ "+yellow+"%-20s"+reset+" │"+reset+"\n", "Authoritative A (real or fake)", "UNCERTAIN")
	printHR()
	fmt.Println()
	fmt.Println("  How it works: the recursive walk knows WHICH server it is talking to")
	fmt.Println("  (root / TLD / authoritative). Root and TLD servers must never return")
	fmt.Println("  data records for a subdomain — the observed GFW signature. Detection")
	fmt.Println("  forces a UDP\u2192TCP retry; the authoritative blind spot is covered by")
	fmt.Println("  spoofguard (re-query confirmation) and hopguard (TTL fingerprint).")
	fmt.Println()
}
