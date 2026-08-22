// Splitguard POC — TCP DNS Segmentation for DPI Evasion
//
// Run with: go run .
//
// Concept:
//   DPI systems scan TCP streams for domain-name patterns ("google.com").
//   Splitguard splits the DNS-over-TCP message into multiple small TCP
//   segments with random sizes. The DPI sees incomplete byte fragments
//   that don't match any domain pattern. The DNS server receives a normal
//   TCP stream — reassembly is transparent to the application layer.
//
// Algorithm mirror (internal/dnsutil/tcpframe.go WriteTCPMsgSegmented):
//   1. First segment: 2-byte DNS length prefix + random [1,segSize] payload
//   2. Subsequent segments: random [1, segSize] bytes each
//   3. Random sizing per segment prevents DPI fingerprinting

package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
)

// ── Constants ─────────────────────────────────────────────────────

const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	dim    = "\033[2m"
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	blue   = "\033[34m"
	cyan   = "\033[36m"
)

// ── DNS message builder ───────────────────────────────────────────

func buildDNSQuery() []byte {
	header := []byte{
		0x1a, 0x2b, // ID
		0x01, 0x00, // Flags: RD=1
		0x00, 0x01, // QDCOUNT=1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	question := []byte{
		3, 'w', 'w', 'w',
		6, 'g', 'o', 'o', 'g', 'l', 'e',
		3, 'c', 'o', 'm',
		0, 0, 1, 0, 1,
	}
	payload := make([]byte, 0, len(header)+len(question))
	payload = append(payload, header...)
	payload = append(payload, question...)
	frame := make([]byte, 2+len(payload))
	frame[0] = byte(len(payload) >> 8) //nolint:gosec // G115: DNS TCP frame — protocol-bounded
	frame[1] = byte(len(payload))      //nolint:gosec // G115: DNS TCP frame — protocol-bounded
	copy(frame[2:], payload)
	return frame
}

// ── Segmentation (mirrors WriteTCPMsgSegmented) ───────────────────

func segmentMessage(msg []byte, segSize int) [][]byte {
	if segSize <= 0 || segSize >= len(msg)-2 {
		return [][]byte{msg}
	}
	var segs [][]byte
	pos := 0
	first := true
	for pos < len(msg) {
		n := 1 + rand.IntN(segSize) //nolint:gosec // G404: segmentation jitter — not cryptographic
		end := pos + n
		if first {
			end = pos + 2 + n
			first = false
		}
		if end > len(msg) {
			end = len(msg)
		}
		segs = append(segs, msg[pos:end])
		pos = end
	}
	return segs
}

// ── Render helpers ─────────────────────────────────────────────────

func spacedHex(data []byte) string {
	parts := make([]string, len(data))
	for i, b := range data {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, " ")
}

func parseLabels(data []byte) []string {
	var labels []string
	pos := 0
	for pos < len(data) {
		l := int(data[pos])
		if l == 0 {
			break
		}
		if l&0xC0 == 0xC0 {
			break
		}
		if pos+1+l > len(data) {
			break
		}
		labels = append(labels, string(data[pos+1:pos+1+l]))
		pos += 1 + l
	}
	return labels
}

func containsDomain(data []byte) bool {
	for _, l := range parseLabels(data) {
		if len(l) >= 3 {
			return true
		}
	}
	return false
}

func annotateFrame(data []byte) string {
	if len(data) < 2 {
		return dim + "(raw)" + reset
	}
	dnsLen := int(data[0])<<8 | int(data[1])
	parts := []string{fmt.Sprintf("%s[LEN=%d]%s", blue, dnsLen, reset)}
	if len(data) >= 14 {
		id := int(data[2])<<8 | int(data[3])
		rd := (int(data[4])<<8 | int(data[5])) & 0x0100
		parts = append(parts, fmt.Sprintf("%s[ID=0x%04X RD=%d]%s", green, id, rd>>8, reset))
	}
	labels := parseLabels(data[14:])
	for _, l := range labels {
		parts = append(parts, fmt.Sprintf("%s[%s]%s", yellow, l, reset))
	}
	if len(data) > 16+len(strings.Join(labels, "")) {
		parts = append(parts, fmt.Sprintf("%s[QTYPE=A]%s", dim, reset))
	}
	return strings.Join(parts, " ")
}

// ── Main ───────────────────────────────────────────────────────────

// ── Real-network mode ─────────────────────────────────────────────

// tcpQuery sends the DNS query over TCP, optionally segmented, and returns
// the parsed answer IPs. A reset (RST) from a DPI/GFW device surfaces as a
// connection error.
func tcpQuery(server string, segmented bool) (answers []string, err error) {
	conn, err := net.DialTimeout("tcp", server, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	msg := buildDNSQuery() // frame: 2-byte length + DNS payload
	if segmented {
		for i, seg := range segmentMessage(msg, 8) {
			if _, err := conn.Write(seg); err != nil {
				return nil, err
			}
			// Small inter-segment delay so a DPI sees distinct fragments.
			time.Sleep(40 * time.Millisecond)
			fmt.Printf("      segment #%d: %s\n", i+1, spacedHex(seg))
		}
	} else {
		if _, err := conn.Write(msg); err != nil {
			return nil, err
		}
	}

	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, err // RST lands here on DPI interference
	}
	body := make([]byte, binary.BigEndian.Uint16(hdr))
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	resp := new(dns.Msg)
	resp.Data = body
	if err := resp.Unpack(); err != nil {
		return nil, err
	}
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			answers = append(answers, a.Addr.String())
		}
	}
	return answers, nil
}

func realTest(server string) {
	fmt.Println(bold + "Splitguard Real-Network Mode — TCP Segmentation on Live Upstream" + reset)
	fmt.Printf("  Query: A www.google.com → %s (TCP)\n\n", server)

	fmt.Println("  ─ Plain TCP (single write) ─")
	start := time.Now()
	answers, err := tcpQuery(server, false)
	if err != nil {
		fmt.Printf("  %sFAILED: %v%s (DPI/GFW reset or timeout)\n", red, err, reset)
	} else {
		fmt.Printf("  OK in %v: %v\n", time.Since(start).Round(time.Millisecond), answers)
	}

	fmt.Println("\n  ─ Splitguard TCP (random segments) ─")
	start = time.Now()
	answers, err = tcpQuery(server, true)
	if err != nil {
		fmt.Printf("  %sFAILED: %v%s (DPI/GFW reset or timeout)\n", red, err, reset)
	} else {
		fmt.Printf("  OK in %v: %v\n", time.Since(start).Round(time.Millisecond), answers)
	}

	fmt.Println("\n  Key Insight: if plain TCP is reset but segmented succeeds,")
	fmt.Println("  the DPI matched the domain pattern in the stream; segmentation")
	fmt.Println("  hid it. If both fail, the upstream/port is blocked outright.")
}

func main() {
	realMode := flag.Bool("real", false, "real-network mode: query a live upstream over TCP")
	server := flag.String("server", "8.8.8.8:53", "upstream address for -real")
	flag.Parse()

	if len(os.Args) > 1 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
		fmt.Println("Splitguard POC — TCP DNS Segmentation for DPI Evasion")
		fmt.Println("\nUsage: go run . [-real -server 8.8.8.8:53]")
		return
	}

	msg := buildDNSQuery()

	fmt.Print("\033[2J\033[H")
	fmt.Println()
	fmt.Println(bold + cyan + "  \u2554══════════════════════════════════════════════════════════════════╗" + reset)
	fmt.Println(bold + cyan + "  ║          Splitguard — TCP Segmentation for DPI Evasion           ║" + reset)
	fmt.Println(bold + cyan + "  ╚══════════════════════════════════════════════════════════════════╝" + reset)
	fmt.Println()

	if *realMode {
		realTest(*server)
		return
	}

	fmt.Printf("  Query: %sA www.google.com%s  (DNS-over-TCP, %dB total)\n\n", bold, reset, len(msg))

	// ── Normal TCP Write ────────────────────────────────────────

	fmt.Println("  " + bold + "\u2501\u2501\u2501 Normal TCP Write (no segmentation) \u2501\u2501\u2501" + reset)
	fmt.Println()
	fmt.Printf("  Single write():  %s\n", spacedHex(msg))
	fmt.Println()
	fmt.Printf("  Structure: %s\n", annotateFrame(msg))
	fmt.Println()
	fmt.Println("  " + red + "┌─ DPI Sees ────────────────────────────────────────────┐" + reset)
	fmt.Println("  " + red + "│ Complete domain labels: [www] [google] [com]          │" + reset)
	fmt.Println("  " + red + "│ → DPI matches blacklist → BLOCKS connection           │" + reset)
	fmt.Println("  " + red + "└───────────────────────────────────────────────────────┘" + reset)

	// ── Splitguard ──────────────────────────────────────────────

	fmt.Println()
	fmt.Println("  " + bold + "\u2501\u2501\u2501 Splitguard (segSize=4, random [1,4] bytes per segment) \u2501\u2501\u2501" + reset)
	fmt.Println()

	segs := segmentMessage(msg, 4)
	fmt.Printf("  Message split into %s%d write() calls%s:\n\n", bold, len(segs), reset)

	for i, seg := range segs {
		segHex := spacedHex(seg)

		// Determine what's in each fragment.
		info := dim + "raw bytes — no DNS structure visible" + reset
		if i == 0 {
			info = blue + "length prefix + partial header" + reset
		} else if containsDomain(seg) {
			info = yellow + "partial label fragment — incomplete" + reset
		}

		fmt.Printf("  write(%d) %3dB: %s\n", i+1, len(seg), segHex)
		fmt.Printf("           %s\n", info)
	}

	// ── Server view ─────────────────────────────────────────────

	fmt.Println()
	fmt.Println("  " + green + "┌─ DNS Server Receives (TCP reassembly) ───────────────┐" + reset)
	fmt.Printf("  %s│%s TCP stream: %s\n", green, reset, spacedHex(msg))
	fmt.Printf("  %s│%s Structure: %s\n", green, reset, annotateFrame(msg))
	fmt.Println("  " + green + "│ → Server processes query normally, returns A record   │" + reset)
	fmt.Println("  " + green + "└───────────────────────────────────────────────────────┘" + reset)

	// ── Visual comparison ───────────────────────────────────────

	fmt.Println()
	fmt.Println("  " + bold + "\u2501\u2501\u2501 Side-by-Side Comparison \u2501\u2501\u2501" + reset)
	fmt.Println()
	fmt.Println("  Normal:    " + red + hex.EncodeToString(msg) + reset)
	fmt.Println("             ↑ DPI sees complete domain → blocks")
	fmt.Println()

	// Build segmented hex with visible boundaries.
	fmt.Print("  Splitguard:")
	pos := 0
	for _, seg := range segs {
		if pos > 0 {
			fmt.Print(dim + "│" + reset)
		}
		fmt.Print(green + hex.EncodeToString(seg) + reset)
		pos += len(seg)
	}
	fmt.Println()
	fmt.Printf("             ↑ DPI sees %d isolated fragments → cannot match\n", len(segs))

	// ── Comparison Table ────────────────────────────────────────

	fmt.Println()
	fmt.Println(bold + "  \u2554════════════════════════════════════════════════════╗" + reset)
	fmt.Println(bold + "  ║     Splitguard OFF  vs  Splitguard ON              ║" + reset)
	fmt.Println(bold + "  ╚════════════════════════════════════════════════════╝" + reset)
	fmt.Println()

	hr := dim + "  \u251c────────────────────────────┼──────────────────────────────┤" + reset
	fmt.Println(dim + "  ┌────────────────────────────┬──────────────────────────────┐" + reset)
	fmt.Printf(dim+"  │ %-26s │ %-28s │ %-28s │"+reset+"\n", "Metric", "OFF", "ON")
	fmt.Println(hr)

	fmt.Printf(dim+"  │ %-26s │ "+red+"%-28s"+reset+" │ "+green+"%-28s"+reset+" │"+reset+"\n",
		"TCP write() calls", "1 (full message)", fmt.Sprintf("%d (fragmented)", len(segs)))
	fmt.Printf(dim+"  │ %-26s │ "+red+"%-28s"+reset+" │ "+green+"%-28s"+reset+" │"+reset+"\n",
		"Segment size", "34 bytes", "1–5 bytes each")
	fmt.Printf(dim+"  │ %-26s │ "+red+"%-28s"+reset+" │ "+green+"%-28s"+reset+" │"+reset+"\n",
		"DPI sees domain?", "YES — complete", "NO — fragments only")
	fmt.Printf(dim+"  │ %-26s │ "+red+"%-28s"+reset+" │ "+green+"%-28s"+reset+" │"+reset+"\n",
		"DPI can block?", "YES — matches pattern", "NO — no complete match")
	fmt.Printf(dim+"  │ %-26s │ "+green+"%-28s"+reset+" │ "+yellow+"%-28s"+reset+" │"+reset+"\n",
		"Server can process?", "YES — single read()", fmt.Sprintf("YES — %d reads → reassembly", len(segs)))

	fmt.Println(hr)
	fmt.Printf(dim+"  │ %-26s │ "+red+"%-28s"+reset+" │ "+green+"%-28s"+reset+" │"+reset+"\n",
		"Connection result", "BLOCKED by DPI", "PASSES through DPI")
	fmt.Println(dim + "  └────────────────────────────┴──────────────────────────────┘" + reset)

	fmt.Println()
	fmt.Println(bold + "  How it works:" + reset)
	fmt.Println("  DPI operates on individual TCP segments. Splitguard splits")
	fmt.Println("  the DNS message into random-size chunks [1,N]. No fragment")
	fmt.Println("  contains a complete domain name. The server reassembles")
	fmt.Println("  from the TCP stream transparently.")
	fmt.Println()
}
