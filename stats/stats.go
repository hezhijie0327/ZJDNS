// Package stats provides best-effort in-memory DNS query statistics with
// latency histogram. All counters are atomic — Record() is lock-free.
// No composite keys, no maps, just flat counters per dimension.
package stats

import (
	"fmt"
	"strings"
	"sync/atomic"
	"zjdns/internal/log"
	"zjdns/internal/lrumap"

	"codeberg.org/miekg/dns"
)

// Request holds per-query metadata for stats aggregation.
type Request struct {
	Protocol     string
	Result       string
	ResponseTime int64
	Rcode        int
	DNSSECStatus string
	Poisoned     bool
}

// Collector aggregates DNS query statistics in memory.
type Collector struct {
	startTime  atomic.Int64 // unix seconds when counters were last reset
	total      atomic.Int64
	totalMS    atomic.Int64
	hit        atomic.Int64
	miss       atomic.Int64
	stale      atomic.Int64
	zone       atomic.Int64
	blocked    atomic.Int64
	badcookie  atomic.Int64
	errorCount atomic.Int64

	udp, tcp, tls, quic, https, http3, dtls      atomic.Int64
	dnscrypt, dnscryptTCP, tlcp, httpTLCP, dtlcp atomic.Int64

	secure, insecure, bogus atomic.Int64
	poisoned                atomic.Int64

	prefetch atomic.Int64

	// rCode covers all rcodes this server can produce, including BADCOOKIE
	// (23) — narrower arrays silently dropped them from the rcode line.
	rCode [24]atomic.Int64

	latCounts [latBuckets]atomic.Int64
	latTotal  atomic.Int64

	// persist is the lrumap-backed snapshot store; nil until SetPersist.
	// Record() never touches it — only SavePersist / SetPersist do.
	persist *lrumap.Map[string, []int64]
}

type metric struct {
	name  string
	count int64
	pct   float64
}

const latBuckets = 12

var latBounds = [latBuckets]int64{1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000}

// New creates a Collector.
func New() *Collector {
	c := &Collector{}
	c.startTime.Store(log.NowUnix())
	return c
}

// Record increments counters for a single request. Fully lock-free.
func (c *Collector) Record(r *Request) {
	if c == nil || r == nil {
		return
	}
	c.total.Add(1)
	c.totalMS.Add(r.ResponseTime)

	switch r.Result {
	case "hit":
		c.hit.Add(1)
	case "miss":
		c.miss.Add(1)
	case "stale":
		c.stale.Add(1)
	case "zone":
		c.zone.Add(1)
	case "blocked":
		c.blocked.Add(1)
	case "badcookie":
		c.badcookie.Add(1)
	case "prefetch":
		c.prefetch.Add(1)
	case "error":
		c.errorCount.Add(1)
	}

	// Prefetch is a background operation — no protocol, rcode, or DNSSEC context.
	if r.Result == "prefetch" {
		return
	}

	switch r.Protocol {
	case "udp":
		c.udp.Add(1)
	case "tcp":
		c.tcp.Add(1)
	case "tls":
		c.tls.Add(1)
	case "quic":
		c.quic.Add(1)
	case "https":
		c.https.Add(1)
	case "http3":
		c.http3.Add(1)
	case "dtls":
		c.dtls.Add(1)
	case "dnscrypt":
		c.dnscrypt.Add(1)
	case "dnscrypt-tcp":
		c.dnscryptTCP.Add(1)
	case "tlcp":
		c.tlcp.Add(1)
	case "http-tlcp":
		c.httpTLCP.Add(1)
	case "dtlcp":
		c.dtlcp.Add(1)
	}

	switch r.DNSSECStatus {
	case "secure":
		c.secure.Add(1)
	case "insecure":
		c.insecure.Add(1)
	case "bogus":
		c.bogus.Add(1)
	}
	if r.Poisoned {
		c.poisoned.Add(1)
	}

	if r.Rcode >= 0 && r.Rcode < len(c.rCode) {
		c.rCode[r.Rcode].Add(1)
	}

	for i, b := range latBounds {
		if r.ResponseTime <= b {
			c.latCounts[i].Add(1)
			break
		}
	}
	if r.ResponseTime > latBounds[len(latBounds)-1] {
		c.latCounts[len(latBounds)-1].Add(1)
	}
	c.latTotal.Add(1)
}

func formatLine(metrics ...metric) string {
	n := 0
	for _, m := range metrics {
		if m.count != 0 {
			n++
		}
	}
	if n == 0 {
		return ""
	}
	// Pre-size: name + = + count + ( + pct + %) + " " separator ≈ 40 chars/entry.
	var b strings.Builder
	b.Grow(n * 40)
	for _, m := range metrics {
		if m.count == 0 {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%s=%d(%.1f%%)", m.name, m.count, m.pct)
	}
	return b.String()
}

// Stats returns all statistics in a compact multi-line format.
//
// Best-effort snapshot: each counter is loaded individually, so concurrent
// Record()/Reset() calls can make category percentages disagree slightly with
// the total. This is a monitoring view, not a transactional report.
func (c *Collector) Stats() []string {
	total := c.total.Load()
	totalMS := c.totalMS.Load()

	// Result counters.
	h, m, s, pf, z := c.hit.Load(), c.miss.Load(), c.stale.Load(), c.prefetch.Load(), c.zone.Load()
	b, bc, errC := c.blocked.Load(), c.badcookie.Load(), c.errorCount.Load()

	// Rcodes.
	noerr, formerr, servfail, nx, nimp, ref := c.rCode[0].Load(), c.rCode[1].Load(), c.rCode[2].Load(),
		c.rCode[3].Load(), c.rCode[4].Load(), c.rCode[5].Load()
	badcookieRC := c.rCode[dns.RcodeBadCookie].Load()

	// Transport protocols.
	udp, tcpN, tls, quic, https, http3, dtls := c.udp.Load(), c.tcp.Load(), c.tls.Load(), c.quic.Load(), c.https.Load(), c.http3.Load(), c.dtls.Load()
	dnscrypt, dnscryptTCP, tlcp, httpTLCP, dtlcp := c.dnscrypt.Load(), c.dnscryptTCP.Load(), c.tlcp.Load(), c.httpTLCP.Load(), c.dtlcp.Load()

	// DNSSEC + independent counters.
	sec, ins, bog := c.secure.Load(), c.insecure.Load(), c.bogus.Load()
	pois := c.poisoned.Load()
	// Zeroed before conditional fill to avoid NaN in output.
	hitR, missR, staleR, pfR, zoneR, blockedR, badcookieR, errorR := float64(0), float64(0), float64(0), float64(0), float64(0), float64(0), float64(0), float64(0)
	noerrR, formerrR, servfailR, nxR, nimpR, refR := float64(0), float64(0), float64(0), float64(0), float64(0), float64(0)
	udpR, tcpR, tlsR, quicR, httpsR, http3R, dtlsR := float64(0), float64(0), float64(0), float64(0), float64(0), float64(0), float64(0)
	dnscryptR, dnscryptTCPR, tlcpR, httpTLCPR, dtlcpR := float64(0), float64(0), float64(0), float64(0), float64(0)
	secR, insR, bogR, poisR := float64(0), float64(0), float64(0), float64(0)
	if total > 0 {
		t := float64(total)
		hitR, missR, staleR, pfR, zoneR = float64(h)/t*100, float64(m)/t*100, float64(s)/t*100, float64(pf)/t*100, float64(z)/t*100
		blockedR, badcookieR, errorR = float64(b)/t*100, float64(bc)/t*100, float64(errC)/t*100
		noerrR, formerrR, servfailR, nxR, nimpR, refR = float64(noerr)/t*100, float64(formerr)/t*100, float64(servfail)/t*100, float64(nx)/t*100, float64(nimp)/t*100, float64(ref)/t*100
		udpR, tcpR, tlsR, quicR, httpsR, http3R, dtlsR = float64(udp)/t*100, float64(tcpN)/t*100, float64(tls)/t*100, float64(quic)/t*100, float64(https)/t*100, float64(http3)/t*100, float64(dtls)/t*100
		dnscryptR, dnscryptTCPR, tlcpR, httpTLCPR, dtlcpR = float64(dnscrypt)/t*100, float64(dnscryptTCP)/t*100, float64(tlcp)/t*100, float64(httpTLCP)/t*100, float64(dtlcp)/t*100
		poisR = float64(pois) / t * 100
	}
	if dnssecTotal := sec + ins + bog; dnssecTotal > 0 {
		dt := float64(dnssecTotal)
		secR, insR, bogR = float64(sec)/dt*100, float64(ins)/dt*100, float64(bog)/dt*100
	}
	qps := float64(0)
	if elapsed := log.NowUnix() - c.startTime.Load(); elapsed > 0 {
		qps = float64(total) / float64(elapsed)
	}
	out := make([]string, 0, 8)

	// QPS + Latency percentiles + mean (always shown).
	avg := float64(0)
	if total > 0 {
		avg = float64(totalMS) / float64(total)
	}
	out = append(out, fmt.Sprintf("qps=%.1f/s avg=%.0fms p50=%.0fms p95=%.0fms p99=%.0fms",
		qps, avg, c.percentile(50), c.percentile(95), c.percentile(99)))

	// Results — omit zero-count entries.
	if s := formatLine(
		metric{"hit", h, hitR}, metric{"miss", m, missR}, metric{"stale", s, staleR},
		metric{"prefetch", pf, pfR}, metric{"zone", z, zoneR},
		metric{"blocked", b, blockedR}, metric{"badcookie", bc, badcookieR}, metric{"error", errC, errorR},
	); s != "" {
		out = append(out, s)
	}

	// Rcodes (BADCOOKIE 23 is counted separately when present).
	if s := formatLine(
		metric{"noerr", noerr, noerrR}, metric{"formerr", formerr, formerrR},
		metric{"servfail", servfail, servfailR}, metric{"nx", nx, nxR},
		metric{"nimp", nimp, nimpR}, metric{"ref", ref, refR},
		metric{"badcookie", badcookieRC, float64(badcookieRC) / float64(total) * 100},
	); s != "" {
		out = append(out, s)
	}

	// Transport protocols.
	if s := formatLine(
		metric{"udp", udp, udpR}, metric{"tcp", tcpN, tcpR}, metric{"tls", tls, tlsR},
		metric{"quic", quic, quicR}, metric{"https", https, httpsR}, metric{"http3", http3, http3R},
		metric{"dtls", dtls, dtlsR}, metric{"dnscrypt", dnscrypt, dnscryptR},
		metric{"dnscrypt-tcp", dnscryptTCP, dnscryptTCPR}, metric{"tlcp", tlcp, tlcpR},
		metric{"http-tlcp", httpTLCP, httpTLCPR}, metric{"dtlcp", dtlcp, dtlcpR},
	); s != "" {
		out = append(out, s)
	}

	// DNSSEC.
	if s := formatLine(
		metric{"secure", sec, secR}, metric{"insecure", ins, insR}, metric{"bogus", bog, bogR},
	); s != "" {
		out = append(out, s)
	}

	// Poisoned.
	if s := formatLine(metric{"poisoned", pois, poisR}); s != "" {
		out = append(out, s)
	}

	return out
}

func (c *Collector) percentile(p float64) float64 {
	total := c.latTotal.Load()
	if total == 0 {
		return 0
	}
	target := max(int64(float64(total)*p/100), 1)
	var cum int64
	for i := range c.latCounts {
		cum += c.latCounts[i].Load()
		if cum >= target {
			return float64(latBounds[i])
		}
	}
	return float64(latBounds[latBuckets-1])
}

// Reset clears all counters. Each counter is zeroed individually with atomic
// stores — a whole-struct copy would race the lock-free Record()/Stats()
// readers (torn reads, lost increments). The reset is still not a
// transactional snapshot: counters may be incremented while Reset runs.
func (c *Collector) Reset() {
	now := log.NowUnix()
	c.startTime.Store(now)
	c.total.Store(0)
	c.totalMS.Store(0)
	c.hit.Store(0)
	c.miss.Store(0)
	c.stale.Store(0)
	c.zone.Store(0)
	c.blocked.Store(0)
	c.badcookie.Store(0)
	c.errorCount.Store(0)
	c.udp.Store(0)
	c.tcp.Store(0)
	c.tls.Store(0)
	c.quic.Store(0)
	c.https.Store(0)
	c.http3.Store(0)
	c.dtls.Store(0)
	c.dnscrypt.Store(0)
	c.dnscryptTCP.Store(0)
	c.tlcp.Store(0)
	c.httpTLCP.Store(0)
	c.dtlcp.Store(0)
	c.secure.Store(0)
	c.insecure.Store(0)
	c.bogus.Store(0)
	c.poisoned.Store(0)
	c.prefetch.Store(0)
	for i := range c.rCode {
		c.rCode[i].Store(0)
	}
	for i := range c.latCounts {
		c.latCounts[i].Store(0)
	}
	c.latTotal.Store(0)
}
