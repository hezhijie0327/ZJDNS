// Package stats provides best-effort in-memory DNS query statistics with
// latency histogram. All counters are atomic — Record() is lock-free.
// No composite keys, no maps, just flat counters per dimension.
package stats

import (
	"fmt"
	"sync/atomic"
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

	rCode [6]atomic.Int64

	latCounts [latBuckets]atomic.Int64
	latTotal  atomic.Int64
}

const latBuckets = 12

var latBounds = [latBuckets]int64{1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000}

// New creates a Collector.
func New() *Collector { return &Collector{} }

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
	case "error":
		c.errorCount.Add(1)
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
	c.latTotal.Add(1)
}

// Stats returns all statistics in a compact multi-line format.
func (c *Collector) Stats() []string {
	total := c.total.Load()
	h, m, s, z := c.hit.Load(), c.miss.Load(), c.stale.Load(), c.zone.Load()
	b, bc, errC := c.blocked.Load(), c.badcookie.Load(), c.errorCount.Load()
	noerr, formerr, servfail, nx, nimp, ref := c.rCode[0].Load(), c.rCode[1].Load(), c.rCode[2].Load(),
		c.rCode[3].Load(), c.rCode[4].Load(), c.rCode[5].Load()
	udp, tcpN, tls, quic, https, http3, dtls := c.udp.Load(), c.tcp.Load(), c.tls.Load(), c.quic.Load(), c.https.Load(), c.http3.Load(), c.dtls.Load()
	dnscrypt, dnscryptTCP, tlcp, httpTLCP, dtlcp := c.dnscrypt.Load(), c.dnscryptTCP.Load(), c.tlcp.Load(), c.httpTLCP.Load(), c.dtlcp.Load()
	sec, ins, bog := c.secure.Load(), c.insecure.Load(), c.bogus.Load()
	pois := c.poisoned.Load()

	hitR, missR, staleR, zoneR, blockedR, badcookieR, errorR := float64(0), float64(0), float64(0), float64(0), float64(0), float64(0), float64(0)
	noerrR, formerrR, servfailR, nxR, nimpR, refR := float64(0), float64(0), float64(0), float64(0), float64(0), float64(0)
	udpR, tcpR, tlsR, quicR, httpsR, http3R, dtlsR := float64(0), float64(0), float64(0), float64(0), float64(0), float64(0), float64(0)
	dnscryptR, dnscryptTCPR, tlcpR, httpTLCPR, dtlcpR := float64(0), float64(0), float64(0), float64(0), float64(0)
	secR, insR, bogR, poisR := float64(0), float64(0), float64(0), float64(0)
	if total > 0 {
		t := float64(total)
		hitR, missR, staleR, zoneR = float64(h)/t*100, float64(m)/t*100, float64(s)/t*100, float64(z)/t*100
		blockedR, badcookieR, errorR = float64(b)/t*100, float64(bc)/t*100, float64(errC)/t*100
		noerrR, formerrR, servfailR, nxR, nimpR, refR = float64(noerr)/t*100, float64(formerr)/t*100, float64(servfail)/t*100, float64(nx)/t*100, float64(nimp)/t*100, float64(ref)/t*100
		udpR, tcpR, tlsR, quicR, httpsR, http3R, dtlsR = float64(udp)/t*100, float64(tcpN)/t*100, float64(tls)/t*100, float64(quic)/t*100, float64(https)/t*100, float64(http3)/t*100, float64(dtls)/t*100
		dnscryptR, dnscryptTCPR, tlcpR, httpTLCPR, dtlcpR = float64(dnscrypt)/t*100, float64(dnscryptTCP)/t*100, float64(tlcp)/t*100, float64(httpTLCP)/t*100, float64(dtlcp)/t*100
		secR, insR, bogR = float64(sec)/t*100, float64(ins)/t*100, float64(bog)/t*100
		poisR = float64(pois) / t * 100
	}
	return []string{
		// Latency percentiles.
		fmt.Sprintf("p50=%.0fms p95=%.0fms p99=%.0fms",
			c.percentile(50), c.percentile(95), c.percentile(99)),
		// Results (partitions total → 100%).
		fmt.Sprintf("hit=%d(%.1f%%) miss=%d(%.1f%%) stale=%d(%.1f%%) zone=%d(%.1f%%) blocked=%d(%.1f%%) badcookie=%d(%.1f%%) error=%d(%.1f%%)",
			h, hitR, m, missR, s, staleR, z, zoneR, b, blockedR, bc, badcookieR, errC, errorR),
		// Rcodes (partitions total → 100%).
		fmt.Sprintf("noerr=%d(%.1f%%) formerr=%d(%.1f%%) servfail=%d(%.1f%%) nx=%d(%.1f%%) nimp=%d(%.1f%%) ref=%d(%.1f%%)",
			noerr, noerrR, formerr, formerrR, servfail, servfailR, nx, nxR, nimp, nimpR, ref, refR),
		// Transport protocols (partitions total → 100%).
		fmt.Sprintf("udp=%d(%.1f%%) tcp=%d(%.1f%%) tls=%d(%.1f%%) quic=%d(%.1f%%) https=%d(%.1f%%) http3=%d(%.1f%%) dtls=%d(%.1f%%) dnscrypt=%d(%.1f%%) dnscrypt-tcp=%d(%.1f%%) tlcp=%d(%.1f%%) http-tlcp=%d(%.1f%%) dtlcp=%d(%.1f%%)",
			udp, udpR, tcpN, tcpR, tls, tlsR, quic, quicR, https, httpsR, http3, http3R, dtls, dtlsR,
			dnscrypt, dnscryptR, dnscryptTCP, dnscryptTCPR, tlcp, tlcpR, httpTLCP, httpTLCPR, dtlcp, dtlcpR),
		// DNSSEC (partitions DNSSEC-evaluated queries → 100%).
		fmt.Sprintf("secure=%d(%.1f%%) insecure=%d(%.1f%%) bogus=%d(%.1f%%)",
			sec, secR, ins, insR, bog, bogR),
		// Poisoned (independent boolean flag).
		fmt.Sprintf("poisoned=%d(%.1f%%)", pois, poisR),
	}
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

// Reset clears all counters.
func (c *Collector) Reset() {
	*c = Collector{}
}
