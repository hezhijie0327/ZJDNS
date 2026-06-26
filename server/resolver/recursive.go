package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"zjdns/cache"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	"zjdns/server/latency"
)

// DefaultRootServers is the IANA root server address list.
var DefaultRootServers = []string{
	"198.41.0.4:53", "[2001:503:ba3e::2:30]:53",
	"170.247.170.2:53", "[2801:1b8:10::b]:53",
	"192.33.4.12:53", "[2001:500:2::c]:53",
	"199.7.91.13:53", "[2001:500:2d::d]:53",
	"192.203.230.10:53", "[2001:500:a8::e]:53",
	"192.5.5.241:53", "[2001:500:2f::f]:53",
	"192.112.36.4:53", "[2001:500:12::d0d]:53",
	"198.97.190.53:53", "[2001:500:1::53]:53",
	"192.36.148.17:53", "[2001:7fe::53]:53",
	"192.58.128.30:53", "[2001:503:c27::2:30]:53",
	"193.0.14.129:53", "[2001:7fd::1]:53",
	"199.7.83.42:53", "[2001:500:9f::42]:53",
	"202.12.27.33:53", "[2001:dc3::35]:53",
}

const (
	nsAddrKeyPrefix = "dns:_addrs:"
	nsAddrKeySuffix = ":0:1"
)

// Recursive performs iterative DNS resolution by walking the root, TLD, and
// authoritative nameserver hierarchy. When DNSSEC validation is enabled, it
// builds a cryptographic chain of trust at each delegation step.
//
// Both root servers and per-nameserver addresses share the same latency-sorted
// cache mechanism: nsAddrKey(zone) stores TXT records, getRootServers /
// lookupNSAddrsFromCache serve-stale on expiry and trigger background re-probes.
type Recursive struct {
	resolver          *Resolver
	lastDNSSECEDECode atomic.Uint64 // EDE code from the most recent DNSSEC validation failure
	cache             cache.Store
	bgCtx             context.Context // background context for async probes; cancelled on shutdown
}

// DNSSECEDECode returns the last DNSSEC EDE code atomically.
func (r *Recursive) DNSSECEDECode() uint16 {
	return uint16(r.lastDNSSECEDECode.Load())
}

// dnssecChain tracks the cryptographic trust chain state during recursive
// resolution. At each delegation level, verified parent DNSKEYs and child DS
// records are used to authenticate the child zone's DNSKEYs.
func (rr *Recursive) resolve(ctx context.Context, question dns.Question, ecs *edns.ECSOption, depth int, forceTCP bool) ([]dns.RR, []dns.RR, []dns.RR, bool, *edns.ECSOption, string, bool, error) {
	if depth > config.DefaultMaxRecursionDepth {
		log.Warnf("RECURSION: depth exceeded (depth=%d, max=%d) for %s", depth, config.DefaultMaxRecursionDepth, question.Name)
		return nil, nil, nil, false, nil, "", false, fmt.Errorf("recursion depth exceeded: %d", depth)
	}

	// Clear any stale DNSSEC EDE code from a previous CNAME hop or recursive
	// call. Without this, a DNSSEC failure in one hop can leak through a
	// successful validation in the next hop, causing false "bogus" verdicts.
	rr.lastDNSSECEDECode.Store(0)

	qname := dns.Fqdn(question.Name)
	question.Name = qname
	nameservers := rr.getRootServers()
	currentDomain := "."
	normalizedQname := dnsutil.NormalizeDomain(qname)
	var hijackDetected bool

	log.Debugf("RECURSION: depth=%d, querying %s (type=%s, tcp=%t, zone=%s, ns=%v)", depth, question.Name, dns.TypeToString[question.Qtype], forceTCP, currentDomain, nameservers)

	// Initialize DNSSEC trust chain with root trust anchors (when available).
	chain := &dnssecChain{}
	if crypto := rr.resolver.validator.Crypto; crypto != nil {
		chain.parentDNSKEYs = crypto.GetRootKeys()
	}

	if normalizedQname == "" {
		response, err := rr.queryNameserversConcurrent(ctx, nameservers, question, ecs, forceTCP)
		if err != nil {
			return nil, nil, nil, false, nil, "", false, fmt.Errorf("root domain query: %w", err)
		}

		if rr.resolver.validator.Hijack.IsEnabled() {
			if valid, reason := rr.resolver.validator.Hijack.CheckResponse(currentDomain, normalizedQname, response); !valid {
				pool.DefaultMessagePool.Put(response)
				return rr.handleSuspiciousResponse(reason, forceTCP)
			}
		}

		cryptoValidated := rr.validateWithDNSSEC(response, currentDomain, chain)
		validated := cryptoValidated
		ecsResponse := rr.resolver.edns.ParseFromDNS(response)
		answer, authority, additional := response.Answer, response.Ns, response.Extra
		pool.DefaultMessagePool.Put(response)
		return answer, authority, additional, validated, ecsResponse, config.RecursiveIndicator, false, nil
	}

	for {
		select {
		case <-ctx.Done():
			return nil, nil, nil, false, nil, "", false, ctx.Err()
		default:
		}

		response, err := rr.queryNameserversConcurrent(ctx, nameservers, question, ecs, forceTCP)
		if err != nil {
			if !forceTCP && errors.Is(err, ErrHijackDetected) {
				return rr.resolve(ctx, question, ecs, depth, true)
			}
			return nil, nil, nil, false, nil, "", false, fmt.Errorf("query %s: %w", currentDomain, err)
		}

		if rr.resolver.validator.Hijack.IsEnabled() {
			if valid, reason := rr.resolver.validator.Hijack.CheckResponse(currentDomain, normalizedQname, response); !valid {
				pool.DefaultMessagePool.Put(response)
				answer, authority, additional, validated, ecsResponse, server, hijackDetectedNow, err := rr.handleSuspiciousResponse(reason, forceTCP)
				if hijackDetectedNow {
					hijackDetected = true
				}
				if !forceTCP && errors.Is(err, ErrHijackDetected) {
					return rr.resolve(ctx, question, ecs, depth, true)
				}
				return answer, authority, additional, validated, ecsResponse, server, hijackDetected, err
			}
		}

		// Cryptographic DNSSEC validation at this delegation level
		cryptoValidated := rr.validateWithDNSSEC(response, currentDomain, chain)
		ecsResponse := rr.resolver.edns.ParseFromDNS(response)

		validated := cryptoValidated

		if len(response.Answer) > 0 {
			validated = rr.finalizeDNSSEC(ctx, response, nameservers, question, currentDomain, ecs, forceTCP, chain)

			// If the answer RRSIGs are signed by a child zone's keys
			// (zone cut), process the response as a referral instead of
			// returning it as the final answer. This handles cases where
			// an authoritative server returns an answer directly from a
			// delegated subdomain instead of issuing a referral.
			if !validated && chain.zoneCutDetected {
				log.Debugf("SECURITY: zone cut — resolving DNSSEC chain for child zone of %s", question.Name)
				chain.zoneCutDetected = false
				// Build the DNSSEC chain for the child zone directly by querying
				// for DS and DNSKEY records, then validate the original answer
				// against the child zone's verified keys. This avoids relying on
				// the delegation-following path which requires NS+DS records in
				// specific response sections that may not be present.
				if cutValidated, cutErr := rr.resolveZoneCut(ctx, response, nameservers, question, currentDomain, ecs, forceTCP, chain); cutErr == nil {
					validated = cutValidated
					// Always record the DNSSEC EDE code for stats and client EDE hints,
					// even when enforcement is off.
					if err := rr.recordDNSSECFailure(chain, validated,
						fmt.Sprintf("bogus zone cut delegation for %s", question.Name)); err != nil {
						log.Debugf("SECURITY: DNSSEC validation failed for %s — zone cut child has DS but RRSIG verification failed", question.Name)
						pool.DefaultMessagePool.Put(response)
						return nil, nil, nil, false, ecsResponse, config.RecursiveIndicator, false, err
					}
				} else {
					log.Debugf("SECURITY: zone cut resolution failed for %s: %v", question.Name, cutErr)
					// Zone cut resolution failed (e.g. no DS, DS verification
					// failure). Always record the EDE code; return SERVFAIL only
					// when enforcement is on.
					if len(chain.childDS) > 0 {
						rr.lastDNSSECEDECode.Store(uint64(chain.lastEDECode))
						if rr.resolver.DNSSECEnforce {
							log.Debugf("SECURITY: DNSSEC validation failed for %s — zone cut resolution failed with DS present", question.Name)
							pool.DefaultMessagePool.Put(response)
							return nil, nil, nil, false, ecsResponse, config.RecursiveIndicator, false,
								fmt.Errorf("DNSSEC validation failed: zone cut resolution error for %s: %w", question.Name, cutErr)
						}
					}
					validated = false
				}
				// Strip cross-zone answer records so the CNAME resolver follows the
				// chain independently. Records signed by unrelated zone keys (e.g.
				// A records for CDN CNAME targets) are validated via separate
				// recursive resolution against their own zone's DNSKEYs.
				answer := stripCrossZoneRecords(response.Answer, response.Extra, currentDomain)
				pool.DefaultMessagePool.Put(response)
				return answer, response.Ns, response.Extra, validated, ecsResponse, config.RecursiveIndicator, false, nil
			} else {
				// When DNSSEC crypto is enabled and the zone has DS records in the
				// parent, a crypto verification failure means the answer is bogus.
				// Always record the EDE code for client hints and stats; return
				// SERVFAIL only when enforcement is on (RFC 4035).
				if len(chain.childDS) > 0 && !validated {
					rr.lastDNSSECEDECode.Store(uint64(chain.lastEDECode))
					if rr.resolver.DNSSECEnforce {
						log.Debugf("SECURITY: DNSSEC validation failed for %s — zone has DS but DNSKEY/RRSIG verification failed", question.Name)
						pool.DefaultMessagePool.Put(response)
						return nil, nil, nil, false, ecsResponse, config.RecursiveIndicator, false,
							fmt.Errorf("DNSSEC validation failed: bogus delegation for %s", question.Name)
					}
				}
				// Strip cross-zone answer records so the CNAME resolver follows the
				// chain independently. Records signed by unrelated zone keys (e.g.
				// A records for CDN CNAME targets) are validated via separate
				// recursive resolution against their own zone's DNSKEYs.
				answer := stripCrossZoneRecords(response.Answer, response.Extra, currentDomain)
				pool.DefaultMessagePool.Put(response)
				return answer, response.Ns, response.Extra, validated, ecsResponse, config.RecursiveIndicator, false, nil
			}
		}

		// For NODATA/NXDOMAIN responses (no answer section), cryptographically
		// verify NSEC/NSEC3 records against the zone's verified DNSKEYs to
		// enable the AuthenticatedData flag when denial-of-existence is proven
		// (RFC 4035 §3.1.3). Genuine DNSSEC failures (bad RRSIGs on answer
		// records) are caught by the answer-path SERVFAIL check above.
		if len(response.Answer) == 0 {
			if len(chain.zoneDNSKEYs) == 0 {
				rr.ensureZoneDNSKEYs(ctx, nameservers, currentDomain, chain)
			}
			if len(chain.zoneDNSKEYs) > 0 {
				if nsecValidated, _ := rr.resolver.validator.Crypto.ValidateResponse(response, currentDomain, chain.zoneDNSKEYs); nsecValidated {
					validated = true
				}
			}
		}

		// Collect NS records from both Authority and Answer sections.
		// NS records appear in the Answer section when the queried
		// server is authoritative for the delegated zone (common when
		// the same server hosts both parent and child zones).
		var allRRSections []dns.RR
		allRRSections = append(allRRSections, response.Ns...)
		allRRSections = append(allRRSections, response.Answer...)

		bestMatch := ""
		var bestNSRecords []*dns.NS
		for _, rrec := range allRRSections {
			if ns, ok := rrec.(*dns.NS); ok {
				nsName := dnsutil.NormalizeDomain(rrec.Header().Name)
				isMatch := normalizedQname == nsName ||
					(nsName != "" && strings.HasSuffix(normalizedQname, "."+nsName))
				if isMatch && len(nsName) >= len(bestMatch) {
					if len(nsName) > len(bestMatch) {
						bestMatch = nsName
						bestNSRecords = []*dns.NS{ns}
					} else {
						bestNSRecords = append(bestNSRecords, ns)
					}
				}
			}
		}

		if len(bestNSRecords) == 0 {
			nsSlice, extraSlice := response.Ns, response.Extra
			pool.DefaultMessagePool.Put(response)
			return nil, nsSlice, extraSlice, validated, ecsResponse, config.RecursiveIndicator, false, nil
		}

		currentDomainNormalized := dnsutil.NormalizeDomain(currentDomain)
		if bestMatch == currentDomainNormalized && currentDomainNormalized != "" {
			// When the response has no answer and the NS records point
			// back to the same zone, verify this is actually an
			// authoritative response (AA flag). A non-authoritative
			// response with matching NS records indicates a lame
			// delegation — the server is not actually authoritative
			// for this zone and we should return SERVFAIL rather than
			// silently accepting the response (Cloudflare/Google both
			// return SERVFAIL for these cases).
			if len(response.Answer) == 0 && !response.Authoritative {
				log.Debugf("RECURSION: lame delegation detected for %s — NS records point to same zone but response is not authoritative", currentDomain)
				pool.DefaultMessagePool.Put(response)
				rr.lastDNSSECEDECode.Store(uint64(edns.EDECodeNoReachableAuthority))
				return nil, nil, nil, false, ecsResponse, config.RecursiveIndicator, false,
					fmt.Errorf("lame delegation: no reachable authority for %s", currentDomain)
			}
			nsSlice, extraSlice := response.Ns, response.Extra
			pool.DefaultMessagePool.Put(response)
			return nil, nsSlice, extraSlice, validated, ecsResponse, config.RecursiveIndicator, false, nil
		}

		// Update DNSSEC chain: extract DS from current delegation, prepare
		// for child zone verification in the next iteration.
		//
		// Delegation responses do not contain DNSKEY records — we must
		// explicitly query the current (parent) zone's nameservers for
		// its DNSKEY RRset before we can cryptographically verify the
		// child's DS RRSIGs.
		rr.updateDNSSECChain(ctx, response, currentDomain, bestMatch, nameservers, chain)

		// Save parent zone before updating — glue name validation uses
		// the parent zone (the zone that published the delegation),
		// not the delegated-to zone.
		parentDomain := currentDomain
		currentDomain = bestMatch + "."

		// Try cache first for all NS names — latency-sorted records
		// from previous resolutions (or restarted snapshots) skip the
		// glue extraction + inline probe entirely.
		var nextNS []string
		var nextNSSource string // "cache" or "glue" or "resolution"
		if rr.cache != nil {
			for _, ns := range bestNSRecords {
				nsName := dns.Fqdn(ns.Ns)
				cached := rr.lookupNSAddrsFromCache(nsName)
				if len(cached) > 0 {
					nextNS = append(nextNS, cached...)
					// Log per-NS latency ranking (fastest first) so
					// operators can verify the probe is working.
					if len(cached) > 1 {
						rankParts := make([]string, 0, len(cached))
						for i, addr := range cached {
							rankParts = append(rankParts, fmt.Sprintf("#%d=%s", i+1, addr))
						}
						log.Debugf("RECURSION: NS %s cached (sorted): %s", nsName, strings.Join(rankParts, " "))
					}
				}
			}
			if len(nextNS) > 0 {
				nextNSSource = "cache"
			}
		}

		// Fall back to glue records when cache doesn't cover all NS names.
		nsGlue := make(map[string][]dns.RR) // NS name → A/AAAA glue records
		if len(nextNS) == 0 {
			for _, ns := range bestNSRecords {
				for _, rrec := range response.Extra {
					switch a := rrec.(type) {
					case *dns.A:
						if strings.EqualFold(a.Header().Name, ns.Ns) {
							// Validate glue name is within the parent zone
							glueName := dnsutil.NormalizeDomain(a.Header().Name)
							parDom := dnsutil.NormalizeDomain(parentDomain)
							if glueName != parDom && !strings.HasSuffix(glueName, "."+parDom) && parDom != "" {
								continue
							}
							nsKey := dns.Fqdn(a.Header().Name)
							nsGlue[nsKey] = append(nsGlue[nsKey], a)
							nextNS = append(nextNS, net.JoinHostPort(a.A.String(), config.DefaultDNSPort))
						}
					case *dns.AAAA:
						if strings.EqualFold(a.Header().Name, ns.Ns) {
							glueName := dnsutil.NormalizeDomain(a.Header().Name)
							parDom := dnsutil.NormalizeDomain(parentDomain)
							if glueName != parDom && !strings.HasSuffix(glueName, "."+parDom) && parDom != "" {
								continue
							}
							nsKey := dns.Fqdn(a.Header().Name)
							nsGlue[nsKey] = append(nsGlue[nsKey], a)
							nextNS = append(nextNS, net.JoinHostPort(a.AAAA.String(), config.DefaultDNSPort))
						}
					}
				}
			}
		}

		// Use glue records directly when available; only fall back to
		// independent NS resolution when the delegation has no glue.
		if len(nextNS) == 0 {
			nextNS = rr.resolveNSAddressesConcurrent(ctx, bestNSRecords, qname, depth, forceTCP)
			if len(nextNS) > 0 {
				nextNSSource = "resolution"
			}
		} else if nextNSSource == "" {
			nextNSSource = "glue"
		}

		// Log the addresses being used for this delegation step so operators
		// can verify latency ordering. The first address is queried first
		// (within the concurrency limit); with first-win semantics, faster
		// servers win races.
		if len(nextNS) > 0 {
			log.Debugf("RECURSION: zone=%s, %d NS names → %d addresses (source=%s): %v",
				currentDomain, len(bestNSRecords), len(nextNS), nextNSSource, nextNS)
		}

		if len(nextNS) == 0 {
			nsSlice, extraSlice := response.Ns, response.Extra
			pool.DefaultMessagePool.Put(response)
			return nil, nsSlice, extraSlice, validated, ecsResponse, config.RecursiveIndicator, false, nil
		}

		// Cache A/AAAA glue records per NS name immediately so
		// future queries hit warm cache. A background latency probe
		// will reorder them later — the current query uses addresses
		// as-is to avoid blocking the resolution pipeline.
		if rr.cache != nil && len(nsGlue) > 0 {
			for nsName, records := range nsGlue {
				if len(records) > 0 {
					qtype := records[0].Header().Rrtype
					cacheKey := cache.BuildCacheKey(dns.Question{Name: nsName, Qtype: qtype, Qclass: dns.ClassINET}, nil, false)
					rr.cache.Set(cacheKey, records, nil, nil, false, nil)
				}
			}
			// Fire async latency probe to update cache with sorted records.
			// Copy the map so the goroutine owns the data.
			glueCopy := make(map[string][]dns.RR, len(nsGlue))
			for nsName, records := range nsGlue {
				glueCopy[nsName] = records
			}
			go rr.probeAndCacheNSGlue(glueCopy)
		}

		pool.DefaultMessagePool.Put(response)
		nameservers = nextNS
	}
}

// ── Unified latency-sorted address cache ──────────────────────────────────────
//
// Both root servers (zone ".") and per-nameserver addresses share a single key
// space: dns:_addrs:<zone>:0:1.  Each entry stores TXT records whose Txt values
// are "ip:port" strings ordered by measured latency (fastest first, across both
// address families).  This is separate from per-type (A/AAAA) cache entries so
// the NS lookup path always gets the true latency ranking without heuristics.

// nsAddrKey returns the unified cache key for latency-sorted server addresses.
func nsAddrKey(zone string) string {
	return nsAddrKeyPrefix + dnsutil.NormalizeDomain(zone) + nsAddrKeySuffix
}

// addrsToTXTRecords converts "ip:port" strings to TXT DNS records with the
// given TTL (in seconds).  The TTL controls how frequently the latency order
// is refreshed: a shorter TTL means more frequent re-probes.
func addrsToTXTRecords(name string, addrs []string, ttlSeconds int) []dns.RR {
	records := make([]dns.RR, 0, len(addrs))
	for _, addr := range addrs {
		records = append(records, &dns.TXT{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: uint32(ttlSeconds)},
			Txt: []string{addr},
		})
	}
	return records
}

// readTXTAddrs extracts "ip:port" strings from a cache entry stored by
// addrsToTXTRecords (or by probeAndCacheNSGlue).
func readTXTAddrs(entry *cache.CacheEntry) []string {
	if entry == nil || len(entry.Answer) == 0 {
		return nil
	}
	records := cache.ExpandRecords(entry.Answer)
	addrs := make([]string, 0, len(records))
	for _, r := range records {
		if txt, ok := r.(*dns.TXT); ok && len(txt.Txt) > 0 {
			addrs = append(addrs, txt.Txt...)
		}
	}
	return addrs
}

// rrToAddr extracts the "ip:port" string from an A or AAAA record. Returns
// empty string for other record types.
func rrToAddr(rr dns.RR) string {
	switch r := rr.(type) {
	case *dns.A:
		return net.JoinHostPort(r.A.String(), config.DefaultDNSPort)
	case *dns.AAAA:
		return net.JoinHostPort(r.AAAA.String(), config.DefaultDNSPort)
	}
	return ""
}

// probeAndCacheAddrs probes the given addresses, sorts them by latency, and
// stores the result under nsAddrKey(zone). Shared by root (zone=".") and
// per-nameserver (zone=<nsName>) refresh paths.
func (rr *Recursive) probeAndCacheAddrs(zone string, addrs []string) {
	defer dnsutil.HandlePanic("probeAndCacheAddrs")
	if len(addrs) <= 1 || rr.cache == nil {
		return
	}
	ctx := rr.bgCtx
	if ctx == nil {
		ctx = context.Background()
	}
	sorted := sortAddrsByLatency(ctx, addrs, config.DefaultInfraProbeTimeout)
	if len(sorted) > 0 {
		txtRecords := addrsToTXTRecords(zone, sorted, config.DefaultNSLatencyTTL)
		rr.cache.Set(nsAddrKey(zone), txtRecords, nil, nil, false, nil)
	}
}

// getRootServers returns root servers ordered by latency. It reads from the
// unified nsAddrKey(".") — the same cache space as per-nameserver addresses.
// On cache miss (cold start) it returns DefaultRootServers and triggers an
// initial probe. On expiry it serves the stale order and triggers a background
// re-probe — matching the NS refresh pattern in lookupNSAddrsFromCache.
func (rr *Recursive) getRootServers() []string {
	if rr == nil {
		return DefaultRootServers
	}

	// Serve from unified cache (hit, expired, or miss).
	if rr.cache != nil {
		if entry, found, expired := rr.cache.Get(nsAddrKey(".")); found && entry != nil {
			if addrs := readTXTAddrs(entry); len(addrs) > 0 {
				if expired {
					go rr.probeRootAddrs()
				}
				return addrs
			}
		}
	}

	// Cold start: probe in background, return IANA order.
	go rr.probeRootAddrs()
	return DefaultRootServers
}

// probeRootAddrs re-probes the full IANA root server list. Delegates to
// probeAndCacheAddrs so root and per-NS refresh share the same code path.
func (rr *Recursive) probeRootAddrs() {
	log.Debugf("RECURSION: probing root server latency (%d addresses)", len(DefaultRootServers))
	rr.probeAndCacheAddrs(".", DefaultRootServers)
}

// refreshNSAddrOrder re-probes a single NS name's addresses. Delegates to
// probeAndCacheAddrs so root and per-NS refresh share the same code path.
func (rr *Recursive) refreshNSAddrOrder(nsName string, addrs []string) {
	log.Debugf("RECURSION: refreshing latency order for NS %s (%d addresses)", nsName, len(addrs))
	rr.probeAndCacheAddrs(nsName, addrs)
}

// probeAndCacheNSGlue runs latency probes against all IPs in the nsGlue map
// and caches the latency-sorted results. Each NS name gets an entry under
// nsAddrKey(nsName) — the unified key space shared with root servers.
// Per-type cache entries (A/AAAA) are also updated with intra-type ordering
// for normal DNS query responses.
func (rr *Recursive) probeAndCacheNSGlue(nsGlue map[string][]dns.RR) {
	defer dnsutil.HandlePanic("probeAndCacheNSGlue")
	if rr.cache == nil || len(nsGlue) == 0 {
		return
	}

	// Concurrency is bounded by the latency package's own semaphore
	// (config.DefaultMaxProbes) and dedup cache — no additional locking
	// needed at this level; the dedup cache prevents redundant probes
	// for identical IP sets.

	// Collect all addresses from all NS names so they are ranked together.
	var allAddrs []string
	for _, records := range nsGlue {
		for _, rrec := range records {
			if addr := rrToAddr(rrec); addr != "" {
				allAddrs = append(allAddrs, addr)
			}
		}
	}

	if len(allAddrs) <= 1 {
		return
	}

	ctx := rr.bgCtx
	if ctx == nil {
		ctx = context.Background()
	}
	sorted := sortAddrsByLatency(ctx, allAddrs, config.DefaultInfraProbeTimeout)
	if len(sorted) == 0 {
		return
	}

	// For each NS name: reorder all records by global latency ranking,
	// cache under the unified nsAddrKey, and update per-type entries.
	for nsName, records := range nsGlue {
		sortedRecords := reorderRecordsByAddrs(records, sorted)
		if len(sortedRecords) == 0 {
			continue
		}

		// Build "ip:port" strings in latency order for the unified key.
		sortedAddrs := make([]string, 0, len(sortedRecords))
		for _, r := range sortedRecords {
			if addr := rrToAddr(r); addr != "" {
				sortedAddrs = append(sortedAddrs, addr)
			}
		}

		// Unified latency-sorted key (shared format with root servers).
		txtRecords := addrsToTXTRecords(nsName, sortedAddrs, config.DefaultNSLatencyTTL)
		rr.cache.Set(nsAddrKey(nsName), txtRecords, nil, nil, false, nil)
		log.Debugf("RECURSION: async-cached %d latency-sorted NS addresses for %s", len(txtRecords), nsName)

		// Also update per-type cache entries (A/AAAA) with intra-type
		// latency ordering for normal DNS query responses.
		typeGroups := make(map[uint16][]dns.RR)
		for _, r := range sortedRecords {
			qtype := r.Header().Rrtype
			typeGroups[qtype] = append(typeGroups[qtype], r)
		}
		for qtype, typeRecords := range typeGroups {
			cacheKey := cache.BuildCacheKey(dns.Question{Name: nsName, Qtype: qtype, Qclass: dns.ClassINET}, nil, false)
			rr.cache.Set(cacheKey, typeRecords, nil, nil, false, nil)
		}
	}
}

// sortAddrsByLatency extracts IPs from addr:port strings, probes them
// concurrently, and returns the addresses sorted fastest-first. Addresses
// without valid public IPs are placed at the end in original order.
func sortAddrsByLatency(parentCtx context.Context, addresses []string, timeout time.Duration) []string {
	if len(addresses) <= 1 {
		return addresses
	}

	// Extract valid, public IPs alongside their original addresses.
	type entry struct {
		addr string
		ip   net.IP
	}
	entries := make([]entry, 0, len(addresses))
	probeIPs := make([]net.IP, 0, len(addresses))

	for _, addr := range addresses {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			continue
		}
		ip := net.ParseIP(strings.Trim(host, "[]"))
		if ip != nil && !ip.IsLoopback() && !ip.IsPrivate() {
			entries = append(entries, entry{addr: addr, ip: ip})
			probeIPs = append(probeIPs, ip)
		}
	}

	if len(probeIPs) <= 1 {
		return addresses
	}

	ctx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()
	sortedIPs := latency.SortIPsByLatency(ctx, probeIPs)

	// Map IPs back to original addresses preserving probe order.
	ipToAddr := make(map[string]string, len(entries))
	for _, e := range entries {
		ipToAddr[e.ip.String()] = e.addr
	}

	result := make([]string, 0, len(addresses))
	seen := make(map[string]bool, len(addresses))
	for _, ip := range sortedIPs {
		if addr, ok := ipToAddr[ip.String()]; ok && !seen[addr] {
			result = append(result, addr)
			seen[addr] = true
		}
	}
	// Append unprobed entries at the end.
	for _, addr := range addresses {
		if !seen[addr] {
			result = append(result, addr)
			seen[addr] = true
		}
	}

	return result
}

// lookupNSAddrsFromCache looks up latency-sorted NS addresses via the unified
// nsAddrKey. When the entry is expired, it serves the stale order and
// triggers a background re-probe — matching the root server refresh pattern.
// Falls back to per-type (A/AAAA) cache entries when the probe hasn't
// populated the unified key yet (cold start).
func (rr *Recursive) lookupNSAddrsFromCache(nsName string) []string {
	if rr == nil || rr.cache == nil {
		return nil
	}

	// Fast path: unified latency-sorted key (TXT records in probe order).
	if entry, found, expired := rr.cache.Get(nsAddrKey(nsName)); found && entry != nil {
		if addrs := readTXTAddrs(entry); len(addrs) > 0 {
			if expired {
				go rr.refreshNSAddrOrder(nsName, addrs)
			}
			return addrs
		}
	}

	// Fallback: per-type cache entries (unsorted or intra-type sorted only).
	aAddrs := lookupCachedRRs(rr.cache, nsName, dns.TypeA)
	aaaaAddrs := lookupCachedRRs(rr.cache, nsName, dns.TypeAAAA)
	if len(aAddrs) == 0 && len(aaaaAddrs) == 0 {
		return nil
	}
	addrs := make([]string, 0, len(aAddrs)+len(aaaaAddrs))
	addrs = append(addrs, aAddrs...)
	addrs = append(addrs, aaaaAddrs...)
	return addrs
}

// lookupCachedRRs fetches cached A or AAAA records for a name and converts
// them to "ip:port" strings, preserving the cache entry's record order.
// Expired entries within the serve-stale window (config.DefaultStaleMaxAge)
// are still returned to avoid triggering expensive re-resolution for NS
// addresses whose TTL just expired — NS IPs change very rarely.
func lookupCachedRRs(store cache.Store, name string, qtype uint16) []string {
	q := dns.Question{Name: name, Qtype: qtype, Qclass: dns.ClassINET}
	key := cache.BuildCacheKey(q, nil, false)
	entry, found, expired := store.Get(key)
	if !found || entry == nil || len(entry.Answer) == 0 {
		return nil
	}
	if expired && !entry.CanServeExpired(config.DefaultStaleMaxAge) {
		return nil
	}

	records := cache.ExpandRecords(entry.Answer)
	addrs := make([]string, 0, len(records))
	for _, rr := range records {
		if addr := rrToAddr(rr); addr != "" {
			addrs = append(addrs, addr)
		}
	}
	return addrs
}

// CNAME handles CNAME record chasing during DNS resolution, following the
// redirection chain up to config.DefaultMaxCNAMEChain hops. Defined in the same
// file as Recursive because CNAME resolution depends directly on recursive
// resolution (ch.resolve → rr.resolve). Splitting into a separate file would
// add unnecessary indirection without reducing coupling.
type CNAME struct {
	resolver *Resolver
}

func (ch *CNAME) resolve(ctx context.Context, question dns.Question, ecs *edns.ECSOption) ([]dns.RR, []dns.RR, []dns.RR, bool, *edns.ECSOption, string, bool, error) {
	var allAnswers []dns.RR
	var finalAuthority, finalAdditional []dns.RR
	var finalECSResponse *edns.ECSOption
	var usedServer string
	var hijackOccurred bool
	allValidated := true

	currentQuestion := question
	visitedCNAMEs := make(map[string]bool)
	cnameDepth := 0

	for cnameDepth = range config.DefaultMaxCNAMEChain {
		select {
		case <-ctx.Done():
			return nil, nil, nil, false, nil, "", false, ctx.Err()
		default:
		}

		currentName := dnsutil.NormalizeDomain(currentQuestion.Name)
		if visitedCNAMEs[currentName] {
			log.Warnf("RECURSION: CNAME loop detected for %s", currentName)
			return nil, nil, nil, false, nil, "", false, fmt.Errorf("CNAME loop detected: %s", currentName)
		}
		visitedCNAMEs[currentName] = true

		answer, authority, additional, validated, ecsResponse, server, hijackDetectedNow, err := ch.resolver.recursive.resolve(ctx, currentQuestion, ecs, 0, false)
		if err != nil {
			return nil, nil, nil, false, nil, "", false, err
		}

		if usedServer == "" {
			usedServer = server
		}
		if hijackDetectedNow {
			hijackOccurred = true
		}
		if !validated {
			allValidated = false
		}
		if ecsResponse != nil {
			finalECSResponse = ecsResponse
		}

		allAnswers = append(allAnswers, answer...)
		finalAuthority = authority
		finalAdditional = additional

		var nextCNAME *dns.CNAME
		hasTargetType := false
		for _, rr := range answer {
			if cname, ok := rr.(*dns.CNAME); ok {
				if strings.EqualFold(rr.Header().Name, currentQuestion.Name) {
					nextCNAME = cname
				}
			} else if rr.Header().Rrtype == currentQuestion.Qtype {
				hasTargetType = true
			}
		}

		if hasTargetType || currentQuestion.Qtype == dns.TypeCNAME || nextCNAME == nil {
			break
		}

		currentQuestion = dns.Question{
			Name:   nextCNAME.Target,
			Qtype:  question.Qtype,
			Qclass: question.Qclass,
		}
	}

	if cnameDepth >= config.DefaultMaxCNAMEChain-1 {
		log.Warnf("RECURSION: CNAME chain exhausted (max=%d) for %s", config.DefaultMaxCNAMEChain, dnsutil.NormalizeDomain(question.Name))
	}
	return allAnswers, finalAuthority, finalAdditional, allValidated, finalECSResponse, usedServer, hijackOccurred, nil
}
