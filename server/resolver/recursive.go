package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
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

// Recursive performs iterative DNS resolution by walking the root, TLD, and
// authoritative nameserver hierarchy. When DNSSEC validation is enabled, it
// builds a cryptographic chain of trust at each delegation step.
type Recursive struct {
	resolver          *Resolver
	lastDNSSECEDECode atomic.Uint64 // EDE code from the most recent DNSSEC validation failure
	cache             cache.Store

	// Root server latency ordering — probed once asynchronously on first use.
	sortedRootServers atomic.Value // stores []string
	rootServersOnce   sync.Once
}

// infrastructureProbeSteps defines the built-in latency probe sequence for
// root and authoritative nameserver IPs: ICMP ping first (fastest), then
// UDP port 53, then TCP port 53. This is independent of the user-facing
// latency_probe configuration which may include HTTP/HTTPS/HTTP3 steps.
var infrastructureProbeSteps = []config.LatencyProbeStep{
	{Protocol: "ping", Timeout: 100},
	{Protocol: "udp", Port: 53, Timeout: 100},
	{Protocol: "tcp", Port: 53, Timeout: 100},
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

	// Initialize DNSSEC trust chain with root trust anchors
	crypto := rr.resolver.validator.Crypto
	chain := &dnssecChain{}
	chain.parentDNSKEYs = crypto.GetRootKeys()

	if normalizedQname == "" {
		response, err := rr.queryNameserversConcurrent(ctx, nameservers, question, ecs, forceTCP)
		if err != nil {
			return nil, nil, nil, false, nil, "", false, fmt.Errorf("root domain query: %w", err)
		}

		if rr.resolver.validator.Hijack.IsEnabled() {
			if valid, reason := rr.resolver.validator.Hijack.CheckResponse(currentDomain, normalizedQname, response); !valid {
				pool.DefaultMessagePool.Put(response)
				return rr.handleSuspiciousResponse(reason, forceTCP, ctx, question, ecs, depth)
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
				answer, authority, additional, validated, ecsResponse, server, hijackDetectedNow, err := rr.handleSuspiciousResponse(reason, forceTCP, ctx, question, ecs, depth)
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
					if len(chain.childDS) > 0 && !validated {
						rr.lastDNSSECEDECode.Store(uint64(chain.lastEDECode))
						if rr.resolver.DNSSECEnforce {
							log.Debugf("SECURITY: DNSSEC validation failed for %s — zone cut child has DS but RRSIG verification failed", question.Name)
							pool.DefaultMessagePool.Put(response)
							return nil, nil, nil, false, ecsResponse, config.RecursiveIndicator, false,
								fmt.Errorf("DNSSEC validation failed: bogus zone cut delegation for %s", question.Name)
						}
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
		if rr.cache != nil {
			for _, ns := range bestNSRecords {
				nsName := dns.Fqdn(ns.Ns)
				cached := rr.lookupNSAddrsFromCache(nsName)
				if len(cached) > 0 {
					nextNS = append(nextNS, cached...)
				}
			}
			if len(nextNS) > 0 {
				log.Debugf("RECURSION: NS cache hit for %d/%d nameservers (%d addresses), skipping glue",
					len(nextNS), len(bestNSRecords), len(nextNS))
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
		}

		if len(nextNS) == 0 {
			nsSlice, extraSlice := response.Ns, response.Extra
			pool.DefaultMessagePool.Put(response)
			return nil, nsSlice, extraSlice, validated, ecsResponse, config.RecursiveIndicator, false, nil
		}

		// Only probe when addresses came from glue/resolution (not cache).
		if len(nsGlue) > 0 || len(nextNS) > 0 {
			nextNS = rr.orderNSAddresses(nextNS)
		}

		// Cache latency-sorted A/AAAA glue records per NS name so
		// future queries (including after restart) hit warm cache.
		if rr.cache != nil && len(nsGlue) > 0 {
			for nsName, records := range nsGlue {
				sortedRecords := reorderRecordsByAddrs(records, nextNS)
				if len(sortedRecords) > 0 {
					qtype := records[0].Header().Rrtype
					cacheKey := cache.BuildCacheKey(dns.Question{Name: nsName, Qtype: qtype, Qclass: dns.ClassINET}, nil, false)
					rr.cache.Set(cacheKey, sortedRecords, nil, nil, false, nil)
					log.Debugf("RECURSION: cached %d latency-sorted glue records for NS %s", len(sortedRecords), nsName)
				}
			}
		}

		pool.DefaultMessagePool.Put(response)
		nameservers = nextNS
	}
}

// rootServersCacheKey is a synthetic cache key for persisting the latency-sorted
// root server address list across restarts.
const rootServersCacheKey = "dns:_internal:root-servers:16:1"

// getRootServers returns root servers ordered by latency. It checks memory
// first, then the DNS cache (survives restarts via snapshot), then falls back
// to the default IANA order while an async probe runs.
func (rr *Recursive) getRootServers() []string {
	if rr == nil {
		return DefaultRootServers
	}

	if sorted := rr.sortedRootServers.Load(); sorted != nil {
		return sorted.([]string)
	}

	// Check persisted cache from previous run.
	if rr.cache != nil {
		if entry, found, _ := rr.cache.Get(rootServersCacheKey); found && entry != nil {
			records := cache.ExpandRecords(entry.Answer)
			addrs := make([]string, 0, len(records))
			for _, rr := range records {
				if txt, ok := rr.(*dns.TXT); ok && len(txt.Txt) > 0 {
					addrs = append(addrs, txt.Txt...)
				}
			}
			if len(addrs) > 0 {
				rr.sortedRootServers.Store(addrs)
				log.Debugf("RECURSION: root server order loaded from cache (%d addresses)", len(addrs))
				return addrs
			}
		}
	}

	rr.rootServersOnce.Do(func() {
		go rr.probeRootServers()
	})

	return DefaultRootServers
}

// probeRootServers measures latency to all root server IPs and stores the
// sorted order in memory and the DNS cache for persistence across restarts.
func (rr *Recursive) probeRootServers() {
	sorted := sortAddrsByLatency(DefaultRootServers, infrastructureProbeSteps, 30*time.Second)
	if len(sorted) > 0 {
		rr.sortedRootServers.Store(sorted)
		log.Debugf("RECURSION: root servers reordered by latency (%d total)", len(sorted))

		// Persist to DNS cache as TXT records so the order survives restarts.
		if rr.cache != nil {
			txtRecords := make([]dns.RR, 0, len(sorted))
			for _, addr := range sorted {
				txtRecords = append(txtRecords, &dns.TXT{
					Hdr: dns.RR_Header{Name: "_internal.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 86400},
					Txt: []string{addr},
				})
			}
			rr.cache.Set(rootServersCacheKey, txtRecords, nil, nil, false, nil)
		}
	}
}

// orderNSAddresses orders NS addresses by latency using built-in ICMP/UDP53/TCP53
// probing. It runs inline with a capped timeout so it does not stall resolution.
func (rr *Recursive) orderNSAddresses(addresses []string) []string {
	if len(addresses) <= 1 || rr == nil {
		return addresses
	}
	sorted := sortAddrsByLatency(addresses, infrastructureProbeSteps, config.Timeout)
	if len(sorted) > 0 && sorted[0] != addresses[0] {
		log.Debugf("RECURSION: NS reordered by latency (fastest=%s, was=%s)", sorted[0], addresses[0])
	}
	return sorted
}

// sortAddrsByLatency extracts IPs from addr:port strings, probes them
// concurrently, and returns the addresses sorted fastest-first. Addresses
// without valid public IPs are placed at the end in original order.
func sortAddrsByLatency(addresses []string, steps []config.LatencyProbeStep, timeout time.Duration) []string {
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

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	sortedIPs := latency.SortIPsByLatency(ctx, probeIPs, steps)

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

// lookupNSAddrsFromCache looks up cached A and AAAA records for a nameserver
// domain name, returning the resolved IP:port addresses. Records are returned
// in the order stored in the cache, which preserves latency-probed ordering.
func (rr *Recursive) lookupNSAddrsFromCache(nsName string) []string {
	if rr == nil || rr.cache == nil {
		return nil
	}

	var addrs []string

	// A records
	if aAddrs := lookupCachedRRs(rr.cache, nsName, dns.TypeA); len(aAddrs) > 0 {
		addrs = append(addrs, aAddrs...)
	}
	// AAAA records
	if aaaaAddrs := lookupCachedRRs(rr.cache, nsName, dns.TypeAAAA); len(aaaaAddrs) > 0 {
		addrs = append(addrs, aaaaAddrs...)
	}

	return addrs
}

// lookupCachedRRs fetches cached A or AAAA records for a name and converts
// them to "ip:port" strings, preserving the cache entry's record order.
func lookupCachedRRs(store cache.Store, name string, qtype uint16) []string {
	q := dns.Question{Name: name, Qtype: qtype, Qclass: dns.ClassINET}
	key := cache.BuildCacheKey(q, nil, false)
	entry, found, expired := store.Get(key)
	if !found || expired || entry == nil || len(entry.Answer) == 0 {
		return nil
	}

	records := cache.ExpandRecords(entry.Answer)
	addrs := make([]string, 0, len(records))
	for _, rr := range records {
		switch r := rr.(type) {
		case *dns.A:
			if r != nil {
				addrs = append(addrs, net.JoinHostPort(r.A.String(), config.DefaultDNSPort))
			}
		case *dns.AAAA:
			if r != nil {
				addrs = append(addrs, net.JoinHostPort(r.AAAA.String(), config.DefaultDNSPort))
			}
		}
	}
	return addrs
}
