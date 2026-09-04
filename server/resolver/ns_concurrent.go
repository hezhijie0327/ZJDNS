// Concurrent nameserver querying: the authority race (latency-ranked
// first-six widening to all after the window), per-server workers with
// defense verdicts, and the NS-address resolution fan-out.

package resolver

import (
	"context"
	"errors"
	"sync/atomic"
	"time"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	"zjdns/server/defense"

	zdnsutil "zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"golang.org/x/sync/errgroup"
)

func (r *Recursive) queryNameserversConcurrent(ctx context.Context, nameservers []string, question Question, ecs *edns.ECSOption, forceTCP bool, currentDomain string, detector defense.Detector) (*dns.Msg, defense.Verdict, error) {
	if len(nameservers) == 0 {
		return nil, defense.VerdictClean, errors.New("no nameservers")
	}

	// Drop the address family this host cannot reach (probed once at
	// startup): a 26-address root batch carrying 13 instant-failing IPv6
	// addresses churned the UDP pool (dial + evict per address) and doubled
	// the per-query error log noise.  Ordering (latency-sorted) is kept.
	nameservers = filterByFamily(nameservers, r.addressFamily)
	if len(nameservers) == 0 {
		return nil, defense.VerdictClean, errors.New("no nameservers")
	}

	deadlineCtx, deadlineCancel := context.WithTimeout(ctx, config.DefaultRecursiveQueryTimeout)
	defer deadlineCancel()
	queryCtx, cancel := context.WithCancel(deadlineCtx)
	defer cancel()

	resultChan := make(chan *dns.Msg, 1)
	g, queryCtx := errgroup.WithContext(queryCtx)
	// Batched racing: the latency-ranked first DefaultFanoutFirstBatch
	// authorities launch at t=0 and the rest widen in after
	// DefaultFanoutWidenDelay without a winner.  Unlike a hard cap
	// (errgroup SetLimit / semaphore — measured 41ms→382ms→3000ms on a
	// 15-server batch: slow servers held the slots while fast ones queued
	// behind the launch loop), widening is timer-driven, so slow batch
	// members never hold anything the rest queue behind, and the first
	// responder almost always lands in the batch (authorities answer in
	// tens of ms).  A burst of unique qnames no longer multiplies
	// goroutines/context/timers by 13-26 (root) per level per walk; the
	// widen goroutine runs INSIDE the errgroup so g.Wait() cannot race a
	// late g.Go against the pooled baseMsg return.  The win path's
	// cancel() aborts the batch, the pending widen and the stragglers.

	var poisonRejected atomic.Bool
	// nxdomainMsg holds the first collected NXDOMAIN (secondary result —
	// served only when no NOERROR wins the race or the deferral window
	// expires).
	var nxdomainMsg atomic.Pointer[dns.Msg]
	// nxdomainCh wakes the wait loop on the first NXDOMAIN collection so the
	// deferral window starts from the earliest possible instant.
	nxdomainCh := make(chan struct{}, 1)
	normalizedQname := dnsutil.Canonical(question.Name)

	baseMsg := r.resolver.buildMsg(question, ecs, false, false)
	baseMsg.UDPSize = pool.RecursiveUDPBufferSize
	// RFC 10029: bundle the configured types (minus the primary QTYPE).
	attachMQType(baseMsg, r.mqtype, question.Qtype)
	launchNS := func(nsAddr string) {
		protocol := config.ProtoUDP
		if forceTCP {
			protocol = config.ProtoTCP
		}
		server := &config.UpstreamServer{
			Address:    nsAddr,
			Protocol:   protocol,
			Proxy:      r.resolver.recursiveProxyURL,
			Spoofguard: r.spoofguard && protocol == config.ProtoUDP,
			Splitguard: r.splitguard && protocol == config.ProtoTCP,
			HopGuard:   r.hopguard && protocol == config.ProtoUDP,
			CapsGuard:  r.capsguard, // protocol-agnostic (DNS 0x20 echo check)
		}

		g.Go(func() error {
			defer zdnsutil.HandlePanic("Query nameserver")

			select {
			case <-queryCtx.Done():
				return nil
			default:
			}

			// Global in-flight cap: last-line guard against query
			// amplification (delegation loops with unreachable authorities).
			// Over the cap the level fails fast — dropping this query is
			// cheaper than letting another unreachable-authority timeout
			// join the storm.
			if r.inFlightQueries.Add(1) > config.DefaultMaxRecursiveInflightQueries {
				r.inFlightQueries.Add(-1)
				log.Debugf("RECURSION: in-flight query cap (%d) reached — skipping %s for %s", config.DefaultMaxRecursiveInflightQueries, nsAddr, question.Name)
				return nil
			}
			defer r.inFlightQueries.Add(-1)

			msg := pool.DefaultMessage.Get()
			defer pool.DefaultMessage.Put(msg)
			if len(baseMsg.Question) > 0 {
				msg.Question = append(msg.Question, baseMsg.Question[0])
			}
			msg.RecursionDesired = baseMsg.RecursionDesired
			msg.CheckingDisabled = baseMsg.CheckingDisabled
			msg.Security = baseMsg.Security
			msg.CompactAnswers = baseMsg.CompactAnswers
			msg.UDPSize = baseMsg.UDPSize
			// EDNS(0) options (ECS SUBNET, cookie, padding) live in Pseudo in
			// this fork — without this copy the caller's explicit ECS never
			// reached the authoritative servers (geo-aware resolution broke).
			msg.Pseudo = append(msg.Pseudo, baseMsg.Pseudo...)
			// ExecuteQuery reads msg via Pack()/Data — caller retains ownership.
			// No per-NS sub-context: ExecuteQuery applies its own timeout, and
			// queryCtx already carries the 9s deadline — a nested WithTimeout
			// duplicated the timer and context per NS (a dominant allocation
			// under full guards, where every recursion level fans out here).
			result := r.resolver.queryClient.ExecuteQuery(queryCtx, msg, server)
			// RFC 10029 fallback: a query carrying MQTYPE-Query can be
			// dropped (timeout), interfered with, refused, or answered with
			// any failure rcode by authorities that do not implement the
			// option (observed: Tencent NS refusing MQTYPE-Query queries in
			// some deployments).  Retry once without the option whenever the
			// query did not succeed (NOERROR or NXDOMAIN); the merge benefit
			// is lost but resolution must not fail because of it.
			// Fallback for genuinely failed queries: "operation was
			// canceled" is a normal first-success race (skip — the walk
			// already has a winner), but timeouts and fast failures
			// (REFUSED, socket closed) are real — an authority that drops
			// MQTYPE-Query queries answers the optionless retry.  The retry
			// uses an independent context so an exhausted queryCtx does not
			// block it.
			if hasMQQUERY(msg.Pseudo) &&
				!errors.Is(result.Error, context.Canceled) &&
				(result.Error != nil || (result.Response != nil &&
					result.Response.Rcode != dns.RcodeSuccess && result.Response.Rcode != dns.RcodeNameError)) {
				if result.Response != nil {
					pool.DefaultMessage.Put(result.Response)
				}
				msg.Pseudo = removeMQQUERY(msg.Pseudo)
				// Independent retry context: a fresh budget guarantees the
				// fallback runs even if the first attempt consumed queryCtx.
				retryCtx, retryCancel := context.WithTimeout(context.WithoutCancel(queryCtx), config.DefaultMQTypeResolveTimeout)
				result = r.resolver.queryClient.ExecuteQuery(retryCtx, msg, server)
				retryCancel()
			}
			if result.Error == nil && result.Response != nil {
				// RFC 5452 §9.3: reject responses that do not echo the query's
				// question — a replayed signed response for a different name
				// in the same zone would otherwise validate and poison the
				// cache (R3-H1).
				if !responseEchoesQuestion(result.Response, question) {
					log.Debugf("RECURSION: ns=%s question echo mismatch for %s %s", nsAddr, question.Name, dns.TypeToString[question.Qtype])
					pool.DefaultMessage.Put(result.Response)
					return nil
				}
				rcode := result.Response.Rcode

				if rcode == dns.RcodeNameError && len(result.Response.Answer) > 0 && !result.Response.Authoritative {
					// RFC 6604 §3: NXDOMAIN may include CNAME/DNAME records
					// when the original query name is an alias whose target
					// does not exist. Only reject when non-alias answer records
					// are present — those indicate data injection.
					//
					// Note: this check only triggers when the AA flag is absent.
					// GFW-injected responses can carry fake AA=1, so this gate
					// alone is insufficient. NXDOMAIN deferral (below) provides
					// the primary defence: fake NXDOMAIN never wins the race
					// against a real NOERROR response.
					hasNonAlias := false
					for _, rr := range result.Response.Answer {
						switch rr.(type) {
						case *dns.CNAME, *dns.DNAME:
						default:
							hasNonAlias = true
						}
					}
					if hasNonAlias {
						log.Debugf("RECURSION: rejecting malformed NXDOMAIN+answer — poison from %s", nsAddr)
						poisonRejected.Store(true)
						pool.DefaultMessage.Put(result.Response)
						return nil
					}
				}
				if rcode == dns.RcodeSuccess {
					// Reject truncated responses: a TC bit over TCP means
					// the authoritative server could not deliver a complete
					// answer even over a stream transport (RFC 1035 §4.2.2).
					if result.Response.Truncated {
						log.Debugf("RECURSION: ns=%s truncated response for %s %s — skipping", nsAddr, question.Name, dns.TypeToString[question.Qtype])
						pool.DefaultMessage.Put(result.Response)
						return nil
					}
					if r.poisonguard && protocol == config.ProtoUDP {
						// UDP-only heuristic: GFW injection is spoofed UDP
						// datagrams; a response that arrived over TCP passed
						// the handshake + sequence checks and cannot be
						// injected this way (that is why detection forces
						// TCP).  Judging TCP responses only produced false
						// positives (e.g. the .cn registry authoritatively
						// answers A for cnnic.cn).
						v := detector.Validate(currentDomain, normalizedQname, result.Response)
						if v == defense.VerdictPoisoned {
							log.Debugf("RECURSION: rejecting poisoned response from %s", nsAddr)
							poisonRejected.Store(true)
							pool.DefaultMessage.Put(result.Response)
							return nil
						}
					}

					select {
					case resultChan <- result.Response:
						cancel()
						return nil
					case <-queryCtx.Done():
						pool.DefaultMessage.Put(result.Response)
						return queryCtx.Err()
					}
				}

				if rcode == dns.RcodeNameError {
					// NXDOMAIN is accepted as the level's answer once
					// collected (first-wins; GFW pollution is A/AAAA
					// injection and packet drops, not NXDOMAIN).  It is
					// stored via CAS so the first one wins, and the wait
					// loop below serves it immediately or after the
					// optional deferral window.
					if r.poisonguard && protocol == config.ProtoUDP {
						// UDP-only heuristic — see the NOERROR branch.
						v := detector.Validate(currentDomain, normalizedQname, result.Response)
						if v == defense.VerdictPoisoned {
							log.Debugf("RECURSION: rejecting poisoned response from %s", nsAddr)
							poisonRejected.Store(true)
							pool.DefaultMessage.Put(result.Response)
							return nil
						}
					}

					if !nxdomainMsg.CompareAndSwap(nil, result.Response) {
						pool.DefaultMessage.Put(result.Response)
					} else {
						// First NXDOMAIN collected — arm the deferral window
						// in the wait loop below.
						select {
						case nxdomainCh <- struct{}{}:
						default:
						}
					}
					return nil
				}

				if rcode == dns.RcodeFormatError {
					pool.DefaultMessage.Put(result.Response)
					r.retryWithoutEDNS(queryCtx, resultChan, cancel, server, question, nsAddr, detector, currentDomain, normalizedQname, &poisonRejected)
					return nil
				}

				log.Debugf("RECURSION: ns=%s rcode=%s for %s %s", nsAddr, dns.RcodeToString[rcode], question.Name, dns.TypeToString[question.Qtype])
				pool.DefaultMessage.Put(result.Response)
			} else if result.Error != nil {
				log.Debugf("RECURSION: ns=%s error=%v for %s %s", nsAddr, result.Error, question.Name, dns.TypeToString[question.Qtype])
			}
			return nil
		})
	}

	// t=0: race the first batch; widen to every remaining authority after
	// DefaultFanoutWidenDelay without a winner.  The widen worker runs in
	// the same errgroup — g.Wait() covers its late g.Go launches, so the
	// pooled baseMsg is never returned while a widened worker still reads
	// it, and a first-win cancel() aborts the widen before it fires.
	if len(nameservers) > config.DefaultFanoutFirstBatch {
		for _, ns := range nameservers[:config.DefaultFanoutFirstBatch] {
			launchNS(ns)
		}
		rest := nameservers[config.DefaultFanoutFirstBatch:]
		g.Go(func() error {
			defer zdnsutil.HandlePanic("Fan-out widen")
			t := time.NewTimer(config.DefaultFanoutWidenDelay)
			defer t.Stop()
			select {
			case <-t.C:
				for _, ns := range rest {
					launchNS(ns)
				}
			case <-queryCtx.Done():
			}
			return nil
		})
	} else {
		for _, ns := range nameservers {
			launchNS(ns)
		}
	}

	// Wait for first successful response, or until all goroutines complete.
	// This ensures every nameserver gets a fair chance — when some
	// addresses fail instantly (e.g. IPv6 unreachable on an IPv4-only host),
	// we don't prematurely time out before the remaining addresses have been
	// tried. With spoofguard, goroutines internally collect for up to 500ms
	// before sending a result, so the errgroup naturally accounts for that.
	errgroupDone := make(chan struct{})
	go func() {
		defer zdnsutil.HandlePanic("Query nameservers wait")
		defer close(errgroupDone)
		if err := g.Wait(); err != nil {
			log.Debugf("RECURSION: NS query errgroup: %v", err)
		}
		// baseMsg is read by every worker (including stragglers still
		// winding down after the caller returned early on the first
		// response) — returning it here, after g.Wait, guarantees no
		// worker reads a pooled message that was already zeroed or
		// reused by another query.
		pool.DefaultMessage.Put(baseMsg)
	}()

	verdict := defense.VerdictClean

	// serveWinner handles a NOERROR race winner: returns the collected
	// NXDOMAIN (if any) to the pool, carries the poison verdict, and drains
	// orphan responses that slipped into the buffer between the winner's
	// send and cancel() propagation (M10).
	serveWinner := func(resp *dns.Msg) (*dns.Msg, defense.Verdict, error) {
		if nx := nxdomainMsg.Load(); nx != nil {
			pool.DefaultMessage.Put(nx)
		}
		if poisonRejected.Load() {
			verdict = defense.VerdictPoisoned
		}
		for {
			select {
			case m := <-resultChan:
				pool.DefaultMessage.Put(m)
			default:
				return resp, verdict, nil
			}
		}
	}

	// NXDOMAIN handling: the first collected NXDOMAIN is accepted — GFW's
	// A/AAAA-injection pollution does not include NXDOMAIN, so there is no
	// injected-NXDOMAIN race to defer for.  A bounded deferral window is kept
	// as an optional knob for misconfigured/stale authorities that answer
	// NXDOMAIN before healthy peers return the real NOERROR: raising
	// DefaultNXDOMAINDeferralWindow re-arms that race at the cost of a fixed
	// delay per all-NXDOMAIN level.  The default 0 serves the first NXDOMAIN
	// immediately — the level does not wait for the SLOWEST nameserver to
	// complete (a rate-limited or packet-lossy server would otherwise stretch
	// every all-NXDOMAIN level to its full tail — measured 41ms→382ms on a
	// 15-server batch).  The poisonguard verdict + TCP fallback still gate
	// poisoned responses.
	var deferralTimer *time.Timer
	var deferralCh <-chan time.Time
	// The timer is created lazily inside the loop; stop it from function
	// scope so a pending window never outlives the query (Stop on an
	// already-fired timer is a no-op).
	defer func() {
		if deferralTimer != nil {
			deferralTimer.Stop()
		}
	}()
waitLoop:
	for {
		select {
		case resp := <-resultChan:
			return serveWinner(resp)
		case <-nxdomainCh:
			if deferralTimer == nil {
				deferralTimer = time.NewTimer(config.DefaultNXDOMAINDeferralWindow)
				deferralCh = deferralTimer.C
			}
		case <-deferralCh:
			nx := nxdomainMsg.Load()
			if nx == nil { // unreachable: the channel only fires after a store
				return nil, verdict, errors.New("no successful response")
			}
			if poisonRejected.Load() {
				verdict = defense.VerdictPoisoned
			}
			return nx, verdict, nil
		case <-errgroupDone:
			break waitLoop
		case <-ctx.Done():
			break waitLoop
		}
	}

	// Drain a NOERROR result that arrived concurrently with errgroupDone or
	// ctx cancellation: both select cases can be ready at once (Go picks
	// uniformly), and dropping the buffered response here would fall through
	// to the NXDOMAIN fallback with a wrong answer.
	select {
	case resp := <-resultChan:
		if nx := nxdomainMsg.Load(); nx != nil {
			pool.DefaultMessage.Put(nx)
		}
		if poisonRejected.Load() {
			verdict = defense.VerdictPoisoned
		}
		return resp, verdict, nil
	default:
	}

	// No NOERROR response — fall back to NXDOMAIN if one was collected.
	if nx := nxdomainMsg.Load(); nx != nil {
		if poisonRejected.Load() {
			verdict = defense.VerdictPoisoned
		}
		return nx, verdict, nil
	}

	if poisonRejected.Load() {
		verdict = defense.VerdictPoisoned
	}
	log.Debugf("RECURSION: all %d nameservers failed for %s (zone=%s)", len(nameservers), question.Name, currentDomain)
	return nil, verdict, errors.New("no successful response")
}

// retryWithoutEDNS attempts a query without EDNS options and sends the result
// to resultChan. Used as a FORMERR fallback per RFC 6891 §6.2.2.
func (r *Recursive) retryWithoutEDNS(ctx context.Context, resultChan chan<- *dns.Msg, cancel context.CancelFunc, server *config.UpstreamServer, question Question, nsAddr string, detector defense.Detector, currentDomain, normalizedQname string, poisonRejected *atomic.Bool) {
	log.Debugf("RECURSION: ns=%s FORMERR, retrying without EDNS for %s %s", nsAddr, question.Name, dns.TypeToString[question.Qtype])

	bareMsg := pool.DefaultMessage.Get()
	defer pool.DefaultMessage.Put(bareMsg)
	dnsutil.SetQuestion(bareMsg, dnsutil.Fqdn(question.Name), question.Qtype, question.Qclass)
	bareMsg.RecursionDesired = false

	retryCtx, retryCancel := context.WithTimeout(ctx, config.DefaultDNSQueryTimeout)
	defer retryCancel()
	retryResult := r.resolver.queryClient.ExecuteQuery(retryCtx, bareMsg, server)

	if retryResult.Error != nil {
		log.Debugf("RECURSION: ns=%s FORMERR retry error=%v for %s %s", nsAddr, retryResult.Error, question.Name, dns.TypeToString[question.Qtype])
		return
	}
	if retryResult.Response == nil {
		return
	}
	// RFC 5452 §9.3: same question-echo gate as the main path (R3-H1).
	if !responseEchoesQuestion(retryResult.Response, question) {
		log.Debugf("RECURSION: ns=%s FORMERR retry question echo mismatch for %s %s", nsAddr, question.Name, dns.TypeToString[question.Qtype])
		pool.DefaultMessage.Put(retryResult.Response)
		return
	}

	retryRcode := retryResult.Response.Rcode
	if retryRcode != dns.RcodeSuccess && retryRcode != dns.RcodeNameError {
		log.Debugf("RECURSION: ns=%s FORMERR retry rcode=%s for %s %s", nsAddr, dns.RcodeToString[retryRcode], question.Name, dns.TypeToString[question.Qtype])
		pool.DefaultMessage.Put(retryResult.Response)
		return
	}

	// Reject hijacked responses in FORMERR retry path as well.
	// UDP-only heuristic — see the NOERROR branch in queryNameserversConcurrent.
	if r.poisonguard && server.Protocol == config.ProtoUDP {
		v := detector.Validate(currentDomain, normalizedQname, retryResult.Response)
		if v == defense.VerdictPoisoned {
			log.Debugf("RECURSION: rejecting poisoned FORMERR retry from %s", nsAddr)
			poisonRejected.Store(true)
			pool.DefaultMessage.Put(retryResult.Response)
			return
		}
	}

	select {
	case resultChan <- retryResult.Response:
		cancel()
	case <-ctx.Done():
		pool.DefaultMessage.Put(retryResult.Response)
	}
}
