package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"

	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"
)

func (rr *Recursive) handleSuspiciousResponse(reason string, currentlyTCP bool, _ context.Context, _ dns.Question, _ *edns.ECSOption, _ int) ([]dns.RR, []dns.RR, []dns.RR, bool, *edns.ECSOption, string, bool, error) {
	if !currentlyTCP {
		return nil, nil, nil, false, nil, "", true, fmt.Errorf("%w: %s", ErrHijackDetected, reason)
	}
	return nil, nil, nil, false, nil, "", true, fmt.Errorf("DNS hijacking detected (TCP): %s", reason)
}

func (rr *Recursive) queryNameserversConcurrent(ctx context.Context, nameservers []string, question dns.Question, ecs *edns.ECSOption, forceTCP bool) (*dns.Msg, error) {
	if len(nameservers) == 0 {
		return nil, errors.New("no nameservers")
	}

	queryCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(errors.New("query resolution completed"))

	resultChan := make(chan *dns.Msg, 1)
	g, queryCtx := errgroup.WithContext(queryCtx)
	g.SetLimit(concurrencyLimit(len(nameservers)))

	var activeConnections atomic.Int32

	for _, ns := range nameservers {
		nsAddr := ns
		protocol := "udp"
		if forceTCP {
			protocol = "tcp"
		}
		server := &config.UpstreamServer{Address: nsAddr, Protocol: protocol}

		g.Go(func() error {
			defer dnsutil.HandlePanic("Query nameserver")
			activeConnections.Add(1)
			defer activeConnections.Add(-1)

			select {
			case <-queryCtx.Done():
				return queryCtx.Err()
			default:
			}

			msg := rr.resolver.buildMsg(question, ecs, true, false)
			defer pool.DefaultMessagePool.Put(msg)

			subCtx, subCancel := context.WithTimeout(queryCtx, config.Timeout)
			defer subCancel()

			result := rr.resolver.client.ExecuteQuery(subCtx, msg, server)
			if result.Error == nil && result.Response != nil {
				rcode := result.Response.Rcode
				if rcode == dns.RcodeSuccess || rcode == dns.RcodeNameError {
					select {
					case resultChan <- result.Response:
						cancel(errors.New("first win"))
						return nil
					case <-queryCtx.Done():
						pool.DefaultMessagePool.Put(result.Response)
						return queryCtx.Err()
					}
				}

				// FORMERR fallback: some authoritative servers (e.g. Microsoft
				// mail.protection.outlook.com) reject all EDNS queries with FORMERR.
				// Retry once without EDNS to recover (RFC 6891 §6.2.2).
				if rcode == dns.RcodeFormatError {
					pool.DefaultMessagePool.Put(result.Response)
					log.Debugf("RECURSION: ns=%s FORMERR, retrying without EDNS for %s %s", nsAddr, question.Name, dns.TypeToString[question.Qtype])

					// Build a bare query without EDNS options
					bareMsg := pool.DefaultMessagePool.Get()
					bareMsg.SetQuestion(dns.Fqdn(question.Name), question.Qtype)
					bareMsg.RecursionDesired = true

					retryCtx, retryCancel := context.WithTimeout(queryCtx, config.Timeout)
					retryResult := rr.resolver.client.ExecuteQuery(retryCtx, bareMsg, server)
					retryCancel()
					pool.DefaultMessagePool.Put(bareMsg)

					if retryResult.Error == nil && retryResult.Response != nil {
						retryRcode := retryResult.Response.Rcode
						if retryRcode == dns.RcodeSuccess || retryRcode == dns.RcodeNameError {
							select {
							case resultChan <- retryResult.Response:
								cancel(errors.New("first win after FORMERR retry"))
								return nil
							case <-queryCtx.Done():
								pool.DefaultMessagePool.Put(retryResult.Response)
								return queryCtx.Err()
							}
						}
						log.Debugf("RECURSION: ns=%s FORMERR retry rcode=%s for %s %s", nsAddr, dns.RcodeToString[retryRcode], question.Name, dns.TypeToString[question.Qtype])
						pool.DefaultMessagePool.Put(retryResult.Response)
					} else if retryResult.Error != nil {
						log.Debugf("RECURSION: ns=%s FORMERR retry error=%v for %s %s", nsAddr, retryResult.Error, question.Name, dns.TypeToString[question.Qtype])
					}
					return nil
				}

				log.Debugf("RECURSION: ns=%s rcode=%s for %s %s", nsAddr, dns.RcodeToString[rcode], question.Name, dns.TypeToString[question.Qtype])
				pool.DefaultMessagePool.Put(result.Response)
			} else if result.Error != nil {
				log.Debugf("RECURSION: ns=%s error=%v for %s %s", nsAddr, result.Error, question.Name, dns.TypeToString[question.Qtype])
			}
			return nil
		})
	}

	go func() {
		_ = g.Wait()
		close(resultChan)
	}()

	select {
	case result, ok := <-resultChan:
		if ok && result != nil {
			return result, nil
		}
		return nil, errors.New("no successful response")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (rr *Recursive) resolveNSAddressesConcurrent(ctx context.Context, nsRecords []*dns.NS, qname string, depth int, forceTCP bool) []string {
	if len(nsRecords) == 0 {
		return nil
	}

	nsRecords = ShuffleSlice(nsRecords)
	resolveCtx, resolveCancel := context.WithTimeout(ctx, config.Timeout)
	defer resolveCancel()

	g, queryCtx := errgroup.WithContext(resolveCtx)
	g.SetLimit(concurrencyLimit(len(nsRecords)))

	var allMu sync.Mutex
	var allAddresses []string

	for _, ns := range nsRecords {
		nsRecord := ns
		g.Go(func() error {
			defer dnsutil.HandlePanic("Resolve NS addresses")
			select {
			case <-queryCtx.Done():
				return nil
			default:
			}

			if strings.EqualFold(strings.TrimSuffix(nsRecord.Ns, "."), strings.TrimSuffix(qname, ".")) {
				return nil
			}

			// Query A and AAAA concurrently per NS record —
			// collect results from both as they arrive.
			var nsAddrs []string
			var addrMu sync.Mutex
			var wg sync.WaitGroup
			wg.Add(2)

			go func() {
				defer dnsutil.HandlePanic("Resolve NS A")
				defer wg.Done()
				aQuestion := dns.Question{Name: dns.Fqdn(nsRecord.Ns), Qtype: dns.TypeA, Qclass: dns.ClassINET}
				ans, _, extra, _, _, _, _, err := rr.resolve(queryCtx, aQuestion, nil, depth+1, forceTCP)
				if err != nil {
					return
				}
				addrMu.Lock()
				for _, rrec := range ans {
					if a, ok := rrec.(*dns.A); ok {
						nsAddrs = append(nsAddrs, net.JoinHostPort(a.A.String(), config.DefaultDNSPort))
					}
				}
				// Also collect AAAA glue from the Additional section
				for _, rrec := range extra {
					if aaaa, ok := rrec.(*dns.AAAA); ok && strings.EqualFold(aaaa.Header().Name, nsRecord.Ns) {
						nsAddrs = append(nsAddrs, net.JoinHostPort(aaaa.AAAA.String(), config.DefaultDNSPort))
					}
				}
				addrMu.Unlock()
			}()

			go func() {
				defer dnsutil.HandlePanic("Resolve NS AAAA")
				defer wg.Done()
				aaaaQuestion := dns.Question{Name: dns.Fqdn(nsRecord.Ns), Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}
				ans, _, _, _, _, _, _, err := rr.resolve(queryCtx, aaaaQuestion, nil, depth+1, forceTCP)
				if err != nil {
					return
				}
				addrMu.Lock()
				for _, rrec := range ans {
					if aaaa, ok := rrec.(*dns.AAAA); ok {
						nsAddrs = append(nsAddrs, net.JoinHostPort(aaaa.AAAA.String(), config.DefaultDNSPort))
					}
				}
				addrMu.Unlock()
			}()

			wg.Wait()

			if len(nsAddrs) > 0 {
				allMu.Lock()
				allAddresses = append(allAddresses, nsAddrs...)
				allMu.Unlock()
			}
			return nil
		})
	}

	_ = g.Wait()
	allMu.Lock()
	defer allMu.Unlock()
	return allAddresses
}
