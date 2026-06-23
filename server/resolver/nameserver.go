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

			subCtx, subCancel := context.WithTimeout(queryCtx, config.IdleTimeout)
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
				pool.DefaultMessagePool.Put(result.Response)
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
	resolveCtx, resolveCancel := context.WithTimeout(ctx, config.IdleTimeout)
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

			var nsAddrs []string

			aQuestion := dns.Question{Name: dns.Fqdn(nsRecord.Ns), Qtype: dns.TypeA, Qclass: dns.ClassINET}
			if ans, _, extra, _, _, _, _, err := rr.resolve(resolveCtx, aQuestion, nil, depth+1, forceTCP); err == nil {
				for _, rrec := range ans {
					if a, ok := rrec.(*dns.A); ok {
						nsAddrs = append(nsAddrs, net.JoinHostPort(a.A.String(), config.DefaultDNSPort))
					}
				}
				// Check Additional section for AAAA glue before making a separate query
				for _, rrec := range extra {
					if aaaa, ok := rrec.(*dns.AAAA); ok && strings.EqualFold(aaaa.Header().Name, nsRecord.Ns) {
						nsAddrs = append(nsAddrs, net.JoinHostPort(aaaa.AAAA.String(), config.DefaultDNSPort))
					}
				}
			}

			hasAaaa := false
			for _, addr := range nsAddrs {
				host, _, _ := net.SplitHostPort(addr)
				if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
					hasAaaa = true
					break
				}
			}
			if !hasAaaa {
				aaaaQuestion := dns.Question{Name: dns.Fqdn(nsRecord.Ns), Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}
				if ans, _, _, _, _, _, _, err := rr.resolve(resolveCtx, aaaaQuestion, nil, depth+1, forceTCP); err == nil {
					for _, rrec := range ans {
						if aaaa, ok := rrec.(*dns.AAAA); ok {
							nsAddrs = append(nsAddrs, net.JoinHostPort(aaaa.AAAA.String(), config.DefaultDNSPort))
						}
					}
				}
			}

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
