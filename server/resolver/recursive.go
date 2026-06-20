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
// authoritative nameserver hierarchy.
type Recursive struct {
	resolver *Resolver
}

func (rr *Recursive) resolve(ctx context.Context, question dns.Question, ecs *edns.ECSOption, depth int, forceTCP bool) ([]dns.RR, []dns.RR, []dns.RR, bool, *edns.ECSOption, string, bool, error) {
	log.Debugf("RECURSION: depth=%d, querying %s (type=%s, tcp=%t)", depth, question.Name, dns.TypeToString[question.Qtype], forceTCP)
	if depth > MaxRecursionDep {
		log.Warnf("RECURSION: depth exceeded (depth=%d, max=%d) for %s", depth, MaxRecursionDep, question.Name)
		return nil, nil, nil, false, nil, "", false, fmt.Errorf("recursion depth exceeded: %d", depth)
	}

	qname := dns.Fqdn(question.Name)
	question.Name = qname
	nameservers := ShuffleSlice(DefaultRootServers)
	currentDomain := "."
	normalizedQname := dnsutil.NormalizeDomain(qname)
	var hijackDetected bool

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

		validated := rr.resolver.validator.DNSSEC.ValidateResponse(response, true)
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

		validated := rr.resolver.validator.DNSSEC.ValidateResponse(response, true)
		ecsResponse := rr.resolver.edns.ParseFromDNS(response)

		if len(response.Answer) > 0 {
			answer, authority, additional := response.Answer, response.Ns, response.Extra
			pool.DefaultMessagePool.Put(response)
			return answer, authority, additional, validated, ecsResponse, config.RecursiveIndicator, false, nil
		}

		bestMatch := ""
		var bestNSRecords []*dns.NS
		for _, rrec := range response.Ns {
			if ns, ok := rrec.(*dns.NS); ok {
				nsName := dnsutil.NormalizeDomain(rrec.Header().Name)
				isMatch := normalizedQname == nsName ||
					(nsName != "" && strings.HasSuffix(normalizedQname, "."+nsName)) ||
					(nsName == "" && normalizedQname != "")
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
			nsSlice, extraSlice := response.Ns, response.Extra
			pool.DefaultMessagePool.Put(response)
			return nil, nsSlice, extraSlice, validated, ecsResponse, config.RecursiveIndicator, false, nil
		}

		currentDomain = bestMatch + "."

		var nextNS []string
		for _, ns := range bestNSRecords {
			for _, rrec := range response.Extra {
				switch a := rrec.(type) {
				case *dns.A:
					if strings.EqualFold(a.Header().Name, ns.Ns) {
						nextNS = append(nextNS, net.JoinHostPort(a.A.String(), config.DefaultDNSPort))
					}
				case *dns.AAAA:
					if strings.EqualFold(a.Header().Name, ns.Ns) {
						nextNS = append(nextNS, net.JoinHostPort(a.AAAA.String(), config.DefaultDNSPort))
					}
				}
			}
		}

		if len(nextNS) == 0 {
			nextNS = rr.resolveNSAddressesConcurrent(ctx, bestNSRecords, qname, depth, forceTCP)
		}

		if len(nextNS) == 0 {
			nsSlice, extraSlice := response.Ns, response.Extra
			pool.DefaultMessagePool.Put(response)
			return nil, nsSlice, extraSlice, validated, ecsResponse, config.RecursiveIndicator, false, nil
		}

		nextNS = ShuffleSlice(nextNS)
		pool.DefaultMessagePool.Put(response)
		nameservers = nextNS
	}
}

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

	nameservers = ShuffleSlice(nameservers)
	queryCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(errors.New("query resolution completed"))

	resultChan := make(chan *dns.Msg, 1)
	g, queryCtx := errgroup.WithContext(queryCtx)
	g.SetLimit(ConcurrencyLimit(len(nameservers)))

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

			subCtx, subCancel := context.WithTimeout(queryCtx, config.IdleTimeout/2)
			defer subCancel()

			result := rr.resolver.client.ExecuteQuery(subCtx, msg, server)
			if result.Error == nil && result.Response != nil {
				rcode := result.Response.Rcode
				if rcode == dns.RcodeSuccess || rcode == dns.RcodeNameError {
					result.Validated = rr.resolver.validator.DNSSEC.ValidateResponse(result.Response, true)
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
	g.SetLimit(ConcurrencyLimit(len(nsRecords)))

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
			if ans, _, _, _, _, _, _, err := rr.resolve(resolveCtx, aQuestion, nil, depth+1, forceTCP); err == nil {
				for _, rrec := range ans {
					if a, ok := rrec.(*dns.A); ok {
						nsAddrs = append(nsAddrs, net.JoinHostPort(a.A.String(), config.DefaultDNSPort))
					}
				}
			}

			aaaaQuestion := dns.Question{Name: dns.Fqdn(nsRecord.Ns), Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}
			if ans, _, _, _, _, _, _, err := rr.resolve(resolveCtx, aaaaQuestion, nil, depth+1, forceTCP); err == nil {
				for _, rrec := range ans {
					if aaaa, ok := rrec.(*dns.AAAA); ok {
						nsAddrs = append(nsAddrs, net.JoinHostPort(aaaa.AAAA.String(), config.DefaultDNSPort))
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
