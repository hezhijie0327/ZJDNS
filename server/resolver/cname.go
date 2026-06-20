package resolver

import (
	"context"
	"fmt"
	"strings"

	"github.com/miekg/dns"

	"zjdns/edns"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
)

// CNAME handles CNAME record chasing during DNS resolution, following the
// redirection chain up to MaxCNAMEChain hops.
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

	for cnameDepth = range MaxCNAMEChain {
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

	if cnameDepth >= MaxCNAMEChain-1 {
		log.Warnf("RECURSION: CNAME chain exhausted (max=%d) for %s", MaxCNAMEChain, dnsutil.NormalizeDomain(question.Name))
	}
	return allAnswers, finalAuthority, finalAdditional, allValidated, finalECSResponse, usedServer, hijackOccurred, nil
}
