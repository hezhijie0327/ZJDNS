package server

import (
	"context"
	"errors"
	"fmt"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"

	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/pool"
)

// recursiveUpstream wraps our recursive resolver as a dnsproxy upstream.Upstream.
type recursiveUpstream struct {
	server *Server
}

// Exchange implements upstream.Upstream.
func (u *recursiveUpstream) Exchange(req *dns.Msg) (*dns.Msg, error) {
	if len(req.Question) == 0 {
		return nil, errors.New("empty question")
	}

	question := req.Question[0]
	var ecsOpt *edns.ECSOption
	if opt := req.IsEdns0(); opt != nil {
		ecsOpt = u.server.ednsMgr.ParseFromDNS(req)
	}
	if ecsOpt == nil {
		ecsOpt = u.server.ednsMgr.DefaultECSForQType(question.Qtype)
	}

	ctx, cancel := context.WithTimeout(context.Background(), config.DefaultRecursiveResolveTimeout)
	defer cancel()

	qr := u.server.resolver.Query(ctx, question, ecsOpt)
	if qr.Err != nil {
		return nil, fmt.Errorf("recursive resolve: %w", qr.Err)
	}

	resp := pool.DefaultMessagePool.Get()
	resp.SetReply(req)
	resp.Answer = qr.Answer
	resp.Ns = qr.Authority
	resp.Extra = qr.Additional
	resp.RecursionAvailable = true
	if qr.Validated {
		resp.AuthenticatedData = true
	}

	return resp, nil
}

// Address implements upstream.Upstream.
func (u *recursiveUpstream) Address() string {
	return config.RecursiveIndicator
}

// Close implements upstream.Upstream.
func (u *recursiveUpstream) Close() error {
	return nil
}

var _ upstream.Upstream = (*recursiveUpstream)(nil)
