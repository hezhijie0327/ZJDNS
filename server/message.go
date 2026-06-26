package server

import (
	"net"
	"strings"

	"github.com/miekg/dns"

	"zjdns/edns"
	"zjdns/internal/log"
	"zjdns/internal/pool"
)

func (s *Server) addEDNS(msg *dns.Msg, req *dns.Msg, isSecureConnection bool, clientIP net.IP, cookieOpt *edns.CookieOption, ede *edns.EDEOption) {
	if msg == nil || req == nil {
		return
	}

	clientRequestedDNSSEC := false
	var ecsOpt *edns.ECSOption

	if opt := req.IsEdns0(); opt != nil {
		clientRequestedDNSSEC = opt.Do()
		ecsOpt = s.ednsMgr.ParseFromDNS(req)
	}

	if ecsOpt == nil && len(req.Question) > 0 {
		ecsOpt = s.ednsMgr.DefaultECSForQType(req.Question[0].Qtype)
	}

	s.applyEDNS(msg, isSecureConnection, clientIP, ecsOpt, clientRequestedDNSSEC, cookieOpt, ede)
}

// applyEDNS applies EDNS options to a response without re-parsing the request.
// It accepts already-parsed ECS and DNSSEC values to avoid redundant work on
// the hot path where these are already known from the initial request parse.
func (s *Server) applyEDNS(msg *dns.Msg, isSecureConnection bool, clientIP net.IP, ecsOpt *edns.ECSOption, clientRequestedDNSSEC bool, cookieOpt *edns.CookieOption, ede *edns.EDEOption) {
	cookieStr := s.generateCookieResponse(cookieOpt, clientIP)

	shouldAddEDNS := ecsOpt != nil || clientRequestedDNSSEC || cookieStr != "" || ede != nil || isSecureConnection

	if shouldAddEDNS {
		s.ednsMgr.ApplyToMessage(msg, ecsOpt, clientRequestedDNSSEC, isSecureConnection, cookieStr, ede)
	}
}

func (s *Server) generateCookieResponse(cookieOpt *edns.CookieOption, clientIP net.IP) string {
	if s.ednsMgr == nil || s.ednsMgr.CookieGenerator == nil || cookieOpt == nil {
		return ""
	}

	if clientIP == nil {
		clientIP = net.ParseIP("0.0.0.0")
	}

	if len(cookieOpt.ClientCookie) != edns.DefaultCookieClientLen {
		log.Debugf("EDNS: invalid client cookie length %d (expected %d)", len(cookieOpt.ClientCookie), edns.DefaultCookieClientLen)
		return ""
	}

	var serverCookie []byte
	if len(cookieOpt.ServerCookie) >= edns.DefaultCookieServerLen {
		if s.ednsMgr.CookieGenerator.ValidateServerCookie(clientIP, cookieOpt.ClientCookie, cookieOpt.ServerCookie) {
			log.Debugf("EDNS: server cookie validated for %s", clientIP)
			serverCookie = s.ednsMgr.CookieGenerator.GenerateServerCookie(clientIP, cookieOpt.ClientCookie)
		} else {
			log.Debugf("EDNS: server cookie invalid for %s, regenerating", clientIP)
			serverCookie = s.ednsMgr.CookieGenerator.GenerateServerCookie(clientIP, cookieOpt.ClientCookie)
		}
	}

	if serverCookie == nil {
		log.Debugf("EDNS: generating new server cookie for %s", clientIP)
		serverCookie = s.ednsMgr.CookieGenerator.GenerateServerCookie(clientIP, cookieOpt.ClientCookie)
	}

	return edns.BuildCookieResponse(cookieOpt.ClientCookie, serverCookie)
}

func (s *Server) buildResponse(req *dns.Msg) *dns.Msg {
	msg := pool.DefaultMessagePool.Get()

	if req != nil && len(req.Question) > 0 {
		msg.SetReply(req)
	} else if req != nil {
		msg.Response = true
		msg.Rcode = dns.RcodeFormatError
	}

	msg.Authoritative = false
	msg.RecursionAvailable = true
	msg.Compress = true
	return msg
}

func (s *Server) restoreOriginalDomain(msg *dns.Msg, currentName, originalName string) {
	if msg == nil || strings.EqualFold(currentName, originalName) {
		return
	}
	normalized := strings.ToLower(currentName)
	for _, rr := range msg.Answer {
		if rr != nil && strings.ToLower(rr.Header().Name) == normalized {
			rr.Header().Name = originalName
		}
	}
	// Also restore in Authority and Additional sections — NS and glue records
	// may reference the rewritten domain name.
	for _, rr := range msg.Ns {
		if rr != nil && strings.ToLower(rr.Header().Name) == normalized {
			rr.Header().Name = originalName
		}
	}
	for _, rr := range msg.Extra {
		if rr != nil && strings.ToLower(rr.Header().Name) == normalized {
			rr.Header().Name = originalName
		}
	}
}

func (s *Server) buildQueryMessage(question dns.Question, ecs *edns.ECSOption, recursionDesired bool, isSecureConnection bool) *dns.Msg {
	msg := pool.DefaultMessagePool.Get()

	msg.SetQuestion(dns.Fqdn(question.Name), question.Qtype)
	msg.RecursionDesired = recursionDesired

	if s.ednsMgr != nil {
		s.ednsMgr.ApplyToMessage(msg, ecs, true, isSecureConnection, "", nil)
	}

	return msg
}
