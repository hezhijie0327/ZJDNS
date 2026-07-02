package handler

import (
	"net"
	"strings"

	"github.com/miekg/dns"

	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/log"
	"zjdns/internal/pool"
)

func (h *Handler) addEDNS(msg *dns.Msg, req *dns.Msg, isSecureConnection bool, clientIP net.IP, cookieOpt *edns.CookieOption, ede *edns.EDEOption) {
	if msg == nil || req == nil {
		return
	}

	clientRequestedDNSSEC := false
	var ecsOpt *edns.ECSOption

	if opt := req.IsEdns0(); opt != nil {
		clientRequestedDNSSEC = opt.Do()
		ecsOpt = h.edns.ParseFromDNS(req)
	}

	if ecsOpt == nil && len(req.Question) > 0 {
		ecsOpt = h.edns.ECSForQType(req.Question[0].Qtype)
	}

	clientWantsPadding := edns.HasPaddingOption(req)
	h.applyEDNS(msg, isSecureConnection, clientIP, ecsOpt, clientRequestedDNSSEC, cookieOpt, ede, clientWantsPadding)
}

func (h *Handler) applyEDNS(msg *dns.Msg, isSecureConnection bool, clientIP net.IP, ecsOpt *edns.ECSOption, clientRequestedDNSSEC bool, cookieOpt *edns.CookieOption, ede *edns.EDEOption, clientWantsPadding bool) {
	cookieStr := h.generateCookieResponse(cookieOpt, clientIP)

	shouldAddEDNS := ecsOpt != nil || clientRequestedDNSSEC || cookieStr != "" || ede != nil || isSecureConnection

	if shouldAddEDNS {
		h.edns.ApplyToMessage(msg, ecsOpt, isSecureConnection, cookieStr, ede, false, clientWantsPadding)
	}
}

func (h *Handler) generateCookieResponse(cookieOpt *edns.CookieOption, clientIP net.IP) string {
	if h.edns == nil || h.edns.CookieGenerator == nil || cookieOpt == nil {
		return ""
	}

	if clientIP == nil {
		clientIP = net.ParseIP(config.FallbackClientIP)
	}

	if len(cookieOpt.ClientCookie) != edns.DefaultCookieClientLen {
		log.Debugf("EDNS: invalid client cookie length %d (expected %d)", len(cookieOpt.ClientCookie), edns.DefaultCookieClientLen)
		return ""
	}

	if len(cookieOpt.ServerCookie) >= edns.DefaultCookieServerLen {
		if h.edns.CookieGenerator.IsServerCookieValid(clientIP, cookieOpt.ClientCookie, cookieOpt.ServerCookie) {
			log.Debugf("EDNS: server cookie validated for %s", clientIP)
		} else {
			log.Debugf("EDNS: server cookie invalid for %s, regenerating", clientIP)
		}
	} else {
		log.Debugf("EDNS: generating new server cookie for %s", clientIP)
	}
	serverCookie := h.edns.CookieGenerator.GenerateServerCookie(clientIP, cookieOpt.ClientCookie)

	return edns.BuildCookieResponse(cookieOpt.ClientCookie, serverCookie)
}

func (h *Handler) buildResponse(req *dns.Msg) *dns.Msg {
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

func (h *Handler) restoreOriginalDomain(msg *dns.Msg, currentName, originalName string) {
	if msg == nil || strings.EqualFold(currentName, originalName) {
		return
	}
	for _, rr := range msg.Answer {
		if rr != nil && strings.EqualFold(rr.Header().Name, currentName) {
			rr.Header().Name = originalName
		}
	}
	for _, rr := range msg.Ns {
		if rr != nil && strings.EqualFold(rr.Header().Name, currentName) {
			rr.Header().Name = originalName
		}
	}
	for _, rr := range msg.Extra {
		if rr != nil && strings.EqualFold(rr.Header().Name, currentName) {
			rr.Header().Name = originalName
		}
	}
}
