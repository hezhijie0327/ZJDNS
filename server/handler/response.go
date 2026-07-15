package handler

import (
	"net"
	"strings"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/log"
	"zjdns/internal/pool"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

func (h *Handler) addEDNS(msg, req *dns.Msg, isSecureConnection bool, clientIP net.IP, cookieOpt *edns.CookieOption, ede *edns.EDEOption, tcpKeepaliveTimeout uint16) {
	if msg == nil || req == nil {
		return
	}

	clientRequestedDNSSEC := req.Security
	var ecsOpt *edns.ECSOption

	ecsOpt = h.edns.ParseFromDNS(req)

	if ecsOpt == nil && len(req.Question) > 0 {
		ecsOpt = h.edns.ECSForQType(dns.RRToType(req.Question[0]))
	}

	clientWantsPadding := edns.HasPaddingOption(req)
	h.applyEDNS(msg, isSecureConnection, clientIP, ecsOpt, clientRequestedDNSSEC, cookieOpt, ede, clientWantsPadding, tcpKeepaliveTimeout)
}

func (h *Handler) applyEDNS(msg *dns.Msg, isSecureConnection bool, clientIP net.IP, ecsOpt *edns.ECSOption, clientRequestedDNSSEC bool, cookieOpt *edns.CookieOption, ede *edns.EDEOption, clientWantsPadding bool, tcpKeepaliveTimeout uint16) {
	cookieStr := h.generateCookieResponse(cookieOpt, clientIP)

	shouldAddEDNS := ecsOpt != nil || clientRequestedDNSSEC || cookieStr != "" || ede != nil || isSecureConnection || tcpKeepaliveTimeout > 0

	if shouldAddEDNS {
		h.edns.ApplyToMessage(msg, ecsOpt, isSecureConnection, cookieStr, ede, false, clientWantsPadding, tcpKeepaliveTimeout)
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

	var serverCookie []byte
	if len(cookieOpt.ServerCookie) == edns.DefaultCookieServerLen {
		status := h.edns.CookieGenerator.IsServerCookieValid(clientIP, cookieOpt.ClientCookie, cookieOpt.ServerCookie)
		if status == edns.CookieValid {
			log.Debugf("EDNS: server cookie valid for %s, reusing", clientIP)
			serverCookie = cookieOpt.ServerCookie
		} else {
			log.Debugf("EDNS: server cookie status=%d for %s, renewing", status, clientIP)
			serverCookie = h.edns.CookieGenerator.GenerateServerCookie(clientIP, cookieOpt.ClientCookie)
		}
	} else {
		log.Debugf("EDNS: generating new server cookie for %s", clientIP)
		serverCookie = h.edns.CookieGenerator.GenerateServerCookie(clientIP, cookieOpt.ClientCookie)
	}

	if serverCookie == nil {
		return ""
	}
	return edns.BuildCookieResponse(cookieOpt.ClientCookie, serverCookie)
}

func (h *Handler) buildResponse(req *dns.Msg) *dns.Msg {
	msg := pool.DefaultMessagePool.Get()

	if req != nil && len(req.Question) > 0 {
		dnsutil.SetReply(msg, req)
	} else if req != nil {
		msg.Response = true
		msg.Rcode = dns.RcodeFormatError
	}

	msg.Authoritative = false
	msg.RecursionAvailable = true
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
