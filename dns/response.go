package dns

import (
	"net"

	"zjdns/utils"

	"github.com/miekg/dns"
)

func (r *RecursiveDNSServer) buildResponse(req *dns.Msg) *dns.Msg {
	msg := utils.GlobalResourceManager.GetDNSMessage()
	if msg == nil {
		msg = &dns.Msg{}
	}

	if req != nil {
		if len(req.Question) > 0 {
			if msg.Question == nil {
				msg.Question = make([]dns.Question, 0, len(req.Question))
			}
			msg.SetReply(req)
		} else {
			msg.Response = true
			msg.Rcode = dns.RcodeFormatError
		}
	}

	msg.Authoritative = false
	msg.RecursionAvailable = true
	msg.Compress = true
	return msg
}

func (r *RecursiveDNSServer) createDirectIPResponse(req *dns.Msg, qtype uint16, ip net.IP, tracker *utils.RequestTracker) *dns.Msg {
	if tracker != nil {
		tracker.AddStep("🎯 创建直接IP响应: %s", ip.String())
	}

	msg := r.buildResponse(req)

	// 根据查询类型和IP地址类型返回相应记录
	if qtype == dns.TypeA && ip.To4() != nil {
		// IPv4地址查询
		msg.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{
				Name:   req.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    uint32(DefaultCacheTTLSeconds),
			},
			A: ip,
		}}
	} else if qtype == dns.TypeAAAA && ip.To4() == nil {
		// IPv6地址查询
		msg.Answer = []dns.RR{&dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   req.Question[0].Name,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    uint32(DefaultCacheTTLSeconds),
			},
			AAAA: ip,
		}}
	}
	// 对于IPv4地址查询但得到IPv6地址，或IPv6地址查询但得到IPv4地址的情况，返回空答案

	return msg
}
