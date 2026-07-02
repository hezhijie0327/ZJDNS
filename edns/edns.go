// Package edns implements EDNS(0) option handling including ECS, DNS Cookie,
// EDE, and Padding.
package edns

import (
	"fmt"
	"sync/atomic"

	"github.com/miekg/dns"

	"zjdns/config"
	"zjdns/internal/ipdetect"
	"zjdns/internal/log"
	"zjdns/internal/pool"
)

// Handler manages EDNS(0) options for outgoing DNS queries and response
// parsing.
type Handler struct {
	defaultECSIPv4   atomic.Pointer[ECSOption]
	defaultECSIPv6   atomic.Pointer[ECSOption]
	defaultECSConfig config.ECSConfig
	detector         *ipdetect.Detector
	CookieGenerator  *CookieGenerator
}

// NewHandler creates a Handler with the given default ECS configuration.
func NewHandler(defaultECS config.ECSConfig) (*Handler, error) {
	h := &Handler{
		defaultECSConfig: defaultECS,
		detector: &ipdetect.Detector{
			TraceURL: defaultECS.AutoDetectURL,
		},
		CookieGenerator: NewCookieGenerator(),
	}

	if !defaultECS.IsEmpty() {
		if defaultECS.IPv4 != "" {
			if config.IsAutoECSValue(defaultECS.IPv4) {
				log.Infof("EDNS: Default ECS IPv4 set to auto; refresh will run in background")
			} else {
				ecs, err := h.parseECSConfig(defaultECS.IPv4, false)
				if err != nil {
					return nil, fmt.Errorf("parse default_ecs_subnet.ipv4: %w", err)
				}
				if ecs != nil {
					h.defaultECSIPv4.Store(ecs)
					log.Infof("EDNS: Default ECS IPv4: %s/%d", ecs.Address, ecs.SourcePrefix)
				}
			}
		}
		if defaultECS.IPv6 != "" {
			if config.IsAutoECSValue(defaultECS.IPv6) {
				log.Infof("EDNS: Default ECS IPv6 set to auto; refresh will run in background")
			} else {
				ecs, err := h.parseECSConfig(defaultECS.IPv6, true)
				if err != nil {
					return nil, fmt.Errorf("parse default_ecs_subnet.ipv6: %w", err)
				}
				if ecs != nil {
					h.defaultECSIPv6.Store(ecs)
					log.Infof("EDNS: Default ECS IPv6: %s/%d", ecs.Address, ecs.SourcePrefix)
				}
			}
		}
	}

	return h, nil
}

// ApplyToMessage adds EDNS(0) options (ECS, Cookie, EDE, Padding, TCP
// Keepalive) to a DNS message. isRequest selects the padding block size:
// 128 bytes for queries (RFC 8467), 468 bytes for responses.
// clientWantsPadding, parsed via HasPaddingOption, lets the client opt out
// via +nopadding / +noalignment. tcpKeepaliveTimeout, in 100ms units
// (RFC 7828), is only included in TCP-server responses (not requests).
func (h *Handler) ApplyToMessage(msg *dns.Msg, ecs *ECSOption, isSecureConnection bool, cookieStr string, ede *EDEOption, isRequest bool, clientWantsPadding bool, tcpKeepaliveTimeout uint16) {
	if h == nil || msg == nil {
		return
	}

	if len(msg.Extra) > 0 {
		cleanExtra := make([]dns.RR, 0, len(msg.Extra))
		for _, rr := range msg.Extra {
			if rr != nil && rr.Header().Rrtype != dns.TypeOPT {
				cleanExtra = append(cleanExtra, rr)
			}
		}
		msg.Extra = cleanExtra
	}

	opt := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
			Class:  pool.UDPBufferSize,
		},
	}
	opt.SetDo()

	var options []dns.EDNS0

	if ecs != nil {
		options = append(options, &dns.EDNS0_SUBNET{
			Code:          dns.EDNS0SUBNET,
			Family:        ecs.Family,
			SourceNetmask: ecs.SourcePrefix,
			SourceScope:   DefaultECSScope,
			Address:       ecs.Address,
		})
	}

	if cookieStr != "" {
		options = append(options, &dns.EDNS0_COOKIE{
			Code:   dns.EDNS0COOKIE,
			Cookie: cookieStr,
		})
	}

	if ede != nil {
		options = append(options, &dns.EDNS0_EDE{
			InfoCode:  ede.InfoCode,
			ExtraText: ede.ExtraText,
		})
	}

	if !isRequest && tcpKeepaliveTimeout > 0 {
		options = append(options, &dns.EDNS0_TCP_KEEPALIVE{
			Code:    dns.EDNS0TCPKEEPALIVE,
			Timeout: tcpKeepaliveTimeout,
		})
	}

	var paddingBytes int
	paddingBlockSize := config.DefaultPaddingResponseBlockSize
	if isRequest {
		paddingBlockSize = config.DefaultPaddingRequestBlockSize
	}
	options, paddingBytes = addPadding(msg, options, isSecureConnection, paddingBlockSize, clientWantsPadding)

	opt.Option = options
	msg.Extra = append(msg.Extra, opt)

	log.Debugf("EDNS: built OPT secure=%t ecs=%t cookie=%t ede=%t keepalive=%d padding=%d bytes block=%d req=%t wantPad=%t",
		isSecureConnection, ecs != nil, cookieStr != "", ede != nil, tcpKeepaliveTimeout, paddingBytes, paddingBlockSize, isRequest, clientWantsPadding)
}
