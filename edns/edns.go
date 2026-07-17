// Package edns implements EDNS(0) option handling including ECS, DNS Cookie,
// EDE, and Padding.
package edns

import (
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"zjdns/config"
	"zjdns/internal/ipdetect"
	"zjdns/internal/log"
	"zjdns/internal/pool"

	"codeberg.org/miekg/dns"
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
// DefaultPaddingRequestBlockSize for queries, DefaultPaddingResponseBlockSize
// for responses (RFC 8467). clientWantsPadding, parsed via HasPaddingOption,
// lets the client opt out via +nopadding / +noalignment. tcpKeepaliveTimeout,
// in 100ms units (RFC 7828), is only included in TCP-server responses.
func (h *Handler) ApplyToMessage(msg *dns.Msg, ecs *ECSOption, isSecureConnection bool, cookieStr string, ede *EDEOption, isRequest, clientWantsPadding bool, tcpKeepaliveTimeout uint16) {
	if h == nil || msg == nil {
		return
	}

	// Set EDNS flags directly on the message header (v2 API).
	msg.UDPSize = pool.UDPBufferSize
	msg.Security = true

	if ecs != nil {
		msg.Pseudo = append(msg.Pseudo, &dns.SUBNET{
			Family:  ecs.Family,
			Netmask: ecs.SourcePrefix,
			Scope:   DefaultECSScope,
			Address: addrToNetip(ecs.Address),
		})
	}

	if cookieStr != "" {
		msg.Pseudo = append(msg.Pseudo, &dns.COOKIE{Cookie: cookieStr})
	}

	if ede != nil {
		msg.Pseudo = append(msg.Pseudo, &dns.EDE{
			InfoCode:  ede.InfoCode,
			ExtraText: ede.ExtraText,
		})
	}

	if !isRequest && tcpKeepaliveTimeout > 0 {
		msg.Pseudo = append(msg.Pseudo, &dns.TCPKEEPALIVE{
			Timeout: tcpKeepaliveTimeout,
		})
	}

	var paddingBytes int
	paddingBlockSize := config.DefaultPaddingResponseBlockSize
	if isRequest {
		paddingBlockSize = config.DefaultPaddingRequestBlockSize
	}
	paddingBytes = addPaddingV2(msg, isSecureConnection, paddingBlockSize, clientWantsPadding)

	log.Debugf("EDNS: built OPT secure=%t ecs=%t cookie=%t ede=%t keepalive=%d padding=%d bytes block=%d req=%t wantPad=%t",
		isSecureConnection, ecs != nil, cookieStr != "", ede != nil, tcpKeepaliveTimeout, paddingBytes, paddingBlockSize, isRequest, clientWantsPadding)
}

// addrToNetip converts a net.IP to netip.Addr for v2 dns.SUBNET.Address.
func addrToNetip(ip net.IP) netip.Addr {
	if ip == nil {
		return netip.Addr{}
	}
	if ip4 := ip.To4(); ip4 != nil {
		addr, _ := netip.AddrFromSlice(ip4)
		return addr
	}
	addr, _ := netip.AddrFromSlice(ip)
	return addr
}

// GenerateServerCookie delegates to CookieGenerator.
func (h *Handler) GenerateServerCookie(clientIP net.IP, clientCookie []byte) []byte {
	return h.CookieGenerator.GenerateServerCookie(clientIP, clientCookie)
}

// IsServerCookieValid delegates to CookieGenerator.
func (h *Handler) IsServerCookieValid(clientIP net.IP, clientCookie, serverCookie []byte) CookieValStatus {
	return h.CookieGenerator.IsServerCookieValid(clientIP, clientCookie, serverCookie)
}

// netipToIP converts a netip.Addr back to net.IP for ECSOption compatibility.
func netipToIP(addr netip.Addr) net.IP {
	if !addr.IsValid() {
		return nil
	}
	return net.IP(addr.AsSlice())
}
