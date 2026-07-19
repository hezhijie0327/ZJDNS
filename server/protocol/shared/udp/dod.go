package udp

import (
	"errors"
	"io"
	"net"
	"time"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
)

// ServeDTLS accepts connections from a shared UDP listener and handles
// each one as a DNS-over-DTLS or DNS-over-DTLCP connection.
func handleSharedDTLSConn(conn net.Conn, handler edns.DNSHandler, protoLabel string) {
	buf := make([]byte, 65536)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(config.DefaultDTLSIdleTimeout))

		n, err := conn.Read(buf)
		if err != nil {
			if !errors.Is(err, io.EOF) && !isTemporaryError(err) {
				log.Debugf("SHARED: %s read error from %s: %v", protoLabel, conn.RemoteAddr(), err)
			}
			return
		}

		// DTLS/DTLCP records may arrive in a single Read.
		// The first 2 bytes are the DNS-over-DTLS length prefix (RFC 8094 §5.2).
		if n < 2 {
			continue
		}
		msgLen := int(buf[0])<<8 | int(buf[1])
		if msgLen+2 > n || msgLen == 0 {
			continue
		}

		req := new(dns.Msg)
		req.Data = buf[2 : 2+msgLen]
		if err := req.Unpack(); err != nil {
			continue
		}

		var clientIP net.IP
		if addr := conn.RemoteAddr(); addr != nil {
			if udpAddr, ok := addr.(*net.UDPAddr); ok {
				clientIP = udpAddr.IP
			}
		}

		protocol := config.ProtoDTLS
		if protoLabel == "DTLCP" {
			protocol = config.ProtoDTLCP
		}

		response := handler.ServeDNS(req, clientIP, true, protocol)
		if response == nil {
			return
		}

		if err := response.Pack(); err != nil {
			log.Debugf("SHARED: %s pack error: %v", protoLabel, err)
			return
		}

		respData := response.Data
		prefix := [2]byte{byte(len(respData) >> 8), byte(len(respData))} //nolint:gosec // G115: DNS wire format
		if _, err := conn.Write(prefix[:]); err != nil {
			return
		}
		if _, err := conn.Write(respData); err != nil {
			return
		}
	}
}

// isTemporaryError reports whether err is a temporary network error.
func isTemporaryError(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) {
		return ne.Timeout()
	}
	return false
}
