// Protocol dispatch and execution: routing a query to its transport
// (UDP/TCP/TLS/QUIC/HTTPS/HTTP3/DTLS/TLCP/DNSCrypt, with SOCKS5 proxying)
// and the secure-transport query path.

package upstream

import (
	"context"
	"errors"
	"fmt"
	"time"
	"zjdns/config"
	"zjdns/internal/log"
	zpool "zjdns/internal/pool"

	zdnsutil "zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
)

// execute performs one DNS exchange attempt: deadline wrapping, protocol
// dispatch, and DNSCrypt/UDP→TCP fallback.  The 0x20 randomization and echo
// verification live in ExecuteQuery — the mismatch retry reuses this path
// with the original-case message — and Duration is accounted there so a
// retry measures the combined attempts.
func (c *Client) execute(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer) *Result {
	result := &Result{Server: server.Address, Protocol: server.Protocol}

	qname := ""
	if len(msg.Question) > 0 {
		qname = msg.Question[0].Header().Name
	}

	// Avoid a nested timeout timer when the caller already carries a tighter
	// deadline (recursive resolution wraps every NS query in a 9s deadline) —
	// a second WithTimeout duplicated the timer + context per query (a
	// dominant allocation under full guards).
	queryCtx := ctx
	var cancel context.CancelFunc
	if dl, ok := ctx.Deadline(); !ok || time.Until(dl) > c.timeout {
		queryCtx, cancel = context.WithTimeout(ctx, c.timeout)
	}
	if cancel != nil {
		defer cancel()
	}

	// Protocol is normalized to lowercase at registration (ConfigureServers);
	// the per-query ToLower scan is gone from the upstream hot path.
	protocol := server.Protocol

	if protocol == config.ProtoDNSCrypt || protocol == config.ProtoDNSCryptTCP {
		useTCP := protocol == config.ProtoDNSCryptTCP
		result.Response, result.Error = c.dnscryptClient.Execute(queryCtx, msg, server, useTCP)

		if !useTCP && result.Error == nil && result.Response != nil && result.Response.Truncated {
			log.Debugf("UPSTREAM: DNSCrypt UDP response truncated for %s, falling back to TCP", qname)
			useTCP = true
		} else if !useTCP && result.Error != nil && !errors.Is(result.Error, context.Canceled) {
			// Same cancellation gate as the plain-UDP branch: a first-win
			// cancel is not a transport failure, and a doomed TCP attempt
			// on it only burns a slot (U10).
			log.Debugf("UPSTREAM: DNSCrypt UDP query failed for %s, falling back to TCP: %v", qname, result.Error)
			useTCP = true
		}

		if useTCP && protocol == config.ProtoDNSCrypt {
			// Use a fresh context for the TCP fallback — the UDP
			// attempt may have exhausted the original deadline.
			udpErr := result.Error
			tcpCtx, tcpCancel := context.WithTimeout(ctx, c.timeout)
			defer tcpCancel()
			if result.Response != nil {
				zpool.DefaultMessage.Put(result.Response)
				result.Response = nil
			}
			result.Response, result.Error = c.dnscryptClient.Execute(tcpCtx, msg, server, true)
			if result.Error != nil && udpErr != nil {
				// Keep the UDP-side root cause for diagnostics — the plain
				// branch joins both; the DNSCrypt branch overwrote it (U10).
				result.Error = errors.Join(udpErr, result.Error)
			}
			if result.Error == nil {
				protocol = config.ProtoDNSCryptTCP
				log.Debugf("UPSTREAM: DNSCrypt TCP fallback succeeded for %s", qname)
			} else {
				log.Debugf("UPSTREAM: DNSCrypt TCP fallback failed for %s: %v", qname, result.Error)
			}
		} else if result.Error != nil {
			log.Debugf("UPSTREAM: DNSCrypt query failed for %s via %s: %v", qname, server.Address, result.Error)
		}

		result.Protocol = protocol
		return result
	}

	if zdnsutil.IsSecureProtocol(protocol) {
		result.Response, result.Error = c.executeSecureQuery(queryCtx, msg, server, protocol)
	} else {
		if protocol == config.ProtoTCP {
			result.Response, result.Error = c.plainClient.ExecuteTCP(queryCtx, msg, server)
		} else {
			result.Response, result.Error = c.plainClient.ExecuteUDP(queryCtx, msg, server)
		}

		result.Protocol = server.Protocol

		if c.needsTCPFallback(result, protocol) {
			if result.Response != nil && result.Response.Truncated {
				log.Debugf("UPSTREAM: UDP response truncated for %s, falling back to TCP for %s", qname, server.Address)
			} else {
				log.Debugf("UPSTREAM: UDP query failed for %s, falling back to TCP for %s: %v", qname, server.Address, result.Error)
			}

			// Use a fresh context — the UDP attempt may have
			// exhausted the original deadline.  WithTimeout takes the
			// EARLIER of parent-deadline and timeout, so when the caller
			// set a budget the combined wait cannot exceed it; only
			// deadline-less parents get the full c.timeout here (M-low).
			tcpCtx, tcpCancel := context.WithTimeout(ctx, c.timeout)
			defer tcpCancel()

			tcpServer := *server
			tcpServer.Protocol = config.ProtoTCP

			if tcpResp, tcpErr := c.plainClient.ExecuteTCP(tcpCtx, msg, &tcpServer); tcpErr == nil {
				if result.Response != nil {
					zpool.DefaultMessage.Put(result.Response)
				}
				result.Response = tcpResp
				result.Error = nil
				result.Protocol = config.ProtoTCP
				log.Debugf("UPSTREAM: TCP fallback succeeded for %s via %s", qname, server.Address)
			} else {
				log.Debugf("UPSTREAM: TCP fallback failed for %s via %s: %v", qname, server.Address, tcpErr)
				// Discard the truncated UDP response — returning it as a
				// success would serve incomplete data without a TC signal.
				if result.Response != nil {
					zpool.DefaultMessage.Put(result.Response)
					result.Response = nil
				}
				if result.Error == nil {
					result.Error = fmt.Errorf("tcp fallback after truncated response failed: %w", tcpErr)
				} else {
					// Both transports failed — join the errors so neither
					// the original UDP failure nor the TCP failure is lost
					// for diagnostics (M-low).
					result.Error = errors.Join(result.Error, fmt.Errorf("tcp fallback failed: %w", tcpErr))
				}
			}
		}
	}

	return result
}

func (c *Client) executeSecureQuery(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer, protocol string) (*dns.Msg, error) {
	if server.SkipTLSVerify {
		if _, loaded := c.skipVerifyWarned.LoadOrStore(server.ServerName, struct{}{}); !loaded {
			log.Warnf("UPSTREAM: TLS verification disabled for %s — connection is vulnerable to MITM attacks!", server.ServerName)
		}
	}

	log.Debugf("UPSTREAM: secure query to %s via %s", server.Address, protocol)
	switch protocol {
	case config.ProtoTLS:
		return c.tlsClient.ExecuteTLS(ctx, msg, server)
	case config.ProtoQUIC:
		return c.tlsClient.ExecuteQUIC(ctx, msg, server)
	case config.ProtoHTTPS:
		return c.tlsClient.ExecuteHTTPS(ctx, msg, server)
	case config.ProtoHTTP3:
		return c.tlsClient.ExecuteHTTP3(ctx, msg, server)
	case config.ProtoDTLS:
		// RFC 8094 §3.3: fall back to TLS when DTLS fails (e.g. PMTU
		// drops large responses).  This works when DTLS and TLS share
		// the same port — the standard deployment is port 853 where
		// DTLS is UDP and TLS (DoT) is TCP.  The fallback dials TCP
		// to the same address; if the upstream has no TLS listener on
		// that port the fallback fails with "connection refused" (no
		// worse than no fallback at all).
		resp, err := c.tlsClient.ExecuteDTLS(ctx, msg, server)
		if err == nil {
			return resp, nil
		}
		log.Debugf("UPSTREAM: DTLS query failed for %s, falling back to TLS: %v", server.Address, err)
		// Use Background+timeout, not ctx: the DTLS attempt consumed the
		// caller's deadline, and WithTimeout(ctx, ...) inherits the
		// already-expired parent deadline (min(parent, timeout) = past).
		// The cross-protocol fallback gets its own full budget.
		tlsCtx, tlsCancel := context.WithTimeout(context.Background(), c.timeout)
		defer tlsCancel()
		return c.tlsClient.ExecuteTLS(tlsCtx, msg, server)
	case config.ProtoTLCP:
		return c.tlcpClient.ExecuteTLCP(ctx, msg, server)
	case config.ProtoHTTPTLCP:
		return c.tlcpClient.ExecuteHTTPTLCP(ctx, msg, server)
	case config.ProtoDTLCP:
		// Same RFC 8094 §3.3 pattern as DTLS→TLS: fall back to TLCP
		// when DTLCP fails.  Works when both share the same port.
		resp, err := c.tlcpClient.ExecuteDTLCP(ctx, msg, server)
		if err == nil {
			return resp, nil
		}
		log.Debugf("UPSTREAM: DTLCP query failed for %s, falling back to TLCP: %v", server.Address, err)
		// Use Background+timeout — same reason as DTLS→TLS: the DTLCP
		// attempt exhausted the caller's deadline.
		tlcpCtx, tlcpCancel := context.WithTimeout(context.Background(), c.timeout)
		defer tlcpCancel()
		return c.tlcpClient.ExecuteTLCP(tlcpCtx, msg, server)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", protocol)
	}
}
