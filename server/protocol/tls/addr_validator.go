package tls

import (
	"net"
	"sync"
	"time"
	"zjdns/config"
)

// quicAddrValidator caches recently-seen client addresses so the server can
// skip QUIC Retry address validation on reconnection. Without this, quic-go
// sends a Retry packet for every new source address — which frequently gets
// dropped by NAT/firewall, breaking cross-network QUIC connectivity.
type quicAddrValidator struct {
	mu     sync.RWMutex
	seen   map[string]time.Time
	closed chan struct{}
	once   sync.Once
}

func newQUICAddrValidator() *quicAddrValidator {
	v := &quicAddrValidator{
		seen:   make(map[string]time.Time),
		closed: make(chan struct{}),
	}
	go v.sweepLoop()
	return v
}

func (v *quicAddrValidator) requiresValidation(addr net.Addr) bool {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return true
	}
	key := udpAddr.IP.String()

	v.mu.RLock()
	_, exists := v.seen[key]
	v.mu.RUnlock()

	if exists {
		return false
	}

	v.mu.Lock()
	v.seen[key] = time.Now()
	v.mu.Unlock()

	return true
}

func (v *quicAddrValidator) sweepLoop() {
	ticker := time.NewTicker(config.DefaultQUICServerIdleTimeout)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			cutoff := time.Now().Add(-config.DefaultQUICAddrCacheTTL)
			v.mu.Lock()
			for ip, t := range v.seen {
				if t.Before(cutoff) {
					delete(v.seen, ip)
				}
			}
			v.mu.Unlock()
		case <-v.closed:
			return
		}
	}
}

func (v *quicAddrValidator) close() {
	v.once.Do(func() {
		close(v.closed)
	})
}
