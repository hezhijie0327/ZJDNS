// Minimal SOCKS5 server with UDP ASSOCIATE for ZJDNS loopback tests
// (docs/debug/DEBUG.md's documented helper, rebuilt after the upstream
// cmd package vanished).  Test-only: error paths beyond the handshake are
// deliberately fire-and-forget, no auth beyond no-auth, one outbound
// socket per relay (single-upstream rigs).
package main //nolint:all // minimal loopback test proxy, not production code

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"sync"
)

func main() {
	ln, err := net.Listen("tcp", "127.0.0.1:11080")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("socks5 (udp-assoc) on 127.0.0.1:11080")
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go handle(c)
	}
}

func handle(c net.Conn) {
	defer func() { _ = c.Close() }()
	h := make([]byte, 2)
	if _, err := io.ReadFull(c, h); err != nil || h[0] != 5 {
		return
	}
	_, _ = io.ReadFull(c, make([]byte, h[1]))
	_, _ = c.Write([]byte{5, 0})

	hd := make([]byte, 4)
	if _, err := io.ReadFull(c, hd); err != nil || hd[1] != 3 { // UDP ASSOCIATE only
		return
	}
	switch hd[3] {
	case 1:
		_, _ = io.ReadFull(c, make([]byte, 4))
	case 3:
		l := make([]byte, 1)
		_, _ = io.ReadFull(c, l)
		_, _ = io.ReadFull(c, make([]byte, l[0]))
	case 4:
		_, _ = io.ReadFull(c, make([]byte, 16))
	}
	_, _ = io.ReadFull(c, make([]byte, 2)) // DST.PORT (client hint, unused)

	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return
	}
	defer func() { _ = relay.Close() }()
	port := relay.LocalAddr().(*net.UDPAddr).Port
	rsp := []byte{5, 0, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)} //nolint:gosec // G115: port is a uint16 wire field
	_, _ = c.Write(rsp)

	var mu sync.Mutex
	var client net.Addr
	var outSock *net.UDPConn
	// The relay dies with the TCP control conn.
	go func() {
		b := make([]byte, 64)
		for {
			if _, err := c.Read(b); err != nil {
				mu.Lock()
				_ = relay.Close()
				mu.Unlock()
				return
			}
		}
	}()
	buf := make([]byte, 65536)
	for {
		n, src, err := relay.ReadFrom(buf)
		if err != nil {
			return
		}
		mu.Lock()
		cl := client
		if cl == nil {
			// First datagram from the DNS client: register the peer.
			client = src
			cl = src
		}
		mu.Unlock()
		if src != cl {
			continue
		}
		// Client → remote: strip the 10-byte header, forward via one
		// persistent out socket whose pump wraps replies back to the peer.
		if n < 10 {
			continue
		}
		dst := parseAddr(buf[3:10])
		if dst == nil {
			continue
		}
		mu.Lock()
		out := outSock
		if out == nil {
			out, _ = net.DialUDP("udp", nil, dst)
			outSock = out
			go func() {
				rb := make([]byte, 65536)
				for {
					rn, rsrc, err := out.ReadFrom(rb)
					if err != nil {
						return
					}
					mu.Lock()
					cl := client
					mu.Unlock()
					if cl == nil {
						continue
					}
					addr, ok := rsrc.(*net.UDPAddr)
					if !ok || addr.IP.To4() == nil {
						continue
					}
					ip := addr.IP.To4()
					port := addr.Port
					hdr := []byte{0, 0, 0, 1, ip[0], ip[1], ip[2], ip[3], byte(port >> 8), byte(port)} //nolint:gosec // G115: port is a uint16 wire field
					_, _ = relay.WriteTo(append(hdr, rb[:rn]...), cl)
				}
			}()
		}
		mu.Unlock()
		if out != nil {
			_, _ = out.Write(buf[10:n])
		}
	}
}

// parseAddr parses ATYP+ADDR+PORT from the 10-byte UDP request header's
// tail (b[0]=ATYP, as offset by the caller's buf[3:10] slice).
func parseAddr(b []byte) *net.UDPAddr {
	switch b[0] {
	case 1:
		port := int(binary.BigEndian.Uint16(b[5:7]))
		return &net.UDPAddr{IP: net.IP(b[1:5]), Port: port}
	case 4:
		if len(b) < 19 {
			return nil
		}
		port := int(binary.BigEndian.Uint16(b[17:19]))
		return &net.UDPAddr{IP: net.IP(b[1:17]), Port: port}
	}
	return nil
}
