package dnsutil

import (
	"io"
	"net"

	"codeberg.org/miekg/dns"
)

// ReadTCPMsg reads a DNS message prefixed with a 2-byte big-endian length
// from conn (RFC 1035 §4.2.2).  Shared by server and upstream TLCP/TLS stacks.
func ReadTCPMsg(conn net.Conn) (*dns.Msg, error) {
	var prefix [2]byte
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		return nil, err
	}
	length := int(prefix[0])<<8 | int(prefix[1])
	buf := make([]byte, length)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	msg := new(dns.Msg)
	msg.Data = buf
	if err := msg.Unpack(); err != nil {
		return nil, err
	}
	return msg, nil
}

// WriteTCPMsg writes a DNS message prefixed with a 2-byte big-endian length
// to conn (RFC 1035 §4.2.2).  Shared by server and upstream TLCP/TLS stacks.
func WriteTCPMsg(conn net.Conn, msg *dns.Msg) error {
	if err := msg.Pack(); err != nil {
		return err
	}
	length := uint16(len(msg.Data))                    //nolint:gosec // G115: DNS TCP message — protocol-bounded uint16
	prefix := [2]byte{byte(length >> 8), byte(length)} //nolint:gosec // G115: DNS wire format — protocol-bounded byte
	if _, err := conn.Write(prefix[:]); err != nil {
		return err
	}
	_, err := conn.Write(msg.Data)
	return err
}
