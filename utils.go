// Package main implements ZJDNS - High Performance DNS Server
package main

import (
	"net"
	"os"
	"runtime"
	"strings"

	"github.com/miekg/dns"
)

// IsSecureProtocol checks if the protocol is secure (TLS/QUIC/HTTPS)
func IsSecureProtocol(protocol string) bool {
	switch protocol {
	case "tls", "quic", "https", "http3":
		return true
	default:
		return false
	}
}

// NormalizeDomain normalizes a domain name to lowercase and removes trailing dot
func NormalizeDomain(domain string) string {
	return strings.ToLower(strings.TrimSuffix(domain, "."))
}

// HandlePanic recovers from panics and logs the stack trace
func HandlePanic(operation string) {
	if r := recover(); r != nil {
		buf := make([]byte, TCPBufferSize)
		n := runtime.Stack(buf, false)
		stackTrace := string(buf[:n])
		LogError("PANIC: Panic [%s]: %v\nStack:\n%s\nExiting due to panic", operation, r, stackTrace)
		os.Exit(1)
	}
}

// CloseWithLog closes a resource and logs any errors
func CloseWithLog(c any, name string) {
	if c == nil {
		return
	}
	if closer, ok := c.(interface{ Close() error }); ok {
		if err := closer.Close(); err != nil {
			LogWarn("SERVER: Close %s failed: %v", name, err)
		}
	}
}

// ExtractIPsFromServers extracts IP addresses from server addresses
func ExtractIPsFromServers(servers []string) []string {
	ips := make([]string, len(servers))
	for i, server := range servers {
		host, _, err := net.SplitHostPort(server)
		if err != nil {
			ips[i] = server
		} else {
			ips[i] = host
		}
	}
	return ips
}

// ToRRSlice converts a typed slice to dns.RR slice
func ToRRSlice[T dns.RR](records []T) []dns.RR {
	result := make([]dns.RR, len(records))
	for i, r := range records {
		result[i] = r
	}
	return result
}
