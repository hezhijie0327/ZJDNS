package tls

import (
	"testing"
	"zjdns/config"
)

// BenchmarkStdTLSConfigClone documents the per-query DoQ cost that the
// pool-hit path no longer pays since the config build moved from
// ExecuteQUIC's body into the dial closure: before the move every query
// (pool hit included) built this config plus its VerifyConnection closure
// and discarded it; now only dials build it (quic.go, same discipline as
// DoT's dial closure in tls.go).
func BenchmarkStdTLSConfigClone(b *testing.B) {
	c := &Client{}
	server := &config.UpstreamServer{Address: "127.0.0.1:853", ServerName: "bench.test"}
	b.ReportAllocs()
	for b.Loop() {
		cfg := c.stdTLSConfig(server).Clone()
		_ = cfg
	}
}
