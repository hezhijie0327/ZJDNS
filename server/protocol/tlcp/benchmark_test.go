package tlcp

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
	"zjdns/config"

	"gitee.com/Trisia/gotlcp/tlcp"
)

// benchFrameLen is a representative DoT response frame (2-byte length
// prefix + ~200-byte DNS message).
const benchFrameLen = 202

// benchWriterPerFrame replicates the pre-P4 writer discipline — one
// SetWriteDeadline plus one Write per frame — for the before/after
// comparison against the production dotWriterLoop
// (BenchmarkDOTWriterBatched).
func benchWriterPerFrame(conn net.Conn, writeCh <-chan dotWriteTask, connCancel context.CancelFunc) {
	for task := range writeCh {
		_ = conn.SetWriteDeadline(time.Now().Add(config.DefaultDNSQueryTimeout))
		if _, err := conn.Write(task.data); err != nil {
			connCancel()
			return
		}
	}
}

// newDOTBenchPair establishes a real TLCP server/client pair over loopback
// TCP using the production self-signed SM2 certificates; the client side
// drains everything it receives.
func newDOTBenchPair(b *testing.B) (srv *tlcp.Conn, cleanup func()) {
	b.Helper()

	signCert, encCert, _, _, err := generateSelfSignedSMCerts("bench.example.org")
	if err != nil {
		b.Fatalf("generate certs: %v", err)
	}
	srvCfg := &tlcp.Config{
		Certificates:     []tlcp.Certificate{signCert, encCert},
		CurvePreferences: []tlcp.CurveID{tlcp.CurveSM2},
	}
	cliCfg := &tlcp.Config{
		InsecureSkipVerify: true, //nolint:gosec // self-signed benchmark certificate
		CurvePreferences:   []tlcp.CurveID{tlcp.CurveSM2},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("listen: %v", err)
	}

	srvCh := make(chan *tlcp.Conn, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		srv := tlcp.Server(raw, srvCfg)
		if err := srv.Handshake(); err != nil {
			_ = raw.Close()
			return
		}
		srvCh <- srv
	}()

	cli, err := tlcp.Dial("tcp", ln.Addr().String(), cliCfg)
	if err != nil {
		_ = ln.Close()
		b.Fatalf("client dial: %v", err)
	}
	go func() { _, _ = io.Copy(io.Discard, cli) }()

	select {
	case srv = <-srvCh:
	case <-time.After(5 * time.Second):
		_ = cli.Close()
		_ = ln.Close()
		b.Fatal("server handshake timeout")
	}

	cleanup = func() {
		_ = cli.Close()
		_ = srv.Close()
		_ = ln.Close()
	}
	return srv, cleanup
}

// benchDOTWriter drives one writer discipline with b.N identical heap
// frames (pooled=false — the comparison isolates the write path from the
// buffer pool) through the production writeCh handoff.
func benchDOTWriter(b *testing.B, run func(conn net.Conn, writeCh <-chan dotWriteTask, cancel context.CancelFunc)) {
	srv, cleanup := newDOTBenchPair(b)
	defer cleanup()

	frame := make([]byte, benchFrameLen)
	frame[0] = byte(benchFrameLen >> 8) // 2-byte big-endian length prefix
	frame[1] = byte(benchFrameLen)

	writeCh := make(chan dotWriteTask, config.DefaultDOTWriteChannelSize)
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		run(srv, writeCh, cancel)
		close(done)
	}()

	task := dotWriteTask{data: frame}
	b.ResetTimer()
	for b.Loop() {
		writeCh <- task
	}
	close(writeCh)
	<-done
}

// BenchmarkDOTWriterPerFrame is the pre-P4 baseline: per-frame deadline +
// Write (one TLCP record per frame, one deadline per frame).
func BenchmarkDOTWriterPerFrame(b *testing.B) {
	benchDOTWriter(b, benchWriterPerFrame)
}

// BenchmarkDOTWriterBatched drives the production dotWriterLoop: up to 16
// frames per net.Buffers flush with one write deadline per batch.
func BenchmarkDOTWriterBatched(b *testing.B) {
	benchDOTWriter(b, func(conn net.Conn, writeCh <-chan dotWriteTask, cancel context.CancelFunc) {
		dotWriterLoop(conn, writeCh, nil, cancel)
	})
}
