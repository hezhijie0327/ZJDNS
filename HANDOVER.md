# HANDOVER

## Pending: HopGuard TTL Capture on Pooled UDP Sockets

### Problem
When `spoofguard + hopguard` are both enabled, the pooled UDP collect path
cannot extract IP-layer TTL/HopLimit because `net.Conn.Read()` doesn't
provide control messages.  The exclusive-socket path uses `ipttl.Capture`
which wraps `*net.UDPConn` and calls `ReadMsgUDP`.

### Current State (committed)
`ExecuteUDP` dispatch:
- `spoofguard + hopguard` → exclusive socket (`executeUDPMultiRead`)
- `spoofguard-only` → pooled collect (`executeUDPCollect`)
- normal → pooled one-shot (`executeUDPPooled`)

### What Needs to Happen
To route hopguard through the pooled path:

1. **pool/udp.go — readLoop TTL capture**: Replace `conn.Read(buf)` with
   `ipttlCapture.ReadFrom(buf)` when available. Create ipttl.Capture in
   `dialAndAdd` via `ipttl.New(conn.(*net.UDPConn))`.

2. **pool/udp.go — collectPacket type**: Change `collectCh` from `chan []byte`
   to a struct carrying `{Data []byte, TTL uint8}`.

3. **plain/udp.go — executeUDPCollect HopGuard gates**: Add hg.Validate,
   hg.Feed, ttlConfident signal to the collect loop.

4. **plain/udp.go — dispatch**: Remove HopGuard exclusion; both spoofguard
   and hopguard go through executeUDPCollect.

### Windows Caveat
`ipttl.New` returns nil on Windows (no control-message support).
HopGuard gracefully degrades to spoofguard-only behavior (TTL=0).
