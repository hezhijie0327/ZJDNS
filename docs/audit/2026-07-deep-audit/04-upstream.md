# Upstream DNSCrypt Audit

## Files Audited

- `server/upstream/dnscrypt/client.go` — Client Execute, WarmUp, Close
- `server/upstream/dnscrypt/state.go` — State management, cert fetching, parsing
- `server/upstream/dnscrypt/crypto.go` — Query preparation (classical + PQ)
- `server/upstream/dnscrypt/cert.go` — Certificate fetching (UDP + TCP)

## Findings

### CRITICAL — None

### HIGH — None

### MEDIUM — None

### LOW

| ID | File | Line | Category | Description |
|----|------|------|----------|-------------|
| L16 | `server/upstream/dnscrypt/crypto.go` | 81 | comment | `_, _ = rand.Read(...)` discards error without inline comment per §6.2 item 11 |

## Assessment

Upstream DNSCrypt implementation is clean and well-structured. Certificate fetching has
proper UDP→TCP fallback. PQ ticket handling correctly stores tickets from server responses
and uses them for resumed queries. TC escalation with `minQueryLen` doubling follows
the reference implementation pattern.
