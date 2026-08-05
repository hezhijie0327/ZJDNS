export const meta = {
  name: 'zjdns-round3-audit',
  description: 'Fill 2026-08 round-2 audit gaps: protocol package, goversion, 89 zero-coverage files, fix-direction review',
  phases: [
    { title: 'Audit', detail: '8 package/cross-cut agents over zero-coverage files' },
    { title: 'Verify', detail: 'fix-direction review of round-2 00-plan.md' },
  ],
}

const COMMON = 'You are auditing the ZJDNS codebase — a high-performance recursive DNS server in Go (module "zjdns", Go 1.26.4, pure Go) at /Users/hezhijie/Downloads/ZJDNS. Working tree is clean at HEAD (commit 6bedbfb).\n\n' +
  'STANDARDS — read before auditing:\n' +
  '- docs/AUDIT-METHODOLOGY.md §1.1 (18 audit dimensions), §4.1 (severity definitions), §4.2 + §6 (systemic root-cause patterns and lessons)\n' +
  '- docs/audit/2026-08-round3/dedup-index.txt — all 152 findings already reported by the previous audit round. Your findings MUST be NOVEL: not present in that index (same file+line, or same issue). If you hit an already-reported issue, do NOT re-report it. If you confirm a previously-reported issue with NEW evidence or an important correction, you may include it with novel=false and a note.\n\n' +
  'METHOD:\n' +
  '1. Read every assigned file in full (Read tool). They are listed below.\n' +
  '2. Run targeted greps (grep -rn via Bash) for your assigned patterns.\n' +
  '3. For each candidate issue, VERIFY by reading the actual code around the line — no speculation, no heuristics. Trace callers where the severity depends on reachability.\n' +
  '4. Apply the 18 dimensions: code quality, memory safety (leaks, unbounded growth, sync.Pool misuse), lock correctness (data race, deadlock, lock-in-IO), coupling (import DAG), architecture, performance (hot-path allocs, SQL), panic detection (nil deref, slice bounds, empty-map write, bare type assertion, double channel close, division by zero, use-after-Put), error handling (%w chains, errors.Is/As, sentinel placement), context propagation (ctx first param, cancellation, context.TODO/Background in prod), goroutine lifecycle (HandlePanic, owner, cancel path, errgroup SetLimit, channel close owner), resource lifecycle (Close idempotency via sync.Once/atomic, New/Close symmetry, no blocking IO under lock), logging quality (level correctness, hot-path info/warn spam, missing context), parameter validation (nil/empty/zero checks, discarded errors with _, bare type asserts), constant extraction (magic numbers, RFC values, cross-package dup), RFC consistency (deviation from RFC, docs/rfc/ archive, comment RFC references), comment accuracy (stale refs to renamed/deleted symbols, dead TODOs), function ordering, Go version features.\n\n' +
  'REPORT FORMAT — via the StructuredOutput tool (schema provided): each finding: severity (CRITICAL=data corruption/crash/panic/security bypass; HIGH=resource exhaustion/goroutine leak/race/deadlock; MEDIUM=maintainability/edge-correctness; LOW=docs/micro), file (repo-relative path), line (1-indexed, anchor), category (short kebab slug e.g. pool-leak, lock, rfc, panic, validation), title (one line), description (concrete technical problem), evidence (quote the exact code), risk (consequence if unfixed), fix (concrete change direction), novel (bool — true if not in dedup-index.txt).\n\n' +
  'Return raw findings only — your final text is the return value, not a human report. Aim for precision over volume: 3-10 high-confidence findings beats 30 guesses. Zero findings is acceptable if the files are clean.'

const FINDINGS_SCHEMA = {
  type: 'object',
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          severity: { type: 'string', enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] },
          file: { type: 'string' },
          line: { type: 'number' },
          category: { type: 'string' },
          title: { type: 'string' },
          description: { type: 'string' },
          evidence: { type: 'string' },
          risk: { type: 'string' },
          fix: { type: 'string' },
          novel: { type: 'boolean' },
        },
        required: ['severity', 'file', 'line', 'category', 'title', 'description', 'risk', 'fix', 'novel'],
      },
    },
  },
  required: ['findings'],
}

phase('Audit')
log('Launching 8 audit agents over zero-coverage files + 1 fix-direction reviewer')

const agents = await parallel([
  () => agent(COMMON + '\n\nSCOPE — server/protocol/* package audit (this is the round-2 agent 03 that DIED mid-run — the audit never happened). Audit ALL files:\n' +
    '- server/protocol/plain/ (server.go, tcp.go, udp.go)\n' +
    '- server/protocol/tls/ (tls.go, quic.go, https.go, http3.go, dtls.go, server.go, certs.go, addr_validator.go)\n' +
    '- server/protocol/tlcp/ (server.go, tlcp.go, dtlcp.go, http_tlcp.go, certs.go)\n' +
    '- server/protocol/dnscrypt/ (server.go, udp.go, tcp.go, crypto.go, persist.go, generate.go)\n\n' +
    'KEY CONTEXT:\n' +
    '- AUDIT-METHODOLOGY §2.3: server/protocol/tls/tls.go is the REFERENCE TEMPLATE for pool discipline: every pool.DefaultMessage.Get() must have a matching defer pool.DefaultMessage.Put(). Check ALL protocol handlers for the Get/Put discipline, per-path Puts that leak on panic, double-Puts, and Data-after-Put use-after-free.\n' +
    '- Known context: dnscrypt WriteMsg→encrypt() path has the round-2 CRITICAL C2 (pre-packed Data wiped by Pack()) — already reported, skip.\n' +
    '- The bridge (server/bridge.go) has len(response.Data)==0 guards before Pack; protocol handlers do their own packing — check each handler response path for pre-packed handling.\n' +
    '- Pay attention to: goroutine ownership in accept loops (tls.go, tlcp.go, dnscrypt), workerCap semantics, buffer pooling (pool.DefaultBuffer) ownership transfer, SetReadDeadline/SetWriteDeadline on all read/write paths, Close() idempotency of protocol servers, Shutdown paths, TLS handshake timeout handling, wire-parse panic safety (ReadTCPMsg on malformed input), write-deadline missing on response writes, per-connection goroutine leaks on idle connections.',
    { label: 'audit:protocol', phase: 'Audit', schema: FINDINGS_SCHEMA }),

  () => agent(COMMON + '\n\nSCOPE — Go version features cross-cut (round-2 agent 25 that DIED mid-run). Go 1.26.4 per go.mod.\n' +
    'TASKS:\n' +
    '1. Run: cd /Users/hezhijie/Downloads/ZJDNS && go fix ./... -diff 2>&1 | head -200 — record which modernizers would fire (do not apply them).\n' +
    '2. grep -rn "errors\\.As(" --include="*.go" (exclude _test.go) — check each for errors.AsType[T] replacement (Go 1.24+); note internal/... usage where errors.AsType is already used as a model.\n' +
    '3. grep -rn "for i := len\\(.*-1\\|for .*>= 0; i--" — hand-written reverse iteration vs slices.Backward/slices.Reverse.\n' +
    '4. Check slices/maps/iter stdlib adoption: hand-rolled min/max, Contains loops → slices.Contains, etc.\n' +
    '5. grep -rn "context\\.WithTimeout" — check for modern context.AfterFunc opportunities only where semantics clearly improve.\n' +
    '6. Report findings ONLY where the replacement is meaningfully better (allocation reduction, clarity) — not style churn. Codebase is already well-modernized (uses errors.AsType at server/upstream/plain/udp.go:190); the audit is for REMAINING hand-written patterns.',
    { label: 'audit:goversion', phase: 'Audit', schema: FINDINGS_SCHEMA }),

  () => agent(COMMON + '\n\nSCOPE — CLI + config + database packages (zero coverage in both prior rounds). Read ALL files:\n' +
    '- cmd/zjdns/main.go, cmd/zjdns/banner.go, cmd/zjdns/version.go, cmd/zjdns/cli/generate.go, cmd/zjdns/cli/sql.go, cmd/zjdns/cli/parse.go, cmd/zjdns/cli/probe.go, cmd/zjdns/cli/dnsstamp.go\n' +
    '- config/config.go, config/defaults.go, config/load.go, config/validate.go, config/chaos.go, config/ddr.go, config/ecs.go\n' +
    '- database/schema.go, database/migration.go, database/sqlutil.go\n\n' +
    'SPECIAL FOCUS:\n' +
    '- cmd/zjdns: flag/args parsing edge cases, --sql write path safety, --generate output, signal handling, exit codes, panic recovery in CLI, file writes without sync\n' +
    '- config: load order/env/file validation, defaults vs RFC values (config/defaults.go magic numbers — compare ports 53/853/443/784/8533/6500 etc. with RFC/IANA), validation gaps (empty strings, out-of-range), chaos.go querylog.clear/ptr.clear/latency.clear endpoint handling (3 of the 4 new endpoints already flagged — check the 4th and any others), ddr.go DDR advertisement correctness\n' +
    '- database: migration ordering, ALTER TABLE correctness, sqlutil helpers, prepare/close symmetry, SQL string building (separator bugs), transaction usage\n' +
    '- Check every net.ParseIP/ParseCIDR result for nil, every discarded error (_, :=) for missing comments, every fmt.Errorf %v wrapping, every Close() for idempotency.',
    { label: 'audit:cli-config-db', phase: 'Audit', schema: FINDINGS_SCHEMA }),

  () => agent(COMMON + '\n\nSCOPE — internal/ foundation packages (zero coverage both rounds). Read ALL files:\n' +
    '- internal/dnscryptcrypto/: certificate.go, keys.go, proto.go, string.go, dns.go, encryption.go, pq.go, xsecretbox.go\n' +
    '- internal/dnsutil/: bind.go, clientip.go, download.go, keepalive.go, tcpframe.go, wire.go\n' +
    '- internal/stamp/: stamp.go, encode.go, parse.go\n' +
    '- internal/latency/: prober.go, probes.go, httppool.go\n' +
    '- internal/doq/doq.go, internal/ipttl/ipttl.go, internal/pending/pending.go, internal/pool/pool.go, internal/siphash/siphash.go, internal/ttl/ttl.go, internal/lrumap/dtls_session.go\n\n' +
    'SPECIAL FOCUS:\n' +
    '- dnscryptcrypto: crypto constant correctness (nonce sizes, XChaCha20Poly1305, key derivation), panic safety on malformed cert/query data (slice bounds on untrusted input — this parses NETWORK data), PQ crypto (X-Wing KEM) error paths, padding computation, control-block parsing\n' +
    '- tcpframe.go: ReadTCPMsg/WriteTCPMsg pool usage (tcpReadBufPool — check the buffer is returned/cleared on ALL paths, msg.Data detached before Put — verify), length-prefix bounds\n' +
    '- stamp (sdns://): base64url decoding panic safety, unknown protocol handling, parse of attacker-supplied stamps (CLI input)\n' +
    '- latency: prober goroutines lifecycle (Start/Stop), httppool idle connections, probes map growth\n' +
    '- pool: sync.Pool usage — zeroing discipline (clear() before Put), Get+Put pairing\n' +
    '- pending: pending.Group channel close ownership, waiting goroutine cancellation, singleflight dedup correctness under ctx cancel\n' +
    '- ipttl: raw socket handling, macOS/Linux portability, buffer reuse\n' +
    '- ttl: expiry math (no time.Now() misuse), overflow\n' +
    '- doq: QUIC stream handling, context propagation\n' +
    '- dtls_session: lrumap value holds session — OnEvict needed?\n' +
    '- siphash: correctness vs reference (test vectors), constant-time concerns\n' +
    '- Logging: hot-path log levels in these packages.',
    { label: 'audit:internal', phase: 'Audit', schema: FINDINGS_SCHEMA }),

  () => agent(COMMON + '\n\nSCOPE — edns + ruleset + zone packages (zero coverage both rounds). Read ALL files:\n' +
    '- edns/ecs.go, edns/cookie.go (also skim edns/edns.go and edns/padding.go — those had findings, only check for NEW issues)\n' +
    '- ruleset/ruleset.go, ruleset/iptrie.go\n' +
    '- zone/zone.go, zone/parse.go, zone/wire.go\n\n' +
    'SPECIAL FOCUS:\n' +
    '- edns: ECS parsing bounds (prefix/address length validation on untrusted input), cookie generation/validation (RFC 7873/9018 — client cookie length, server cookie HMAC key handling, constant-time compare), padding computation overflow, option code parsing\n' +
    '- ruleset: iptrie binary radix trie — insertion/removal/lookup edge cases (prefix containment), ruleset tag matching, nil handling, concurrent mutation vs read\n' +
    '- zone: zone-file parser (RFC 1035 master file) — malformed input panic safety, $INCLUDE handling, wire.go zone wire encoding, evaluator matching, TTL/class parsing, escaping\n' +
    '- All parse functions take NETWORK/CONFIG input: check every slice index, every conversion (strconv on untrusted strings), nil deref on missing fields.',
    { label: 'audit:edns-ruleset-zone', phase: 'Audit', schema: FINDINGS_SCHEMA }),

  () => agent(COMMON + '\n\nSCOPE — server core + handler + defense (zero coverage both rounds). Read ALL files:\n' +
    '- server/init.go, server/tasks.go (NOTE: server/bridge.go and server/server.go had round-2 findings — only hunt NEW issues there), server/handler/context.go, server/handler/handler.go, server/handler/middleware.go, server/handler/pending.go, server/handler/prefetch.go, server/handler/middleware/any.go, server/handler/middleware/ptr.go, server/handler/middleware/resolution.go, server/handler/middleware/validation.go, server/handler/middleware/zone.go, server/defense/hopguard.go\n\n' +
    'SPECIAL FOCUS:\n' +
    '- tasks.go: background task lifecycle — sweeps, cleanup loops (note: sweepTCPWriteMu is dead code due to the round-2 H3 bug — already reported), goroutine ownership, ticker leaks, errgroup limits\n' +
    '- init.go: wiring completeness, nil deps\n' +
    '- handler: QueryContext pool (round-2 checked — verify no regression), pending requests, prefetch cooldown map growth\n' +
    '- middleware: any.go (RFC 8482), ptr.go (reverse lookup — check pool discipline of entries from cache.Get — note TTLOffsets release issue already reported for dns64/mqtype; check ptr.go for the same pattern!), validation.go (label validation), zone.go (rule evaluation — cache.Get usage)\n' +
    '- hopguard.go: TTL fingerprint histogram — memory growth, histogram reset, attack resistance (histogram poisoning), lock discipline\n' +
    '- Check resolution.go: findMQQUERY — the invalid return value discarded at resolution.go:49 (M4 already reported) — only NEW issues.',
    { label: 'audit:server-core', phase: 'Audit', schema: FINDINGS_SCHEMA }),

  () => agent(COMMON + '\n\nSCOPE — resolver package (zero coverage both rounds for these files). Read ALL files:\n' +
    '- server/resolver/dnssec/: validate.go, extract.go, nsec.go, crypto.go, trust_anchor.go\n' +
    '- server/resolver/dnssec_chain.go, server/resolver/qname_minimise.go, server/resolver/recursive_ns.go, server/resolver/recursive_helpers.go, server/resolver/root_hints.go, server/resolver/mqtype_ctx.go, server/resolver/probe/probe.go\n\n' +
    'SPECIAL FOCUS (this is the security-critical recursive resolver):\n' +
    '- DNSSEC: signature validation (RRSIG verification, key tag computation, algorithm support), NSEC/NSEC3 matching for NXNAME/NODATA proofs, trust anchor handling, DNSSEC chain-of-trust construction (dnssec_chain.go), denial-of-existence verification — errors must NOT become SERVFAIL-abuse vectors; crypto.go key parsing panic safety\n' +
    '- qname_minimise.go: RFC 9156 minimisation — name construction edge cases (empty labels, root, wildcards), response-to-question name matching, iteration termination (max 10 iterations — verify termination)\n' +
    '- recursive_ns.go: NS cache, glue validation, lame delegation detection, latency sorting\n' +
    '- root_hints.go: parsing of built-in hints, TTL handling\n' +
    '- mqtype_ctx.go: RFC 10029 context plumbing (MQTYPE merge helpers — check the zonecut merge from commit b2c9824 for pool/entry handling)\n' +
    '- probe/probe.go: latency probe lifecycle\n' +
    '- Wire parse panic safety on untrusted authoritative responses throughout.',
    { label: 'audit:resolver', phase: 'Audit', schema: FINDINGS_SCHEMA }),

  () => agent(COMMON + '\n\nSCOPE — upstream package (zero coverage both rounds for these files). Read ALL files:\n' +
    '- server/upstream/client.go, server/upstream/warmup.go, server/upstream/plain/client.go, server/upstream/dnscrypt/client.go, server/upstream/dnscrypt/crypto.go, server/upstream/tls/client.go, server/upstream/tls/tls.go, server/upstream/tls/dtls.go, server/upstream/tls/quic.go, server/upstream/tls/https.go, server/upstream/tlcp/client.go, server/upstream/tlcp/dtlcp.go, server/upstream/tlcp/http_tlcp.go, server/upstream/pool/tcp.go, server/upstream/pool/quic.go, server/upstream/socks5/socks5.go, server/upstream/socks5/tcp.go, server/upstream/socks5/udp.go\n\n' +
    'SPECIAL FOCUS:\n' +
    '- pool/tcp.go: RFC 7766 pipelined connection pool — inflight registry (map by ID), connection reuse, idle timeout, slowloris resistance, channel close ownership, error path pool return\n' +
    '- pool/quic.go: QUIC conn pool lifecycle\n' +
    '- socks5: UDP ASSOCIATE relay (read pool discipline — verify every ReadPool.Get has a Put on all paths), TCP connect timeout, proxy authentication handling, buffer sizes\n' +
    '- warmup.go: startup warmup goroutine lifecycle, proxyDialer lrumap (Get→Set race with OnEvict — foundation-01 reported Set-overwrite leak; check for OTHER lrumap instances and the OnEvict resource-holding pattern)\n' +
    '- dnscrypt client: cert fetch caching (state.go cache=nil Close race already reported as M1 — check for OTHER Close/nil patterns), shared key cache, nonce handling\n' +
    '- Response ID verification: tls.go:107 does it; tlcp.go:89 does NOT (M7 already reported) — check ALL other exchange functions for ID verification gaps (dtls.go, dtlcp.go, https.go, quic.go, pool/tcp.go) and any response validation (question echo match)\n' +
    '- Connection pool semantics: check pool.Get/Release pairing, half-close handling, deadline restore after dial (context.AfterFunc pattern from tls.go:89 — verify every protocol has it)',
    { label: 'audit:upstream', phase: 'Audit', schema: FINDINGS_SCHEMA }),
])

phase('Verify')
log('Reviewing round-2 fix directions against actual code')

const fixReview = await agent(COMMON + '\n\nSCOPE — verify the round-2 audit fix plan. Read:\n' +
  '- docs/audit/2026-08-round2/12-synthesis.md (findings C1,C2,H1-H4,M1-M8)\n' +
  '- docs/audit/2026-08-round2/00-plan.md (proposed fixes)\n' +
  '- docs/audit/2026-08-round2/_manual-verification.md\n\n' +
  'TASK — for EACH finding (C1, C2, H1, H2, H3, H4, M1, M2, M3, M4, M5, M6, M7, M8):\n' +
  '1. Read the actual code at the cited location (HEAD, commit 6bedbfb — none of these are fixed yet).\n' +
  '2. VERDICT — confirm or refute the bug exists (be adversarial: try to break the claim with a concrete counter-scenario).\n' +
  '3. FIX-CHECK — evaluate the proposed fix in 00-plan.md: will it actually work? Look for interplay the plan missed. Specifically:\n' +
  '   - C1: Get() legacy-format fallback — check the actual Set()/zstd paths to see if the fallback is feasible (isZstdCompressed availability, TTL offset absence handling). Also verify the 10-day impact window claim (DefaultMaxCacheableTTL + DefaultStaleMaxAge in config/defaults.go).\n' +
  '   - C2: if len(m.Data) > 0 in encrypt() — check dnscryptcrypto.Normalize() (called BEFORE encrypt in udp.go:42/tcp.go) — does Normalize already damage pre-packed messages? Is the fix at the encrypt layer sufficient or must it be in WriteMsg? Also check the dnscrypt TCP writer path and the budget/truncation loops interplay with pre-packed Data.\n' +
  '   - H1: fix direction A "move MQTYPE outside CacheStore" — check CacheStore.Wrap early-return (qctx.CacheServed || qctx.ZoneMatched || qctx.Res != nil) and the forwarding-mode gate (m.resolver.UpstreamServers()) — does moving MQTYPE outside break forwarding pass-through (Resolution puts MQTYPE-Query into ctx via resolver.WithMQType)? Trace the complete post-order and pre-order implications of the move.\n' +
  '   - H2: "merge 后置或改写 pre-packed Data" — check merges budget calc (msg.Len() on pre-packed → miekg Len() reads RR fields — is budget computed on empty fields?) and entryRcode. Also verify the claim that Response.Unpack wipes Pseudo (miekg msg.go Unpack resets Pseudo — check v0.6.89).\n' +
  '   - H3: deleting bridge.go:110 Add — verify both paths (goroutine :154, SERVFAIL :112) then balance to zero after the delete.\n' +
  '   - H4: mirror EDNS.pre unpack in MQTYPE.pre — check what EDNS.pre actually does (server/handler/middleware/edns.go) and whether MQTYPE.pre can safely do the same (it runs before EDNS.pre — double-unpack risk when Pseudo non-empty? miekg Unpack on already-unpacked?).\n' +
  '   - M1-M8: verify each is real and the fix is correct.\n' +
  '4. Report per-item: {id, verdict: CONFIRMED|REFUTED|PARTIAL, fixCorrect: yes|no|partial, fixNotes, newEvidence}. PARTIAL = bug exists but scope/severity differs from the report.\n' +
  '5. ALSO report any NEW issue you spot while reading these files (novel flag).',
  { label: 'verify:fix-plan', phase: 'Verify', schema: {
    type: 'object',
    properties: {
      verdicts: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            verdict: { type: 'string', enum: ['CONFIRMED', 'REFUTED', 'PARTIAL'] },
            fixCorrect: { type: 'string', enum: ['yes', 'no', 'partial'] },
            fixNotes: { type: 'string' },
            newEvidence: { type: 'string' },
          },
          required: ['id', 'verdict', 'fixCorrect', 'fixNotes'],
        },
      },
      findings: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            severity: { type: 'string', enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] },
            file: { type: 'string' },
            line: { type: 'number' },
            category: { type: 'string' },
            title: { type: 'string' },
            description: { type: 'string' },
            evidence: { type: 'string' },
            risk: { type: 'string' },
            fix: { type: 'string' },
            novel: { type: 'boolean' },
          },
          required: ['severity', 'file', 'line', 'category', 'title', 'description', 'risk', 'fix', 'novel'],
        },
      },
    },
    required: ['verdicts', 'findings'],
  } })

const all = [...agents.filter(Boolean), fixReview]
const flat = all.flatMap((a) => (a.findings || []))
log('Total novel findings across agents: ' + flat.filter((f) => f.novel !== false).length)
return { agents: all.map((a) => a.findings ? a.findings.length : 0), findings: flat }
