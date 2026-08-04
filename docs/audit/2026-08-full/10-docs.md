# docs — 包级审计报告

> 审计日期: 2026-08-04 | 审计范围: CrossCut Docs; CrossCut-Comments-Flowcharts-GoVersion
> 发现数量: 19 ({"MEDIUM":4,"LOW":15})

### F1 [MEDIUM] docs-inaccurate — PQ client-magic derivation documented as SHA-256(PqPublicKey)[:8], code uses pk[72:80]
- **文件**: docs/ARCHITECTURE.md:198
- **问题**: ARCHITECTURE.md line 198 states 'ClientMagic for PQ = SHA-256(PqPublicKey)[:8]'. The actual derivation in server/protocol/dnscrypt/generate.go:137-139 is `copy(cert.ClientMagic[:], pk[72:72+dnscryptcrypto.ClientMagicSize])` — bytes 72-79 of the X-Wing public key ('matching the official encrypted-dns-server derivation'). A repo-wide grep for SHA-256 in the DNSCrypt path shows SHA-256 only used for shared-key/nonce hashing (internal/dnscryptcrypto/encryption.go:65,84) and the profile-extension hash (pq.go:40-42), never for client magic.
- **风险**: A reader implementing or debugging the PQ handshake follows a wrong derivation; the SHA-256 claim is factually false and would break interoperability if copied.
- **修复建议**: Update ARCHITECTURE.md line 198 to 'ClientMagic for PQ = bytes 72-79 of the X-Wing public key' (or delete the sentence and reference generate.go).

### F2 [MEDIUM] docs-inaccurate — PQ ticket plaintext layout documented with wrong order/sizes; actual layout is 86 bytes
- **文件**: docs/ARCHITECTURE.md:203
- **问题**: ARCHITECTURE.md line 203 documents ticket plaintext as `PQESVersion(2) + ClientMagic(8) + ResumeSecret(32) + Expiry(8)` (implies 50 bytes). Actual layout per internal/dnscryptcrypto/certificate.go:117-138 and EncodeTicketPlaintext (internal/dnscryptcrypto/pq.go:262-274) is: ResumeSecret(32) + ESVersion(2) + ClientMagic(8) + Serial(4) + TSEnd(4) + Expiry(4) + PEHash(32) = 86 bytes. ResumeSecret is FIRST not third, Expiry is 4 bytes not 8, and Serial/TSEnd/PEHash are omitted from the doc entirely.
- **风险**: Wrong field order/sizes mislead anyone implementing or auditing the PQ resumption path (e.g. cross-checking against dnscrypt-proxy), and the documented size does not match TicketPlaintextSize.
- **修复建议**: Rewrite line 203 as: ResumeSecret(32) + ESVersion(2) + ClientMagic(8) + Serial(4) + TSEnd(4) + Expiry(4) + SHA-256(profile-ext)(32) = 86B.

### F3 [MEDIUM] docs-inaccurate — CLAUDE.md claims 8 prepared statements; database/stmts.go prepares 10
- **文件**: CLAUDE.md:304
- **问题**: CLAUDE.md Key Types table (line 304) describes DB as 'WAL mode, 8 prepared stmts'. database/stmts.go:7-86 prepares 10 statements: StmtEntry, StmtQueryLog, StmtQueryStats, StmtInsertLatency, StmtLastProbe, StmtZoneExact, StmtZoneWildcard, StmtIPLatency, StmtDNSCryptLoad, StmtDNSCryptSave. The count was likely correct before the DNSCrypt persistence (v3.7.17) and zone-wildcard additions.
- **风险**: The claim is a stale count; also contradicts the audit methodology's own rule that CLAUDE.md type references must be accurate.
- **修复建议**: Change '8 prepared stmts' to '10 prepared stmts'.

### F4 [LOW] docs-incomplete — DB schema section says 'nine SQLite tables' but documents only seven; version and ruleset_entries missing
- **文件**: docs/ARCHITECTURE.md:7
- **问题**: ARCHITECTURE.md line 7 claims the DB 'contains nine SQLite tables' but the SQL block (lines 9-102) defines only 7: entries, query_stats, query_log, ptr_map, ip_latency, zone_entries, dnscrypt_state. database/schema.go:37-189 defines 9 tables including `version` (line 43) and `ruleset_entries` (lines 153-158), which are never mentioned in ARCHITECTURE.md. README.md's '九表设计' count happens to be right, so the doc internally contradicts itself.
- **风险**: The authoritative schema reference omits two real tables; a reader cannot derive the actual PK layout of ruleset_entries (PRIMARY KEY (type, tag, value)) from the doc.
- **修复建议**: Add the `version` and `ruleset_entries` CREATE TABLE blocks to the ARCHITECTURE.md schema section.

### F5 [LOW] docs-inaccurate — CLAUDE.md says 'Mirrored RFCs and drafts (50 total)'; docs/rfc/ contains 49 .txt files
- **文件**: CLAUDE.md:344
- **问题**: CLAUDE.md line 344 claims 50 mirrored RFCs/drafts. `ls docs/rfc/*.txt | wc -l` yields 49 (47 RFCs + 2 drafts: draft-denis-dns-stamps.txt, draft-denis-dprive-dnscrypt.txt).
- **风险**: Minor numeric drift in the docs index; the file index in docs/rfc/README.md is also missing titles for rfc4035.txt and rfc5077.txt (and has a misplaced 'Transport Layer Security (TLS) Session Resumption' row).
- **修复建议**: Change '(50 total)' to '(49 total)'; fix the two empty title cells and the stray row in docs/rfc/README.md.

### F6 [LOW] stale-baseline — Benchmark baseline missing BenchmarkResolveRootServers; has 104 lines vs 103 benchmark funcs
- **文件**: docs/benchmark/benchmark-baseline.txt:69
- **问题**: CLAUDE.md:139 says '103 benchmarks across 21 files. Baseline: docs/benchmark/benchmark-baseline.txt'. Code has exactly 103 benchmark funcs in 21 files, but the baseline contains 104 lines: BenchmarkPoolAcquire/Cold + /Warm (sub-benchmarks, 2 lines) and NO entry for BenchmarkResolveRootServers, which exists at cmd/zjdns/benchmark_test.go:45.
- **风险**: A perf regression in root-server resolution benchmark would not be caught by the git-diff baseline comparison prescribed in AUDIT-METHODOLOGY.md §3.3.
- **修复建议**: Regenerate the baseline: `go test -bench=. -short -benchtime=500ms ./... | grep '^Benchmark' | sort > docs/benchmark/benchmark-baseline.txt`.

### F7 [LOW] godoc-misattachment — Godoc comment for Conn.Exchange attached to SetSegmentation; Exchange has no doc comment
- **文件**: server/upstream/pool/tcp.go:99
- **问题**: At server/upstream/pool/tcp.go:89-92 the comment '// Exchange sends a DNS message over the pipelined connection and returns the response.' is fused into the block preceding SetSegmentation (line 93), so godoc renders it as SetSegmentation's doc. The exported method Conn.Exchange (line 99) — a documented CLAUDE.md type — has no doc comment of its own.
- **风险**: godoc output mislabels both methods; exported API lacks the doc the comment was written for.
- **修复建议**: Insert a blank line between the Exchange comment and SetSegmentation's comment, or move 'Exchange sends...' directly above func (c *Conn) Exchange.

### F8 [LOW] godoc-misattachment — RecordRequest's doc comment fused with statsMetric's and attached to the unexported type
- **文件**: cache/stats.go:36
- **问题**: cache/stats.go:16-31 documents RecordRequest ('RecordRequest logs a request outcome asynchronously... When the async writer is nil... falls back to synchronous writes'), but it is fused with '// statsMetric is a single (name, count, percentage) entry...' (line 32-33) into one block attached to the unexported `type statsMetric struct` (line 34). The exported method RecordRequest (line 36, part of the Store interface) has no doc comment of its own — its doc text is unreachable via godoc for the method.
- **风险**: The exported cache.Store.RecordRequest contract (async, best-effort, drops under overload) is not visible in godoc where consumers look for it.
- **修复建议**: Insert a blank line before '// statsMetric is a single...' so the RecordRequest block attaches to func (s *SQLiteCache) RecordRequest.

### F9 [LOW] godoc-gap — Exported dns64 API lacks doc comments (New, Prefix, MapAddr, ExtractIPv4, IsSynthesized, Synthesize)
- **文件**: internal/dns64/dns64.go:28
- **问题**: internal/dns64/dns64.go documents only the package (line 1-2) and the Synthesizer type (line 13). The exported constructor New (line 28) and methods Prefix (47), MapAddr (49), ExtractIPv4 (57), IsSynthesized (65), Synthesize (67) have no doc comments; Synthesize's `_, origAuthority, _, aAnswer, _` parameters are also undocumented.
- **风险**: Public package API without godoc; parameters named `_` make Synthesize's contract (RFC 6147 §5.1.7 TTL capping, RFC 6052 embedding) opaque.
- **修复建议**: Add one-line godoc per exported symbol, especially Synthesize's argument order.

### F10 [LOW] docs-inaccurate — 'QNAME minimisation ... max 16 steps' — code caps minimisation at 10 iterations
- **文件**: docs/FLOWCHARTS.md:104
- **问题**: FLOWCHARTS.md:104 and CLAUDE.md:284 both state QNAME minimisation has 'max 16 steps'. The minimisation iteration cap is config.DefaultQnameMinimiseCount = 10 (config/defaults.go:194, consumed by applyQnameMinimisation in server/resolver/recursive_helpers.go:62-72 via labelsToAdd). 16 is DefaultMaxRecursionDepth (defaults.go:192) — a different limit.
- **风险**: The 16-step number is attributed to the wrong mechanism; operators reasoning about minimisation depth (RFC 9156 §2.3) get the wrong bound.
- **修复建议**: Change both to 'max 10 minimisation steps (RFC 9156 §2.3)' or reference DefaultMaxRecursionDepth separately for the walk.

### F11 [LOW] docs-ambiguous — Spoofguard row: 'reject AR=0+NOERROR+EDNS' inverts the actual rejection signature
- **文件**: docs/ARCHITECTURE.md:124
- **问题**: ARCHITECTURE.md:124 documents spoofguard as rejecting 'AR=0+NOERROR+EDNS', which reads as rejecting an EDNS-bearing NOERROR response. The code (server/upstream/plain/udp.go:443-447) rejects non-EDNS responses lacking a CNAME and with AN<2 — i.e. the ABSENCE of EDNS is the GFW signature. FLOWCHARTS.md:282 states it correctly ('GFW signature: AR=0 + NOERROR without EDNS').
- **风险**: The two docs contradict each other; a reader may think EDNS-bearing responses are dropped, the opposite of the behavior.
- **修复建议**: Reword to 'reject AR=0 + NOERROR WITHOUT EDNS (bare A/AAAA, GFW signature)'.

### F12 [LOW] godoc-gap — Exported Detector type lacks a doc comment
- **文件**: internal/ipdetect/ipdetect.go:13
- **问题**: internal/ipdetect/ipdetect.go:13 declares `type Detector struct` with no doc comment (only its fields TraceURL etc. are commented). The package comment (line 1) describes the package, not the type. Note this is a distinct exported Detector from server/defense's Detector, so the ambiguity is real.
- **风险**: godoc shows an undocumented exported type; two exported Detector types in the repo make the missing doc more confusing.
- **修复建议**: Add a type doc, e.g. '// Detector discovers the machine's public IP via external HTTP endpoints (default ifconfig.me) with fallback order.'

### F13 [LOW] godoc-gap — 10 exported PQ crypto functions lack doc comments
- **文件**: internal/dnscryptcrypto/pq.go:46
- **问题**: internal/dnscryptcrypto/pq.go exports HKDFSHA256 (46), PQCertContext (62), PQDeriveSharedKey (85), PQResumeSecret (101), PQResumedSharedKey (114), PQEncapsulate (131), PQDecapsulate (135), PQOpenTicket (175), PQParseControlBlock (213), EncodeTicketPlaintext (262) — none carry a doc comment, unlike the surrounding code which documents layout constants and control-block semantics. This package is a fork of dnscrypt-proxy crypto but lives under internal/ and is audited as project code.
- **风险**: The security-sensitive PQ KEM/ticket API is undocumented; e.g. PQResumeSecret/PQResumedSharedKey nonce-truncation and ticket-scope rules are only discoverable by reading implementations.
- **修复建议**: Add one-line godoc to each function (the certificate.go layout constants already document offsets — reference them).

### F14 [MEDIUM] comment-code-contradiction — Comment claims 'all other accept loops sleep on retry' — DTLS accept loop is the exception and can spin at 100% CPU
- **文件**: server/protocol/dnscrypt/tcp.go:78
- **问题**: The comment at lines 77-78 ('Temporary error: back off too, or a sustained condition spins at 100% CPU (all other accept loops sleep on retry)') claims every other accept loop backs off. Verified against all native accept loops: tls.go:70, quic.go:102, http3.go:88, tlcp.go:79, dtlcp.go:268-281 (50ms) all sleep on accept error — but server/protocol/tls/dtls.go:90-96 continues with no sleep in EITHER branch (temporary and non-temporary errors both just `continue`). The claim is contradicted by the code, and the DTLS listener is exposed to exactly the 100% CPU hot-spin the comment warns about (e.g. sustained EMFILE or garbage-UDP Accept errors).
- **风险**: Misleading comment hides a real defect: under sustained accept errors the DTLS accept loop spins at 100% CPU with no backoff, unlike every other listener in the server.
- **修复建议**: Add `time.Sleep(config.DefaultAcceptRetryDelay)` in the dtls.go accept loop's error branches (matching quic.go:102 / tls.go:70), or if intentional, fix the comment to name DTLS as the exception.

### F15 [LOW] stale-comment — concurrencyLimit comment: 'drop ... 10 to 8 at 20→21 servers' is arithmetically wrong (actual raw drop is 10→7)
- **文件**: server/resolver/resolver.go:257
- **问题**: Comment (lines 254-258) says the raw tier formulas 'drop from 8 to 7 at 12→13 servers and 10 to 8 at 20→21'. Verified against the constants (tier1=4, tier2=12, tier3=20, div2=2, div3=3, lines 120-124): first claim is correct (tier2 at 12 = (12*2+2)/3 = 8; tier3 raw at 13 = (13+1)/2 = 7). Second claim is wrong: raw at 20 = (20+1)/2 = 10, raw at 21 = 21/3 = 7 — the drop is 10→7, not 10→8. The monotonicity floors (max(...,8) for tier3, max(DefaultMinConcurrencyLimit=8, 10) for default) still make the returned values monotonic, so behavior is unaffected.
- **风险**: Misleading comment: a maintainer reasoning from the documented numbers (10→8) about the fan-out floor will misjudge the tier formulas.
- **修复建议**: Correct the comment to '10 to 7 at 20→21 servers'.

### F16 [LOW] flowchart-accuracy — Recursive-resolution diagram attributes 'max 16 steps' to QNAME minimisation; code caps it at 10 (16 is the recursion depth)
- **文件**: docs/FLOWCHARTS.md:104
- **问题**: The QMIN node reads 'QNAME Minimisation<br/>RFC 9156 · max 16 steps'. The QNAME-minimisation iteration bound is DefaultQnameMinimiseCount = 10 (config/defaults.go:194, 'RFC 9156 §2.3: max QNAME minimisation iterations'); 16 is DefaultMaxRecursionDepth (config/defaults.go:192) and DefaultMaxCNAMEChain (defaults.go:191). The '16' belongs to the overall walk/CNAME chain, not to minimisation. Otherwise FLOWCHARTS.md coverage is complete: all 18 checklist areas have diagrams, numeric claims (hopguard 32 samples, spoofguard 500ms, async writer cap 64 / 100ms ticker, singleflight 10000 entries / 60s timeout, ECS refresh 15min, CDS fallback RFC 7344) verified against code, mermaid blocks syntactically plausible, and DoQ/DTLS/DTLCP/TLCP/DoH3 plus DTLS→DoT and DTLCP→TLCP fallbacks are all diagrammed.
- **风险**: A reader designing around QNAME minimisation could apply the wrong bound (16 vs the actual 10 iterations).
- **修复建议**: Change the QMIN label to 'RFC 9156 · max 10 iterations' or drop the number (recursion depth 16 is already implied by the CNAME node).

### F17 [LOW] go-version-idiom — Four sequential errors.As calls in isQUICRetryable replaceable with errors.AsType[T] (Go 1.26)
- **文件**: server/upstream/tls/http3.go:227
- **问题**: isQUICRetryable (lines 226-247) does four errors.As(err, &T) checks for *quic.ApplicationError, *quic.IdleTimeoutError, *quic.StatelessResetError, *quic.TransportError. Go 1.26 (go.mod go 1.26.4) provides errors.AsType[E error](err) (E, bool), already used in this codebase at internal/dnsutil/dnsutil.go:225 (IsTemporaryError). The identical var+As pattern also appears at server/protocol/tls/dtls.go:144, server/protocol/tlcp/dtlcp.go:325, cmd/zjdns/cli/probe.go:313, server/upstream/tls/https.go:114, and server/handler/middleware/cache_store.go:191 — 10 sites total remain on the old form.
- **风险**: None functional; inconsistent with the codebase's own errors.AsType usage and more verbose than the standard idiom.
- **修复建议**: Rewrite each site as e.g. `if qAppErr, ok := errors.AsType[*quic.ApplicationError](err); ok { ... }`.

### F18 [LOW] go-version-idiom — sort.Slice in PrefetchCooldown.Cleanup — should be slices.SortFunc per project standard
- **文件**: server/handler/prefetch.go:78
- **问题**: Line 78: `sort.Slice(entries, func(i, j int) bool { return entries[i].ts < entries[j].ts })` sorts the cooldown map snapshot before evicting the oldest half. This is the only sort.Slice/sort.SliceStable in production code. Go 1.26 slices.SortFunc is the idiomatic replacement and CLAUDE.md explicitly states the project standard ('slices.SortStableFunc over sort.SliceStable'). Since this sort runs on the prefetch path whenever the cooldown map exceeds DefaultPrefetchCooldownMaxEntries, it is also the intended per-package home for this pattern.
- **风险**: None functional; style drift from the project's stated Go-version idiom.
- **修复建议**: Replace with `slices.SortFunc(entries, func(a, b entry) int { return cmp.Compare(a.ts, b.ts) })` (imports slices and cmp).

### F19 [LOW] go-version-idiom — Hand-written reverse scan loop in UnPad replaceable with slices.Backward
- **文件**: internal/dnscryptcrypto/encryption.go:132
- **问题**: UnPad (lines 132-146) implements the ISO/IEC 7816-4 padding removal with a manual `for i := len(packet); ; { ... i-- ... }` loop. This is the only production reverse-iteration loop in the repo (grep of `for i := len(...)`, `; i >= 0; i--` found only this, the excluded siphash test, and server/resolver/resolver.go:248 which is a genuine Fisher-Yates shuffle and must not be changed). Go 1.23+ `for i := range slices.Backward(packet)` expresses the same scan; the 0x80-delimiter and MinDNSPacketSize checks transfer directly (packet[0]==0x80 is rejected via i < MinDNSPacketSize in both forms).
- **风险**: None functional; verbose, easy-to-misread loop in a per-query crypto path.
- **修复建议**: Rewrite with `for i := range slices.Backward(packet) { ... }` and return ErrInvalidPadding after the loop.
