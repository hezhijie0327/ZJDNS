# foundation — 包级审计报告

> 审计日期: 2026-08-04 | 审计范围: internal (foundation: log, pool, lrumap, dnsutil, stamp, ttl, pending, siphash, ipdetect, ipttl, latency, doq, dns64, dnscryptcrypto); CrossCut DeadCode + Arch + Ordering
> 发现数量: 12 ({"HIGH":1,"LOW":8,"MEDIUM":3})

### F1 [HIGH] rfc — MapAddr embeds IPv4 at bytes 12-15 for every prefix length — RFC 6052 placement is prefix-dependent
- **文件**: internal/dns64/dns64.go:49
- **问题**: MapAddr (lines 49-55) unconditionally copies the first 12 prefix bytes and writes the IPv4 address at bytes 12-15 (nat64Offset=12). That is correct ONLY for /96 prefixes. RFC 6052 (mirrored at docs/rfc/rfc6052.txt, Figure 1 and the bullet list after it) requires: /32 -> bits 32-63 (bytes 4-7), /40 -> bits 40-63+72-79, /48 -> bits 48-63+72-87, /56 -> bits 56-63+72-95, /64 -> bits 72-103 (bytes 9-12, u octet at bits 64-71 = 0), /96 -> bits 96-127 (bytes 12-15). RFC 6052 §2.4 example: prefix 2001:db8::/32 + IPv4 192.0.2.33 must yield 2001:db8:c000:221::, but the code produces 2001:db8::c000:221. New() explicitly accepts 32/40/48/56/64/96 (validPrefixLens, line 26) and server/server.go:295 passes the user-configured DNS64.Prefix, so a non-default (network-specific) prefix is a supported configuration. The round-trip test TestMapAddr_CustomPrefix (/32) passes only because ExtractIPv4 (lines 57-63) reads back from the same wrong offset — internal consistency hides the RFC violation. Synthesized AAAA addresses for any non-/96 prefix will not be translated by a standards-conforming NAT64 gateway, silently breaking DNS64.
- **风险**: DNS64 synthesis produces non-RFC-6052 addresses for every valid non-/96 configured prefix; NAT64 gateways (which implement RFC 6052 placement) will not translate them, so AAAA synthesis silently serves unroutable addresses.
- **修复建议**: Make the IPv4 embedding position prefix-dependent: for /96 copy prefix bytes 0-12 and write IPv4 at 12-15; for /32-64 build the address per the RFC 6052 table (IPv4 split across positions PL..63 and 72..(72+31)), with bits 64-71 (u octet) zero. Update ExtractIPv4 and IsSynthesized to the same layout, and add a golden test for a /64 and /32 prefix using the RFC 6052 §2.4 examples.

### F2 [LOW] docs — CompareAndDelete doc comment duplicated — two overlapping paragraphs say the same thing
- **文件**: internal/lrumap/lru.go:156
- **问题**: The doc comment on CompareAndDelete (lines 156-161) contains the description twice: lines 156-158 ('CompareAndDelete removes the entry for key only if it currently holds val. It reports whether the entry was removed. Atomic Get→compare→Delete: a concurrent Set installing a different value for the same key is preserved.') followed by lines 159-161 restating the same contract in different words. This looks like a merge artifact.
- **风险**: No functional impact; duplicated doc text makes the API contract harder to read and suggests the second paragraph was accidentally pasted.
- **修复建议**: Collapse to a single concise doc comment (keep the 'interface equality — V must be comparable' caveat).

### F3 [LOW] comment — TicketPlaintext doc claims it carries 'every field EncodeTicketPlaintext writes' but Serial and TSEnd are absent
- **文件**: internal/dnscryptcrypto/pq.go:15
- **问题**: The TicketPlaintext doc comment (lines 14-18) says: 'It carries every field EncodeTicketPlaintext writes — including esVersion and peHash'. EncodeTicketPlaintext (lines 262-272) writes resume-secret, es-version, client-magic, serial (offset 42), ts-end (offset 46), expiry, pe-hash — but the TicketPlaintext struct (lines 19-25) has no Serial or TSEnd fields. DecodeTicketPlaintext (lines 275-286) also omits them; callers (server/protocol/dnscrypt/crypto.go:285-286) re-index the raw plaintext buffer for serial/ts-end instead.
- **风险**: Misleading API documentation — a reader relying on the comment would assume the struct fully decodes the ticket plaintext; a future refactor could drop the raw-buffer re-indexing and lose the serial/ts-end binding.
- **修复建议**: Either add Serial and TSEnd fields to TicketPlaintext (and populate them in DecodeTicketPlaintext), or fix the comment to say it carries the fields used for validation, with serial/ts-end read from the raw plaintext by callers.

### F4 [LOW] inefficiency — Component filter checked after fmt.Sprintf + sanitize — filtered-out messages still pay full formatting on hot paths
- **文件**: internal/log/log.go:213
- **问题**: In Log(), the level check short-circuits before formatting (line 202), but the component-filter rejection (lines 215-218) runs only after `message := sanitizeLogMessage(fmt.Sprintf(format, args...))` (line 213). In the intended filter scenario (e.g. log_level 'debug:UPSTREAM,RECURSION'), every Debug call from non-listed components — including per-query CACHE/RESULT/etc. debug logs on the request path — is formatted and sanitized (two allocations: the formatted string and the sanitized copy) and then dropped. The format strings for all 23 canonical prefixes are static ('PREFIX: ...'), so the prefix could be extracted from the format string first and the expensive rendered check reserved for the rare dynamic-prefix case the comment at lines 206-209 guards against.
- **风险**: When debug level + component filter is enabled (the exact feature combination the filter exists for), every filtered-out hot-path log call still pays two string allocations, degrading QPS on the debug instrumentation path.
- **修复建议**: Two-stage check: extract the prefix from the format string (static prefix case, all canonical prefixes) and reject before formatting; fall back to the rendered-message check only when the format string has no static prefix.

### F5 [MEDIUM] dead-code — RequestRecord.ECS/DNSSECOK/EntryID are write-only fields — 'for resolving entry_id FK' FK does not exist
- **文件**: cache/cache.go:18
- **问题**: cache.RequestRecord (cache/cache.go:14-28) has fields ECS (line 18), DNSSECOK (line 19) and EntryID (line 27), each commented 'for resolving entry_id FK'. Every one of the ~20 RecordRequest call sites (cache_lookup.go:59-64, 103-108, 115-120, 178-182, 185-190, 194-199; cache_store.go:120-127, 166-172, 198-204, 224-229; middleware/zone.go:78; handler.go:152, 162) sets them, but neither consumer reads them: the sync path (cache/stats.go:54-62) and the async writer batch flush (cache/async_writer.go:159-185) pass only Result/Protocol/Rcode/DNSSECStatus/Poisoned/ResponseTime/Qname/Qtype/Qclass/Server into StmtQueryStats/StmtQueryLog, and the SQL (database/stmts.go:15-35) has no entry_id or ecs columns. No code anywhere reads r.ECS, r.DNSSECOK or r.EntryID.
- **风险**: Dead config surface: misleading comments imply a query_log→entries FK that does not exist; every hot-path RecordRequest carries a pointer + 2 scalars that are discarded; a future reader of these fields would get stale/misinterpreted data. An audit-log consumer (--sql query_log) cannot link log rows to cache entries despite the schema comment promising it.
- **修复建议**: Either remove the three fields and their comments, or actually persist them (add entry_id/ecs_addr/ecs_prefix columns to query_log and pass them in the Exec args) if the FK is intended.

### F6 [MEDIUM] dead-code — QueryContext carries 6 dead fields: ZoneResult, CacheEntry, CacheIsStale, ResolutionError, TCPKeepalive, Dropped
- **文件**: server/handler/context.go:37
- **问题**: Verified write/read counts for every QueryContext field (server/handler/context.go:18-68). Never read anywhere in production: ZoneResult (line 37, written only at middleware/zone.go:84), CacheEntry (line 42, written only at middleware/cache_lookup.go:51), CacheIsStale (line 43, written only at cache_lookup.go:83), ResolutionError (line 50, written 4x at middleware/resolution.go:53,59,67,74 — the qr==nil branches are also unreachable since resolver.Query always returns &qr, resolver.go:226-246). Never written: TCPKeepalive (line 61, read at middleware/response.go:64,67 — the RFC 7828 keepalive option is never parsed from requests, so the EDNS0TCPKeepalive response branch at edns/edns.go:138-141 is unreachable and qctx.TCPKeepalive>0 at response.go:64 is always false) and Dropped (line 58, read at handler.go:142 'errors.Is(err, ErrDrop) || qctx.Dropped' — no code ever sets it, so that disjunct is dead).
- **风险**: Misleading state machine: maintainers extend middleware based on the documented contract and hit fields that do nothing (e.g. ResolutionError looks like the error path to log, TCPKeepalive looks like a working RFC 7828 feature). The dead '|| qctx.Dropped' branch at handler.go:142 gives the false impression of a second drop mechanism. Server never advertises EDNS TCP keepalive on any transport.
- **修复建议**: Delete the six fields and their write/read sites (context.go, zone.go:84, cache_lookup.go:51,83, resolution.go:53-74, response.go:64,67, handler.go:142, edns/edns.go:138-141), or implement the keepalive parse if RFC 7828 is intended.

### F7 [MEDIUM] dead-code — Exported Synthesizer.ExtractIPv4 has zero production consumers (test-only)
- **文件**: internal/dns64/dns64.go:57
- **问题**: func (s *Synthesizer) ExtractIPv4(ip6 netip.Addr) (netip.Addr, bool) at internal/dns64/dns64.go:57 is the only package-level symbol in the entire repo (production + tests, verified by whole-repo identifier scan) with a single definition occurrence and no references outside test files. It is referenced only by dns64_test.go and benchmark_test.go. The DNS64 middleware (server/handler/middleware/dns64.go) uses only Synthesize/MapAddr.
- **风险**: Dead exported API surface: it compiles into the binary and invites misuse (its prefix.Contains check + slicing assumes the nat64Offset layout of the well-known prefix).
- **修复建议**: Remove it (and its tests), or move it to unexported if reverse-mapping is planned for a future ECS/PTR feature.

### F8 [LOW] dead-code — Exported Resolver.Recursive() accessor has zero callers (not even tests)
- **文件**: server/resolver/resolver.go:212
- **问题**: func (r *Resolver) Recursive() *Recursive at server/resolver/resolver.go:212 is referenced nowhere: no production code and no test file calls .Recursive() on a Resolver (whole-repo grep for '.Recursive()' and 'Recursive()' excluding IsRecursive/r.recursive returned only the definition). The recursive resolver is reached through r.cname.resolve / r.recursive fields internally.
- **风险**: Dead exported API surface on a core type; signals an accessor pattern that was added but never wired.
- **修复建议**: Delete the method, or wire a real consumer (e.g. stats/status output) if introspection is intended.

### F9 [LOW] dead-code — LookupResult.EntryID is write-only — ReverseLookup consumer uses only Name and TTL
- **文件**: cache/cache.go:79
- **问题**: LookupResult.EntryID (cache/cache.go:79) is set in ReverseLookup (cache/stats.go:105-109, scanned from the correlated subquery's pm.entry_id at stats.go:77) but the only consumer, server/handler/middleware/ptr.go:43-48, reads only result.Name and result.TTL to build PTR records. No other production or test code reads EntryID.
- **风险**: The ReverseLookup SQL joins entries and computes MAX(timestamp+ttl) purely to surface a value nobody consumes; the field invites future misuse (EntryID refers to a cache entry that may be evicted).
- **修复建议**: Drop the field and the pm.entry_id projection (keep the join/subquery only if it serves the TTL logic), or consume it (e.g. record it in the PTR request log).

### F10 [LOW] duplication — buildResponse (cache_lookup.go) and buildFromCacheEntry (cache_store.go) are byte-identical functions in the same package
- **文件**: server/handler/middleware/cache_lookup.go:224
- **问题**: func (m *CacheLookup) buildResponse at server/handler/middleware/cache_lookup.go:224-230 and func (m *CacheStore) buildFromCacheEntry at server/handler/middleware/cache_store.go:234-241 have identical bodies (script-verified: handler.BuildCacheEntryResponse(qctx.Req, entry, qctx.ClientRequestedDNSSEC, isExpired); if isExpired { qctx.EDE = &dns.EDE{InfoCode: dns.ExtendedErrorStaleAnswer, ExtraText: ""} }; return msg) differing only in receiver type. The same stale-EDE side effect pattern also repeats inline at cache_lookup.go:227 and cache_store.go:237.
- **风险**: Divergent evolution risk in the same package: a fix to stale-EDE handling in one path silently misses the other (both are on the stale-serving hot path).
- **修复建议**: Replace both with a single shared helper (e.g. package-level func buildCacheEntryResponse(qctx, entry, isExpired)) and call it from both middlewares.

### F11 [LOW] duplication — cloneRRs deep-copy helper duplicated across cache and server/handler packages
- **文件**: cache/cache.go:177
- **问题**: func cloneRRs(rrs []dns.RR) []dns.RR is implemented twice with identical logic: cache/cache.go:177-185 (used by cache/store.go:308-314) and server/handler/pending.go:148-159 (the handler copy additionally guards rr != nil). Verified by body-hash comparison across all packages.
- **风险**: Cross-package drift: the nil-guard divergence means the two copies already differ; a future RR-cloning change (e.g. zeroing header fields) can be applied in one package and missed in the other, causing shared-RR mutation races via singleflight followers (pending.go's copy was added precisely for that race).
- **修复建议**: Hoist one implementation into a shared location (e.g. internal/dnsutil.CloneRRs) and have both packages call it, keeping the nil-guard.

### F12 [LOW] ordering — NewConnPool is not the first func after ConnPool's type — the entire Conn method block (63-338) sits between type and constructor
- **文件**: server/upstream/pool/tcp.go:343
- **问题**: In server/upstream/pool/tcp.go the declaration order is: type ConnPool at line 52, const dnsIDMask at 61, then func newConn (63) and the complete *Conn method section (Exchange 99, readLoop 219, close 314, IsFull 333, IsDead 338), and only then func NewConnPool at 343. This violates the project's declared standard 'New* constructors immediately follow their type' (CLAUDE.md File Organization), which is followed in every other file (e.g. cache/store.go New at 67 after the var block). The analogous minor case exists in server/protocol/dnscrypt/server.go where keyEntry.remainingTTL (line 81) is inserted between type Server (36) and New (92).
- **风险**: Reader friction on a core pool type: locating the constructor requires scanning past ~280 lines of a different type's methods; the project's ordering rule is applied inconsistently, making the convention unreliable as a navigation aid.
- **修复建议**: Move func NewConnPool to directly after the const/var block (line ~62) ahead of newConn and the Conn methods; same relocation for the dnscrypt server New.
