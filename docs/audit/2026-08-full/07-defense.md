# defense — 包级审计报告

> 审计日期: 2026-08-04 | 审计范围: server+server/defense+cmd/zjdns
> 发现数量: 4 ({"HIGH":1,"MEDIUM":1,"LOW":2})

### F1 [HIGH] memory — tcpWriteEntry refcount never returns to 0 — tcpWriteMu sweep is dead, map grows unboundedly
- **文件**: server/bridge.go:65
- **问题**: In handleDNSRequest's TCP path, the refs accounting is unbalanced. Line 56: newEntry.refs.Add(1) (pre-increment before LoadOrStore) is never decremented in the creator path — only in the !ok type-assertion branch (line 60). Lines 64-66: `if loaded { entry.refs.Add(1) }` adds another per-request increment that has no matching decrement anywhere (the goroutine's single `defer entry.refs.Add(-1)` at line 121 and the SERVFAIL `defer entry.refs.Add(-1)` at line 81 each balance only the line-76 in-flight increment). Result: for the creator refs ends at 1 permanently ((A)+(C)-(D)); for the loaded path refs grows +1 per request. The sweep in tasks.go:132 (`if entry.refs.Load() != 0 { return true }`) therefore never deletes any entry — the elaborate lastAccess/cutoff eviction logic is unreachable. tcpWriteMu accumulates one entry (struct + 16-slot capacity channel + writeMu channel) per distinct client address for the entire server lifetime.
- **风险**: Unbounded memory growth in tcpWriteMu over server lifetime — under sustained client churn (many ephemeral source ports, e.g. an open resolver or clients behind NAT) the map grows without bound until OOM, and the refs counter grows per request on the loaded path. The sweep's intended function (evicting idle entries after DefaultTCPWriteMuStaleCutoff) is completely defeated.
- **修复建议**: Balance the counters so refs returns to 0 when idle: delete the `if loaded { entry.refs.Add(1) }` block (the line-76 increment is the in-flight count), and after the line-76 Add, drop the creator's pre-increment with `if !loaded { entry.refs.Add(-1) }` — the window between LoadOrStore and line 76 was protected by the pre-increment, so it can be released once the in-flight ref exists. Then refs==0 exactly when idle and the sweep evicts stale entries again.

### F2 [MEDIUM] logic — --sql query failures print the error but exit with code 0
- **文件**: cmd/zjdns/cli/parse.go:257
- **问题**: In the --sql dispatch (lines 250-267), both RunSQLRW and RunSQL errors are printed to stderr (`fmt.Fprintf(os.Stderr, "sql: %v\n", err)`) but the function always returns `"", true, 0`. This contradicts the ParseFlags doc comment (lines 12-15: exit 1 for "command failures (parse errors, probe/generate/dnsstamp failures)") and the sibling commands (--probe line 218-221, --generate-config, --dnsstamp all return exit 1 on error). A failed query (syntax error, missing table, aborted --rw confirmation) is reported as success to the calling shell.
- **风险**: Scripts and CI pipelines that check $? after `zjdns --sql cache.db "SELECT ..."` get a false success for failed queries and aborted --rw confirmations — wrong command-result signalling.
- **修复建议**: Return `"", true, 1` after printing the error in both the RunSQLRW and RunSQL branches, matching the probe/dnsstamp/generate error handling.

### F3 [LOW] dead-code — Unreachable default branch and dead ODoHTarget guard in RunDNSStampDecode
- **文件**: cmd/zjdns/cli/dnsstamp.go:40
- **问题**: The ProtoType switch (lines 27-44) covers all 8 stamp protocol values: ProtoODoHTarget/ProtoDNSCryptRelay/ProtoODoHRelay return an error at lines 34-39, ProtoDOH is handled at line 28-33, and ProtoPlain/ProtoDNSCrypt/ProtoDOT/ProtoDOQ at line 40-41. The `default: entry.Address = s.Address` at line 42-44 is therefore unreachable and identical to the explicit case body. Similarly the guard `s.Proto != zstamp.ProtoODoHTarget` at line 47 is always true — ODoHTarget already returned at line 39.
- **风险**: Dead code misleads future maintainers into thinking the default branch handles unlisted protocols; no functional defect.
- **修复建议**: Remove the `default` branch (or collapse the plain/dnscrypt/dot/doq case into it) and drop the `s.Proto != zstamp.ProtoODoHTarget` condition, keeping the ODoHTarget rejection where it is.

### F4 [LOW] comment — Stale/misplaced '// set below' comment on ZoneEvaluator in middleware.Dependencies
- **文件**: server/server.go:273
- **问题**: In initHandler, the field `ZoneEvaluator: zoneEvaluator, // set below` carries a comment that no longer applies — the value is assigned in-place. The 'set below' note belongs to `TagMatcher` (line 287-291), which is genuinely assigned after the struct literal via `if rulesetEngine != nil`.
- **风险**: Misleading comment for readers tracing how dependencies are wired; trivial.
- **修复建议**: Move the '// set below' note to the TagMatcher assignment (or delete it — the code below is self-evident).
