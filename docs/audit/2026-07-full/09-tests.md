# Test Audit: ALL _test.go files

## Summary
- Test files audited: 44 (excluding benchmark-only files)
- Benchmark files reviewed: 14
- **CRITICAL: 0, HIGH: 4, MEDIUM: 5, LOW: 2**

---

## Test Coverage Gap Analysis

| Package | Production file | Missing test coverage |
|---------|----------------|----------------------|
| `server/defense` | `spoofguard.go` | No unit tests for spoofguard logic (TestCovered only via integration pipeline) |
| `server/defense` | `splitguard.go` | No unit tests for splitguard segmentation (TestCovered only via integration pipeline) |
| `server/resolver` | `recursive.go` | Large recursive walk function with no direct unit tests (relies on pipeline integration) |
| `server/handler/middleware` | `response.go`, `cache_store.go`, `cache_lookup.go`, `resolution.go` | No individual middleware unit tests — only tested via integration pipeline |
| `cache` | `store.go` | `Store.Get` with `serveStale` path (stale cache serving logic) has no dedicated test |
| `edns` | `edns.go` | `EDE` code injection on response has no specific test |
| `server/upstream` | `client.go` | `Client.Execute()` for each protocol path (TCP, TLS, QUIC, DoH, DoH3, DTLS, TLCP, DTLCP) has no dedicated unit test (only DNSCrypt tested) |
| `server/upstream/pool` | `pool.go` | `ConnPool.Acquire/Release` and pipelining logic have no tests (only construction + shutdown tested) |
| `internal/dnsutil` | `bind.go` | `ResolveBindAddrs()` with multiple interfaces and edge cases (no interfaces, nil returns) |
| `zone` | `evaluator.go` | `Evaluator.Evaluate` with EDNS options padding/cookie interaction not tested |

---

## Findings

### HIGH

#### [HIGH] [test-correctness] server/handler/pending_test.go:47,95,200,238,341,380,431 — Flaky goroutine synchronization via time.Sleep

- **Problem**: Seven tests in `pending_test.go` use `time.Sleep(time.Millisecond)` to synchronize goroutines instead of proper channel-based coordination:
  - `TestPendingRequests_LeaderAndFollower` (l.47)
  - `TestPendingRequests_MultipleFollowers` (l.95)
  - `TestPendingRequests_ConcurrentSameKey` (l.200)
  - `TestPendingRequests_NilECSAndZeroECSAreSameKey` (l.238)
  - `TestPendingRefreshes_ConcurrentSameKey` (l.341)
  - `TestPendingRefreshes_MultipleFollowers` (l.380)
  - `TestPendingRefreshes_LeaderDoneFollowerCanProceed` (l.431)

- **Risk**: Under CI load or on slower machines, `1ms` sleep may not be sufficient for all goroutines to enter the blocked state before `Done()` is called. This produces false negatives (tests that fail intermittently) or false positives (tests that pass despite broken code when sleep is "enough").

- **Fix**: Replace `time.Sleep` with proper channel synchronization. For example, a `sync.WaitGroup` or a channel that signals when followers have entered `Join()`/`Start()`. Pattern:
  ```go
  ready := make(chan struct{})
  go func() {
      close(ready) // signals caller that goroutine is about to call Join()
      _, f := pr.Join(...)
      ...
  }()
  <-ready                              // wait for goroutine to be ready
  time.Sleep(time.Millisecond)         // <-- this can be eliminated
  ```

  For the spin-loop pattern (`for entered.Load() < N {}`), add a small bounded retry with `Tick` instead of a bare spin-loop.

---

#### [HIGH] [test-correctness] server/resolver/probe/probe_test.go:88,127,159,251 — Flaky goroutine synchronization via time.Sleep

- **Problem**: Same pattern as `pending_test.go`. Four tests in `probe_test.go` use `time.Sleep(time.Millisecond)` after spin-loops to "ensure" goroutines have entered the blocking state:
  - `TestPendingProbes_ConcurrentSameKey` (l.88)
  - `TestPendingProbes_MultipleFollowers` (l.127)
  - `TestPendingProbes_LeaderDoneFollowerCanProceed` (l.159)
  - `TestTryStartNSProbe_ConcurrentSameKey` (l.251)

- **Risk**: Same flakiness risk as `pending_test.go`. The spin-loop `for entered.Load() < N {}` is a busy-wait that introduces scheduling-dependent behavior.

- **Fix**: Replace with channel-based signaling or use `sync.Cond` for follower readiness notifications.

---

#### [HIGH] [test-correctness] cache/async_writer_test.go:123 — Known race condition in ChannelFullDrops test

- **Problem**: The test comment at line 123 explicitly states: *"NOTE(L8): buffer-size-1 test may race with goroutine consumption. Run with -count=5."* The `TestAsyncStatsWriter_ChannelFullDrops` test uses a channel buffer of 1, but the background goroutine may consume the first record before the second is sent, invalidating the test's assumption that the second record is dropped.

- **Risk**: The test is inherently non-deterministic. It may pass or fail depending on goroutine scheduling, making CI unreliable.

- **Fix**: The test should not rely on timing assumptions. Options:
  1. Make the `testWriter` function accept a flag to disable the background goroutine (inject a no-op goroutine), verifying drop behavior purely by channel buffer semantics.
  2. Use a channel with select/default to verify the channel is full, rather than relying on timing.
  3. At minimum, wrap with `t.Parallel()` and document the expected failure rate.

---

#### [HIGH] [test-gap] server/resolver/dnssec_chain_test.go:222-283 — Lame delegation tests have no assertions (pro forma tests)

- **Problem**: `TestLameDelegation_NonAuthoritativeSameZone` (l.222) and `TestLameDelegation_AuthoritativeNODATA` (l.253) contain no `t.Error`/`t.Fatal` calls. They only use `t.Log` statements inside `if` conditions. If the production code changes, these tests will **always pass** regardless of correctness.

  ```go
  func TestLameDelegation_NonAuthoritativeSameZone(t *testing.T) {
      // ... setup ...
      if len(msg.Answer) == 0 && !msg.Authoritative {
          // ... comparison ...
          if nsName == normalizedCurrent {
              t.Log("Correctly identified lame delegation pattern")
              return
          }
      }
  }
  // Falls through — test passes even if everything is broken.
  ```

- **Risk**: These tests provide a false sense of security. They appear to validate lame delegation detection but silently accept any output.

- **Fix**: Convert to table-driven tests with explicit assertions:
  ```go
  func TestCheckLameDelegation(t *testing.T) {
      tests := []struct {
          name     string
          resp     *dns.Msg
          current  string
          wantLame bool
      }{ ... }
      for _, tt := range tests {
          r := newTestRecursiveWithHelpers()
          termRes := r.checkLameDelegation(tt.resp, tt.current, "...", false, nil)
          if (termRes != nil) != tt.wantLame {
              t.Errorf(...)
          }
      }
  }
  ```

---

### MEDIUM

#### [MEDIUM] [error-handling] cache/cache_test.go:834,852-854,869-875,901-903,1087 — SQL scan errors silently discarded in TestE2E_FullLifecycle

- **Problem**: Multiple SQL query results use `_ = mc.db.SQ.QueryRow(...).Scan(...)` which discards both query execution and scan errors. Found at:
  - Line 834: `_ = mc.db.SQ.QueryRow("SELECT COUNT(*) ...").Scan(&errCount)`
  - Lines 852-854: `_ = mc.db.SQ.QueryRow(...).Scan(&doqStale)`
  - Lines 869-875: `_ = mc.db.SQ.QueryRow(...).Scan(&gitTCP, ...)`
  - Lines 901-903: `_ = mc.db.SQ.QueryRow(...).Scan(&latA, &latB)`
  - Line 1087: `_ = mc.db.SQ.QueryRow(...).Scan(&total, &udp, &tcp)`

- **Risk**: SQL errors (table not found, schema mismatch, query syntax error) would silently pass, producing zero values that might coincidentally match expectations. This masks real bugs.

- **Fix**: Add `err` checks for all SQL queries. Since these are secondary assertions (not primary test logic), use `t.Logf` on error rather than `t.Fatal`:
  ```go
  var errCount int64
  err := mc.db.SQ.QueryRow("SELECT COUNT(*) ...").Scan(&errCount)
  if err != nil {
      t.Errorf("query_log count query: %v", err)
  } else if errCount != 1 {
      t.Errorf(...)
  }
  ```

---

#### [MEDIUM] [test-correctness] internal/ttl/ttl_test.go:305-336 — Real-time tests use 1.1s sleep, potentially flaky

- **Problem**: Three tests use `time.Sleep(1100 * time.Millisecond)` to verify time advancement:
  - `TestNowUnix_Advances` (l.309)
  - `TestElapsed_RealTime` (l.318)
  - `TestRemainingTTL_RealTime` (l.331)

  The tests require that at least 1 second elapses, but CI pauses (GC, CPU contention) could cause the sleep to return before a full second wall-clock has passed.

- **Risk**: Intermittent failures on overloaded CI systems or with `-count=100` stress runs.

- **Fix**: Use a retry loop with a generous timeout instead of a single sleep:
  ```go
  deadline := time.Now().Add(5 * time.Second)
  for time.Now().Before(deadline) && t2 <= t1 {
      t2 = NowUnix()
  }
  ```
  Or simply accept `t2 >= t1` (non-decreasing) rather than `t2 > t1`.

---

#### [MEDIUM] [isolation] ruleset/ruleset_test.go:11 — Modifies shared package-level database.Version in test helper

- **Problem**: `testEngine()` sets `database.Version = "3.2.12"` (line 11), which is a package-level variable in the `database` package. This creates shared mutable state that persists for the duration of the test binary.

- **Risk**: If any test in the `database` package reads `database.Version` during initialization (e.g., schema migration), it will see a stale value from a previous `ruleset` test run. Running `go test ./...` may produce non-deterministic failures if test ordering changes.

- **Fix**: Save and restore the original value:
  ```go
  origVersion := database.Version
  database.Version = "3.2.12"
  t.Cleanup(func() { database.Version = origVersion })
  ```

---

#### [MEDIUM] [test-correctness] server/upstream/dnscrypt/dnscrypt_test.go:55 — Server startup race via time.Sleep(100ms)

- **Problem**: `startTestDNSCryptServer()` uses `time.Sleep(100 * time.Millisecond)` after `srv.Start()` to wait for the server to be ready. The server starts in a goroutine, and there is no health-check or readiness signal.

- **Risk**: On a slow CI machine, 100ms may not be enough for the server to start listening. Tests would fail with connection refused. Conversely, 100ms is wasteful on fast machines.

- **Fix**: Replace the sleep with a retry loop that attempts to connect:
  ```go
  t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
  retry.ForDuration(5*time.Second, func() error {
      conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
      if err == nil { conn.Close(); return nil }
      return err
  })
  ```

---

#### [MEDIUM] [table-driven] internal/dnsutil/dnsutil_test.go:25-32 — Duplicate entries in TestIsSecureProtocol table

- **Problem**: The test table `TestIsSecureProtocol` has 6 duplicate rows (lines 25-32 repeat `"tls"/true`, `"quic"/true`, `"https"/true`, `"http3"/true` after having tested them at lines 17-22). This adds zero coverage and suggests a copy-paste error.

- **Risk**: Low — no functional impact, but wastes test execution time (negligible) and makes the intent unclear. If someone adds a new protocol and only adds it to the duplicates section, it won't fail but the first copy would break without noticing.

- **Fix**: Remove the duplicate rows (lines 25-32). If the intent was to test with different case (`TLS` vs `tls`), add explicit test cases with explanatory names.

---

### LOW

#### [LOW] [test-correctness] internal/dnsutil/bind_test.go:97 — Silent early return instead of t.Skip

- **Problem**: In `TestResolveBindAddrs_SkipsOccupied`, when `ResolveBindAddrs` returns an error (only loopback interface exists and it's occupied), the test does `return` (l.97) without `t.Skip` or `t.Fatal`. The test silently passes without validating anything.

- **Risk**: If the function being tested returns an unexpected error, the test will still pass.

- **Fix**: Use `t.Skipf("no free addresses on any interface: %v", err)` to document why the test body is skipped.

#### [LOW] [error-handling] cache/cache_test.go:1079 — os.Stat error silently discarded

- **Problem**: Line 1079: `info, _ := os.Stat(dbPath)` — the Stat error is silently discarded. If the file doesn't exist, `info` is nil and `info.Size()` will panic or return 0.

- **Risk**: Low — the file should always exist after the test writes to it. But a refactoring that changes the DB path could cause a nil-pointer panic here.

- **Fix**: Add error check: `info, err := os.Stat(dbPath); if err != nil { t.Fatalf(...) }`

---

## Benchmark Quality Assessment

14 benchmark files reviewed. Overall quality is good with the following observations:

| Benchmark file | Strengths | Issues |
|---------------|-----------|--------|
| `edns/benchmark_test.go` | Proper `b.ResetTimer()` before loops, `b.Loop()` used, allocation-free setup | None |
| `cache/benchmark_test.go` | Parallel benchmark included, `b.ResetTimer()` correct | `BenchmarkStoreParallel` allocates inside the loop (`fmt.Sprintf`) which is measured overhead |
| `server/defense/benchmark_test.go` | Clean setup, two scenarios (clean + poisoned), `b.ResetTimer()` correct | None |
| `server/resolver/dnssec/benchmark_test.go` | Crypto-heavy benchmark with proper setup/teardown separation | None |
| `internal/ttl/benchmark_test.go` | Correct `b.ResetTimer()`, simple pure functions | None |
| `internal/lrumap/benchmark_test.go` | Parallel benchmark included, covers all operations | `BenchmarkMapParallel` uses `fmt.Sprintf` inside the loop (measured overhead) |
| `internal/siphash/benchmark_test.go` | Varying message sizes (8/64/256/1024), `b.SetBytes()` for throughput reporting | None |
| `server/resolver/benchmark_test.go` | Simple `ShuffleSlice` benchmark | Single benchmark only |
| `cache/benchmark_test.go` | Two benchmarks (sequential + parallel) | Parallel benchmark has `fmt.Sprintf` + `ipmod` in loop — compiler may optimize differently |
| `internal/dnsutil/benchmark_test.go` | Proper `b.Loop()` usage | None |
| `internal/stamp/benchmark_test.go` | Real-world stamp parsing | None |
| `internal/pending/benchmark_test.go` | Benchmarks `Start`, `Done`, concurrent access | None |
| `internal/dns64/benchmark_test.go` | Pure function benchmark | None |
| `zone/benchmark_test.go` | `Evaluate` benchmark with real zone rules | None |

### Notable benchmark quality findings:

1. **All benchmarks use `b.Loop()`** (Go 1.26 idiom) which handles `b.ReportAllocs()` implicitly — good.

2. **Most benchmarks correctly isolate setup from measurement** with `b.ResetTimer()`.

3. **`BenchmarkStoreParallel` (cache) and `BenchmarkMapParallel` (lrumap)** include `fmt.Sprintf` inside the measured loop. This inflates allocation reports. Consider hoisting formatting out:
   ```go
   keys := make([]string, 1000)
   for i := range keys { keys[i] = fmt.Sprintf("key%d", i) }
   b.ResetTimer()
   b.RunParallel(func(pb *testing.PB) {
       i := 0
       for pb.Next() {
           m.Set(keys[i%1000], i)
           i++
       }
   })
   ```

4. **All benchmarks properly suppress logging** (`log.Default.SetLevel(log.Error)`) — correct pattern.

5. **Benchmarks build but do not run on CI** (no `-bench` flag in standard test invocation) — acceptable; benchmarks are ad-hoc tools.

---

## Summary by Severity

| Severity | Count | Key files affected |
|----------|-------|-------------------|
| CRITICAL | 0 | — |
| HIGH | 4 | `server/handler/pending_test.go`, `server/resolver/probe/probe_test.go`, `cache/async_writer_test.go`, `server/resolver/dnssec_chain_test.go` |
| MEDIUM | 5 | `cache/cache_test.go`, `internal/ttl/ttl_test.go`, `ruleset/ruleset_test.go`, `server/upstream/dnscrypt/dnscrypt_test.go`, `internal/dnsutil/dnsutil_test.go` |
| LOW | 2 | `internal/dnsutil/bind_test.go`, `cache/cache_test.go` |
| **Total** | **11** | |

## Key Recommendations (Priority Order)

1. **Fix pro forma tests** — `TestLameDelegation_NonAuthoritativeSameZone` and `TestLameDelegation_AuthoritativeNODATA` in `dnssec_chain_test.go` have zero assertions. Rewrite with explicit `t.Error`/`t.Fatal`.

2. **Replace time.Sleep synchronization** — The 11 occurrences across `pending_test.go` and `probe_test.go` use sleep for goroutine handoff. Replace with channel-based signaling. This is the highest source of flakiness risk.

3. **Fix SQL error swallowing** — Add error checks for the 6+ SQL `Scan` calls in `cache_test.go` that silently discard errors.

4. **Save/restore database.Version** in `ruleset_test.go` to prevent shared-state pollution.

5. **Replace server startup sleep** in `dnscrypt_test.go` with a connection retry loop.
