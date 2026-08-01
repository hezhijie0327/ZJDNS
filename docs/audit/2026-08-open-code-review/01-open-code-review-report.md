[ocr] Summary: 193 file(s) reviewed, 384 comment(s), ~45202228 token(s) used (input: ~40125530, output: ~5076698), cache(read: ~36263552, write: ~0), 2h9m10s elapsed

─── cmd/zjdns/banner.go:20-20 ───
[maintainability · low] The banner artwork is used directly as a fmt.Sprintf format string, with the
version injected via the embedded `%s` directive. This works today but is fragile: the banner is
opaque text, and any future edit that adds a literal `%` to the artwork (e.g. "100% uptime" or a
progress-style character) would silently produce malformed output (`%!...`/`(MISSING)` markers)
since the whole string is re-interpreted as a format. Prefer a non-printf substitution so the
artwork stays inert text, e.g. change the placeholder in the const to `{version}` and use
`strings.ReplaceAll(b, "{version}", version)`.

- 	return fmt.Sprintf(b[1:], version)
+ 	return strings.ReplaceAll(b, "{version}", version)[1:]


─── cmd/zjdns/cli/parse.go:103-105 ───
[bug · high] CLI failures are never surfaced as a non-zero exit status. When `fs.Parse` fails
(unknown flag, malformed value), the error and usage are printed by the flag package but
`ParseFlags` returns `("", true)`; the same happens for every failed special command
(`--generate-config`, `--probe`, `--dnsstamp` errors are only printed to stderr before `return "",
true`). `main.go` then just `return`s, so the process exits with code 0 on all of these failures.
Scripts/CI cannot distinguish a successful `--generate-config`/`--probe` run from a failed one.
Suggest returning an exit code (or an error) from `ParseFlags` — e.g., return a non-zero exit code
on parse/command failure while keeping 0 for `-h`/`--help`/`--version` — and have `main` `os.Exit`
with it.



─── cmd/zjdns/cli/parse.go:108-113 ───
[bug · medium] Conflicting special modes are silently ignored instead of diagnosed. Dispatch is a
hard-coded priority chain, so `--version --generate-config` runs only version, `--dnsstamp --decode
--encode` runs only decode, `--probe --pipeline --conn-reuse` runs only the first switch case, and
`--dnscrypt` without `--generate-config` is silently dropped. Users making flag mistakes get a
successful run of the wrong operation with no warning. Consider validating that the special modes
are mutually exclusive (at most one of version/generate-config/dnsstamp/probe, and at most one probe
mode) and printing an error before dispatch.



─── cmd/zjdns/cli/generate.go:33-36 ───
[security · high] The example config ships a hardcoded DNSCrypt private key (64-byte hex, whose last
32 bytes are exactly the accompanying public key). Because the source is public, this private key is
effectively public knowledge: any operator who copies this generated example into a deployment (and
DNSCrypt is enabled by default via `cfg.Server.Protocol.DNSCrypt = config.DefaultDNSCryptPort`) runs
a DNSCrypt server whose signing identity is compromised — anyone can impersonate the resolver or
forge certificates for it. The file's own comment (DC-05) notes that key generation was extracted to
internal/dnscryptcrypto, and `serverdnscrypt.GenerateResolverConfig` /
`dnscryptcrypto.GenerateEd25519Keypair` already produce fresh key pairs. Generate a fresh key pair
at example-generation time (and return the error) instead of embedding a static key.

+ 	rc, err := serverdnscrypt.GenerateResolverConfig("dns.example.com", nil)
+ 	if err != nil {
+ 		return "", fmt.Errorf("generating DNSCrypt example keys: %w", err)
+ 	}
  	cfg.Server.Certificate.DNSCrypt = config.DNSCryptCertificate{
- 		PublicKey:  "1A10FA5B04BC9188691C303960080BC93CCE83E7BC922AA5E59C49C34D675074",
- 		PrivateKey: "34E2546B6F4C1FCE695E0C62DD3D74D39CEA52C70A283E7615EF4B67F82178D51A10FA5B04BC9188691C303960080BC93CCE83E7BC922AA5E59C49C34D675074",
+ 		PublicKey:  rc.PublicKey,
+ 		PrivateKey: rc.PrivateKey,
  	}


─── cache/ptr.go:42-43 ───
[bug · low] The dedup key uses the raw `rr.Header().Name`, but DNS names are case-insensitive (RFC
4343). If the same IP appears in the response under names that differ only in case (e.g.,
`www.example.com.` vs `WWW.EXAMPLE.COM.`), the documented dedup by `(rdata_ip, name)` is defeated:
duplicate `ptr_map` rows are written in the same transaction, and `ReverseLookup`
(cache/lifecycle.go) can return the same owner name twice with different casing. Note
`r.A.String()`/`r.AAAA.String()` are already canonicalized, so the IP half is consistent while the
name half is not. Canonicalize the name with `dns.CanonicalName` when building the dedup key (and
ideally before `EIPReverseKey`) so case-variant records collapse into one entry.

-         key := r.rdataIP + "\x00" + r.name
+         key := r.rdataIP + "\x00" + dns.CanonicalName(r.name)
          if !seen[key] {


─── cmd/zjdns/version.go:20-23 ───
[maintainability · low] The provenance check requires BOTH CommitHash and BuildTime to be set. If
only one ldflags variable is populated (e.g., a build pipeline sets the commit hash but the `date
-u` substitution fails, or vice versa), getVersion silently discards the available metadata and
falls back to the generic `v3.8.16 (go...)` string, hiding partial provenance and making binary
identification harder. Consider formatting each field independently (e.g., appending `-<commit>` and
`@<time>` as each is present) so partial metadata is still surfaced.



─── cmd/zjdns/cli/dnsstamp.go:30-32 ───
[bug · medium] ODoH-target decode loses the stamp's Path: the comment says "provider name + path
only" but only ServerName is emitted. `s.Path` (e.g. `/proxy` for `odoh.cloudflare.com/proxy`) is
essential to the target and is dropped, so decode→encode round-trips lose it. Additionally the
produced entry has an empty Address and Protocol "odoh", which is not in the config validator's
`validProtocols` set (config/validate.go), so the printed JSON cannot be loaded back as an upstream
entry. Either fold the path into Address (e.g. ProviderName+Path, as DoH folds path via BuildDoHURL)
or return an error for ODoH-target instead of emitting an unusable/incomplete entry.



─── cmd/zjdns/cli/dnsstamp.go:64-66 ───
[bug · medium] For odoh-target, `--stamp-addr` is accepted (only the empty-addr case is guarded) but
the address is silently dropped from the encoded stamp: `oDohTargetString()` serializes only
ProviderName and Path (internal/stamp/encode.go), never Address. A user passing `--stamp-addr
host:port --proto odoh-target` gets a stamp that omits it with no warning. Reject a non-empty addr
for odoh-target explicitly.

  	if addr == "" && proto != zstamp.ProtoODoHTarget {
  		return fmt.Errorf("--stamp-addr is required for protocol %q", protoStr)
+ 	}
+ 	if addr != "" && proto == zstamp.ProtoODoHTarget {
+ 		return fmt.Errorf("--stamp-addr is not used by %q stamps (target is provider-name + path only)", protoStr)
  	}


─── cmd/zjdns/cli/dnsstamp.go:88-91 ───
[bug · low] An empty DoH/ODoH path is silently converted to "/", changing what gets encoded: `--path
""` yields a stamp whose path is "/" instead of an empty path, and there is no diagnostic. Also note
the same normalization is not applied to odoh-relay (0x85), whose stamps also carry a path, so
`--path dns-query --proto odoh-relay` would encode a path without the leading slash. Consider
erroring on an empty path or documenting that empty means the root path, and applying the same
normalization consistently to odoh-relay.



─── cache/lifecycle.go:127-130 ───
[bug · high] `LatencyLastProbe` does not return the last probe time: when the latency key exists it
returns `log.NowUnix()` (current time), so the `int64` result is always "now" and callers can never
compute an elapsed interval. Both call sites in server/resolver/probe/probe.go (lines 113 and 211)
evaluate `now-lastProbe >= DefaultLatencyProbeMinInterval`; since the diff is always 0, the
condition never fires and an IP is never re-probed while its latency key exists (up to 2× the min
interval). The stored value only contains the latency measurement (`EncodeLatencyValue`), so the
probe timestamp is not recoverable from the DB at all. Store the probe timestamp (e.g. append it to
the value or use the entry's ExpiresAt/creation metadata) and return it here so the method's
contract is honored.



─── cache/lifecycle.go:46-46 ───
[bug · medium] The TTL computed for every reverse-lookup result is always the stale TTL.
`ttl.RemainingTTL(0, int(ttlVal), ...)` passes timestamp 0, and RemainingTTL computes `remaining :=
ttlSeconds - (NowUnix() - 0)`, which is hugely negative for any realistic stored TTL — so it always
falls into the expired branch and returns `config.DefaultStaleTTL` (30). The stored ptr_map TTL is
therefore ignored, and the PTR middleware (server/handler/middleware/ptr.go) answers fresh entries
with a constant 30s TTL instead of the record's actual remaining TTL. Note cache.go computes
remaining TTL from the real write timestamp; here the timestamp is lost because the ptr_map value
stores only the TTL. Derive the remaining time from the entry's ExpiresAt (available via
item.ExpiresAt()) or persist the write timestamp in the value.



─── cache/lifecycle.go:34-37 ───
[bug · low] Errors from the View transaction and per-item `ValueCopy` are silently swallowed: the
callback always returns nil and any `ValueCopy` failure just skips that item, so a transient
BadgerDB failure (I/O error, iterator abort) is indistinguishable from an empty result. The PTR
middleware will then treat a failed scan as "no PTR records" and delegate upstream. If a DB failure
should surface (e.g., via the error return path or a fallback that is at least logged), propagate
the callback error instead of converting it into a successful empty lookup.



─── cache/lifecycle.go:90-90 ───
[bug · low] The write error from `db.Update` is discarded, so a failed latency write looks like a
successful probe. In the probe flow the caller only logs success unconditionally after UpdateLatency
returns, and LatencyLastProbe key-existence semantics will silently fall back to "not probed" —
masking a real store failure. Since the operation is best-effort by design, at minimum log the error
(e.g. `if err := ...; err != nil { log.Warnf(...) }`) so store failures are observable instead of
invisible.



─── cache/cache.go:167-173 ───
[bug · medium] ProcessRecords' fast paths return the caller's RR slices (or a new slice with
original RR pointers), so the returned records share backing storage with caller data; the
documented 'do not mutate' contract is immediately violated by cache_store.go calling ClampTTL on
the result. ClampTTL mutates RR headers in place, racing with the background latency-probe goroutine
that reads the same answer slice after ProcessRecords, and it would mutate shared cache state if
applied to a cached Entry. Make the fast paths clone when the caller mutates (or have ClampTTL
clone/operate on copies) and enforce exclusive ownership.



─── cache/cache.go:106-108 ───
[bug · low] `value` is an arbitrary int64 parameter of the exported ProcessRecords; when value >
math.MaxUint32 this narrowing wraps silently (e.g., 2^32+10 becomes TTL 10), serving a wrong TTL.
The nolint claims the value is "protocol-bounded", but nothing in this function enforces that bound
— current callers happen to pass uint32-bounded values (responseTTL from RemainingTTL, or elapsed
from ttl.Elapsed), but the exported boundary should validate/clamp rather than rely on caller
discipline. Suggest clamping: newRR.Header().TTL = uint32(min(value, int64(^uint32(0)))).



─── cmd/zjdns/main.go:24-24 ───
[bug · low] The error from `fmt.Print(banner(versionStr))` is discarded. If stdout is closed or a
broken pipe occurs (e.g., output piped to a consumer that exited, or redirected to /dev/full), the
banner write fails silently and the program proceeds to start the server. This matters more than it
first appears: the logger also writes to os.Stdout and discards write errors (internal/log/log.go),
so every subsequent error diagnostic — including the log.Errorf calls right before os.Exit(1) —
would be lost too, leaving an operator with no indication the process is failing. At minimum, check
the error and emit a diagnostic to stderr.

- 	fmt.Print(banner(versionStr))
+ 	if _, err := fmt.Print(banner(versionStr)); err != nil {
+ 		fmt.Fprintf(os.Stderr, "warning: failed to print banner: %v\n", err)
+ 	}


─── cmd/zjdns/main.go:45-48 ───
[maintainability · low] The comment asserts the os.Exit(1) calls are safe because main has no defers
— true today, but by this point server.New() has already opened the BadgerDB database and started
background goroutines, and Server has no Close/cleanup method; the srv.Start() failure path abandons
those without any shutdown. Process exit makes the OS reclaim the resources, so this is not
corruption, but it is a latent hazard: any future deferred cleanup added to main (log flush, DB
close, listener shutdown) would be silently skipped on all three error paths. Consider structuring
startup as `run() error` so the exit code is returned from main and defers can execute.



─── config/config.go:216-219 ───
[bug · high] TLS certificate validation is entirely skipped whenever TLSCertificate.IsEnabled() is
false, because validateTLSCertificateConfig returns nil before checking whether a TLS-based protocol
is enabled. As a result both partial configs (only cert_file set) and completely missing cert
sections pass validation: the intended 'must be configured together'/'certificate required' errors
are unreachable, and initProtocolListeners either silently disables TLS/DoT/DoH/DoQ or fails later
with a less actionable error. Reorder validation to check tlsEnabled first, then require an enabled,
complete certificate.



─── config/config.go:211-214 ───
[bug · medium] Same early-return flaw as the TLS validator: validateTLCPCertificateConfig returns
nil whenever TLCPCertificate.IsEnabled() is false, before checking whether a TLCP protocol is
enabled. Partial TLCP cert configs (e.g. sign_cert_file without sign_key_file) and entirely missing
TLCP cert sections therefore pass validation, silently skipping TLCP listeners or deferring failure
to runtime. Check tlcpEnabled first and validate the cert files explicitly.



─── config/config.go:198-200 ───
[bug · medium] A config with only one DNSCrypt key (public XOR private) is treated as "not enabled"
and there is no validation for this case. At startup, `server/protocol/dnscrypt/buildResolverConfig`
regenerates *both* keys whenever either is empty, silently discarding the user-provided key material
and changing the long-term provider identity (only a warning log is emitted). The doc comment here
only covers the fully-empty case, so the partial case is undocumented. Suggest validating that keys
are provided together (both or neither), and returning an error for a single key.



─── config/chaos.go:42-46 ───
[security · high] The `.cache.clear` / `.stats.clear` CHAOS endpoints registered here are wired in
server/init.go (wireZoneDynamicContent) to `store.FlushDB("cache")` — a full `DropPrefix` of the
cache table — and `statsCollector.Reset()`, and are served by the Zone middleware to any client that
can reach any protocol listener. The shared query chain (server/handler/middleware/chain.go)
contains no authentication or source-allowlisting middleware, so any remote client can query
`ZJDNS.cache.clear CH TXT` repeatedly to flush the entire cache on demand (cache thrashing /
upstream amplification DoS) and reset operational stats. Restrict these destructive endpoints to
trusted operator source networks, require a token/allowlist, or move them to a dedicated
authenticated control channel before advertising them as public CHAOS records.



─── config/chaos.go:29-31 ───
[bug · medium] Rules are appended without checking whether cfg.Zone already contains a rule with the
same name. If an operator config already defines `id.server`, `version.bind`, `ZJDNS.stats`, etc.,
both rules land in the same exact-match key in the evaluator, and zone.Evaluator.pickBest keeps the
first equally-scored rule — so the user's earlier rule silently wins and this chaos rule becomes
dead (e.g. cache.clear silently stops working), or the exact chaos rule silently shadows a user
wildcard such as `*.bind`. Skip appending when a rule with the same name already exists.



─── config/chaos.go:28-28 ───
[maintainability · low] Ranging over the `chaosRecords` map appends the four standard CHAOS rules in
randomized order on every run, so cfg.Zone ordering is non-reproducible. It is benign today only
because the evaluator keys rules by normalized qname and the four names are distinct; combined with
the first-wins tie-breaking in zone.Evaluator.pickBest and any future prefix/order-sensitive
processing of cfg.Zone this is fragile. Iterate over a fixed slice instead of a map for
deterministic output.



─── config/chaos.go:35-35 ───
[bug · low] strconv.Quote produces Go string escapes (`\x`, `\u`, `\t`, `\n`), which are not DNS
master-file escapes. `zone.buildRecord` feeds `Content` verbatim into `dns.New` for zone-file
parsing, so a non-ASCII or special character in `os.Hostname()`/version (e.g. `café` →
`"caf\u00e9"`) is parsed literally/incorrectly and mangles the TXT rdata. It only happens to match
zone-file syntax for pure-ASCII hostnames. Use a DNS-aware TXT quoting helper instead.



─── cmd/zjdns/cli/probe.go:221-223 ───
[bug · high] The out-of-order detector cannot detect reordered responses. The `seen` bitmap only
flags duplicate IDs or IDs outside 0..4, so a pipelining server that answers in any permuted order
with unique IDs (e.g. 4,3,2,1,0) leaves `ooo == false` and the probe reports "may not support
pipelining" — a false negative that defeats the purpose of the probe. To detect reordering, track
the highest ID observed so far and flag any later ID that is smaller (monotonicity check), e.g.
initialize `lastID := -1` before the loop and use `if resp.ID < uint16(lastID) { ooo = true }; if
resp.ID > lastID { lastID = resp.ID }`.



─── cmd/zjdns/cli/probe.go:224-224 ───
[bug · high] Index-out-of-range panic on an unexpected response ID. When `resp.ID >=
probePipelineNumQueries`, the `||` short-circuits the condition (avoiding a panic there), but the
next line `seen[resp.ID] = true` executes unconditionally and panics with index-out-of-range. A
server that does not echo the client's query IDs (e.g. always responds with a fixed ID such as
12345, or a middlebox injects a stray response) will crash the probe. Guard the write, e.g. `if
resp.ID < uint16(probePipelineNumQueries) { seen[resp.ID] = true }`.



─── cmd/zjdns/cli/probe.go:287-294 ───
[bug · high] The idle-timeout probe misreports the client's own read deadline expiry as a
server-side connection close. The loop sets a 30s read deadline each iteration; if the server keeps
the connection alive but silent (idle timeout > 30s or no idle timeout at all), `readDNSMsg` returns
a timeout error and the probe prints "Connection closed by server after 30.0s" and returns success —
a false positive. Only an `io.EOF`/connection reset indicates the server actually closed; a
`net.Error.Timeout()` should be treated as "still alive, keep waiting". For example: `if ne, ok :=
errors.AsType[net.Error](err); ok && ne.Timeout() { continue }`.



─── cmd/zjdns/cli/probe.go:143-145 ───
[bug · high] Manually constructed dns.RR values leave Hdr.Rrtype unset: newQuery builds a *dns.A
question without Rrtype (packing QTYPE 0), and the PTR record helper builds a *dns.PTR without
Rrtype (packing TYPE0). Both produce malformed wire messages. Set Rrtype: dns.TypeA / dns.TypePTR,
or use dnsutil.SetQuestion for the query.



─── cmd/zjdns/cli/probe.go:63-65 ───
[bug · low] `dialProbeTarget` dials with no timeout: `net.Dial("tcp", host)` (and the TLS branch's
`net.Dial` before the handshake deadline is set) blocks until the OS-level connect timeout, which on
unroutable/blackholed targets can hang the probe CLI for tens of seconds to minutes with no
feedback. Use `net.DialTimeout` or a `net.Dialer{Timeout: ...}.DialContext` so the probe fails fast
with a clear error.



─── config/defaults.go:89-89 ───
[bug · medium] Internal-default inconsistency: DefaultRecursiveResolveTimeout (30s) is 3×
DefaultHTTPServerWriteTimeout (10s), and these interact on the DoH/DoH3/HTTP-TLCP server paths. In
server/protocol/tls/https.go the handler resolves synchronously (ServeHTTP → handler.ServeDNS), and
resolver.go/forward.go bound the whole recursive resolution by DefaultRecursiveResolveTimeout (30s).
For a net/http-style server, WriteTimeout is a connection write deadline set before the handler
runs, so it spans the handler execution time. A DoH request that triggers a slow recursive
resolution (between 10s and 30s) will blow past the 10s write deadline and the final response write
fails (truncated/empty response), even though the resolver would legitimately have produced an
answer within its own 30s budget. Align the two defaults — e.g. lower DefaultRecursiveResolveTimeout
below the write timeout, raise the server WriteTimeout to cover the resolution budget, or decouple
the DoH response from the connection write deadline (per-request context deadline) so slow recursive
answers are not silently cut off.



─── config/load.go:150-153 ───
[bug · high] DoH (sdns:// ProtoDOH) stamps cannot produce a working upstream. When `protocol` is
omitted, `resolveStamp` sets `server.Protocol = zstamp.ProtoToConfig(ProtoDOH)` = "doh". "doh" is
not recognized anywhere downstream: `zdnsutil.IsSecureProtocol` (internal/dnsutil/dnsutil.go:55)
excludes it, and `server/upstream/client.go:240-281` `executeSecureQuery` has no "doh" case — so
such an upstream silently falls into the plain-UDP path and fails against the https:// URL every
query. When `protocol` IS set explicitly, both options also fail: "http" (ProtoHTTP) is rejected by
`validateUpstreamServers` (not in `validProtocols`), and "https" (ProtoHTTPS) is rejected by this
mismatch check. Net effect: there is no protocol value that works with a DoH stamp. Map DoH stamps
to ProtoHTTPS ("https") consistently (in `ProtoToConfig`/`protocolMatchesStamp` and the
empty-protocol default in `resolveStamp`).



─── config/load.go:33-34 ───
[bug · medium] Unmarshaling into a zero-value `ServerConfig{}` discards the defaults that
`NewDefaultServerConfig` would have applied. A config file that omits `dnssec_enforce`,
`ecs_subnet`, `ddr`, `certificate.domain`, `log_level`, or the protocol ports silently disables
those features — e.g. DNSSEC enforcement becomes false and ECS/DDR hints are dropped — while the
same server started with no config file (empty path) gets DNSSECEnforce=true, ECS auto, and DDR
hints via `NewDefaultServerConfig`. The two load paths therefore yield materially different behavior
for the same logical configuration. Consider starting from `cfg := NewDefaultServerConfig()` before
`json.Unmarshal(data, cfg)` (and reconciling the intentional "empty port = listener skipped"
semantics for ProtocolSettings), or explicitly apply defaults for omitted fields.



─── config/load.go:16-18 ───
[bug · medium] The no-config path bypasses the enrichment steps that file-based configs always run.
`NewDefaultServerConfig` is returned directly, so `addChaosRecord`
(id.server/hostname.bind/version.bind CHAOS records) and the DDR records that
`shouldEnableDDR`+`addDDRRecords` would generate are missing — note the default config satisfies
`shouldEnableDDR` (domain="dns.example.com", IPv4/IPv6 hints, secure ports enabled), so the same
effective configuration produces different zone rules depending on whether a config file is passed.
Route the empty-path config through the same normalize/enrichment pipeline (e.g. build the default
config, then run the same steps) so the two paths stay consistent.



─── config/ecs.go:140-140 ───
[bug · high] `omitzero` (active on go 1.26.4) omits `prefer_ipv4` from the JSON whenever the value
is false. `UnmarshalJSON` then treats the missing field as absent and resets it to `true` (line
127-129). So `PreferIPv4: false` silently becomes `true` after any marshal→unmarshal round trip,
flipping which address family the default ECS subnet prefers (`ValueForQType`). Remove `omitzero`
from this field (or marshal a `*bool` so absent and false remain distinguishable).

- 		PreferIPv4    bool   `json:"prefer_ipv4,omitzero"`
+ 		PreferIPv4    bool   `json:"prefer_ipv4"`


─── config/ecs.go:45-47 ───
[bug · high] ECSOption.Normalize can overwrite Address with nil whenever net.IP's byte length
doesn't match the prefix-derived mask length: net.ParseIP returns 16-byte IPv4 addresses when a
default ECS is configured as a bare IPv4 literal or auto-detected, while the IPv4 mask is 4 bytes;
truncated wire ECS addresses (3-byte IPv4) make To4() nil so bits becomes 128 and a 16-byte mask
mismatches. Guard against a nil Mask result and normalize IPv4 to 4-byte form before constructing
the option.

  	if mask != nil {
- 		e.Address = e.Address.Mask(mask)
+ 		if masked := e.Address.Mask(mask); masked != nil {
+ 			e.Address = masked
+ 		}
  	}


─── config/ecs.go:44-44 ───
[bug · medium] When `SourcePrefix` exceeds the address width (e.g. 33 for an IPv4 address),
`net.CIDRMask` returns nil and `Normalize` silently does nothing, leaving host bits in the address.
The documented guarantee — identical cache keys for IPs in the same subnet — then silently depends
on `IsValid` having been checked before `Normalize`. Clamp/validate the prefix here or explicitly
document the precondition so the no-op cannot produce inconsistent keys.



─── config/ecs.go:190-192 ───
[maintainability · low] These three trailing lines are an orphaned duplicate of the `IsValid` doc
comment with no code attached (the file ends at line 193; there is no second declaration, so the
file still compiles). They look like the remains of an incomplete edit and describe a
FORMERR-rejection behavior that is not implemented in this file. Either complete the intended
implementation or delete the dead comment so it does not imply behavior that does not exist.



─── config/ddr.go:168-169 ───
[bug · medium] The SVCB TargetName is hard-coded to '.', which makes the service endpoint the owner
name (`_dns.resolver.arpa`, `_dns.<domain>`, `_<port>._dns.<domain>`) instead of the certificate
domain. This is inconsistent with the rest of the advertisement: the A/AAAA additional records below
are emitted for `domain`, and TLS clients validating the DoT/DoQ/DoH certificate will check the
underscore owner name, for which no certificate exists. The domain A/AAAA records and
`ipv4hint`/`ipv6hint` already convey the address, so using `domain` as the target makes the record
self-consistent (e.g. `%d %s alpn=... port=...`).

- 			content = fmt.Sprintf("%d . alpn=%s port=%s dohpath=\"%s{?dns}\"",
- 				priority+1, r.alpns, r.port, r.dohpath)
+ 			content = fmt.Sprintf("%d %s alpn=%s port=%s dohpath=\"%s{?dns}\"",
+ 				priority+1, domain, r.alpns, r.port, r.dohpath)


─── config/ddr.go:60-62 ───
[maintainability · low] `addDDRRecords` has no local guard for an empty protocol set: if it is ever
invoked with all encrypted protocol ports empty, it still appends DDR zone rules with an empty SVCB
`Answer` and then logs "DDR enabled ... records: 0". Today this is only prevented by the caller's
`shouldEnableDDR` check, so the invariant is split across two functions. A defensive early return
with a warning at the top of this function would keep the precondition local and prevent advertising
empty/meaningless DDR rules.



─── config/ddr.go:191-193 ───
[maintainability · low] The same `zoneServiceRecords` and `zoneAdditional` slices (shared backing
arrays) are assigned as `Answer`/`Additional` to every `ddrNames` ZoneRule. `ZoneRule` is stored by
value, so all rules alias the same backing memory; any later in-place append or element mutation
performed through one rule's `Answer`/`Additional` would be visible in all the others. The current
consumers (zone evaluator copies the structs without mutation) make this latent, but cloning the
slices per rule (`slices.Clone` or an explicit copy loop) would make ownership explicit and prevent
future aliasing bugs.



─── config/ddr.go:73-81 ───
[bug · medium] The DoH endpoint is not validated or escaped before being embedded in the SVCB rdata
as `dohpath="%s{?dns}"`. Unlike the explicit unsafe-character checks applied to
`domain`/`ddr.IPv4`/`ddr.IPv6`, `normalizeEndpoint` only prepends a '/'. If the configured endpoint
contains a double quote, backslash, newline, or is an absolute URL (e.g. `https://host/dns-query`),
the generated SVCB rdata becomes malformed: `dns.New` in `zone/wire.go` will fail to parse it and
`buildRecord` silently falls back to an RFC3597 record whose Data is the raw (non-hex) content — a
broken SVCB response. Apply the same validation as for the domain/IP fields (reject whitespace,
quotes, backslashes) and verify the result is a path, not a URL.



─── cache/store.go:80-85 ───
[bug · high] Badger's Item.Value contract states the []byte passed to the callback is only valid
within the callback (and transaction) — for value-log entries Badger reuses an internal read buffer,
so the slice can be overwritten once the callback/View returns. Here msgWire is retained and used
after the View transaction (Unpack, minTTL, Entry construction), which can yield corrupted/zeroed
wire data and thus corrupted cache hits. Use item.ValueCopy(nil) to obtain a buffer that outlives
the transaction (as lookupIPLatencies already does).

- 			if err := item.Value(func(v []byte) error {
- 				msgWire = v
- 				return nil
- 			}); err != nil {
+ 			if msgWire, err = item.ValueCopy(nil); err != nil {
  				continue
  			}


─── cache/store.go:233-237 ───
[bug · high] The OPT pseudo-record's TTL field is not a TTL (RFC 6891); it encodes extended
RCODE/version/flags. cache/store.go computes entryTTL while the OPT is still in additional, so a
common OPT TTL of 0 prevents caching or makes hits immediately expired, and the DoH TTL-adjustment
loop subtracts Age from any OPT in Extra, corrupting EDNS flags. Strip/skip OPT before any TTL
computation or adjustment.

  	now := log.NowUnix()
+
+ 	// Strip the EDNS OPT pseudo-record before computing the TTL — the OPT TTL
+ 	// field encodes flags/extended RCODE (RFC 6891), not a cacheable RR TTL.
+ 	additional = stripOPT(additional)
+
  	entryTTL := minTTL(answer, authority, additional)
  	if entryTTL <= 0 {
  		return 0 // RFC 8767 §7: TTL=0 data must not be cached
  	}


─── cache/store.go:377-386 ───
[bug · medium] stripOPT compacts the caller's slice in place, despite the comment in Set stating it
"allocates a new slice". Callers pass slices they continue to use afterwards (e.g. cache_store.go
buildSuccess calls Set with qr.Additional and then reuses qr.Additional to build msg.Extra and feed
the latency prober). After in-place compaction the caller's backing array is left with a duplicated
trailing element (e.g. [OPT,R1,R2] becomes [R1,R2,R2]) and the OPT is dropped from their view,
corrupting the response's Additional section. Allocate a new slice instead of mutating the input.

  func stripOPT(rrs []dns.RR) []dns.RR {
- 	n := 0
+ 	hasOPT := false
+ 	for _, rr := range rrs {
+ 		if dns.RRToType(rr) == dns.TypeOPT {
+ 			hasOPT = true
+ 			break
+ 		}
+ 	}
+ 	if !hasOPT {
+ 		return rrs
+ 	}
+ 	out := make([]dns.RR, 0, len(rrs)-1)
  	for _, rr := range rrs {
  		if dns.RRToType(rr) != dns.TypeOPT {
- 			rrs[n] = rr
- 			n++
+ 			out = append(out, rr)
  		}
  	}
- 	return rrs[:n]
+ 	return out
  }


─── database/keys.go:107-111 ───
[maintainability · low] Both EIPLatencyKey and EntryKey can produce keys inside the e:ip:
reverse-index namespace scanned by EIPReversePrefix. Latency keys are deliberately placed there
(e:ip:{ip}\x00_lat), and an entry qname beginning with 'ip:' collides with it, so ReverseLookup may
parse unrelated rows as reverse entries. Move latency keys out of e:ip (e.g. e:lat:{ip}) and
namespace entry keys separately, or explicitly exclude non-ptr keys during the scan.



─── database/keys.go:131-135 ───
[bug · low] Unlike EncodeLatencyValue, EncodePtrMapValue does not clamp negative input. The caller
in cache/ptr.go builds the TTL via int32(rr.Header().TTL), so a DNS response TTL >= 2^31 (valid on
the wire even if RFC 2181 discourages it) converts to a negative int32, which round-trips through
this encoder and causes ReverseLookup to report the record as stale via ttl.RemainingTTL. Clamp to
[0, math.MaxInt32] here (consistent with EncodeLatencyValue) or change the encoding to uint32 to
preserve the caller's full range.

  func EncodePtrMapValue(ttl int32) []byte {
+ 	if ttl < 0 {
+ 		ttl = 0
+ 	}
  	buf := make([]byte, 4)
  	binary.BigEndian.PutUint32(buf[0:4], uint32(ttl)) //nolint:gosec // G115: protocol-bounded value fits target type
  	return buf
  }


─── database/db.go:67-71 ───
[bug · medium] When `path == ""`, the in-memory branch uses plain
`badger.DefaultOptions("").WithInMemory(true)` and bypasses `defaultDiskOptions()` entirely. This
silently ignores every resolved memory knob
(`opt.MemTableSizeMB`/`BlockCacheSizeMB`/`IndexCacheSizeMB`, just filled by `resolveDefaults()`) and
also diverges from disk-mode tunings (conflict detection, sync writes, value threshold,
compression). Since `server.initDatabase` always passes a non-nil `Options` and `DBPath` has no
config default (empty path = in-memory), deployments running in-memory get none of their configured
memory budgets applied — a silent config no-op. Apply the same tuning to both branches, e.g.
`defaultDiskOptions("", opt).WithInMemory(true)`.

  	if path == "" {
- 		bopts = badger.DefaultOptions("").WithInMemory(true).WithLogger(nil)
+ 		bopts = defaultDiskOptions("", opt).WithInMemory(true)
  	} else {
  		bopts = defaultDiskOptions(path, opt)
  	}


─── config/validate.go:0-0 ───
[bug · medium] IPv6 validation accepts IPv4 addresses: `net.ParseIP(v6).To16()` returns a non-nil
16-byte representation for IPv4 literals as well (e.g. "1.2.3.4"), so IPv4 values pass the
`ip.To16() == nil` check. `ddr.go` later uses this value directly as the Content of a `TypeAAAA`
zone record, silently producing a malformed AAAA record. Also, the error message says "not a valid
IPv4 address" in the IPv6 branch (copy-paste from the IPv4 check). Fix: reject values that are IPv4,
and correct the message.

  	if v6 := cfg.Server.Features.DDR.IPv6; v6 != "" {
- 		if ip := net.ParseIP(v6); ip == nil || ip.To16() == nil {
- 			return fmt.Errorf("server.features.ddr.ipv6: %q is not a valid IPv4 address", v6)
+ 		if ip := net.ParseIP(v6); ip == nil || ip.To4() != nil {
+ 			return fmt.Errorf("server.features.ddr.ipv6: %q is not a valid IPv6 address", v6)
  		}
  	}


─── config/validate.go:424-426 ───
[bug · medium] `tlcpEnabled` omits `proto.DTLCP`: DTLCP (DNS-over-DTLCP, GM/T 0128-2023) is served
by the same TLCP server and loads the sign/enc TLCP certificate pairs (see `server/server.go`
startup condition `certificate.tlcp.IsEnabled() && (tlcp != "" || http_tlcp != "" || dtlcp != "")`).
With DTLCP-only configs, the TLCP cert file existence/load checks below are skipped, so a broken
cert configuration is only discovered at runtime instead of during validation. Add `|| proto.DTLCP
!= ""`.

  	// Only require cert validation if at least one TLCP protocol is enabled.
  	proto := &cfg.Server.Protocol
- 	tlcpEnabled := proto.TLCP != "" || proto.HTTPTLCP.Port != ""
+ 	tlcpEnabled := proto.TLCP != "" || proto.HTTPTLCP.Port != "" || proto.DTLCP != ""


─── config/validate.go:172-183 ───
[bug · medium] Weak address validation for DoH/DoH3/HTTP-TLCP upstreams: (1) `net.SplitHostPort`
splits on the last colon and succeeds on URL strings — e.g. "https://dns.example.com/dns-query" is
accepted as host="https", port="//dns.example.com/dns-query" — so URL-form addresses are never
actually parsed or scheme-checked; (2) the `url.Parse` fallback is extremely lenient: it accepts
relative strings ("dns.example.com/dns-query"), empty strings, and hosts, so malformed or empty
addresses pass config validation and only fail later at runtime. Validate URL-form addresses by
requiring a scheme and non-empty host, and keep `host:port` form for the rest.

  			if !strings.HasPrefix(server.Address, "sdns://") {
- 				if _, _, err := net.SplitHostPort(server.Address); err != nil {
  					if protocol == ProtoHTTPS || protocol == ProtoHTTP3 ||
  						protocol == ProtoHTTPTLCP {
- 						if _, err := url.Parse(server.Address); err != nil {
+ 					// URL form: require an absolute URL with a scheme and host.
+ 					if u, err := url.Parse(server.Address); err == nil && u.Scheme != "" && u.Host != "" {
+ 						// valid URL
+ 					} else if _, _, err := net.SplitHostPort(server.Address); err != nil {
  							return fmt.Errorf("upstream server %d address invalid: %w", i, err)
  						}
- 					} else {
+ 				} else if _, _, err := net.SplitHostPort(server.Address); err != nil {
  						return fmt.Errorf("upstream server %d address invalid: %w", i, err)
- 					}
  				}
  			}


─── edns/edns.go:101-102 ───
[bug · medium] The DO bit (msg.Security) is forced on for every message, including responses
(isRequest=false at both response call sites: middleware/edns.go buildBadCookieResponse and
middleware/response.go finalizeResponse). Per RFC 3225 §3 / RFC 6891 §6.1.3, the response DO bit
must mirror the query's DO bit; a responder must not set DO in a response when the query had it
clear. There is no parameter to control this — callers already track the client's DO bit
(qctx.ClientRequestedDNSSEC) but cannot pass it here — so every response advertises DNSSEC-OK
regardless of the query, and the resolver may attach unsolicited RRSIGs/larger responses to clients
that never requested DNSSEC. Consider setting msg.Security only when isRequest (or better, adding a
dnssecOK parameter derived from the query's DO bit and applying it for responses).

  	msg.UDPSize = pool.UDPBufferSize
+ 	if isRequest {
  	msg.Security = true
+ 	}


─── edns/edns.go:104-111 ───
[bug · low] The SUBNET option is appended even when the ECS address is nil/invalid, because
addrToNetip silently maps nil to the zero netip.Addr. ECSOption is not always validated before
reaching here: a client-supplied ECS with source prefix /0 (or family 0) passes ECSOption.IsValid()
and is echoed back from ParseFromDNS; the early short-circuit path in middleware/response.go:44-48
also skips the FORMERR check that middleware/edns.go:50 applies. A zero/invalid Address with a
non-zero prefix would be serialized as an option whose netmask claims address bytes that are not
present (wire-malformed per RFC 7871 §6), and even the family-0 case emits an invalid option.
Defensively skip the option when the converted address is invalid.

+ 	if ecs != nil {
+ 		addr := addrToNetip(ecs.Address)
+ 		if !addr.IsValid() {
+ 			log.Debugf("EDNS: skipping ECS option with invalid address")
+ 			ecs = nil
+ 		}
+ 	}
  	if ecs != nil {
  		msg.Pseudo = append(msg.Pseudo, &dns.SUBNET{
  			Family:  ecs.Family,
  			Netmask: ecs.SourcePrefix,
  			Scope:   DefaultECSScope,
  			Address: addrToNetip(ecs.Address),
  		})
  	}


─── internal/dnscryptcrypto/certificate.go:346-346 ───
[bug · medium] The PQ public key length is never validated before serialization or signing.
`writeSigned` copies `c.PqPublicKey` into a zero-filled 1216-byte region, so a nil/short key is
silently zero-padded and an oversized key is silently truncated. `Sign`/`MarshalBinary` will then
emit a structurally valid, Ed25519-signed certificate whose X-Wing key is broken or all-zero.
`Validate()` catches this, but it is not called by the marshal/sign path (and the DNSCrypt client
path in `parseCert` only checks dates and signature). Add a `len(c.PqPublicKey) == PQPublicKeySize`
check in `Sign` and `MarshalBinary` (return/panic rather than emit a malformed cert).



─── internal/dnscryptcrypto/certificate.go:204-211 ───
[maintainability · medium] `UnmarshalBinary` commits `c.ESVersion` before all validation completes,
and `unmarshalPQ` copies `Signature`, `PqPublicKey`, and `ClientMagic` before the client-magic check
and before `PQCertContext` is computed. A caller that ignores the returned error (or reuses the same
`Certificate` value for a subsequent parse that fails partway) can observe a partially populated
certificate — e.g. ESVersion set but timestamps/serial unset, or stale PQ fields left over from a
previous unmarshal — and treat it as valid. Validate the entire buffer first and only populate the
struct on success (or clear it on error) to keep the failed parse result unusable.



─── internal/dnscryptcrypto/certificate.go:196-199 ───
[maintainability · low] Length validation is one-sided: `UnmarshalBinary`/`unmarshalPQ` accept any
buffer at least as long as the canonical size (`>= CertByteLength`/`>= PQCertByteLength`) and
silently ignore trailing bytes, even though the DNSCrypt v2 wire format is fixed-size (124/1320).
For PQ certs this also means `PQCertContext(b)` is derived from the raw input buffer rather than the
canonical 1320-byte prefix, so the accepted certificate length is inconsistent with the exact bytes
used for the HKDF binding. Recommend strict equality checks (`len(b) == CertByteLength` / `==
PQCertByteLength`) or slicing to the canonical length before computing the context, so
oversized/malformed records are rejected deterministically.



─── internal/dns64/dns64.go:49-53 ───
[bug · high] RFC 6052 §2.2 places the embedded IPv4 at a prefix-length-dependent offset, not always
byte 12: /32→byte 4, /40→byte 5, /48→byte 6, /56→byte 7, /64→byte 9 (with the u octet at byte 8
zeroed), /96→byte 12. `New` explicitly accepts /32,/40,/48,/56,/64, but `MapAddr` always copies the
IPv4 into bytes 12-15. For any non-/96 configured prefix, the synthesized AAAA embeds the IPv4 in
the wrong 32-bit slot, so the result is not an RFC 6052 IPv4-converted address and cannot be decoded
by a compliant NAT64 gateway or another DNS64 server. The `TestMapAddr_CustomPrefix` round-trip test
passes only because `ExtractIPv4` uses the same wrong offset. Derive the offset from `s.pref.Bits()`
and force the u octet to zero instead of using a constant.

+ func (s *Synthesizer) v4Offset() int {
+ 	// RFC 6052 §2.2 IPv4 position depends on the prefix length.
+ 	switch s.pref.Bits() {
+ 	case 32:
+ 		return 4
+ 	case 40:
+ 		return 5
+ 	case 48:
+ 		return 6
+ 	case 56:
+ 		return 7
+ 	case 64:
+ 		return 9
+ 	default: // /96
+ 		return 12
+ 	}
+ }
+
  func (s *Synthesizer) MapAddr(ip4 netip.Addr) netip.Addr {
  	var ip6 [16]byte
- 	copy(ip6[:nat64Offset], s.bytes[:nat64Offset])
+ 	off := s.v4Offset()
+ 	copy(ip6[:off], s.bytes[:off])
  	ip4b := ip4.As4()
- 	copy(ip6[nat64Offset:], ip4b[:])
+ 	copy(ip6[off:], ip4b[:])
+ 	return netip.AddrFrom16(ip6)
+ }


─── internal/dns64/dns64.go:57-62 ───
[bug · medium] `IsSynthesized` is only `prefix.Contains`, which is correct for the /96 default
(every address in the /96 is a valid mapping) but not for the /32../64 prefixes the constructor
accepts. For those, arbitrary in-prefix addresses with non-zero u octet / suffix bits are
misidentified as synthesized, and `ExtractIPv4` then blindly reads bytes 12-15 — which for compliant
RFC 6052 addresses are not the IPv4 field (for /64 the IPv4 lives at bits 72-103 and bits 104-127
are a suffix; for /32../56 bits 96-127 are part of the suffix). The result is a bogus IPv4 for
addresses the server never synthesized, and mis-decoding of RFC-compliant ones. Validation should
follow RFC 6052 (u octet == 0, prefix-dependent IPv4 slot, zero suffix) in addition to prefix
containment.



─── internal/dns64/dns64.go:73-78 ───
[bug · medium] The final bool parameter (passed `qr.Validated` at the call site) is discarded, and
every non-A RR in `aAnswer` is passed through unchanged while the A RRs are replaced with
synthesized AAAA. The middleware forwards the client's DNSSEC flag on the A lookup, so a signed zone
can make `aAnswer` contain RRSIG(A) records; copying those into the answer next to the newly
synthesized AAAA emits an RRset whose signatures do not cover the AAAA records, which validating
resolvers will reject. RFC 6147 §5.5 also requires that synthesis MUST NOT be performed when the
client sets CD, and §5.1.6 says the A records forming the basis of synthesis are removed. Either
gate synthesis on the bool (return the original empty answer when it is false / DNSSEC-tainting) or
strip RRSIG and other non-A records from the synthesized answer RRset.



─── edns/padding.go:20-28 ───
[bug · high] `len(req.Pseudo) > 0` is not a valid EDNS-presence test. In this fork of miekg/dns,
`Msg.Pseudo` holds only the EDNS0 *options*; the OPT pseudo-record itself is represented by
`Msg.UDPSize`/`Msg.Security` (see `internal/dnscryptcrypto/dns.go`: the fork merges OPT fields into
the Msg header on Unpack and generates the OPT during Pack; `edns.go` likewise sets
`msg.UDPSize`/`msg.Security` and appends options to `Pseudo`). A client that sends an OPT record
with an empty option list — exactly the documented `dig +nopadding`/`+noalignment` opt-out case —
has `len(req.Pseudo) == 0` and is misclassified as a legacy no-EDNS client, so the response is
padded against the client's explicit opt-out. Detect EDNS presence via `req.UDPSize != 0`
(optionally also scanning `req.Extra` for `*dns.OPT` for compatibility), and only default to padding
when there is truly no OPT.

- if len(req.Pseudo) > 0 {
+ hasEDNS := req.UDPSize != 0
  		for _, o := range req.Pseudo {
  			if _, ok := o.(*dns.PADDING); ok {
  				return true
- 			}
  		}
- 		return false
  	}
- 	return true // No EDNS: legacy client, pad by default
+ // No EDNS: legacy client, pad by default. EDNS without a PADDING option is an explicit opt-out.
+ return !hasEDNS


─── edns/padding.go:43-44 ───
[bug · medium] When `targetSize == currentSize+paddingHeaderSize`, `paddingDataSize == 0` and the `>
0` guard skips appending the option — but an empty PADDING option (4-byte option code+length header,
zero-length padding) is exactly what is needed to land on the block boundary, so the message is left
4 bytes short of the intended alignment and the privacy goal is missed. The guard should be `>= 0`.
(Note `paddingDataSize` in 1..3 is also unrepresentable with a single option since an option costs
4+data bytes; computing the remainder as
`(blockSize-(currentSize+paddingHeaderSize)%blockSize)%blockSize` would handle all remainders, or
these cases should be padded to the following block explicitly.)

  paddingDataSize := targetSize - currentSize - paddingHeaderSize
- 	if paddingDataSize > 0 {
+ 	if paddingDataSize >= 0 {


─── edns/padding.go:40-41 ───
[bug · medium] The comment claims OPT pseudo-record packing is "infallible", but in this fork
`Msg.Pack()` can return errors and can even panic — the codebase wraps it in `packSafe`
(server/bridge.go) specifically to recover from panics, and every other call site checks the
returned error. Ignoring the result here means a failed pack leaves `msg.Data` nil or stale, so
`currentSize` (and therefore whether padding is added and its size) is computed from incorrect data
on a privacy-sensitive response path, and a panic would escape into the response middleware instead
of being handled like `packSafe` does. Check the error (or use a guarded pack) and skip padding /
return 0 when packing fails.

- _ = msg.Pack() // _ = error: OPT pseudo-record packing is infallible for static fields
+ if err := msg.Pack(); err != nil {
+ 		return 0
+ 	}
  	currentSize := len(msg.Data)


─── edns/ecs.go:230-233 ───
[bug · medium] `query.SourcePrefix` is an unchecked uint8 from the wire; if it exceeds
`len(query.Address)*8` (e.g. 255, or a short/zero-length address), the `for i := range fullBytes`
loop indexes `query.Address[i]`/`response.Address[i]` past the slice end and panics the resolver.
The current cache path happens to pre-validate the client ECS (`IsValid`) before calling this
function, but this exported function enforces no such invariant on either argument, and the
response-side ECS is parsed from upstream without validation — only the prefix-equality check keeps
the current call sites safe. Add an explicit bounds guard so a malformed option degrades to
'mismatch' instead of an index-out-of-range panic.

+ 	if int(query.SourcePrefix) > len(query.Address)*8 || int(response.SourcePrefix) > len(response.Address)*8 {
+ 		return false
+ 	}
  	fullBytes := int(query.SourcePrefix) / 8
  	if fullBytes > 0 {
  		for i := range fullBytes {
  			if query.Address[i] != response.Address[i] {


─── edns/ecs.go:142-144 ───
[maintainability · medium] IP detection failures are silently swallowed: detectVia/ipdetect return
nil on dial/HTTP/read/parse errors, parseECSConfig returns (nil, nil) for auto mode, and
RefreshDefaultECS treats that as a successful no-op, so a broken or unreachable AutoDetectURL leaves
the default ECS unset/stale indefinitely with no log. Surface detection failures (log the reason or
return an error from the refresh path) so outages are diagnosable.

  	if subnet == config.ECSModeAuto {
- 		return h.detectVia(forceIPv6, false), nil
+ 		ecs := h.detectVia(forceIPv6, false)
+ 		if ecs == nil {
+ 			return nil, errors.New("ECS auto-detection returned no address")
+ 		}
+ 		return ecs, nil
  	}


─── internal/dnscryptcrypto/dns.go:23-37 ───
[bug · medium] The `size < dns.MinMsgSize` floor contradicts the function's own contract when a
small UDP wire budget is passed. When `maxWireLen < dns.MinMsgSize + MinResponseOverhead(XWingPQ)`
(i.e. < 563), `size = maxWireLen - 51` is raised back up to 512, so a plaintext response up to 512
bytes is left untruncated even though its encrypted wire size (512 + 51 + control block) exceeds the
stated anti-amplification budget (§10.3). The caller in udp.go passes `ClientQueryLen` = the raw
query wire length, and valid queries can be as small as ~85 bytes (classical) or ~1160 bytes (PQ
initial), so this range is reachable; the budget guarantee currently only holds because crypto.go's
`encrypt()` independently re-enforces the budget — Normalize alone (as documented and as used in
tests with small budgets) does not. Move the `MinMsgSize` floor into the EDNS/TCP branch so the
wire-budget branch never raises the truncation threshold above the budget.

  var size int
  	if maxWireLen > 0 {
  		// UDP DNSCrypt: the wire budget is the binding constraint — the
  		// encrypted response MUST NOT exceed the query size (§10.3).  EDNS
  		// buffer is irrelevant because the DNS payload is encrypted.
  		// Use PQ overhead (51 bytes) as the safe upper bound; classical
  		// encrypt() will handle the precise 48-byte check internally.
  		size = maxWireLen - MinResponseOverhead(XWingPQ)
  	} else {
  		size = DNSSize(proto, req)
  		size -= EDNSSize
- 	}
  	if size < dns.MinMsgSize {
  		size = dns.MinMsgSize
+ 		}
  	}


─── internal/dnscryptcrypto/dns.go:106-106 ───
[bug · medium] Both DNSCrypt WritePrefixed and DNS-over-TCP framing narrow a length to uint16
without a bounds check; the nolint 'protocol-bounded' claim is not enforced because encrypted
payloads can exceed 65535 (framing overhead) and dns.Msg.Pack does not cap output at MaxMsgSize. A
wrapped length corrupts the frame. Validate the length and return an error before writing the
two-byte prefix.

- binary.BigEndian.PutUint16(l[:], uint16(len(b))) //nolint:gosec // G115: DNS message length bounded by MaxMsgSize
+ if len(b) > dns.MaxMsgSize {
+ 		return ErrQueryTooLarge
+ 	}
+ 	binary.BigEndian.PutUint16(l[:], uint16(len(b)))


─── internal/dnscryptcrypto/keys.go:21-23 ───
[maintainability · low] HexDecodeKey strips every ':' with strings.ReplaceAll without validating
separator placement, so malformed key strings (e.g. ':aabb...', 'aabb:ccdd' with misplaced colons,
or mixed separators) are silently normalized and accepted instead of being rejected. All current
callers pass admin-supplied config or parsed stamp data (not attacker-controlled network input) and
hex.DecodeString still rejects non-hex characters and odd lengths, so impact is low, but the
permissiveness can mask key typos that then fail only later at length/validation checks with
confusing errors. Consider validating that colons only separate complete byte pairs, or documenting
the lenient normalization explicitly.



─── internal/dnscryptcrypto/proto.go:91-91 ───
[maintainability · medium] ResolverMagic is the only exported magic constant declared as a mutable
[]byte; every sibling (CertMagic, PQResumeMagic, PQControlMagic) is a fixed array. It backs both
response construction (`append(response, ResolverMagic...)`) and response validation (`bytes.Equal`
in encrypted.go), so the backing array is process-wide shared state. Because the variable is
exported, any external caller that writes an index or copies into it (e.g. `ResolverMagic[0] = ...`)
silently changes the DNSCrypt response prefix used for every response built/validated, without any
compile-time or runtime signal. Convert it to `[ResolverMagicSize]byte` (and slice at use sites) so
callers cannot mutate it in place, or at minimum document a strict never-mutate contract.

- var ResolverMagic = []byte{0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38}
+ var ResolverMagic = [ResolverMagicSize]byte{0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38}


─── internal/dnscryptcrypto/proto.go:102-102 ───
[maintainability · low] The X-Wing es-version is encoded twice, independently: `XWingPQ = 0x0003`
(uint16, used for construction dispatch in encrypted.go) and `PQESVersion = [2]byte{0x00, 0x03}`
(used to write the profile-extension/ticket bytes in pq.go and compared byte-wise in
server/protocol/dnscrypt/crypto.go). A future edit to one constant without the other silently
desynchronizes the in-memory construction routing from the bytes emitted/validated on the wire.
Derive one from the other (e.g. `PQESVersion = [2]byte{byte(XWingPQ >> 8), byte(XWingPQ)}` or a
shared wire-encoding helper) so there is a single source of truth.



─── internal/dnscryptcrypto/proto.go:57-57 ───
[maintainability · low] EDNSSize (64), ResponseOverhead (48), and MinResponseOverhead (49/51)
describe overlapping response-framing overhead with inconsistent values: ResponseOverhead omits the
1-byte pad delimiter that MinResponseOverhead includes, and EDNSSize is yet another, larger
heuristic reserve. The current call sites (dns.go Normalize and server encrypt) happen to use them
conservatively, so there is no user-visible off-by-N today, but nothing cross-references the
constants or asserts consistency. Since these feed the UDP anti-amplification and truncation
budgets, mixing them in future edits can either admit an over-budget response or truncate a response
that fits. Add cross-referencing comments (and ideally a compile-time/unit assert such as `EDNSSize
>= MinResponseOverhead(XWingPQ)`) so the relationship is explicit.



─── internal/dnscryptcrypto/proto.go:143-149 ───
[maintainability · low] For any unrecognized CryptoConstruction, IsPQ() returns false and
MinResponseOverhead falls back to the classical 49-byte figure. Today this is only latent — the
server reaches this function with q.ESVersion drawn from matched certificates (validated to the two
known constructions) — but the exported function silently under-counts wire overhead by 2 bytes for
an unknown PQ construction. Since a conservative (over-)estimate is always safe for
anti-amplification budgeting while an under-estimate is not, defaulting to the larger PQ overhead
for unknown values (or returning an error) would make the function fail closed if a second PQ
construction is ever added.



─── internal/dnscryptcrypto/encrypted.go:339-341 ───
[bug · medium] The PQ query size cap is applied unconditionally, even when q.IsTCP is set.
MaxDNSUDPPacketSize (4096) is a UDP anti-fragmentation limit; TCP DNSCrypt queries may be up to
65535 bytes. The classical path in this same function imposes no such cap for TCP, so a large
initial/resumed PQ query sent over TCP (client sets IsTCP=useTCP in
server/upstream/dnscrypt/client.go) is incorrectly rejected with ErrQueryTooLarge. Guard the check
with !q.IsTCP.

- 		if err == nil && len(query) > MaxDNSUDPPacketSize {
+ 		if err == nil && !q.IsTCP && len(query) > MaxDNSUDPPacketSize {
  			err = ErrQueryTooLarge
  		}


─── internal/dnscryptcrypto/encrypted.go:541-543 ───
[bug · medium] ParsePQResumedHeader's minimum-length check
(PQResumeMagicLen+PQTicketLenSize+NonceSize/2+TagSize+MinDNSPacketSize) assumes a zero-length
ticket. ticketLen is attacker-controlled (up to 65535), and the only subsequent check is
idx+ticketLen+NonceSize/2 <= len(query). A query that meets the 55-byte minimum but claims a ticket
filling the rest of the packet passes parsing with an encrypted payload of
0..TagSize+MinDNSPacketSize-1 bytes. The caller (server/protocol/dnscrypt/crypto.go:280) then feeds
this short ciphertext straight into the AEAD open, bypassing the declared minimum-payload invariant
and surfacing generic "ciphertext too short" errors instead of ErrInvalidQuery/ErrPQInvalidTicket.
Enforce the payload minimum after parsing the ticket.

  	if idx+ticketLen+NonceSize/2 > len(query) {
  		return nil, nil, 0, ErrPQInvalidTicket
+ 	}
+ 	if len(query)-(idx+ticketLen+NonceSize/2) < TagSize+MinDNSPacketSize {
+ 		return nil, nil, 0, ErrInvalidQuery
  	}


─── internal/dnscryptcrypto/encrypted.go:413-413 ───
[bug · low] The initial PQ path always pads with PQPad(packet, PQMinPaddingInitial), ignoring
q.IsTCP, while the resumed path above honors IsTCP via PadTCP. Per §5.4.3 client queries over TCP
must use random 1–256 byte padding (PadTCP); the initial handshake over TCP therefore emits
UDP-style padding instead. Mirror the resumed path's IsTCP branch so the initial PQ query follows
the TCP padding rule.

- 	padded := PQPad(packet, PQMinPaddingInitial)
+ 	var padded []byte
+ 	if q.IsTCP {
+ 		padded, err = PadTCP(packet)
+ 		if err != nil {
+ 			return nil, Nonce{}, err
+ 		}
+ 	} else {
+ 		padded = PQPad(packet, PQMinPaddingInitial)
+ 	}


─── internal/dnscryptcrypto/encrypted.go:303-309 ───
[bug · low] When a PQ response carries a zero-length control prefix (controlLen == 0), the 2-byte
prefix is stripped but r.PQControl is not cleared. A reused EncryptedResponse therefore retains and
re-reports a stale ticket from a previous response (client-side callers inspect r.PQControl after
Decrypt in server/upstream/dnscrypt/client.go:165). Current call sites allocate a fresh struct per
response, but the public API allows reuse and the stale value is silently wrong; reset PQControl on
the zero-length branch.

  			if controlLen == 0 || hasMagic {
  				if controlLen > 0 {
  					r.PQControl = make([]byte, controlLen)
  					copy(r.PQControl, packet[2:2+controlLen])
+ 				} else {
+ 					r.PQControl = nil
  				}
  				packet = packet[2+controlLen:]
  			}


─── internal/dnscryptcrypto/encrypted.go:454-457 ───
[bug · low] The classical decrypt path trusts any pre-set q.SharedKey. q.SharedKey is populated
during PQ decryption (DecryptPQInitial and the resumed-PQ server path), so reusing one
EncryptedQuery across requests — e.g. a pooled server object that previously handled a PQ query —
would decrypt a subsequent classical query with the stale PQ-derived key instead of re-deriving from
ClientPk, yielding decryption failures or, worse, authenticating under the wrong key. Since the
classical key is always derivable from ClientPk + serverSecretKey and no current caller pre-sets
SharedKey for the classical path, derive it unconditionally here.

  	var sharedKey [SharedKeySize]byte
- 	if q.SharedKey != [SharedKeySize]byte{} {
- 		sharedKey = q.SharedKey
- 	} else {
+ 	sharedKey, err = ComputeSharedKey(q.ESVersion, &serverSecretKey, &q.ClientPk)
+ 	if err != nil {
+ 		return nil, fmt.Errorf("computing shared key: %w", err)
+ 	}


─── internal/dnscryptcrypto/encryption.go:117-118 ───
[bug · medium] The clamp to MaxDNSUDPPacketSize is applied to minWire *before* Pad() runs, but Pad()
re-rounds len(packet)+1 up to the next 64-byte boundary, so the final padded plaintext (and
therefore the sealed UDP query) is not actually bounded by the cap. Concrete example with
QueryOverhead=68, MaxDNSUDPPacketSize=4096 and len(packet)=4000: minWire = min(roundup64(4069),
4096) = 4096, so Pad is asked for minLen=4028, but Pad returns max(4028, roundup64(4001)=4032) =
4032; the sealed query is 68+4032 = 4100 > MaxDNSUDPPacketSize. Note the classical Encrypt() path in
encrypted.go does not run the `len(query) > MaxDNSUDPPacketSize` check that the PQ path has (line
339), so these oversized UDP queries are sent unguarded and can cause IP fragmentation or rejection
by resolvers expecting ≤ 4096. Bound the padded output (e.g. min(...,
MaxDNSUDPPacketSize-QueryOverhead)) and/or return an error when the plaintext cannot fit within the
cap.

  	minWire = min((minWire+63)&^63, MaxDNSUDPPacketSize)
- 	return Pad(packet, minWire-QueryOverhead)
+ 	paddedLen := min(max(minWire-QueryOverhead, (len(packet)+1+63)&^63), MaxDNSUDPPacketSize-QueryOverhead)
+ 	return Pad(packet, paddedLen)


─── internal/dnscryptcrypto/encryption.go:105-106 ───
[maintainability · low] The doc-comment formula does not match the implementation. The code computes
minWire = roundup64(max(minWireSize, QueryOverhead+len+1)) and passes minWire-QueryOverhead to Pad,
while the comment describes targetWire = min(4096, roundup64(max(minQuestionSize, QueryOverhead) +
1)). Because QueryOverhead=68 is not 64-aligned, the placement of the +1 and the redundant `max(...,
QueryOverhead)` change the result: e.g. minWireSize=256, len(packet)=20 gives a 256-byte wire per
the code, but 320 per the comment formula. Align the comment with the actual sizing logic (or fix
the logic if the comment reflects the intended dnscrypt-proxy semantics).



─── internal/dnscryptcrypto/encryption.go:61-62 ───
[bug · low] PadResponse and PadResponseWithin dereference the sharedKey *[SharedKeySize]byte without
a nil check, so a nil pointer panics instead of returning an error (unlike ComputeSharedKey). Add a
nil guard (or explicitly document nil as forbidden) in both exported functions.



─── internal/dnscryptcrypto/string.go:37-40 ───
[bug · medium] UnpackTxtString silently accepts malformed \DDD escapes: out-of-range values such as
\999 wrap in uint8 arithmetic, and truncated escapes (trailing backslash, \1/\12 at end) are dropped
or emitted literally with no error. Since this parses untrusted TXT certificate data, corrupted
bytes flow into Certificate.UnmarshalBinary with no signal. Reject out-of-range and unterminated
escapes, or return an error from UnpackTxtString.

- // dddToByte converts three ASCII decimal digits into a byte value.
  func dddToByte(s []byte) (res byte) {
- 	return (s[0]-'0')*100 + (s[1]-'0')*10 + (s[2] - '0')
+ 	n := int(s[0]-'0')*100 + int(s[1]-'0')*10 + int(s[2]-'0')
+ 	if n > 255 {
+ 		return 0 // or return (byte, error) and reject the escape
+ 	}
+ 	return byte(n)
  }


─── internal/dnscryptcrypto/string.go:45-47 ───
[bug · low] unescapeChar applies C-style escaping (\t→TAB, \r→CR, \n→LF), but DNS TXT/master-file
escaping (RFC 1035 §5.1, the convention for DNSCrypt cert TXT records) defines \X as the literal
character X — there is no \t→TAB mapping. A spec-conformant producer that quotes a literal 't' as \t
would be decoded to 0x09 here, silently corrupting cert bytes. Notably, this repo's own server only
emits backslash-doubling (escapeBackslash in server/protocol/dnscrypt/server.go), so these three
cases have no well-defined producer in either convention. Unless the producer convention is known to
be C-style, drop these cases and pass the character through as-is.



─── internal/dnsutil/clientip.go:12-13 ───
[bug · medium] Both nil-guard helpers test only for a nil interface, so typed nil pointers stored in
an interface (e.g. (*net.TCPAddr)(nil) as net.Addr, or a nil *os.File as io.Closer) pass the guard
and panic when dereferenced/closed. Add explicit typed-nil checks inside each case or document that
callers must not pass typed nils.

  case *net.TCPAddr:
+ 		if a == nil {
+ 			return nil
+ 		}
+ 		return a.IP
+ 	case *net.UDPAddr:
+ 		if a == nil {
+ 			return nil
+ 		}
  		return a.IP


─── internal/dnsutil/clientip.go:16-21 ───
[bug · medium] The fallback depends on `net.SplitHostPort`, which requires a `host:port` form.
Standard `net.Addr` types whose `String()` is IP-only — notably `*net.IPAddr` — fail `SplitHostPort`
and return nil even though an IP is available, violating the documented "handling ... other address
types" behavior. Handle `*net.IPAddr` explicitly (or try `net.ParseIP(addr.String())` before
`SplitHostPort`).

+ case *net.IPAddr:
+ 		return a.IP
  default:
  		host, _, err := net.SplitHostPort(addr.String())
  		if err != nil {
  			return nil
  		}
  		return net.ParseIP(host)


─── internal/dnsutil/bind.go:32-37 ───
[bug · medium] The same IP can legitimately appear on more than one interface (e.g. an IPv6 address
assigned to eth0 and docker0/veth, or a shared IP on multiple NICs). Each probe binds and closes
successfully on its own, so the same host:port is appended to `addrs` multiple times. A later listen
loop that binds each returned address one-by-one will hit EADDRINUSE on the second duplicate and may
fail startup. Deduplicate by the host (or by the full addr) before probing/appending.

- 			addr := net.JoinHostPort(ipNet.IP.String(), port)
+ 			key := ipNet.IP.String()
+ 			if seen[key] {
+ 				continue
+ 			}
+ 			seen[key] = true
+ 			addr := net.JoinHostPort(key, port)
  			if err := TryBind(network, addr); err != nil {
  				skipped = append(skipped, addr)
  				continue
  			}
  			addrs = append(addrs, addr)


─── internal/dnsutil/bind.go:23-26 ───
[bug · medium] A failed `iface.Addrs()` enumeration is silently dropped, so the returned bind list
can be incomplete while the function still reports success. This is inconsistent with the explicit
`skipped` logging for failed bind probes just below. Log the interface enumeration error (or
propagate it) so a partially available host is not silently misconfigured at startup.

  		ips, err := iface.Addrs()
  		if err != nil {
+ 			log.Warnf("SERVER: skipping interface %s: %v", iface.Name, err)
  			continue
  		}


─── internal/dnsutil/bind.go:14-14 ───
[bug · medium] When `port == "0"`, each `TryBind` probe binds and immediately releases a different
ephemeral port, but the returned entries all become `ip:0` strings. Any later listener created from
those entries will bind a new random port each time, so the returned list does not represent a
stable set of addresses to actually listen on. Either reject a zero/empty port up front or
explicitly document that only a fixed non-zero port is supported.

  func ResolveBindAddrs(network, port string) ([]string, error) {
+ 	if port == "0" || port == "" {
+ 		return nil, fmt.Errorf("ResolveBindAddrs requires a fixed port, got %q", port)
+ 	}


─── internal/dnsutil/bind.go:27-31 ───
[maintainability · low] The hard type assertion only accepts `*net.IPNet`. `net.Interface.Addrs()`
returns `[]net.Addr` whose concrete types are platform/implementation dependent and may be
`*net.IPAddr` (or other `net.Addr` implementations) on some systems. Such valid unicast addresses
are silently omitted, again producing an incomplete bind list. Consider a type switch that extracts
the IP from both `*net.IPNet` and `*net.IPAddr` (falling back to skipping anything else).

  		for _, ip := range ips {
- 			ipNet, ok := ip.(*net.IPNet)
- 			if !ok || ipNet.IP.IsLinkLocalUnicast() {
+ 			var ipStr string
+ 			switch v := ip.(type) {
+ 			case *net.IPNet:
+ 				ipStr = v.IP.String()
+ 			case *net.IPAddr:
+ 				ipStr = v.IP.String()
+ 			default:
+ 				continue
+ 			}
+ 			if net.ParseIP(ipStr).IsLinkLocalUnicast() {
  				continue
  			}


─── internal/dnsutil/download.go:70-75 ───
[bug · high] Partial/corrupt downloads are silently accepted on later calls. `DownloadFile` writes
directly to the final `path` with `os.WriteFile`. If a write fails partway (ENOSPC, crash, kill
during download), a truncated/partial file remains at `path`, and the next `ResolveDataFile` call
sees it via `os.Stat` and returns it without retrying — serving corrupt root trust material (trust
anchors / root hints) as valid. Writing through the final path also follows a symlink placed at that
location. Download to a temp file in the same directory and `os.Rename` into place atomically
(rename replaces a symlink rather than following it, and never exposes a partial file), and delete
the temp on any failure.

  	data, err := io.ReadAll(resp.Body)
  	if err != nil {
  		return err
  	}
- 	//nolint:gosec // callers pass paths from os.Executable() or config
- 	return os.WriteFile(path, data, 0o644)
+ 	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
+ 	if err != nil {
+ 		return err
+ 	}
+ 	defer func() { _ = os.Remove(tmp.Name()) }()
+ 	if _, err := tmp.Write(data); err != nil {
+ 		_ = tmp.Close()
+ 		return err
+ 	}
+ 	if err := tmp.Chmod(0o644); err != nil {
+ 		_ = tmp.Close()
+ 		return err
+ 	}
+ 	if err := tmp.Close(); err != nil {
+ 		return err
+ 	}
+ 	return os.Rename(tmp.Name(), path)


─── internal/dnsutil/download.go:50-56 ───
[security · medium] Insecure permissions on root data files are only logged as a warning, but the
file is then returned and used as trust material. The code itself documents that these files
"contain cryptographic trust material and must be protected from tampering" — a group/world-writable
file can be modified by any local user, and silently accepting it (log lines are easily missed) lets
a tampered trust anchor flow into DNSSEC validation. Fresh downloads are fine (0o644), but
pre-existing files created with lax perms (e.g. 0o666 from older versions) are the real risk. Either
refuse to use the file (return "") or correct the permissions (chmod) as part of resolution; a
warn-and-continue path is inconsistent with treating the file as trust material.

  	if info, err := os.Stat(path); err == nil {
  		if info.Mode().Perm()&otherWritePermMask != 0 {
- 			log.Warnf("CONFIG: root data file has insecure permissions (%04o). Consider 'chmod 644 %s'",
- 				info.Mode().Perm(), path)
+ 			log.Errorf("SECURITY: root data file has insecure permissions (%04o); refusing to load trust material",
+ 				info.Mode().Perm())
+ 			return ""
  		}
  	}
  	return path


─── internal/dnsutil/keepalive.go:18-18 ───
[maintainability · low] `defaultTCPKeepAlivePeriod` duplicates `config.DefaultTCPKeepAlivePeriod`
(30s) to avoid importing `config` for layering. This is a silent-drift risk: if the value in
`config` is ever changed, this wrapper will keep using the stale inline value with no compiler or
test signal, so DoT/DoH/TCP connections silently diverge from the configured keep-alive interval.
Prefer passing the period into the constructor (e.g., `NewTCPKeepAliveListener(l net.Listener,
period time.Duration)`), reading it from a shared constants package at the same layer, or adding a
test that asserts both constants stay equal.



─── internal/dnscryptcrypto/xsecretbox.go:89-93 ───
[maintainability · low] poly1305 tag generation relies on hash.Sum(tag[:0]) filling tag through an
append side effect, then discards the returned slice. This depends on Sum reusing the caller's
backing array; if the implementation changes, tag stays zero and every sealed/unsealed box breaks.
Capture the returned slice and copy it into the tag array instead.

- 	var tag [poly1305.TagSize]byte
  	hash := poly1305.New(&polyKey)
  	_, _ = hash.Write(ciphertext) // _ = error: poly1305 hash Write never fails
- 	hash.Sum(tag[:0])             // Sum is infallible for poly1305
- 	copy(tagOut, tag[:])
+ 	copy(tagOut, hash.Sum(tag[:0]))


─── internal/dnscryptcrypto/xsecretbox.go:65-67 ───
[maintainability · low] `chacha20.NewUnauthenticatedCipher` can only fail on an invalid key/nonce
length, and those sizes are validated above with error returns, so discarding the error is safe
today. However, the comment is stale — it references "panic checks" while this code returns errors
instead of panicking (and the trailing comment is accidentally duplicated) — and the guarantee is
enforced only inside this function body. Prefer propagating the error so a future change to the
constants or to the order of the checks cannot silently produce an unusable cipher (same pattern
applies in `XchachaOpen`).

- 	// key/nonce sizes already validated by panic checks above;
- 	// NewUnauthenticatedCipher cannot fail with valid parameters.
- 	cipher, _ := chacha20.NewUnauthenticatedCipher(key, nonce) // _ = error: key/nonce sizes validated above // _ = error: key/nonce sizes validated above
+ 	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
+ 	if err != nil {
+ 		return nil, err
+ 	}


─── internal/ipdetect/ipdetect.go:60-64 ───
[bug · medium] The HTTP response status is never checked before the body is parsed. Any non-2xx
response (captive portal page, proxy error page, 403/502 from a misconfigured AutoDetectURL, or the
landing page of a redirect) that happens to contain an `ip=...` line will be parsed and returned as
the machine's public address. Since this address is later used as the default EDNS Client Subnet in
outgoing queries (edns/ecs.go `detectVia`), a bogus address would be advertised upstream. Add a
status check and return nil for non-2xx responses.

  	resp, err := client.Get(traceURL)
  	if err != nil {
  		return nil
  	}
  	defer func() { _ = resp.Body.Close() }() // _ = error: body close after read, best-effort
+ 	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
+ 		return nil
+ 	}


─── internal/ipdetect/ipdetect.go:74-77 ───
[bug · medium] The parsed address is not validated as public/global before being returned, despite
the package contract of detecting "public IP addresses". If the configured endpoint is behind a
NAT/proxy or misbehaves, `ip=192.168.x.x`, `ip=127.x.x.x`, `ip=169.254.x.x`, etc. would be returned
and then advertised to upstream DNS servers as the default ECS address. Reject non-public addresses
(private, loopback, link-local, unspecified, multicast).

  	ip := net.ParseIP(matches[1])
- 	if ip == nil {
+ 	if ip == nil || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
+ 		ip.IsUnspecified() || ip.IsMulticast() {
  		return nil
  	}


─── internal/latency/httppool.go:80-82 ───
[bug · medium] Close paths in the latency prober/http pool tear down pooled http3.Transports without
waiting for or cancelling in-flight probes: Prober.Close can run while ProbeIPsLatency is executing,
and HTTPPool.Close destroys QUIC connections mid-request, so shutdown fails valid in-flight probes.
Track in-flight work (refcount/WaitGroup) and drain/cancel before closing transports.



─── internal/latency/httppool.go:51-53 ───
[performance · low] Pooled clients are created without http.Client.Timeout and the dialer has no
timeout, so the only bound on a request is the context passed to client.Do. Today this is safe
because every reachable call path (measureIPLatency in probes.go) wraps each step in
context.WithTimeout(stepTimeout), but the pool itself provides no safety net: a future call site
passing an unbounded ctx, or a misconfigured large step.Timeout, would let a stalled endpoint block
a worker goroutine and a semaphore slot indefinitely. Consider setting a defensive Timeout on the
client (and/or net.Dialer.Timeout) as defense in depth.



─── internal/latency/httppool.go:38-40 ───
[maintainability · low] After Close() sets p.clients = nil, get() returns a nil *http.Client with no
error — this contract is implicit and undocumented on the pool type. The only current caller
(probeHTTP) does check for nil and returns errHTTPPoolClosed, so there is no live bug, but any
future caller that forgets the nil check will panic obscurely. Returning (nil, error) from get (or
documenting the nil-return invariant) would make the contract explicit and safe to rely on.



─── internal/ipttl/ipttl.go:32-33 ───
[bug · medium] IP TTL capture can silently yield TTL 0 on family-mismatched/dual-stack sockets:
selecting ipv4.PacketConn via LocalAddr().To4() treats IPv4-mapped IPv6 addresses as IPv4, so
IPV6_HOPLIMIT control messages are never delivered; ReadFrom returns (n, 0, nil) when cm==nil,
indistinguishable from a genuine TTL, and HopGuard rejects every packet as spoofed. Derive family
from the socket domain, and have ReadFrom return an explicit error (or documented sentinel) when no
control message was captured.



─── internal/dnsutil/tcpframe.go:34-36 ───
[maintainability · low] This guard is unreachable: the 2-byte length prefix decodes to at most
65535, which equals dns.MaxMsgSize, so `length > dns.MaxMsgSize` is always false and
errFrameTooLarge is dead code (misleading as a security guard). Moreover, if it were ever reachable
(e.g., if MaxMsgSize is lowered), returning here without consuming the frame body would leave the
connection stream desynced for callers that reuse the connection — the error contract should then
require closing the connection. Current callers happen to close on error, but the dead check should
either be removed or made meaningful with a documented close-required contract.



─── internal/latency/prober.go:76-82 ───
[performance · medium] A goroutine is created for every input IP, but the semaphore only limits the
number of *active* probes (DefaultMaxProbes = 16), not goroutine creation. All N goroutines are
spawned before any of them can block on the semaphore, so a large IP list (e.g. thousands of root/NS
addresses or a huge A/AAAA answer) simultaneously allocates N goroutine stacks (~8KB each → 80MB+ at
10k IPs). This is on a request/background path and is not bounded by configuration. Prefer a bounded
worker pool: spawn min(n, cap) workers that pull IP indices from a channel, or acquire the semaphore
in the spawning loop before starting the goroutine.



─── internal/dnscryptcrypto/pq.go:57-59 ───
[bug · medium] PQCertContext slices binCert at fixed offsets up to CertPQExtOff+CertPQExtLen (1320
bytes) with no length check — a truncated or malformed certificate panics with index-out-of-range.
Today's in-repo callers (unmarshalPQ, which checks len(b) < PQCertByteLength first, and generate.go
with a freshly marshaled cert) are safe, but this exported function accepts arbitrary []byte with no
documented contract, so any future caller passing shorter input crashes the process. Add an explicit
bounds guard at the top (return nil or refactor to return an error) to make the contract robust.

- 	ctx = append(ctx, binCert[CertESVersionOff:CertESVersionOff+2]...)           // es-version
- 	ctx = append(ctx, binCert[CertMinorOff:CertMinorOff+2]...)                   // protocol-minor-version
- 	ctx = append(ctx, binCert[CertPQPkOff:CertPQPkOff+CertPQPkLen]...)           // resolver-pk
+ func PQCertContext(binCert []byte) []byte {
+ 	if len(binCert) < CertPQExtOff+CertPQExtLen {
+ 		return nil
+ 	}
+ 	ctx := make([]byte, 0, 14+


─── internal/dnscryptcrypto/pq.go:118-120 ───
[bug · high] PQDecapsulate forwards ct/sk to xwing.Decapsulate with no length validation and no
error return. circl's Decapsulate slices ct into the ML-KEM (1088) and X25519 (32) halves and
indexes sk at fixed offsets, so a wrong-length input either panics (index-out-of-range) or silently
yields a deterministic garbage KEM secret that PQDeriveSharedKey converts into a "usable" key with
no error. Two concrete risks: (1) the codebase treats the X-Wing private key as a 32-byte seed
(certificate.go comment; crypto.go copies only KeySize bytes into resolverSk before calling this),
while xwing.DeriveKeyPairPacked returns the packed X-Wing secret key (dk_mlkem || sk_x25519, larger
than 32 bytes) — if circl's Decapsulate requires the packed key, the truncated copy panics on every
PQ initial query; (2) a future caller passing a non-PQCiphertextSize ct will crash instead of
failing gracefully. Validate ct and sk lengths (against PQCiphertextSize and xwing.SecretKeySize)
and return an error on mismatch.

- func PQDecapsulate(ct, sk []byte) (kemSS []byte) {
- 	return xwing.Decapsulate(ct, sk)
+ func PQDecapsulate(ct, sk []byte) (kemSS []byte, err error) {
+ 	if len(ct) != PQCiphertextSize {
+ 		return nil, ErrPQInvalidTicket
+ 	}
+ 	return xwing.Decapsulate(ct, sk), nil
  }


─── internal/dnscryptcrypto/pq.go:269-274 ───
[maintainability · medium] DecodeTicketPlaintext silently discards the <es-version> and
<profile-extension-hash> fields that EncodeTicketPlaintext writes, so callers cannot verify a
ticket's profile/version binding from the returned values alone. The only current caller
(server/protocol/dnscrypt/crypto.go:254-257) works around this by re-indexing the raw ticketPlain at
TicketPlaintextESOff/PEHashOff, duplicating offset knowledge — a fragile pattern: if that caller is
refactored to rely only on the returned fields, tickets minted under a different PQ profile/version
would be silently accepted after a server change. Return esVersion and peHash (e.g., alongside
clientMagic/resumeSecret/expiry) and document that the decode is complete, so the binding is
enforced by the API itself.

- func DecodeTicketPlaintext(plaintext []byte) (clientMagic [ClientMagicSize]byte, resumeSecret [SharedKeySize]byte, ticketExpiry uint32, err error) {
+ func DecodeTicketPlaintext(plaintext []byte) (esVersion [2]byte, clientMagic [ClientMagicSize]byte, resumeSecret [SharedKeySize]byte, peHash [32]byte, ticketExpiry uint32, err error) {
  	if len(plaintext) < TicketPlaintextSize {
- 		return [ClientMagicSize]byte{}, [SharedKeySize]byte{}, 0, ErrPQInvalidTicket
+ 		return [2]byte{}, [ClientMagicSize]byte{}, [SharedKeySize]byte{}, [32]byte{}, 0, ErrPQInvalidTicket
  	}
  	copy(resumeSecret[:], plaintext[TicketPlaintextSecretOff:TicketPlaintextSecretOff+TicketPlaintextSecretLen])
+ 	copy(esVersion[:], plaintext[TicketPlaintextESOff:TicketPlaintextESOff+TicketPlaintextESLen])
  	copy(clientMagic[:], plaintext[TicketPlaintextMagicOff:TicketPlaintextMagicOff+TicketPlaintextMagicLen])
+ 	copy(peHash[:], plaintext[TicketPlaintextPEHashOff:TicketPlaintextPEHashOff+TicketPlaintextPEHashLen])


─── internal/dnscryptcrypto/pq.go:242-245 ───
[maintainability · low] PQClientMagic is dead code — no production path calls it (only
crypto_test.go references it) — and its SHA-256(pk)[:8] derivation contradicts the derivation
actually used by the protocol: the PQ client magic is the 8 bytes embedded in the cert at
CertPQMagicOff, which generate.go sets from pk[72:80] ("matching the official encrypted-dns-server
derivation"). Two functions claiming to match the same reference cannot both be right. If this
function is ever wired into query building or ticket sealing by mistake, the resulting client magic
will never match the server's certificate and all PQ queries will fail. Either remove it or align it
with the cert-path derivation so the codebase has a single source of truth.



─── internal/dnsutil/https_dns.go:47-48 ───
[bug · low] Building the DoH URL by concatenating `u.Scheme/u.Host/u.Path` by hand bypasses
`url.URL.String()` normalization: any existing `RawQuery` on the configured endpoint and any
userinfo in the URL are silently dropped, and a path requiring percent-encoding is emitted raw
(which `http.NewRequestWithContext` will re-parse and may reject or send incorrectly). Prefer
cloning the parsed URL, setting `RawQuery`, and calling `String()` so escaping and normalization are
handled by the stdlib.

- urlBuf.WriteString(u.Path)
- 	urlBuf.WriteString("?dns=")
+ reqURL := *u
+ 	reqURL.RawQuery = "dns=" + base64.RawURLEncoding.EncodeToString(buf)
+
+ 	httpReq, err := http.NewRequestWithContext(ctx, httpMethod, reqURL.String(), http.NoBody)


─── internal/dnsutil/https_dns.go:114-116 ───
[security · medium] `dns.OpcodeToString` contains QUERY, IQUERY, STATUS, NOTIFY and UPDATE, so this
accept function admits all five opcodes at the DoH endpoint (wired globally at
`server/server.go:396`). A recursive-resolver DoH server only implements standard queries; accepting
UPDATE (dynamic update), NOTIFY, or the obsolete IQUERY/STATUS widens the reachable input surface
beyond RFC 8484 query semantics and can pass messages with non-query section layouts to the query
handler. Restrict to the QUERY opcode (NOTIFY only if the server actually handles zone
notifications).

- if _, ok := dns.OpcodeToString[m.Opcode]; !ok {
+ if m.Opcode != dns.OpcodeQuery {
  		return dns.MsgRejectNotImplemented
  	}


─── internal/dnsutil/dnsutil.go:112-120 ───
[security · medium] `filepath.Clean` is applied before `filepath.EvalSymlinks`, so a `..` component
is collapsed lexically instead of relative to a symlink's target. For a path like
`/tmp/link/../etc/passwd` where `/tmp/link` is a symlink to `/etc`, Clean turns it into
`/tmp/etc/passwd` and the check validates a different path than the one the OS opens (which resolves
to `/etc/passwd`). If an attacker can create the decoy regular file `/tmp/etc/passwd`, the
dangerous-prefix protection is bypassed even though `EvalSymlinks` then succeeds. Resolve symlinks
on the raw path first, then clean/abs the resolved result.

- 	abs, err := filepath.Abs(filepath.Clean(path))
+ 	// Resolve symlinks on the RAW path before any lexical cleanup.  Cleaning
+ 	// first collapses ".." textually, which resolves it relative to the literal
+ 	// path rather than the symlink target (e.g. /tmp/link/../etc/passwd with
+ 	// /tmp/link -> /etc), so the validated path can differ from the one a
+ 	// caller actually opens.
+ 	resolved, err := filepath.EvalSymlinks(path)
  	if err != nil {
  		return false
  	}
- 	// Resolve symlinks before the prefix check to prevent symlink-based
- 	// traversal attacks (e.g. /tmp/link -> /etc/passwd).
- 	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
- 		abs = resolved
+ 	abs, err := filepath.Abs(filepath.Clean(resolved))
+ 	if err != nil {
+ 		return false
  	}


─── internal/dnsutil/dnsutil.go:159-162 ───
[bug · low] `ExtractIPString` returns `(r.A.String(), true)` without checking `Addr.IsValid()`,
unlike `ExtractIP` which guards with `IsValid()`. A zero/empty address on a programmatically built
A/AAAA record yields `("invalid IP", true)` — an invalid address reported as a valid one, which then
flows into cache keys / probe lookups. Add the same validity guard for consistency and correctness.

  	case *dns.A:
+ 		if r.Addr.IsValid() {
  		return r.A.String(), true
+ 		}
  	case *dns.AAAA:
+ 		if r.Addr.IsValid() {
  		return r.AAAA.String(), true
+ 		}


─── internal/pending/pending.go:56-63 ───
[bug · medium] The dedup group can permanently degrade: Start returns true without tracking when the
map is full, and Done is the only way entries leave, so any leaked key (e.g. the cache_lookup
fresh-hit prefetch skips Done when TryGo fails) fills the map irreversibly and every subsequent
identical query is no longer deduplicated. Add eviction/TTL or a re-check, and/or expose a metric so
the leak surface is observable; callers must reliably register cleanup.



─── internal/pending/pending.go:49-51 ───
[maintainability · low] The zero value is documented as unusable, but nothing enforces or checks it:
Start on a zero-value Group panics with the obscure runtime error "assignment to entry in nil map",
while Done silently tolerates a nil map (delete on nil is a no-op). This inconsistency makes misuse
(forgetting NewGroup) fail confusingly and only on the write path. Add a nil guard in Start with a
clear panic message, or lazily initialize the map, so the contract is enforced consistently.



─── internal/lrumap/lru.go:82-85 ───
[bug · high] LRU callbacks can wedge the map: Set does not defer Unlock, so a panic in OnEvict
leaves the mutex locked forever, and Range invokes the user callback while holding m.mu, so a
re-entrant Get/Set deadlocks and a slow callback stalls all operations. Defer the unlock, and either
snapshot entries/invoke callbacks outside the critical section or explicitly document that callbacks
must not re-enter or block.

+ func (m *Map[K, V]) Set(key K, val V) {
+ 	m.mu.Lock()
+ 	defer m.mu.Unlock()
+ 	if e, ok := m.m[key]; ok {
+ 		e.val = val
+ 		m.moveToFront(e)
+ 		return
+ 	}
  	if m.len >= m.cap {
  		m.evictLocked()
  	}
  	e := &lruEntry[K, V]{key: key, val: val}
+ 	m.m[key] = e
+ 	m.pushFront(e)
+ 	m.len++
+ }


─── internal/lrumap/lru.go:33-36 ───
[bug · medium] OnEvict is an exported field that is read under m.mu (in evictLocked and Clear) but
is assigned without synchronization. If the map is shared with other goroutines and the field is set
after that, concurrent assignment races with eviction reads and can produce a torn/nil function
value (nil dereference when eviction fires). Prefer configuring the callback through a constructor
option or a SetOnEvict method that assigns under the mutex; otherwise document that OnEvict must be
set before the map is shared.



─── internal/lrumap/dtls_session.go:24-24 ───
[maintainability · low] The cache stores `dtls.Session` (containing the resumption master secret) by
value, but the `ID`/`Secret` slices share backing arrays with the caller's buffers and with any
concurrent `Get` result. If pion/dtls (or a future caller of this exported store) ever mutates or
reuses those slices after `Set`/`Get`, it silently corrupts the cached session and races with
concurrent handshakes. Note this also blocks the natural fix for eviction hygiene: an `OnEvict` that
zeroes `Secret` would zero the aliased backing array still referenced by the original handshake
state or an in-flight `Get` result. Recommend deep-copying `ID`/`Secret` in `Set` (and optionally
returning a copy from `Get`) so the cache owns its session data.



─── internal/lrumap/dtls_session.go:17-17 ───
[security · medium] No `OnEvict` is configured, so when the LRU map evicts an entry the DTLS
resumption secret (`dtls.Session.Secret`, the master secret) remains in heap memory until the next
GC cycle, extending the window for memory-dump disclosure of key material. Consider setting
`OnEvict` on the underlying map to explicitly zero the session's `Secret`/`ID` buffers. This is only
safe once `Set` deep-copies the session (see the aliasing note on `Set`); otherwise zeroing would
wipe the original buffers still referenced by the handshake.



─── internal/log/log.go:211-216 ───
[bug · high] Component filtering is applied to the raw format string instead of the rendered
message. `extractPrefix(format)` is evaluated before `fmt.Sprintf(format, args...)`, so any call
site that passes the component prefix as an argument — e.g. `server/server.go` (`log.Infof("%s: %s",
role, info)`) and `internal/dnsutil/dnsutil.go` (`log.Warnf("%s: Close %s failed: %v", prefix, name,
err)`) — yields a prefix of `%S` (uppercased `%s`), which never matches an entry in the filter map.
Those messages are therefore silently dropped whenever any component filter is enabled, even though
the rendered message may have a legitimate prefix or no prefix at all, which also violates the
documented "messages without a recognized prefix always pass through" contract. Consider applying
the prefix check to the sanitized, formatted message (formatting only when a filter is active, to
preserve the early-exit fast path for static prefixes), or treating placeholder-derived prefixes as
"no prefix" so dynamic-prefix call sites still pass through.

  if filter != nil {
- 		prefix := extractPrefix(format)
+ 		// Apply the filter to the rendered message so dynamic prefixes
+ 		// passed as format arguments (e.g. "%s: %s") are matched correctly.
+ 		message := sanitizeLogMessage(fmt.Sprintf(format, args...))
+ 		prefix := extractPrefix(message)
  		if prefix != "" && !filter[prefix] {
  			return
  		}
  	}


─── internal/log/log.go:295-303 ───
[bug · low] `ParseLevelFilter` returns a non-nil empty `[]string{}` for separator-only component
lists such as `"info:,"` or `"info: ,"` because `components` is allocated with `make([]string, 0,
len(raw))` before empty entries are filtered out. The doc contract states "nil components means no
filtering", so a non-nil empty slice contradicts it: a caller distinguishing `nil` from empty (e.g.
building its own allowlist from the returned slice) would treat this as "filter everything that has
a prefix", silently suppressing all prefixed messages. Normalize the result so `nil` is returned
when no non-empty components remain (e.g. return `nil, lvl` when the filtered slice is empty).

  raw := strings.Split(parts[1], ",")
  		components := make([]string, 0, len(raw))
  		for _, c := range raw {
  			c = strings.TrimSpace(c)
  			if c != "" {
  				components = append(components, c)
+ 			}
  			}
+ 		if len(components) == 0 {
+ 			return lvl, nil
  		}
  		return lvl, components


─── internal/latency/probes.go:268-268 ───
[bug · medium] The pooled client (httppool.go) sets no CheckRedirect, so `client.Do` follows up to
10 redirects by default. For a latency probe this is incorrect: if the probed IP answers with
301/302/307, (1) the measured RTT covers the entire redirect chain plus the final host instead of
the target IP, and (2) a HEAD request is subsequently sent to whatever host the Location header
points to — which can be an unrelated or internal address (e.g. 169.254.169.254), outside the
intended probe target. Consider configuring `CheckRedirect: http.ErrUseLastResponse` on the pooled
client so the first response ends the probe, and/or validating that the final response belongs to
the probed IP before counting it as success.



─── internal/latency/probes.go:262-262 ───
[bug · low] Overriding `req.Host` with the bare IP string produces a Host header without a port, and
for IPv6 it becomes an unbracketed literal (e.g. `2001:db8::1`), which is malformed per RFC 7230
§5.4 and also propagates to the HTTP/2/3 `:authority` pseudo-header. The request URL already
contains the correctly-formatted host (including brackets and port), so this override adds nothing
for IPv4 and can cause false probe failures for IPv6 AAAA targets on strict servers. Either drop the
override (Go derives Host from req.URL) or set it to the bracketed form
`net.JoinHostPort(ip.String(), strconv.Itoa(port))`.



─── internal/stamp/encode.go:196-201 ───
[bug · high] Bare IPv6 addresses are misparsed by the last-colon port heuristic in multiple stamp
paths: splitOptionalPort turns `::1` into host `:` port `1`, and the same defect is duplicated in
the plain-DNS and secure/DoH normalization code, truncating bare IPv6 literals and double-bracketing
already-bracketed ones via JoinHostPort. Detect IP literals (strip brackets and net.ParseIP) before
applying colon-split logic so IPv6 is normalized to [addr]:port consistently in encode/validate and
parse paths.

  func splitOptionalPort(s string) (host, port string) {
  	colIndex := strings.LastIndex(s, ":")
  	bracketIndex := strings.LastIndex(s, "]")
  	if colIndex < bracketIndex || colIndex < 0 {
+ 		return s, ""
+ 	}
+ 	// A bare IPv6 address has multiple colons and no brackets: do not treat
+ 	// the last colon as a host:port separator.
+ 	if bracketIndex < 0 && strings.Count(s, ":") > 1 {
  		return s, ""
  	}


─── internal/stamp/stamp.go:130-132 ───
[bug · high] Multiple out-of-bounds reads in the stamp parser: Parse's minimum-length guards do not
leave room for the provider-name/path length-byte reads, and parse.go dereferences bin[pos] after
the hash list or after the provider name when pos == binLen (e.g. a 12-byte ODoH target and a
43-byte DoH/DoT stamp). Parse is called on user-supplied stamps, so this is a reachable crash/DoS.
Revalidate pos < binLen before every length-byte read, including hashes, provider-name, and path
fields.



─── internal/stamp/stamp.go:121-123 ───
[bug · medium] Parse's minimum-length guards are too strict for DNSCrypt and relay stamps: DNSCrypt
payloads can validly be as short as 44 bytes (not 66), and a relay stamp is simply 0x81 || LP(addr)
with a 2-byte structural minimum, so short valid stamps are rejected with ErrTooShort. Lower the
guards to the format minima or rely on per-field validation.



─── server/protocol/plain/server.go:39-42 ───
[bug · medium] Several protocol servers (plain TCP/UDP, TLCP, TLS DoT/DoH/DoH3/DTLS) have
listener-lifecycle bugs: serve/accept goroutines block in Accept or ListenAndServe and do not
observe ctx cancellation, so a later startup failure that cancels ctx and returns an error leaves
already-created listeners/conns/transports open; ports remain bound, goroutines keep serving, and
g.Wait()/Shutdown can hang or never deliver the original error. Close/shutdown every resource
created so far on all startup error paths and wire ctx cancellation to an actual listener
close/Shutdown.



─── server/protocol/plain/server.go:47-47 ───
[bug · low] Protocol server slices (plain udpServers/tcpServers and the TLS listener/conn/transport
slices) are appended during Start without synchronization while Shutdown can run concurrently from
the signal handler, causing data races and missed cleanup of listeners created after Shutdown has
iterated. Guard the slices with a mutex or populate them synchronously before Shutdown can run, and
make Shutdown wait on the same errgroup.



─── server/protocol/dnscrypt/tcp.go:40-40 ───
[bug · high] Several protocol write paths do not set a write deadline before writing, so a client
that stops reading can block the response/handshake write forever, pinning goroutines, worker slots,
or connections and hanging shutdown: DNSCrypt TCP (WritePrefixed in both the response and handshake
paths), plain TCP (dns.Server WriteTimeout left at 0), TLCP DoT (WriteTCPMsg), and DoQ
(stream.Write). Set an explicit write deadline before each blocking write or a server-level
WriteTimeout.

+ 	_ = w.conn.SetWriteDeadline(time.Now().Add(defaultReadTimeout))
  	return dnscryptcrypto.WritePrefixed(res, w.conn)


─── server/protocol/dnscrypt/tcp.go:86-87 ───
[bug · low] DNSCrypt TCP/UDP handler registration can race with Shutdown: wg.Add/Go happens after
Accept inside a spawned goroutine with no happens-before edge against wg.Wait(), so a connection
accepted during shutdown can Add while Wait is in progress, risking early return or WaitGroup
misuse. Register goroutines before spawning them or synchronize Add with the shutdown path.

+ 		if !s.isStarted() {
+ 			_ = conn.Close()
+ 			s.mu.Lock()
+ 			delete(s.tcpConns, conn)
+ 			s.mu.Unlock()
+ 			continue
+ 		}
  		s.wg.Go(func() {
  			defer zdnsutil.HandlePanic("DNSCrypt TCP handler")


─── server/protocol/dnscrypt/generate.go:229-232 ───
[maintainability · medium] DNSCrypt resolver key generation is not persisted or round-tripped:
GenerateResolverConfig generates an X25519 pair but the written config only stores the Ed25519
signing keys, so reloads regenerate a fresh pair and certs/ClientMagic change every restart;
NewCert's fallback random pair is also never written back to rc, so NewCertPair can produce
classical and PQ certs derived from unrelated seeds. Persist the resolver seed (or write back the
regenerated pair) and derive both certs from the same seed.



─── server/protocol/tlcp/certs.go:105-108 ───
[bug · medium] Self-signed CA generation is ineffective in the TLS/TLCP cert generators: the freshly
generated CA is neither returned, included in the served chain, nor persisted, so clients cannot
validate the leaf; every restart generates a new CA/keypair and invalidates previously distributed
pins/trust anchors. Return/include the CA for persistence and chain distribution, or document that
clients must re-accept certs every boot and remove the dead generation.

  	signCert = tlcp.Certificate{
- 		Certificate: [][]byte{signDER},
+ 		Certificate: [][]byte{signDER, caDER},
  		PrivateKey:  signKey,
  	}


─── server/protocol/dnscrypt/crypto.go:126-126 ───
[bug · high] DNSCrypt ticket key state is racy:
s.ticketKey/s.ticketKeyID/prevTicketKey/prevTicketKeyID are written by rotateKeys under s.mu but
read on the PQ initial and resumed query paths without holding s.mu, causing torn key/ID pairs,
spurious PQOpenTicket failures, and data races. Snapshot the four arrays under s.mu.RLock() and pass
local copies to PQSealTicket/PQOpenTicket.



─── server/protocol/tlcp/tlcp.go:42-47 ───
[bug · medium] In TLCP startup, net.Listen failures for configured addresses are only logged and
skipped, and startDOTServer/startDOHServer return nil even if every address failed to bind, so
Server.Start reports success while serving nothing. Track the number of successfully bound listeners
and return an error when zero are bound; move success logs after binding.

+ 	bound := 0
  	for _, addr := range addrs {
  		rawListener, err := net.Listen("tcp", addr)
  		if err != nil {
  			log.Warnf("TLCP: skipping tcp address %s: %v", addr, err)
  			continue
  		}
+ 		bound++


─── server/protocol/tlcp/dtlcp.go:294-300 ───
[bug · high] DTLS/TLCP DTLCP deadline and temporary-error handling can hang or spin: read deadline
timeouts are classified as temporary by IsTemporaryError, so the connection loops retry forever
instead of closing idle peers; the TLCP DTLCP shared-socket deadline is not cleared after a handler
exits, so the accept loop can inherit an expired deadline and spin; and temporary accept errors are
retried with no backoff. Treat net.Error.Timeout() as connection teardown, clear/set deadlines
properly, and add backoff on temporary accept errors.



─── server/resolver/dnssec/crypto.go:128-131 ───
[bug · medium] DNSSEC validation incorrectly requires the SEP bit on DNSKEYs in both DS matching
(verifyDS) and SelfVerifyDNSKEY. RFC 4034/4035 do not require the key referenced by a DS or the key
signing the DNSKEY RRset to have SEP set, so valid key sets with non-SEP keys can be marked bogus.
Try all matching keys and prefer SEP only as a tie-break.



─── server/handler/pending.go:58-58 ───
[bug · high] Pending singleflight eviction can lose results and break ownership: evicting an
in-flight call closes its done channel without publishing a result, and Done() finds calls by key so
an evicted leader's Done() can complete a newer call with stale data, while the result write races
with the eviction close. Publish a synthesized error on eviction, verify ownership by pointer in
Done(), and synchronize result publication with the eviction path.



─── server/handler/middleware/edns.go:57-60 ───
[bug · medium] Malformed client COOKIE options are not rejected with FORMERR: ParseCookie returns
nil for both absent and malformed cookies, so truncated/invalid client cookies bypass RFC 7873
validation; buildBadCookieResponse also assumes the client cookie is exactly 8 octets without a
guard. Make ParseCookie distinguish malformed from absent, reject malformed cookies with FORMERR,
and add an explicit length guard in the bad-cookie helper.



─── server/protocol/plain/server.go:47-54 ───
[bug · medium] Shutdown methods hide failures: plain's Shutdown discards each dns.Server.Shutdown
error and logs success regardless, and TLCP's Shutdown only logs serverGroup.Wait() error and
returns nil, so callers cannot detect failed graceful shutdowns. Collect per-server errors and
return them from Shutdown.



─── internal/siphash/siphash.go:11-13 ───
[bug · medium] A nil key silently produces a valid-looking MAC computed with the all-zero key (0,0)
— identical to a legitimate zero key and publicly computable by anyone. For an authentication MAC, a
caller bug (e.g. a nil pointer propagated from configuration) becomes a silently forgeable
authentication result instead of a loud failure, and this behavior is undocumented. Since Sum64 has
no error return, panic on nil (matching Go's normal nil-pointer convention) or accept the key by
value/slice so nil cannot be passed. Today the only caller (edns/cookie.go rfc9018MAC) always passes
a non-nil local array, so this is a latent API-contract footgun rather than an active exploit.

  	if key == nil {
- 		return 0
+ 		panic("siphash: nil key")
  	}


─── internal/siphash/siphash.go:36-38 ───
[maintainability · low] Eight copies of the 17-line SipRound body are hand-duplicated in this file
(compression ×2, tail ×2, finalization ×4). They are currently all correct, and the random
cross-check tests guard against divergence — but a single future edit to any one copy (a rotation
constant or a dropped step) would silently corrupt every digest while remaining compile-clean. The
package doc justifies this as avoiding function-call overhead; a small `sipRound` helper with
pointer args is inlined by the compiler at -O levels and would eliminate the duplication hazard with
no hot-path cost.



─── ruleset/ruleset.go:69-71 ───
[bug · high] Domain rules are inserted under the fully-normalized rule value (`domainKey(value)`),
which keeps all labels (e.g. `www.example.com` → key `www.example.com`), but `Match` only ever looks
up `tldPlusOne(qname)` — exactly the last two labels (e.g. `www.example.com` → `example.com`). The
two key spaces do not agree, so any rule deeper than two labels is silently inserted and can never
match a query, even the exact same name (`www.example.com` won't match a query for
`www.example.com`). Existing tests only use two-label rules (`google.com`, `*.youtube.com`), so this
is uncovered. Fix: normalize rule keys with the same reduction used at lookup (e.g. apply
`tldPlusOne` in `insertRule`), or better, make `Match` walk the qname's label suffixes so
multi-label rules such as `www.example.com` and `example.co.uk` are honored as true suffix rules.

  	case "domain":
- 		key := domainKey(value)
+ 		key := tldPlusOne(value)
  		e.domainRules[key] = append(e.domainRules[key], tag)


─── ruleset/ruleset.go:117-119 ───
[bug · low] For a tag that exists in `e.tags` but has no CIDR rules, the non-negated call returns
`(false, true)` while the negated form `!tag` returns `(true, true)` — i.e. `!tag` matches every IP
address. This asymmetry is surprising for an API contract: both forms describe the same (empty) IP
set, so a direct caller of `!tag` would accept all addresses. Today this path is unreachable from
the production caller (`filterRecordsByCIDR` in server/resolver/forward.go pre-filters tags with
`HasIPTag`), but any future caller that invokes `MatchIP` with a raw `!tag` will silently match
everything. Consider returning `(false, true)` for a negated tag with no IP rules (or documenting
the complement-of-empty-set semantics explicitly).



─── internal/stamp/encode.go:140-141 ───
[bug · high] `appendBootstrapIPs` writes nothing when `bootstrapIPs` is empty, whereas
`appendHashes` explicitly appends the `0x00` VLP terminator for an empty list. Per the DNS stamp
spec the bootstrap-IPs VLP field is always present (an empty list is encoded as a single `0x00`
byte), so every secure stamp encoded with empty `BootstrapIPs` (the default) is missing its trailing
VLP field and will be rejected as truncated by conforming decoders (e.g. the reference
dnscrypt-proxy implementation, whose `readVLP` errors on end-of-data without a terminator). Add the
empty-list case to mirror `appendHashes`.

  func appendBootstrapIPs(bin []byte, bootstrapIPs []string) []byte {
+ 	if len(bootstrapIPs) == 0 {
+ 		return append(bin, 0x00)
+ 	}
  	last := len(bootstrapIPs) - 1


─── internal/stamp/encode.go:113-121 ───
[bug · high] `encodeAddrAndHostname` silently drops a non-default port when `hostname` is empty:
with `addr = "1.2.3.4:8443"` and an empty provider name, `addr` is reduced to `"1.2.3.4"` and port
8443 is lost, so the encoded stamp resolves to the protocol default port instead. Since
`stripDefaultPort` removes the default port from the hostname field anyway, move the port onto the
hostname whenever the hostname is empty rather than discarding it.

  	if host, port := splitOptionalPort(addr); port != "" {
  		addr = host
  		if hostname != "" {
  			if _, hostPort := splitOptionalPort(hostname); hostPort == "" {
  				hostname = hostname + ":" + port
  			}
+ 		} else {
+ 			hostname = addr + ":" + port
  		}
  	}
  	return addr, stripDefaultPort(hostname, defaultPort)


─── internal/stamp/encode.go:162-164 ───
[bug · medium] `validateAddrAndHostname` discards the port portion of `addr` (`ip, _ :=
splitOptionalPort(addr)`), so an out-of-range port such as `1.2.3.4:99999` passes validation and can
then be carried into the encoded stamp or used downstream. Validate the extracted port with
`validatePort` when present.

  	if addr != "" {
  		// Strip optional port suffix before bracket/IP validation.
- 		ip, _ := splitOptionalPort(addr)
+ 		ip, port := splitOptionalPort(addr)
+ 		if port != "" {
+ 			if err := validatePort(port); err != nil {
+ 				return err
+ 			}
+ 		}


─── ruleset/iptrie.go:87-90 ───
[bug · medium] Family-scope leak: IPv6 rules whose CIDR is a prefix of ::ffff:0:0/96 (e.g. ::/0,
::/64 — any all-zero prefix up to bit 80) are stored at nodes on the exact path match() walks for
IPv4 addresses, because IPv4 is mapped into the ::ffff:0:0/96 subtree and match() collects tags from
every ancestor from bit 0 without checking the address family boundary. Concretely, insert(::/0,
"all") makes match("8.8.8.8") return "all". If rulesets are meant to be family-separated (an IPv6
catch-all should not tag IPv4 clients — the typical expectation for client-IP rulesets), this is a
correctness bug. Verify the intended semantics; if separation is required, only collect tags from
nodes at depth >= 96 for IPv4 addresses (or keep IPv4/IPv6 under distinct roots).



─── ruleset/iptrie.go:71-71 ───
[maintainability · low] match() can return duplicate tags: insert() appends the tag unconditionally,
so (a) the same tag inserted for multiple overlapping CIDRs appears once per matching ancestor, and
(b) an identical CIDR+tag pair inserted twice duplicates it in a single node.tags. The sole caller
today (Engine.Match) dedups into a map, so there is no user-visible consequence yet, but the "all
matching tags" contract is surprising and the returned slice can grow with overlap. Consider
skipping already-present tags in insert (slices.Contains) or deduping in match().



─── internal/pool/pool.go:34-39 ───
[maintainability · low] The generic allocator package `internal/pool` imports quic-go solely to
declare DoQ application error codes. Every consumer of these allocators (25+ files, including
cache/store.go, edns/edns.go, and plain UDP/TCP handlers that never use QUIC) now transitively
depends on quic-go — a heavy transport dependency — in exchange for two call sites
(server/protocol/tls and server/upstream/tls). Since these constants are protocol-specific rather
than pooling concerns, consider relocating them to a dedicated shared package (e.g., internal/doq)
and re-exporting only where needed, so the foundational pool package stays free of transport-layer
dependencies.



─── internal/pool/pool.go:112-115 ───
[bug · low] `NewBuffer` guards against a negative `poolSize` but not a negative `size`:
`make([]byte, size)` and the pre-fill loop will panic if `size < 0`. All current callers pass
positive constants, so this is not reachable today, but it is an exported constructor with an
unvalidated input that can turn a bad argument into a runtime panic (or, via a large value, an
oversized allocation). Mirror the poolSize guard (clamp to 0) or document that size must be positive
and panic explicitly.

  func NewBuffer(size, poolSize int) *Buffer {
+ 	if size < 0 {
+ 		size = 0
+ 	}
  	if poolSize < 0 {
  		poolSize = 0
  	}


─── internal/stamp/stamp.go:220-223 ───
[bug · medium] When `Address` has no port, `net.SplitHostPort` fails and this fallback concatenates
the raw address into the URL, which (a) yields an invalid URL for IPv6 literals because they are not
bracketed (`https://2606:4700:4700::1111/dns-query`), (b) silently drops the documented
`ProviderName` host override — a stamp with `Address="1.1.1.1"` and
`ProviderName="cloudflare-dns.com"` produces `https://1.1.1.1/dns-query` instead of the provider
host, and (c) produces `https:///dns-query` for an empty address. Also note `host:` (empty port)
passes `SplitHostPort` and becomes `https://host:/dns-query` via `JoinHostPort`. Build the host from
`ProviderName` (falling back to the address host), bracket IPv6 literals, and default to port 443.



─── internal/stamp/stamp.go:92-94 ───
[documentation · low] This comment block documents `parsePlainDNS` (which lives in parse.go) but is
attached to the exported `Parse` function, so `Parse` has no meaningful doc comment. It is also
factually wrong about the format: per RFC the plain payload is `0x00 ‖ props(8) ‖ LP(addr)` — the
8-byte props field is omitted here. Replace it with a doc comment describing `Parse`.



─── internal/stamp/stamp.go:190-192 ───
[documentation · low] The doc comment contradicts the implementation: it claims relays and the ODoH
target map to "" because they have no direct config mapping, but the code returns "dnscrypt-relay",
"odoh-relay", and "odoh" for those three cases. Update the comment to reflect the actual mapping.



─── server/handler/context.go:55-55 ───
[bug · medium] `Res` serves double duty as both the response payload and the short-circuit signal
(non-nil = stop the chain). This is fragile: any middleware that populates a partial response (e.g.,
sets EDNS/headers and expects a later middleware to fill in the answer) will silently terminate the
pipeline, because downstream middlewares treat any non-nil `Res` as "final response — skip". There
is no way to distinguish "complete response" from "partial response in progress". Recommend adding
an explicit completion flag (e.g., `Responded bool`) set only when the response is truly final, or
using a dedicated sentinel/error to signal short-circuit, so a partial response doesn't accidentally
truncate the chain.



─── server/handler/context.go:37-38 ───
[maintainability · medium] The bool+pointer pairs (`ZoneMatched`/`ZoneResult`,
`CacheHit`/`CacheEntry`, `Resolved`/`ResolutionResult`) rely on a documented-but-unenforced
invariant. Because these are plain public fields on a mutable struct, any middleware that sets the
bool without the pointer (or leaves the bool true after clearing the pointer) will cause nil
dereferences or stale state downstream with no compile-time or runtime protection. Consider
collapsing each pair into a single pointer field (nil = false), or adding accessor methods that
enforce the invariant and make inconsistency unrepresentable.



─── server/handler/context.go:60-61 ───
[maintainability · low] After a zone rewrite, post-zone middlewares must remember to read
`RewrittenName` (when set) instead of `Qname`; the struct provides no single "effective qname"
accessor, so a middleware that simply reads `Qname` after a rewrite will silently operate on the
original name (wrong cache keys, wrong logging, wrong answers). Suggest adding a helper such as
`func (c *QueryContext) EffectiveName() string` that returns `RewrittenName` when non-empty,
otherwise `Qname`, making the correct choice the default for all consumers.



─── server/handler/context.go:23-23 ───
[maintainability · low] `ClientIP` is documented as nil for unix-domain/internal queries, but the
nil contract is only enforced at consumption sites. Any consumer that indexes the slice (`ip[0]`) or
uses it in address math will panic; formatting helpers like `net.JoinHostPort`/`net.IP.String`
degrade to "<nil>"/garbage rather than failing loudly. Consider an accessor such as `func (c
*QueryContext) ClientAddr() net.IP` that returns a non-nil zero-length IP (or empty string) when the
original is nil, so callers cannot accidentally dereference it.



─── internal/ttl/ttl.go:24-28 ───
[bug · low] Boundary inconsistency with IsExpired: at the exact expiry instant (elapsed ==
ttlSeconds), IsExpired returns false (fresh) because it uses strict `>`, but here `remaining == 0`
falls through to the stale branch and returns staleTTL (30). A caller that classifies with IsExpired
and then computes the served TTL via RemainingTTL will emit a positive stale TTL for an entry it
just deemed fresh, and a record is never served with remaining TTL 0. The two tests
`TestIsExpired_AtBoundary` and `TestRemainingTTL_StaleStart` currently codify opposite sides of the
same boundary. Align the boundaries — e.g., treat `remaining >= 0` as fresh here so RemainingTTL
returns 0 (RFC-preferred) at exact expiry and only returns staleTTL when elapsed actually exceeds
the TTL.

  func RemainingTTL(timestamp int64, ttlSeconds int, staleTTL uint32) uint32 {
  	remaining := int64(ttlSeconds) - (NowUnix() - timestamp)
- 	if remaining > 0 {
+ 	if remaining >= 0 {
  		return uint32(remaining) //nolint:gosec // G115: DNS TTL — protocol-bounded uint32
  	}


─── internal/ttl/ttl.go:21-23 ───
[maintainability · low] Comment/behavior mismatch: the doc comment describes a cyclical countdown
that "decrements from staleTTL→1, then resets for the next window", but the implementation returns
the constant staleTTL (or 30) regardless of elapsed. The `StaleConstant*` tests in ttl_test.go
assert the constant behavior, so the comment is misleading and can mislead future maintainers (the
audit docs also treat the countdown as implemented). Either implement the documented per-window
decrement or update the comment to state that a constant stale TTL is served per RFC 8767 §4
RECOMMENDED.



─── internal/ttl/ttl.go:90-90 ───
[bug · medium] Cyclical wrap resets expired records to a full TTL: when elapsed is an exact multiple
of origTTL, the served TTL is origTTL - (elapsed % origTTL) = origTTL, so the TTL never reaches 0.
In the only production consumer (server/handler/middleware/zone.go, driven by
ttl.Elapsed(zoneResult.CreatedAt)), a zone result that has been alive longer than an RR's TTL is
re-served with the full original TTL, so downstream resolvers treat the record as freshly valid for
another full TTL and expired zone data can be retained indefinitely. For DNS TTL semantics the
elapsed TTL should decrease monotonically and clamp at 0 (or fall back to a small stale TTL as
RemainingTTL does). If the wrap is deliberate for static zone responses, that trade-off should be
documented. Also note the package comment claims all functions are zero-allocation, which is
violated here (result slice allocation plus per-RR Clone).



─── server/handler/middleware.go:64-66 ───
[maintainability · low] The drop contract depends on identity preservation: the central handler
decides silence vs. SERVFAIL via `errors.Is(err, ErrDrop)` (handler.go:146), and the doc comment
above promises that *any* non-ErrDrop error becomes SERVFAIL. Nothing in this contract tells wrapper
implementers that wrapping ErrDrop with `fmt.Errorf("...: %v", err)` (instead of `%w`) silently
converts a drop into SERVFAIL — a user-visible behavior change that the compiler cannot catch.
Current middlewares happen not to wrap errors, but the contract should state the invariant
explicitly, e.g. "middleware must preserve ErrDrop identity (wrap with %w, not %v) or the drop
silently becomes SERVFAIL".



─── server/handler/middleware.go:55-55 ───
[maintainability · low] This interface duplicates the concrete `edns.Handler.ApplyToMessage`
signature but with divergent parameter names (`isSecure` vs `isSecureConnection`, `wantsPadding` vs
`clientWantsPadding`, `tcpKeepalive` vs `tcpKeepaliveTimeout`), and the three booleans (`isSecure`,
`isRequest`, `wantsPadding`) are interleaved with other params, making positional misuse
compiler-invisible. The existing call sites pass the right order, but this is a latent trap:
recommend renaming the interface parameters to match the implementation exactly, and ideally
consolidating the booleans into an options struct so call sites read as named fields.



─── server/handler/middleware.go:39-39 ───
[documentation · low] The interface does not document the ownership/mutation contract for
`matchedTags`. Today it is safe: `zone.Evaluator` only reads the map (matchScore uses `_, exists :=
matchedTags[...]`) and the zone middleware allocates a fresh map per query. But a future
implementation or caller could write into the map or reuse one across queries, leaking tags between
evaluations with no compile-time signal. Add an explicit contract, e.g. "matchedTags is read-only
input; implementations must not write to it, and callers must not reuse the map across evaluations".



─── server/bridge.go:46-46 ───
[bug · medium] Sweeper vs. in-flight request race: `startTCPWriteMuSweep` (server/tasks.go) deletes
entries purely on `lastAccess` age (2 min cutoff, 5 min sweep). But `lastAccess` is only updated
when `handler.ServeDNS` returns a non-nil response (line 112). For a new connection (lastAccess ==
0) or a connection whose query is stuck in the handler > 2 min (slow upstream with sequential
retries), the sweeper can `Delete` the entry while G1 still holds it and is waiting to acquire
`entry.writeMu`. A subsequent pipelined query on the SAME connection then does `LoadOrStore` and
gets a brand-new entry with a separate `writeMu`/`capacity` channel. G1 (old entry) and G2 (new
entry) can then hold different write-mutexes and write concurrently to the same `net.Conn`,
interleaving length-prefixed frames and corrupting the TCP stream; the per-connection
`DefaultMaxPipe` in-flight limit is also split across the two entries. Suggest guarding eviction
with an in-flight refcount (or a `len(entry.capacity)==0` check combined with atomic delete/load
coordination) instead of time-based deletion, and/or updating `lastAccess` on every request, not
just on successful responses.



─── server/bridge.go:104-105 ───
[maintainability · low] The wait on the global `tcpSem` has no timeout (only `s.ctx.Done()`), and it
is performed AFTER the per-client capacity slot is acquired. Under sustained saturation of the
1024-slot semaphore (e.g., a few clients with slow upstreams), each queued request holds a
per-client capacity slot indefinitely, so the affected clients' subsequent queries start receiving
SERVFAIL (capacity exhausted) while the queued goroutines can wait far longer than
`DefaultDNSQueryTimeout`. This is a deliberate backpressure design, but consider bounding the wait
(e.g., select on a timeout and answer SERVFAIL) so per-client capacity is not consumed by unbounded
waits.



─── server/handler/middleware/chain.go:124-124 ───
[bug · medium] The Dependencies doc comment above lists ZoneEvaluator as an optional field
("nil-checked before use"), but this call is unconditional: if ZoneEvaluator is nil (or holds a
typed-nil *zone.Evaluator), calling HasRules() panics during chain assembly. All other optional
fields (Closed, PendingRefrs, RefreshGroup, Prober, pending, tagMatcher) are nil-guarded inside
their consuming middlewares, so this is the only field that violates the documented contract. Guard
it before use.

- 	if deps.ZoneEvaluator.HasRules() {
+ 	if deps.ZoneEvaluator != nil && deps.ZoneEvaluator.HasRules() {


─── server/handler/middleware/chain.go:22-23 ───
[documentation · low] Stats is dereferenced unconditionally in CacheLookup/CacheStore/Zone (e.g.
m.stats.Record on every query) but is absent from both the "Required fields" and "Optional fields"
lists in this struct's doc comment. A caller building Dependencies per the documented contract could
pass a nil Stats and crash the entire query path. Add Stats to the required (must be non-nil) list
or nil-check it where used.



─── server/handler/middleware/cache_lookup.go:172-173 ───
[bug · high] Foreground refresh success never writes back to the cache. When the `<-done` branch
fires with `qr.Err == nil`, the response is rebuilt with fresh records but `m.store.Set` is never
called (unlike the timer-fallback path below, which does `m.store.Set`). The cached entry therefore
remains expired, so every subsequent request for this name repeats the full foreground-refresh cycle
— an upstream query plus the serve-expired wait — defeating the purpose of the refresh. Guard with
`qr.Cacheable` and update the store in this branch.

  			qctx.Res = msg
  			qctx.CacheServed = false
+ 			if qr.Cacheable {
+ 				m.store.Set(qname, qtype, qclass, ecsOpt, false, qr.Answer, qr.Authority, qr.Additional, qr.Validated)
+ 			}


─── server/handler/middleware/cache_lookup.go:172-173 ───
[bug · medium] Stale-answer EDE leaks into a freshly refreshed response. When serving the expired
entry, `buildResponse(qctx, entry, true)` sets `qctx.EDE = &dns.EDE{InfoCode:
dns.ExtendedErrorStaleAnswer}`. In the successful refresh path here, `qctx.Res` is replaced with
fresh data but `qctx.EDE` is never cleared; the response middleware later applies `qctx.EDE` to the
outgoing message (`response.go: ApplyToMessage(..., qctx.EDE, ...)`), so a client receives EDE 3
(Stale Answer) alongside non-stale records. Clear `qctx.EDE` (set to nil) when serving the refreshed
response.

+ 			qctx.EDE = nil
  			qctx.Res = msg
  			qctx.CacheServed = false


─── server/handler/middleware/cache_lookup.go:67-69 ───
[bug · medium] `finishRefresh` is never called when the prefetch `TryGo` is rejected.
`tryStartRefresh` has already registered the key in `m.pendingRefreshes` (Start returns true), but
the result of `m.refreshGroup.TryGo` is discarded. `refreshGroup` is created with
`SetLimit(DefaultCacheRefreshConcurrency)` (server.go), so `TryGo` can return false when the group
is at capacity; the pending key is then never released, and all future refresh/prefetch attempts for
that name permanently skip work because `Start` sees the key still in flight. Both the preferStale
and serveExpiredWithRefresh paths already handle this with `m.finishRefresh(...)` on a rejected
`TryGo`; do the same here.

  				if m.refreshGroup != nil {
- 					_ = m.refreshGroup.TryGo(func() error {
+ 					if !m.refreshGroup.TryGo(func() error {
  						defer zdnsutil.HandlePanic("Cache refresh: prefetch fresh-hit")
+ 						defer m.finishRefresh(qname, qtype, qclass, ecsOpt)
+ 						_ = m.refreshCacheEntry(qname, qtype, qclass, ecsOpt)
+ 						return nil
+ 					}) {
+ 						m.finishRefresh(qname, qtype, qclass, ecsOpt)
+ 					}
+ 				}


─── server/handler/handler.go:153-158 ───
[bug · medium] When the middleware chain returns a non-nil error while qctx.Res is already populated
(a partial/invalid response), this block does not fire and execution falls through: the error is
silently discarded — it is not logged, no stats entry is recorded (only the BADCOOKIE case below is
handled), and the partially built response is returned to the client. This contradicts the
documented QueryHandler contract in middleware.go ("Returning ErrDrop discards the query silently.
Any other error produces a SERVFAIL."). Even though the current chain always returns nil, this
public entry point should either treat err != nil as SERVFAIL regardless of Res, or at minimum log
the error and record an "error" stat so a partial response is not emitted without any signal.

  	if err != nil && qctx.Res == nil {
  		msg := BuildResponseMsg(req)
  		msg.Rcode = dns.RcodeServerFailure
  		h.stats.Record(&stats.Request{Result: "error", Protocol: protocol, Rcode: dns.RcodeServerFailure, ResponseTime: ElapsedMS(qctx.StartTime)})
  		return msg
+ 	}
+ 	if err != nil {
+ 		log.Errorf("QUERY: chain error %v (partial response rcode=%s returned)", err, dns.RcodeToString[qctx.Res.Rcode])
+ 		h.stats.Record(&stats.Request{Result: "error", Protocol: protocol, Rcode: qctx.Res.Rcode, ResponseTime: ElapsedMS(qctx.StartTime)})
  	}


─── server/defense/hopguard.go:94-97 ───
[security · medium] The documented learning contract no longer matches reality: Feed is described as
receiving only spoofguard-confirmed-clean responses, "preventing GFW-injected responses from
poisoning the histogram." However, the actual call site (server/upstream/plain/udp.go) invokes
hg.Feed(serverIP, ttl) for EVERY observed packet before Validate and before the message-ID/len
check, so GFW-injected and ID-mismatched packets are fed into the histogram too. Because
rebuildTrusted promotes any TTL whose count >= max(modeCount/4, 4) after decay, a GFW that
consistently injects responses with one TTL value will eventually have that TTL promoted into the
trusted set, silently weakening hopguard's discrimination (udp.go even documents this: rejected TTLs
"become trusted after decay cycles if they repeat consistently"). Either gate Feed on
spoofguard-clean acceptance, or update this documentation and harden the promotion rule (e.g.,
require the candidate to be the mode itself, not merely >= mode/4) so attacker-controlled TTLs
cannot enter the baseline.



─── server/defense/hopguard.go:117-121 ───
[maintainability · low] Rebuild/decay is triggered purely by sample count (every hopGuardMinSamples
observations), not by time. On a low-traffic upstream, a routing change (anycast reroute, PoP shift)
leaves the stale trusted baseline in force for a long time: the new TTL is rejected by Validate on
every packet and can only displace the old baseline after ~2-3 rebuild cycles (64-96 new-TTL
packets) accumulate in the histogram. For a low-QPS upstream that means prolonged rejection of its
legitimate responses. Consider combining the sample-based rebuild with a time-based decay so the
baseline converges even when the query rate is low.



─── server/handler/middleware/cache_store.go:171-172 ───
[bug · medium] When a fresh or stale cache entry rescues a failed resolution, the response actually
served by buildFromCacheEntry is built from the cached RRs and has rcode NOERROR (cache.Entry
carries no rcode), yet this stat unconditionally records RcodeServerFailure and Result "error".
stats.Record feeds both the error counter and the SERVFAIL rcode histogram, so every cache-rescued
request is counted as a SERVFAIL even though the client got a valid cached answer — corrupting
availability/error metrics. This also contradicts cache_lookup.go, which records RcodeSuccess for
cache-served responses. Record the rcode of the response actually served (dns.RcodeSuccess) and
consider a dedicated result classification (e.g. "stale"/"hit") instead of "error".

- m.stats.Record(&stats.Request{Protocol: qctx.Protocol, Result: "error", Rcode: dns.RcodeServerFailure, ResponseTime: handler.ElapsedMS(qctx.StartTime)})
+ m.stats.Record(&stats.Request{Protocol: qctx.Protocol, Result: "error", Rcode: dns.RcodeSuccess, ResponseTime: handler.ElapsedMS(qctx.StartTime)})
  			return m.buildFromCacheEntry(qctx, entry, isExpired)


─── server/defense/poisonguard.go:111-114 ───
[bug · low] IsPoisonedByTLD flags any A/AAAA answer whose owner equals the query name, but applies
none of the exemptions that classifyRoot/classifyTLD in this same file treat as legitimate: (1)
root-servers.net hostnames — the root zone legitimately serves A/AAAA for them (classifyRoot returns
Clean for every type under root-servers.net); (2) the TLD apex — classifyTLD returns Clean for name
== zone regardless of record type. The only caller (Recursive.probeTLDForPoison) feeds this function
responses from TLD servers for the full query name; when the query name is the TLD apex itself (e.g.
a client querying "com" A/AAAA against a TLD that publishes apex addresses) or a root-servers.net
name, a legitimate answer would be misreported as poison and force an unnecessary TCP fallback. This
also contradicts the docstring's "TLD or root server" contract. Consider returning false when the
query name is a root-server domain or the TLD apex.

  		switch dns.RRToType(rr) {
  		case dns.TypeA, dns.TypeAAAA:
+ 			// Root-server hostnames and TLD-apex queries are legitimate
+ 			// A/AAAA answers for root/TLD servers (see classifyRoot/classifyTLD).
+ 			if d.isRootServerDomain(n) || d.isTLD(n) {
+ 				return false
+ 			}
  			return true
  		}


─── server/defense/poisonguard.go:83-86 ───
[security · medium] Validate only inspects Answer RRs whose owner exactly equals the query name, so
injected out-of-zone answers with an ancestor owner — e.g. a DNAME for example.com returned in
response to a www.example.com query — are skipped entirely and evade VerdictPoisoned, even though
they violate the documented invariant that the server "does not return answer records outside its
delegated zone authority". Legitimate root/TLD responses only contain root-servers.net records and
NS/DS delegations, so also classifying RRs whose owner is an ancestor of the query name closes this
evasion gap without introducing false positives.

  	for _, rr := range response.Answer {
- 		if dnsutil.Canonical(rr.Header().Name) != n {
+ 		if rr == nil {
+ 			continue
+ 		}
+ 		owner := dnsutil.Canonical(rr.Header().Name)
+ 		// Also inspect answers whose owner is an ancestor of the query
+ 		// name (e.g. injected DNAME for example.com on www.example.com).
+ 		if owner != n && !dnsutil.IsBelow(owner, n) {
  			continue
  		}


─── server/defense/poisonguard.go:81-86 ───
[bug · low] Both Validate and IsPoisonedByTLD iterate response.Answer and dereference rr.Header()
with no nil guard; a nil element in the Answer slice would panic on the resolver hot path. The rest
of this codebase treats nil RRs as possible (zonecut.go guards `if r == nil { continue }`), and
pooled messages (pool.DefaultMessage) are reused across responses. Add a nil check before Header().

  	n := dnsutil.Canonical(queryName)
  	for _, rr := range response.Answer {
+ 		if rr == nil {
+ 			continue
+ 		}
  		if dnsutil.Canonical(rr.Header().Name) != n {
  			continue
  		}


─── server/handler/middleware/dns64.go:38-40 ───
[bug · high] `qctx.Req.Question[0]` is a `dns.Question` value, not a `dns.RR`. `dns.RRToType(qd)`
and `qd.Header()` are RR-interface APIs; in standard miekg/dns `Question` has no `Header()` method
and does not implement `RR`, so this either fails to compile or silently reads zero values depending
on fork extensions. Use the plain struct fields (`qd.Qtype`, `qd.Name`, `qd.Qclass`) — note
`qctx.Qtype`/`qctx.Qname` are already pre-extracted in the QueryContext. This is the gate for the
whole middleware, so a wrong qtype would enable/disable DNS64 incorrectly.

  		qd := qctx.Req.Question[0]
- 		qtype := dns.RRToType(qd)
+ 		qtype := qd.Qtype
  		if qtype != dns.TypeAAAA || len(qr.Answer) > 0 {


─── server/handler/middleware/dns64.go:40-42 ───
[bug · high] The guard `len(qr.Answer) > 0` suppresses DNS64 synthesis whenever the AAAA response
contains any answer record, including a CNAME-only chain. The recursive resolver's CNAME chaser
(server/resolver/recursive.go) returns the CNAME chain with no AAAA when the final target has no
AAAA but does have an A record — exactly the case DNS64 must handle (RFC 6147 §5.1.2). Check for the
presence of AAAA records rather than non-empty answers, so synthesis still runs for CNAME-only
responses.

- 		if qtype != dns.TypeAAAA || len(qr.Answer) > 0 {
+ 		if qtype != dns.TypeAAAA || hasAAAA(qr.Answer) {
  			return err
  		}


─── server/handler/middleware/dns64.go:61-66 ───
[bug · medium] When the secondary A lookup fails (`aqr.Err != nil`), the error is silently dropped:
the middleware returns the original empty AAAA result, so the client receives NOERROR/NODATA and the
upstream failure is completely masked (and may be cached as NODATA). Log the failure and propagate
it (e.g., set `qr.Err`/return an error so the response becomes SERVFAIL) instead of silently
converting an upstream error into NODATA.

  		if aqr != nil && aqr.Err == nil && len(aqr.Answer) > 0 {
  			qr.Answer, qr.Authority, qr.Additional = m.synthesizer.Synthesize(
  				qr.Answer, qr.Authority, qr.Additional,
  				aqr.Answer, aqr.Authority, aqr.Additional, qr.Validated)
  			log.Debugf("DNS64: synthesized %d AAAA records for %s", len(qr.Answer), qname)
+ 		} else if aqr != nil && aqr.Err != nil {
+ 			log.Warnf("DNS64: A lookup failed for %s: %v", qname, aqr.Err)
  		}


─── server/handler/middleware/resolution.go:52-55 ───
[bug · medium] When the resolver returns nil (or DoJoin returns nil for a follower whose pending
call was evicted before the leader completed), this branch only sets qctx.ResolutionError and
returns nil. `ResolutionError` is never read by any middleware, and CacheStore bails out on
`!qctx.Resolved` (which stays false here), so Handler.ServeDNS ultimately returns a nil *dns.Msg —
the client receives no response at all (silent drop / client timeout) instead of the SERVFAIL the
terminal-handler contract promises. Note the same defect exists in the non-pending branch below
(lines 66-69). Fix: build a SERVFAIL response here, e.g. `msg := handler.BuildResponseMsg(qctx.Req);
msg.Rcode = dns.RcodeServerFailure; qctx.Res = msg`, or set `qctx.Resolved = true` plus a non-nil
error QueryResult so CacheStore's buildError path can produce SERVFAIL.



─── server/handler/middleware/resolution.go:49-51 ───
[bug · medium] The singleflight work function captures this request's `ctx`, and DoJoin runs it on
behalf of every deduplicated follower. If the leading client disconnects, its context is canceled
and resolver.Query (which passes ctx down to queryUpstream/cname.resolve) aborts — all followers
waiting on the same query then receive the canceled/failed result even though their own connections
are alive. Additionally, followers never select on their own `ctx` while waiting on the pending
call, so a disconnected follower keeps blocking until the leader finishes or the follower timeout
fires. Consider running the shared query with a server-scoped context (e.g. the lifecycle ctx from
Dependencies) instead of the first caller's context, and/or selecting on the follower's ctx in the
wait.



─── server/handler/middleware/dns64.go:0-0 ───
[security · medium] `dnssecOK` is only used as a singleflight key; `resolver.Query` has no DNSSEC
parameter, so the A lookup is issued without the client's DO/validation context. Meanwhile
`qr.Validated` (the original AAAA NODATA's DNSSEC status) is passed into `Synthesize` (which
currently discards it) and later drives the response AD bit in CacheStore.buildSuccess. The
synthesized AAAA records therefore inherit authentication status from a NODATA proof that has
nothing to do with them, while the A lookup's own `aqr.Validated` is never consulted. When synthesis
occurs, clear `qr.Validated` (or propagate `aqr.Validated`) so the response does not assert
AD/authenticated data for records derived from a separate, unvalidated A response.

  		if m.pending != nil {
- 			if aqr = m.pending.DoJoin(qname, dns.TypeA, qclass, ecsOpt, dnssecOK, func() *resolver.QueryResult {
+ 			aqr = m.pending.DoJoin(qname, dns.TypeA, qclass, ecsOpt, dnssecOK, func() *resolver.QueryResult {
  				aQuestion := handler.Question{Name: qname, Qtype: dns.TypeA, Qclass: qclass}
  				return m.resolver.Query(ctx, aQuestion, ecsOpt)
- 			}); aqr == nil {
+ 			})
+ 			if aqr == nil {
  				return err
  			}


─── server/handler/middleware/response.go:64-67 ───
[bug · medium] The gate contradicts the comment right above it. `qctx.IsSecure` is a transport flag
set by the protocol listener (DoT/DoH/DoQ/...), not proof the request carried an OPT record, and
`ecsOpt` may be a default ECS fabricated by `ECSForQType` when the client never sent ECS. So a plain
non-EDNS query over a secure transport — or any query when `default_ecs_subnet` is configured — gets
a response with an unsolicited OPT record (and possibly an invented ECS), violating RFC 6891 §6.1.1
/ RFC 7871; strict clients/middleboxes may reject it. Note also that on short-circuit paths (Zone
match, Validation failure) the EDNS middleware never runs, so `req.Pseudo` is still empty (only the
question section is unpacked before the chain) — `ParseFromDNS` there always returns nil and only
the fabricated default ECS can ever be added. Suggest gating on real request-OPT evidence
(`req.Security || req.UDPSize != 0 || len(req.Pseudo) > 0`) and dropping `qctx.IsSecure` from the
gate (padding is already independently gated by `clientWantsPadding` inside `ApplyToMessage`).



─── server/handler/middleware/response.go:132-136 ───
[bug · medium] `restoreDomain` renames every RR whose owner equals `currentName` — including
RRSIG/NSEC records — without recomputing or stripping signatures. On the wildcard-rewrite path
(zone.go sets `OriginalName`/`RewrittenName` then falls through to CacheLookup/Resolution with the
rewritten qname), a DO=1 client can receive DNSSEC-signed data for the rewritten name. Renaming the
owner of both the RRset and its RRSIG leaves signature bytes computed over the rewritten name, so
DNSSEC-validating clients see BOGUS. Consider stripping RRSIGs covering renamed RRsets (and
NSEC/NSEC3), clearing the AD bit, or skipping the restore when the response carries DNSSEC records.



─── server/handler/middleware/response.go:74-74 ───
[maintainability · low] `qctx.TCPKeepalive` is never assigned anywhere in the codebase (a
codebase-wide search finds only the struct field in `server/handler/context.go` and these reads), so
`qctx.TCPKeepalive > 0` is always false: the RFC 7828 keepalive option is never emitted and this
term in the `shouldAddEDNS` gate is dead. If keepalive support is intended, parse the client's TCP
keepalive option (e.g., from `req.Pseudo`) and populate the field; otherwise remove the dead
condition to avoid misleading readers.



─── server/handler/middleware/zone.go:50-51 ───
[bug · high] `ZoneMatched` is set before the fall-through branch (lines 84-94) that delegates to
`next.ServeDNS`. In that branch the middleware does NOT build `qctx.Res` (synthetic responses are
only built in the rcode/records branches above), so when the inner chain unwinds, `CacheStore` hits
its `if qctx.CacheServed || qctx.ZoneMatched || qctx.Res != nil { return err }` early-return and
never builds a response from `ResolutionResult`. `Handler.ServeDNS` then returns nil and the client
query is silently dropped (timeout). This is reachable whenever `Evaluate` returns a matched result
with RcodeSuccess and empty Answer/Authority/Additional (e.g. a rule whose records fail to
pack/unpack via `unpackRRs`), and it also means the documented wildcard-rewrite path can never
actually answer: nothing rewrites `req.Question[0]` before Resolution (resolution still queries the
original name), and CacheStore discards the resolution result. Recommend setting
`qctx.ZoneMatched`/`qctx.ZoneResult` only in the branches that actually short-circuit with a
synthetic response, and treating the matched-but-empty case as a plain delegation (or building the
response here).



─── server/handler/middleware/zone.go:22-22 ───
[maintainability · low] The `cache` field is assigned in chain.go (`cache: deps.Cache`) but never
read anywhere in this file — it is dead state on the middleware. Remove the field (and its wiring)
to avoid implying a cache dependency that does not exist.



─── server/handler/middleware/validation.go:62-62 ───
[bug · medium] `len(qname)` measures the presentation form, not the wire-encoded name length (RFC
1035 §2.3.4 limits the wire form to 255 octets including per-label length octets and the root). This
check both over- and under-enforces the limit:
- False rejection: a valid max-length FQDN is 253 label octets + trailing dot = 254 presentation
chars, which exceeds `config.MaxDomainLength` (253) and is REFUSED even though its wire form is
legal (the project's own audit, `docs/audit/2026-07-badgerdb-migration-audit/18-package-handler.md`
#4 / M-RES5, flags this). Names containing `\DDD` escapes are likewise inflated in presentation form
and can be falsely rejected even when the wire form is ≤255 octets.
- False acceptance: a name with many labels can pass `len(qname) <= 253` and `dnsutil.IsName` while
its wire form (labels + length octets + root) exceeds 255 octets, so an invalid name is forwarded
downstream.
Suggest measuring the wire length (e.g., pack the name and compare the packed length against 255)
or, at minimum, strip the trailing dot and count unescaped octets before comparing.

- 		if len(qname) <= config.MaxDomainLength &&
+ 		// Compare against the RFC 1035 wire-form limit (255 octets incl. root):
+ 		// len(qname) counts the trailing dot and \DDD escapes and is not a
+ 		// valid proxy for wire length.
+ 		wireLen, err := dns.PackDomainName(qname, make([]byte, 256), 0, nil, false)
+ 		if err == nil && wireLen <= 255 &&


─── server/handler/middleware/validation.go:47-47 ───
[bug · low] Only `Question[0]` is validated. A query with QDCOUNT > 1 (permitted by the wire format,
though non-standard in practice) can smuggle an invalid name or an ANY/AXFR/IXFR type in
`Question[1]` past this gate and into downstream handlers, which all assume a single question
(`Question[0]`). The reject paths compound this: `dnsutil.SetReply` echoes only the first question,
so the FORMERR/REFUSED response question section won't match the query. Recommend rejecting QDCOUNT
!= 1 up front (e.g., FORMERR) or iterating over the whole question section in the validation checks.

+ 		// Reject multi-question queries: downstream handlers and SetReply only
+ 		// handle a single question, and the other questions would bypass this
+ 		// validation entirely.
+ 		if len(qctx.Req.Question) != 1 {
+ 			msg := pool.DefaultMessage.Get()
+ 			dnsutil.SetReply(msg, qctx.Req)
+ 			msg.Rcode = dns.RcodeFormatError
+ 			qctx.EDE = &dns.EDE{InfoCode: dns.ExtendedErrorOther, ExtraText: ""}
+ 			qctx.Res = msg
+ 			return nil
+ 		}
+
  		qd := qctx.Req.Question[0]


─── server/handler/response.go:21-23 ───
[bug · medium] When `req` has no question section, `dnsutil.SetReply` is skipped, so the request's
transaction ID (and opcode/RD/CD) is never copied into the pooled response. Because
`pool.DefaultMessage.Get()` returns a zeroed message (`Put` does `*msg = dns.Msg{}`), this FORMERR
is always emitted with Id=0. DNS clients correlate responses by transaction ID and will discard a
response whose ID differs from the query, so the FORMERR is effectively invisible to the client. The
main entry point (handler.go) guards this case, but the branch is still reachable from other callers
(e.g. the EDNS full-unpack failure path in middleware/edns.go). Copy the request header fields here,
e.g. always run `dnsutil.SetReply(msg, req)` for non-nil req and then override Rcode to FormatError.

  	case req != nil:
+ 		msg.Id = req.Id
+ 		msg.Opcode = req.Opcode
  		msg.Response = true
  		msg.Rcode = dns.RcodeFormatError


─── server/handler/response.go:36-37 ───
[bug · medium] Cached negative responses lose their Rcode: `cache.Entry` has no Rcode field (and
neither does `QueryResult`/`Store.Set`), while `dnsutil.SetReply` used here always leaves
Rcode=NoError. Negative responses are cacheable — the resolver sets `Cacheable: true` for NXDOMAIN
results with the SOA in the authority section — so a cache hit for a previously NXDOMAIN name is
answered as NOERROR + SOA, silently degrading NXDOMAIN into NODATA. This changes client-visible DNS
semantics (wildcard/negative-trust handling) and makes DNSSEC-validated negative responses
(NSEC/NSEC3 proofs) internally inconsistent. Persist the Rcode in the cache Entry (and resolution
result) and restore it onto `msg.Rcode` here.



─── server/init.go:70-70 ───
[bug · high] Data race: `statsCollector.Reset()` is reachable from `DynamicContent`, which is
invoked on DNS query-handling goroutines (zone.Evaluator.evalDynamic). These run concurrently with
other requests that call `stats.Record()`/`Stats()` on the same collector. `Collector.Reset()`
(stats/stats.go) is implemented as `*c = Collector{}` — a non-atomic whole-struct overwrite — which
races with the atomic `Add`/`Load` calls on the same fields (`total`, `hit`, `latCounts`, ...). This
can tear reads in `Stats()` and lose increments from in-flight queries. Reset each counter
individually (e.g., `Store(0)` per atomic field, including `latCounts`/`rCode`/`latTotal`) or guard
Reset with a mutex so the lock-free `Record()` invariant is preserved.

  rules[i].DynamicContent = makeFlushFunc(func() (int64, error) { statsCollector.Reset(); return int64(0), nil }, "reset")


─── server/init.go:72-75 ───
[bug · medium] Suspicious behavior: the `.cache.clear` rule also calls `statsCollector.Reset()`, so
flushing the DNS cache silently wipes all query statistics as a side effect. Unless this combined
'reset everything' behavior is intentional (in which case it should be documented/renamed), drop the
`statsCollector.Reset()` call here so cache.clear only clears the cache. Note the same Reset race
described above applies on this path as well.

  rules[i].DynamicContent = makeFlushFunc(func() (int64, error) {
- 				statsCollector.Reset()
  				return store.FlushDB("cache")
  			}, "flushed")


─── server/init.go:55-57 ───
[security · medium] The raw `error` text is placed verbatim into a DNS TXT answer (`error=%v`).
`FlushDB` errors wrap badger/internal details (e.g., `flushDB cache: ...`), which can include
filesystem/database internals. Any client able to query the CHAOS zone (these dynamic rules answer
arbitrary queries) can read those internals. Log the detailed error server-side and return a generic
message in the DNS response (e.g., `error=flush-failed`), or gate these control rules behind an
allowlist/trusted-network check.

  if err != nil {
- 			return []string{fmt.Sprintf("error=%v", err)}
+ 			log.Errorf("%s failed: %v", verb, err)
+ 			return []string{"error=flush-failed"}
  		}


─── server/handler/prefetch.go:78-82 ───
[bug · medium] Eviction deletes the oldest half of the map regardless of whether those entries are
still inside their cooldown window. Under sustained diverse-query load, a key that was prefetched
moments ago (e.g. still within the 3s DefaultPrefetchThrottleInterval) can be evicted before its
cooldown expires, so the same name can pass ShouldStart again and trigger a duplicate upstream
refresh — the very load the cooldown is meant to prevent. Note this path is reachable per-request
from cache_lookup.go, so a high-QPS adversary can evict a hot key's entry and force repeated
refreshes (cache-stampede amplification). At minimum, expire stale entries first and evict unexpired
ones only as a last resort, or keep the eviction timestamp so the cooldown still gates the key after
eviction.



─── server/handler/prefetch.go:49-51 ───
[maintainability · low] ShouldStart inserts a new timestamp unconditionally; the only path that
removes entries or enforces DefaultPrefetchCooldownMaxEntries is Cleanup, which is scheduled
externally (server/tasks.go, every 30s). The map's bounded-ness therefore relies on that ticker
always running: if it is ever removed, stopped, or delayed, the map grows without limit (each entry
retained until the next cleanup, and up to 10k entries can accumulate within one cleanup period).
Consider enforcing the cap (or a soft cap) inline in the ShouldStart slow path so growth is bounded
even if Cleanup scheduling changes.



─── server/handler/prefetch.go:18-22 ───
[maintainability · low] PrefetchCooldown is an exported type (used cross-package via
handler.PrefetchCooldown in middleware/chain.go and server/server.go), but its zero value has a nil
data map. Any code that constructs &PrefetchCooldown{} or PrefetchCooldown{} instead of
NewPrefetchCooldown() will pass the read-only fast path (nil map reads return zero values) and then
panic on the write pc.data[key] = now in ShouldStart. In-repo call sites use the constructor, so
this is a latent API footgun rather than a live crash; make the zero value usable by lazily
initializing data in ShouldStart, or document and guard against nil data.



─── server/handler/middleware/edns.go:50-56 ───
[bug · medium] The FORMERR response for a malformed ECS echoes the malformed SUBNET back to the
client. When this branch returns, `qctx.ECSOpt` still points at the invalid option and the full
re-unpack (which already succeeded) left the malformed SUBNET in `req.Pseudo`. The outer Response
middleware (`server/handler/middleware/response.go` `finalizeResponse`) then runs for every
non-BADCOOKIE response — `shouldAddEDNS` is true (`len(qctx.Req.Pseudo) > 0`), and it re-applies
`qctx.ECSOpt` / falls back to `ParseFromDNS(req)` — so the FORMERR response carries
`dns.SUBNET{Family: <invalid>, Netmask: <invalid>}` built from attacker-controlled values. Per RFC
7871 §6/§7.3 the server must not echo the malformed option. Clear the malformed ECS state (and strip
the SUBNET from `req.Pseudo`, since the fallback re-parses it) before returning, or have the
Response middleware skip EDNS on non-OK rcodes.

  		if qctx.ECSOpt != nil && !qctx.ECSOpt.IsValid() {
  			log.Debugf("EDNS: malformed ECS option from %s", qctx.ClientIP)
+ 			// Clear the malformed ECS state: the outer Response middleware re-applies
+ 			// qctx.ECSOpt (and falls back to re-parsing req.Pseudo) for every
+ 			// non-BADCOOKIE response, which would echo the malformed SUBNET option
+ 			// back into the FORMERR response.
+ 			qctx.ECSOpt = nil
+ 			pseudo := qctx.Req.Pseudo[:0]
+ 			for _, opt := range qctx.Req.Pseudo {
+ 				if _, isSubnet := opt.(*dns.SUBNET); !isSubnet {
+ 					pseudo = append(pseudo, opt)
+ 				}
+ 			}
+ 			qctx.Req.Pseudo = pseudo
  			msg := handler.BuildResponseMsg(req)
  			msg.Rcode = dns.RcodeFormatError
  			qctx.Res = msg
  			return nil
  		}


─── server/handler/pending.go:88-93 ───
[bug · low] This module builds with Go 1.26, i.e. the Go 1.23+ timer channel semantics (unbuffered
channels) apply. When the select picks the `actual.done` case at the same instant the timer fires,
`timer.Stop()` can return false while the time value has not yet been delivered, and the blocking
`<-timer.C` is not guaranteed to complete on every interleaving/version. Use a non-blocking drain,
which is safe under both old buffered and new unbuffered timer semantics:

  	timer := time.NewTimer(config.DefaultPendingFollowerTimeout)
  	select {
  	case <-actual.done:
  		if !timer.Stop() {
- 			<-timer.C
+ 			select {
+ 			case <-timer.C:
+ 			default:
+ 			}
  		}


─── server/protocol/plain/server.go:35-37 ───
[bug · low] Start returns an error, so nil group/handler arguments can be reported as a normal error
instead of panicking and crashing the whole process from a library API. Prefer returning an error
(e.g., errors.New("plain: nil group or handler")) at this public boundary.



─── server/protocol/dnscrypt/tcp.go:105-105 ───
[bug · medium] The error from SetReadDeadline is discarded. ReadPrefixed's contract requires a read
deadline to have been set; if this call fails, a peer that connects and sends nothing (or only a
partial prefix) can occupy the worker slot indefinitely, since nothing else in this path bounds the
read until the external deadline reset in Shutdown. Handle the error: log it and close the
connection rather than proceeding without a deadline.

- 	_ = conn.SetReadDeadline(time.Now().Add(defaultReadTimeout))
+ 	if err := conn.SetReadDeadline(time.Now().Add(defaultReadTimeout)); err != nil {
+ 		log.Debugf("DNSCRYPT: setting TCP read deadline for %s: %v", conn.RemoteAddr(), err)
+ 		_ = conn.Close()
+ 		return
+ 	}


─── server/protocol/dnscrypt/generate.go:211-213 ───
[bug · medium] The validation only checks for the presence of a colon, so a bare IPv6 address (e.g.,
"::1" or "2001:db8::1") passes, and `addr[strings.LastIndex(addr, ":")+1:]` then extracts a garbage
"port" ("1") from the last address segment, which is written into cfg.Server.Protocol.DNSCrypt.
"host:" likewise yields an empty port that silently falls back to the default listener port, and a
non-numeric port is accepted unchecked. Use net.SplitHostPort (which correctly requires brackets
around IPv6) and validate that the extracted port is numeric and non-empty.



─── server/protocol/tlcp/certs.go:73-74 ───
[bug · high] The encryption certificate reuses the same server template as the signing certificate,
so it only carries KeyUsageDigitalSignature. In TLCP (GB/T 38636-2020 / GM/T 0024), the encryption
certificate is presented for key agreement/key transport, and strict peers validate key usage on the
received cert. An encryption cert without KeyAgreement/KeyEncipherment/DataEncipherment may be
rejected during the handshake. Give the encryption template a distinct key usage (e.g.
KeyUsageKeyAgreement | KeyUsageKeyEncipherment | KeyUsageDataEncipherment), e.g. by parameterizing
serverTemplate(keyUsage smx509.KeyUsage).

- 			KeyUsage:     smx509.KeyUsageDigitalSignature,
+ 			KeyUsage:     keyUsage,
  			ExtKeyUsage:  []smx509.ExtKeyUsage{smx509.ExtKeyUsageServerAuth},


─── server/protocol/tlcp/certs.go:70-70 ───
[bug · high] Server certificates only set CommonName and never set DNSNames/IPAddresses (the
function takes no host parameter). Modern clients perform hostname/IP verification against the
SubjectAltName per RFC 6125 and generally ignore CN, so these certificates will fail verification
for any domain or IP a client connects to. The sibling TLS generator (server/protocol/tls/certs.go)
sets DNSNames/IPAddresses from the domain — do the same here by accepting a host/IP parameter and
populating the SAN fields.



─── server/protocol/dnscrypt/crypto.go:50-54 ───
[bug · medium] The resumption ticket is not accounted for in the truncation budget, so a
ticket-bearing PQ response over TCP can exceed the 4096-byte cap (§5.4.7: "TCP encrypted responses
MUST be < 4096 bytes"). MinResponseOverhead for XWingPQ only reserves the 2-byte control-length
prefix (51 bytes total), and encryptPQ later appends the sealed ticket (~128 bytes: 4 keyID + 24
nonce + 84 plaintext + 16 tag) plus the 11-byte control block header before r.Encrypt is called.
encryptPQResponse's TCP branch (encrypted.go:236-249) has no size enforcement, so nothing prevents
an oversized frame from being sent. With the loop guaranteeing len(packet) ≤ 4096-51-320 = 3725 and
PadResponse adding up to ~320 bytes, the final frame can reach ~4234 bytes. The truncation loop must
reserve the worst-case ticket size (sealed ticket + 11-byte control block + 2 control-len) for PQ
initial queries, or the size must be re-checked after the ticket is attached.



─── server/protocol/tls/certs.go:49-50 ───
[bug · medium] The leaf's NotAfter uses `config.DefaultServerCertValidity` while the CA uses
`config.DefaultCACertValidity` — two independent constants with nothing enforcing CA validity >=
leaf validity. If the constants ever diverge (e.g. CA shortened for rotation hygiene), the leaf
outlives its signer and the chain becomes untrusted before the leaf's advertised expiry. Also,
because `time.Now()` is evaluated separately for each template, the CA's NotAfter is always slightly
earlier than the leaf's NotAfter even with equal durations. Consider deriving the leaf NotAfter from
the CA's NotAfter (or clamping it) so the leaf never outlives its signer.



─── server/protocol/tlcp/http_tlcp.go:33-33 ───
[bug · high] ALPN mismatch: `config.NextProtoDOH` is `[]string{"h2"}`, but this listener is served
by `http.Server.Serve(tlcpListener)` where `tlcpListener` is a gotlcp `tlcp.Listener`, not a
`*tls.Listener`. `net/http` only performs the TLS handshake and ALPN dispatch for `*tls.Conn`; here
the handshake happens lazily inside the gotlcp listener and the server always parses HTTP/1.1.
Advertising `h2` makes ALPN-compliant clients (including this project's own TLCP DoH client at
server/upstream/tlcp/http_tlcp.go, which sets `ForceAttemptHTTP2: true`) negotiate HTTP/2 and send
the HTTP/2 preface, which the HTTP/1.1 parser rejects — the connection breaks (the log line above
even states "TLCP HTTP/1.1"). Advertise `http/1.1` instead.

- 		tlcpCfg.NextProtos = config.NextProtoDOH
+ 		tlcpCfg.NextProtos = []string{"http/1.1"} // this http.Server only speaks HTTP/1.1; do not advertise h2


─── server/protocol/tlcp/http_tlcp.go:40-40 ───
[security · medium] No `ReadTimeout` is configured, only `ReadHeaderTimeout`. After the headers are
received, a client can trickle a POST body byte-by-byte (bounded in size only by
`http.MaxBytesReader`, not in time), holding the connection/goroutine and file descriptor
indefinitely — a Slowloris-style DoS against an internet-facing DoH endpoint. `IdleTimeout` does not
apply while the request is being read. Add a `ReadTimeout` covering the full request read (e.g., a
`config.DefaultHTTPServerReadTimeout` constant alongside `DefaultHTTPReadHeaderTimeout`).

  			ReadHeaderTimeout: config.DefaultHTTPReadHeaderTimeout,
+ 			ReadTimeout:       config.DefaultHTTPServerReadTimeout, // add this constant to config/defaults.go


─── server/protocol/tlcp/server.go:83-86 ───
[maintainability · low] Handshake logs hardcode `RemoteAddr: "client"` for both the TLCP and DTLCP
`VerifyConnection` callbacks, so every handshake log line attributes the connection to a literal
"client" with no peer address, making client attribution in the debug logs impossible.
`ConnectionState` passed to `VerifyConnection` does not expose the peer address, so consider logging
the handshake parameters at the accept/handler site where `conn.RemoteAddr()` is available, or drop
the address field rather than emit a misleading constant.



─── server/protocol/dnscrypt/udp.go:130-139 ───
[security · high] Anti-amplification truncation does not guarantee `len(reply) <= len(b)`.
`dnsutil.Truncate` truncates to the library's fixed default size (it has no parameter for the client
query size), and the code never re-verifies `len(truncated.Data) <= len(b)` before sending. For
small queries (a minimal handshake is well under 100 bytes), the truncated response can still exceed
the request, defeating the §10.3 anti-amplification guarantee this block is meant to enforce.
Additionally, on `Unpack()`/`Pack()` failure the original oversized reply is sent unchanged while
the log misleadingly claims "returning TC". Recommend dropping the response when it cannot be made
to fit within `len(b)` (or verifying the post-truncation size before sending).

  		if len(reply) > len(b) {
  			origLen := len(reply)
  			truncated := &dns.Msg{}
  			truncated.Data = reply
  			if unpackErr := truncated.Unpack(); unpackErr == nil {
  				dnsutil.Truncate(truncated)
- 				if packErr := truncated.Pack(); packErr == nil {
+ 				if packErr := truncated.Pack(); packErr == nil && len(truncated.Data) <= len(b) {
  					reply = truncated.Data
+ 				} else {
+ 					// Cannot shrink the response to fit the request: drop it to
+ 					// honor the §10.3 anti-amplification limit.
+ 					log.Debugf("DNSCRYPT: dropping UDP cert response (%d bytes) for %d-byte request", origLen, len(b))
+ 					return
+ 				}
+ 			} else {
+ 				log.Debugf("DNSCRYPT: dropping unparseable UDP cert response: %v", unpackErr)
+ 				return
  				}
+ 			log.Debugf("DNSCRYPT: UDP cert response (%d bytes) exceeds request (%d bytes) — returning TC", origLen, len(b))
  			}


─── server/protocol/dnscrypt/udp.go:62-64 ───
[bug · medium] The loop's pooled buffer is only returned via explicit `Put` calls at each exit path
— it is not deferred. If anything in the loop body panics, `defer zdnsutil.HandlePanic` recovers but
the held buffer is never returned to `DefaultBuffer` (a pooled 8192-byte buffer is lost) and the
DNSCrypt UDP listener silently terminates. Other protocol handlers (`tls.go`, `dtls.go`) use `defer
pool.DefaultBuffer.Put(buf)` for exactly this reason. Use a single `defer func() {
pool.DefaultBuffer.Put(buf) }()` right after `Get()` (the closure reads the final `buf` value after
each swap) and remove the per-path `Put` calls to make all exit paths — including panics —
panic-safe.

  	buf := pool.DefaultBuffer.Get()
+ 	defer func() { pool.DefaultBuffer.Put(buf) }()

  	for s.isStarted() {


─── server/protocol/tlcp/dtlcp.go:180-181 ───
[security · critical] The DTLCP handshake runs with no deadline at all. `readFirstDatagram` consumes
the client's first datagram, then `conn.Handshake()` blocks on reads from the shared UDP socket
until the peer sends the remaining handshake messages. A client that sends one datagram
(ClientHello) and then goes silent stalls the handshake forever. Because `handleDTLCPConnections`
serves connections synchronously and sets the initial deadline only *after* `Accept()` returns, a
single stalled handshake permanently blocks the entire DTLCP server for all clients. Set a handshake
deadline on `bpc`/the shared socket before calling `Handshake()` (and clear it afterward, e.g.
`defer conn.SetDeadline(time.Time{})`).



─── server/protocol/tlcp/dtlcp.go:260-262 ───
[bug · high] `SetDeadline` sets both read and write deadlines on the shared socket, but the
per-connection loop refreshes only the *read* deadline (`SetReadDeadline`) on each iteration. The
write deadline therefore remains fixed at accept-time + `DefaultDTLSIdleTimeout` (30s). Any
connection that stays alive longer than 30s — which is guaranteed for active clients because the
read deadline keeps getting refreshed — will have `conn.Write(resp)` in `sendDTLCPResponse` fail
with a timeout error and be torn down mid-conversation. Refresh the write deadline per response
(e.g. `conn.SetWriteDeadline(time.Now().Add(idleTimeout))` before each write) or set it together
with the read deadline in the loop.



─── server/protocol/tls/addr_validator.go:26-31 ───
[bug · high] The return values are inverted with respect to quic-go's
`Transport.VerifySourceAddress` contract and this function's own doc comment. In quic-go, returning
`true` means the source address is considered verified and the server proceeds WITHOUT sending a
Retry; returning `false` makes the server send a Retry packet to the client. Here the code returns
`true` for an address that is NOT in the cache and `false` for one that IS — exactly backwards.
Consequences: (1) the very first Initial from any new — or spoofed — source address is treated as
verified, so the handshake proceeds without a Retry, defeating RFC 9000 §8.1 anti-amplification (a
tiny spoofed Initial elicits full handshake responses sent to the victim IP); (2) previously-seen
(cached) clients — precisely the repeat clients the comment says should skip the Retry — are sent a
Retry, so the intended NAT/firewall workaround has the opposite effect and the LRU cache is
counterproductive. Swap the returns: `true` on cache hit, and `false` after inserting the new
address on miss.

  		key := udpAddr.IP.String()
  		if _, exists := cache.Get(key); exists {
- 			return false
+ 			return true
  		}
  		cache.Set(key, time.Now())
- 		return true
+ 		return false


─── server/protocol/tls/addr_validator.go:9-11 ───
[security · high] Even after the return polarity is corrected to the intended behavior, whitelisting
by raw source IP is not a substitute for token-based address validation and is trivially poisonable:
an unauthenticated UDP datagram with a spoofed source IP inserts the victim's IP into the cache,
after which the server skips the Retry for that IP and answers spoofed-source Initials with full
handshake packets — permanently defeating the anti-amplification protection the Retry exists to
provide (the attacker does not need to be on-path). The problem is compounded because entries never
expire by time: the stored `time.Time` value is never read, and LRU eviction only triggers once the
128-entry cap is reached, so under low traffic a single spoofed packet whitelists a victim IP
indefinitely (the "naturally aged out" claim in the comment does not hold). Prefer
cookie/token-based validation (only whitelist an address after it completes a handshake or echoes a
Retry token) and/or add real time-based expiry that actually reads the stored timestamp.



─── server/protocol/tls/http3.go:86-88 ───
[security · high] Unbounded goroutine growth: every accepted QUIC connection spawns a long-lived
goroutine running h3Server.ServeQUICConn, with no admission cap on total or per-client connections.
quic.Config only limits streams (MaxIncomingStreams), not connections, and with Allow0RTT + the
source-address cache (which skips Retry after the first validated connection from an IP) a single
client can cheaply open a large number of connections and exhaust goroutines/memory. Consider
bounding concurrent connections (e.g., a semaphore or a max-connections counter per listener/IP)
and/or rejecting/handling excess connections instead of spawning a goroutine per connection.



─── server/protocol/tls/https.go:137-140 ───
[bug · medium] The GET size check compares the *base64url-encoded* `dns` query parameter against
`config.DefaultDOHMaxRequestSize` (65535 bytes), but that constant bounds the raw DNS wire message
(it is applied to the POST body via `MaxBytesReader`). Base64url expands data by ~4/3, so a valid
message between ~49152 and 65535 bytes encodes to more than 65535 characters and is wrongly rejected
with 400, making the GET limit inconsistent with the POST limit (RFC 8484 §4.1/§4.2.1 intend the
same message-size bound for both). Decode the parameter first (e.g.
`base64.RawURLEncoding.DecodeString`) and check the decoded length, or scale the limit to account
for the 4/3 expansion.

  		dnsParam := r.URL.Query().Get("dns")
- 		if dnsParam == "" || len(dnsParam) > config.DefaultDOHMaxRequestSize {
+ 		if dnsParam == "" {
+ 			return nil, http.StatusBadRequest
+ 		}
+ 		if decoded, err := base64.RawURLEncoding.DecodeString(dnsParam); err == nil {
+ 			if len(decoded) > config.DefaultDOHMaxRequestSize {
  			return nil, http.StatusBadRequest
+ 			}
  		}


─── server/protocol/tls/https.go:175-178 ───
[bug · low] When `w.Write` returns a short write together with a non-nil error (which is what the
`io.Writer` contract requires for `n < len(bytes)`), the original error is discarded and replaced by
the `short write: ...` message, losing the underlying cause (e.g. `ErrClosedPipe`/connection reset)
for diagnostics. Preserve the cause with `%w` so callers can still inspect it via
`errors.Is`/`errors.As`.

  	n, err := w.Write(bytes) //nolint:gosec // G705: DNS wire format, not user-facing HTML
  	if n != len(bytes) {
- 		return fmt.Errorf("short write: %d/%d bytes", n, len(bytes))
+ 		return fmt.Errorf("short write: %d/%d bytes: %w", n, len(bytes), err)
  	}


─── server/protocol/tls/quic.go:250-261 ───
[bug · medium] req is unconditionally returned to the pool here, and response is later returned via
the deferred Put(response) with no identity guard. If a DNSHandler implementation (the
edns.DNSHandler interface does not forbid it) returns the same *dns.Msg it received, the identical
pointer is Put into the sync.Pool twice, so two concurrent pool users can Get the same message and
race on it. The comment even warns "req must not be double-Put", but nothing enforces it. Guard the
deferred Put so the same object is never pooled twice.

  	response := s.handler.ServeDNS(req, clientIP, true, config.ProtoQUIC)
  	// req is transferred to ServeDNS — response holds the result.
- 	// Both req and response are returned to the pool below and in
- 	// the caller; req must not be double-Put.
+ 	// The caller owns req and returns it to the pool exactly once.
  	pool.DefaultMessage.Put(req)

  	if err := s.respondQUIC(stream, response); err != nil {
  		log.Debugf("TLS: DoQ response failed: %v", err)
  	}
- 	if response != nil {
+ 	if response != nil && response != req {
  		defer pool.DefaultMessage.Put(response)
  	}


─── server/protocol/tls/tls.go:266-266 ───
[bug · high] The 16-bit DNS length prefix is written as `uint16(len(respBuf))`, but nothing here
bounds `len(respBuf)` before the cast. A response larger than 65535 bytes (e.g. a relayed large TCP
answer, a response augmented with DNSSEC/additional records, or a zone-transfer-style reply)
silently wraps the prefix, so the client reads the wrong frame length and the entire TCP/TLS stream
desynchronizes for all subsequent queries on this connection. Note the DTLS/DTLCP paths in this
codebase enforce a PMTU-based bound before framing; this DoT path has no equivalent guard, and the
`//nolint:gosec` rationale ('max 65535 fits uint16') is invalid because `len(respBuf)` is unbounded.
Fix: if `len(respBuf) > dns.MaxMsgSize` (or 65535), set the TC bit and truncate the message (RFC
2181 §9) or drop the response.

- binary.BigEndian.PutUint16(writeBuf[:zdnsutil.DNSFramePrefixLen], uint16(len(respBuf))) //nolint:gosec // G115: DNS length prefix — max 65535 fits uint16
+ if len(respBuf) > dns.MaxMsgSize {
+     // Cannot be framed in a 16-bit length prefix; truncate (set TC) or drop.
+     return
+ }
+ binary.BigEndian.PutUint16(writeBuf[:zdnsutil.DNSFramePrefixLen], uint16(len(respBuf)))
+ copy(writeBuf[zdnsutil.DNSFramePrefixLen:], respBuf)


─── server/protocol/tls/tls.go:62-76 ───
[security · medium] Every accepted TCP connection immediately spawns a handler goroutine in the
package-wide `serverGroup` (errgroup `SetLimit(DefaultServerGoroutineLimit = 1024)`), before the TLS
handshake even completes. The group limit is the only cap and it is shared by all listeners in this
package (DoT, DoQ, DoH, DoH3, DTLS). A TCP-connect flood of idle connections that never complete the
handshake holds a slot for the full `DefaultTCPPoolIdleTimeout` (60 s); once 1024 are held,
`errgroup.Group.Go` blocks inside the accept loop and every other protocol sharing the group stops
accepting, effectively taking down the whole TLS server family for up to 60 s per wave. Consider a
dedicated per-protocol connection cap (and/or a much shorter pre-handshake deadline) so a DoT flood
cannot starve the other TLS-family listeners.



─── server/resolver/dnssec/crypto.go:297-303 ───
[bug · high] Validation succeeds if any single RRset validates, not all RRSets. Groups whose records
have no RRSIG (`len(sigs) == 0`) are silently skipped with `continue`, and the final `return
anyValidated, nil` reports the whole response as validated as soon as one RRset verifies. A response
mixing one valid signed RRset with unsigned RRSets (e.g. a signed CNAME RRset whose target record
lives in an unsigned zone, or an on-path attacker injecting an unsigned record) is therefore marked
authenticated, and callers (recursive.go → isValidWithDNSSEC/validateOrRetry) propagate that as the
response's Validated/AD status. RFC 6840 §4.1 requires the AD bit to be cleared when any RRset in
the answer is unauthenticated. Track groups that fail to validate (no RRSIG / no matching verified
key) and return failure unless the group is deliberately deferred as a cross-zone CNAME target.



─── server/resolver/dnssec/crypto.go:108-111 ───
[maintainability · low] VerifyRRset (and its callers, which match DNSKEYs to RRSIGs only by key tag)
never checks that RRSIG.SignerName equals the DNSKEY owner name (RFC 4034 §3.1.1) or bears the
correct relationship to the RRset owner name. This invariant is enforced only implicitly inside
miekg/dns's RRSIG.Verify (ErrKeySigner). Given that this function already performs an explicit
manual RFC 4034 §3.1.5 validity-period check to produce distinct sentinel errors for EDE mapping,
add an explicit signer-name check here as well — both for defense in depth and so the invariant is
not silently dependent on library behavior.



─── server/resolver/dnssec/validate.go:21-25 ───
[security · high] The DNSSEC validation fallbacks in validate.go treat the mere presence of DNSSEC
records (or the upstream AD bit plus such records) as proof of validation. Because forward.go always
enables this with dnssecOK=true, an arbitrary plain-DNS forwarder (or on-path attacker) can supply
RRSIG/NSEC/NSEC3-looking records and a forged AD bit, causing unauthenticated responses to be marked
Validated and served with AuthenticatedData=true/cached as secure. Remove or strictly gate these
fallbacks (e.g. only trust AD from a known validating upstream over an authenticated transport); the
record-presence path must not set AD for clients.

  	// Fallback: upstream may have validated but not set AD (e.g. CD=1 query).
+ 	// Presence of DNSSEC record types is NOT proof of validation; only the
+ 	// cryptographic validator (CryptoValidator.IsResponseValid) can confirm it.
  	if hasDNSSECRecords(response) {
- 		log.Debugf("SECURITY: validated via DNSSEC records (no AD flag)")
- 		return true
+ 		log.Debugf("SECURITY: DNSSEC records present but AD not set; validation unconfirmed")
+ 		return false
  	}


─── server/resolver/dnssec_chain.go:123-126 ───
[security · high] When a delegation response contains no DS records, the code unconditionally treats
the delegation as insecure without any authenticated NSEC/NSEC3 proof that no DS exists, and without
checking whether the parent zone is signed. resolveZoneCut also collapses no DS, DS-to-DNSKEY
mismatch, and RRSIG-validation failure into (false,nil), so a bogus result is handled the same as a
legitimately insecure zone. This lets an on-path attacker strip a signed DS RRset and bypass
DNSSECEnforce. Require an authenticated denial before concluding a delegation is insecure, and
return a typed/sentinel result so bogus is not conflated with insecure.



─── server/resolver/dnssec_chain.go:504-504 ───
[bug · high] Data race / cross-query EDE contamination on Recursive.lastEDECode: Recursive is a
per-Resolver singleton shared by all concurrent queries, but lastEDECode is a plain uint16 written
in dnssec_chain.go/recursive_helpers.go, reset in recursive.go, and read by DNSSECEDECode(), without
synchronization. Concurrent in-flight queries (including parallel A/AAAA NS lookups) race on it, and
one query's DNSSEC EDE can leak into another query's response. Carry the EDE through per-query state
(dnssecChain/QueryResult) instead of the shared struct; DNSSECEDECode() should be removed or changed
to only reflect an explicitly query-scoped value.



─── server/resolver/dnssec_chain.go:188-193 ───
[security · critical] Offline-KSK fallback bypasses cryptographic authentication: when
`VerifyDelegationDS` fails, the DNSKEY set is accepted if (a) the DNSKEY RRSIG's 16-bit key tag
merely matches a parent DS key tag and (b) an *unauthenticated* CDS/CDNSKEY response matches the
public parent DS digest. The CDS/CDNSKEY records are queried from the same servers over the same
unsecured channel and are never RRSIG-verified (the code comments concede the RRSIG can't be
checked). An on-path attacker can generate a DNSKEY whose key tag collides with the DS key tag (2^16
space — trivial), sign a forged DNSKEY RRset with it, and replay the public DS digest in a forged
CDS response; no cryptographic break is required, and the forged keys then pass `IsResponseValid`
for the answer. The same pattern is repeated in `isDNSSECValid`'s `else if rrsigKeyTagMatchesDS(...)
&& r.verifyOfflineKSK(...)` branch, giving a complete DNSSEC chain-of-trust bypass. Fix: require
genuine cryptographic authentication of the child's DNSKEY material (e.g., verify CDS/CDNSKEY RRSIGs
against a key that is itself authenticated, or drop the fallback entirely).



─── server/resolver/dnssec_chain.go:227-230 ───
[bug · medium] Stale `parentDNSKEYs` used as fallback during DS verification: `updateDNSSECChain`
only assigns `chain.parentDNSKEYs = chain.zoneDNSKEYs` *after* `verifyDelegationDSRRSIG` returns, so
at the time of the fallback `parentDNSKEYs` still holds the previous delegation level's keys (or the
root trust anchors initialized in `resolve`). If `ensureZoneDNSKEYs` fails to obtain the current
parent's DNSKEYs (query timeout, cache miss), `zoneDNSKEYs` stays empty and the current delegation's
DS RRset is verified against the *previous* zone's keys — this always fails, marking valid
delegations as `dsPresentButUnverified` and then bogus (a false negative that breaks otherwise valid
resolutions). The fallback is only ever correct at the first (root→TLD) level. Fix: remove the
`parentDNSKEYs` fallback, or set `parentDNSKEYs` from `zoneDNSKEYs` before verification / scope it
to the current parent zone.



─── server/resolver/dnssec/extract.go:165-170 ───
[maintainability · medium] The `ttl` computed here (capped at config.DefaultDNSKeyCacheTTL = 86400s)
is never used: cache.Set derives the entry lifetime itself from the RR TTLs via minTTL(), capped at
config.DefaultMaxCacheableTTL (604800s). The intended 1-day DNSKEY cache cap is therefore silently
dropped — DNSKEYs with TTL in (86400, 604800] get cached for up to 7 days — and the whole loop is
dead code that misleads readers into thinking the TTL is enforced. Either remove the loop or clamp
each key's TTL (on a copy) before calling Set.

- 	ttl := config.DefaultDNSKeyCacheTTL
+ 	// cache.Set derives the entry TTL from the RR TTLs itself (minTTL,
+ 	// capped at DefaultMaxCacheableTTL). The ttl loop above is dead code
+ 	// and the intended DefaultDNSKeyCacheTTL cap is never applied.
+ 	rrKeys := make([]dns.RR, 0, len(keys))
  	for _, k := range keys {
- 		if k != nil && int(k.Header().TTL) > 0 && int(k.Header().TTL) < ttl {
- 			ttl = int(k.Header().TTL)
+ 		if k != nil {
+ 			rrKeys = append(rrKeys, k)
  		}
  	}


─── server/resolver/dnssec/extract.go:198-198 ───
[maintainability · low] slices.Clone copies only the slice header; the *dns.DNSKEY pointers returned
here are still shared with c.rootKeys. Any caller that mutates a returned key (e.g., TTL, Flags, or
PublicKey) corrupts the root trust anchors, which are security-critical validation state. Return
deep copies (k.Clone() per element) or document an explicit no-mutate contract.

- 	return slices.Clone(c.rootKeys)
+ 	keys := make([]*dns.DNSKEY, len(c.rootKeys))
+ 	for i, k := range c.rootKeys {
+ 		keys[i] = k.Clone()
+ 	}
+ 	return keys


─── server/resolver/dnssec/extract.go:43-43 ───
[bug · low] strings.EqualFold compares presentation-form strings, not DNS owner names. Two names
that are identical per RFC 4034 §6.1 can have different presentation forms (escaped labels such as
foo\.bar.example.com, non-ASCII/escaped octets, or a missing/extra trailing dot), so valid RRSIGs
can be silently dropped here. Use a DNS-aware name equality check (e.g., dns.IsSubDomain in both
directions, which also handles case) instead of EqualFold.

- 		if rrsig.TypeCovered == typeCovered && strings.EqualFold(rrsig.Header().Name, ownerName) {
+ 		if rrsig.TypeCovered == typeCovered && dns.IsSubDomain(ownerName, rrsig.Header().Name) && dns.IsSubDomain(rrsig.Header().Name, ownerName) {


─── server/resolver/dnssec/extract.go:149-153 ───
[bug · low] When lower == upper (an NSEC whose Next Domain equals its owner — RFC 4034 §4.1: the
record covers the entire namespace except the owner name itself), loUp == 0 falls through to `return
false`, so a valid single-name-zone NSEC proof is rejected for every name. Handle the loUp == 0 case
explicitly (covered unless name == lower).

  	if loUp > 0 {
  		return loName < 0 || naUp < 0
+ 	}
+ 	if loUp == 0 {
+ 		// RFC 4034 §4.1: Next Domain == owner covers the whole
+ 		// namespace except the owner name itself.
+ 		return loName != 0
  	}

  	return false


─── server/resolver/nameserver.go:190-201 ───
[bug · high] Race: when a NOERROR response is already buffered in resultChan and the errgroup
simultaneously completes (the sender returns immediately after sending + cancel()), both select
cases are ready and Go picks one uniformly at random. If `<-errgroupDone` is picked, the valid
NOERROR response is never consumed — it is neither returned to the caller nor Put back into
pool.DefaultMessage — and the query falls through to the NXDOMAIN/error fallback, returning a wrong
answer (e.g. NXDOMAIN for a name that actually resolved). Drain resultChan non-blockingly after the
select, before falling back to NXDOMAIN.

  	select {
  	case resp := <-resultChan:
  		if nx := nxdomainMsg.Load(); nx != nil {
  			pool.DefaultMessage.Put(nx)
  		}
  		if poisonRejected.Load() {
  			verdict = defense.VerdictPoisoned
  		}
  		return resp, verdict, nil
  	case <-errgroupDone:
  	case <-ctx.Done():
+ 	}
+
+ 	// Drain a NOERROR result that arrived concurrently with errgroupDone/ctx cancellation.
+ 	select {
+ 	case resp := <-resultChan:
+ 		if nx := nxdomainMsg.Load(); nx != nil {
+ 			pool.DefaultMessage.Put(nx)
+ 		}
+ 		if poisonRejected.Load() {
+ 			verdict = defense.VerdictPoisoned
+ 		}
+ 		return resp, verdict, nil
+ 	default:
  	}


─── server/resolver/nameserver.go:76-79 ───
[bug · high] EDNS/ECS options are silently dropped for every upstream query. buildMsg →
BuildQueryMsg → ednsH.ApplyToMessage stores EDNS(0) options (ECS SUBNET, cookie, padding) in
`msg.Pseudo` (the codeberg.org/miekg/dns v2 API — see edns/edns.go ApplyToMessage), but this
per-goroutine copy only copies Question/RD/CD/Security/UDPSize and never copies `Pseudo`. As a
result the ECS option the caller explicitly passed (for geo-aware resolution) never reaches the
authoritative servers, diverging from the forward path (forward.go:104) which sends buildMsg's
message directly. Copy Pseudo as well.

  			msg.RecursionDesired = baseMsg.RecursionDesired
  			msg.CheckingDisabled = baseMsg.CheckingDisabled
  			msg.Security = baseMsg.Security
  			msg.UDPSize = baseMsg.UDPSize
+ 			msg.Pseudo = append(msg.Pseudo, baseMsg.Pseudo...)


─── server/resolver/nameserver.go:71-76 ───
[bug · medium] Several paths return pooled memory (or slices/addresses aliasing it) to a global pool
before all consumers are done: nameserver.go goroutines copy baseMsg after
queryNameserversConcurrent returns and pool.Put zeroes it; recursive_helpers.go returns QueryResult
Authority/Additional slices aliasing a pooled response after Put; socks5/udp.go returns a net.Addr
whose IP slice aliases a pooled buffer that is cleared/returned before the caller reads it.
Concurrent reuse can corrupt returned/cached data or cause data races. Deep-copy (or delay the Put)
so no async consumer observes memory owned by the pool.



─── server/resolver/ns_addresses.go:89-90 ───
[bug · medium] The documented contract ("returns root server addresses ordered by probe latency") is
not satisfied. The root-server order is nondeterministic because `hints` comes from `loadHints()` (a
map ranged in random order), and `lookupNSAddrsFromCache` further concatenates all TypeA addresses
before all TypeAAAA addresses, so IPv6 records are always deprioritized regardless of measured
latency and each family is only sorted within its own cache entry — there is no global latency sort
across families/names. Since the caller `queryNameserversConcurrent` starts servers in slice order
(and cancels the remaining queries once the first success arrives), which root servers actually get
queried varies per query and is not the fastest set. Consider collecting the addresses for all root
names and sorting the combined slice by probe latency in one place.



─── server/resolver/ns_addresses.go:99-102 ───
[bug · low] If one or more root names fail to bootstrap (e.g., unparseable hint addresses are
skipped by `cacheRootHint`, or the cache write/read fails), `all` will be non-empty but incomplete
and `allRootAddrs()` is bypassed, silently returning a partial root-server set. Consider falling
back (or merging) whenever the collected count is below the expected hint count, e.g. `if len(all) <
len(hints) { merge in allRootAddrs() }`, so a transient failure of one name does not permanently
shrink the root set.



─── server/resolver/ns_addresses.go:125-126 ───
[performance · low] Performance: `getRootServers` runs at the top of every `resolve()` call
(including every recursion depth for NS-address, CNAME and DNSSEC-chain resolutions), and each call
re-walks all ~13 root names × 2 families through `cache.Get` (≈26 Badger `txn.Get` + wire unpack
operations) plus up to 13 background probe goroutines during the prefetch window — for a root-server
list that is effectively static. Consider memoizing the flattened, latency-sorted root address list
with a periodic refresh (e.g., re-read only when entries expire) instead of re-reading the cache on
every query.



─── server/resolver/probe/probe.go:112-113 ───
[bug · medium] The interval comparison here is effectively dead code: `LatencyLastProbe` as
implemented (cache/lifecycle.go:130) returns `log.NowUnix()` — the current wall clock — whenever a
latency key exists, not the timestamp of the last probe. So when `ok == true`, `now-lastProbe` is
always ≈0 and `now-lastProbe >= DefaultLatencyProbeMinInterval` can never be true. Re-probing is
actually gated only by the latency key's TTL (2×interval, set in `UpdateLatency`), so an IP is never
re-probed until its key expires, and then the whole set is re-probed together. Either have the cache
return the real last-probe timestamp, or drop the interval arithmetic and document the TTL-gated
behavior. Same pattern exists in `ProbeNSAddrs` below.



─── server/resolver/probe/probe.go:106-107 ───
[bug · medium] The comment claims each IP is checked individually and shared/CDN IPs are deduped
globally, but this loop is all-or-nothing: `allRecent` is only false when at least one IP is stale,
in which case the *entire* unfiltered `answer` is probed — including IPs that were measured very
recently. Any single stale/unknown IP forces a full re-probe of all addresses (and writes new
latency rows for fresh ones too), defeating the stated per-IP global dedup. `ProbeNSAddrs` below
already builds a `needProbe` list; `Start`/`probeAndReorder` should do the same — filter to stale
IPs first, then probe only those — instead of passing the whole answer.



─── server/resolver/probe/probe.go:123-124 ───
[bug · low] The in-flight dedup key is only `qname+qtype`. Two concurrent responses for the same
qname with a different ECS scope or a different IP set are collapsed: the second response is skipped
even though its IPs were never covered by the first probe, so newly-appeared (stale) IPs can go
unprobed until the next cache miss. Relatedly, `ecsResponse` is threaded through `Start` into
`probeAndReorder` but never used there — it's a dead parameter that hints the ECS-aware behavior was
planned but not implemented. Consider keying the singleflight on the actual IP set being probed
(like `buildNSProbeKey` does for `nsPending`) and/or incorporating ECS, or remove the unused
parameter.



─── server/resolver/probe/probe.go:143-143 ───
[maintainability · low] `probeAndReorder` never reorders anything: it discards the `sorted` return
of `ProbeIPsLatency` and only calls `UpdateLatency`. The actual A/AAAA reorder happens later in the
cache read path (`sortAnswerByLatency` in cache/store.go, driven by the `ip_latency` values written
here), so the flow is correct but the name and the package/struct comments ("reorders A/AAAA records
in the cache") are misleading. Rename to something like `probeAndUpdateLatency`, or document that
reordering is applied by the cache at Get/Set time.



─── server/resolver/dnssec/trust_anchor.go:68-69 ───
[security · medium] Trust-anchor validity windows are not enforced safely: kd.ValidFrom is never
parsed, so future/published KSKs are trusted early, and an unparseable kd.ValidUntil is logged as
accepting as valid and kept. For a security-critical trust store this should fail closed: skip keys
before their validFrom and skip keys with malformed/expired validUntil.

+ 		// Skip keys that are not yet valid.
+ 		if kd.ValidFrom != "" {
+ 			validFrom, err := time.Parse(time.RFC3339, kd.ValidFrom)
+ 			if err != nil {
+ 				log.Debugf("SECURITY: unparseable validFrom for trust anchor key_tag=%d: %v — skipping", kd.KeyTag, err)
+ 				continue
+ 			}
+ 			if now.Before(validFrom) {
+ 				log.Debugf("SECURITY: skipping trust anchor that is not yet valid (key_tag=%d, valid_from=%s)", kd.KeyTag, kd.ValidFrom)
+ 				continue
+ 			}
+ 		}
+
  		// Skip expired keys.
  		if kd.ValidUntil != "" {


─── server/resolver/dnssec/trust_anchor.go:98-99 ───
[security · low] The XML `KeyDigest`/`KeyTag` fields are parsed but never cross-checked against the
reconstructed DNSKEY. A corrupt or tampered file whose `PublicKey` disagrees with `Digest` (or whose
computed key tag differs from `KeyTag`) is silently trusted, defeating the integrity check RFC 7958
§3.2 intends the digest to provide. Consider verifying `dnskey.KeyTag() == kd.KeyTag` and that the
DS digest (`Digest`, `DigestType`) matches the reconstructed key before appending.



─── server/resolver/dnssec/nsec.go:342-344 ───
[bug · high] RFC 5155 §9.2 does not make an Opt-Out proof bogus — it only requires that the AD bit
NOT be set. Returning ErrBogusSignature here causes valid responses from Opt-Out zones (e.g.
.com/.org) to be treated as validation failures by callers (see dnssec_chain.go), which can force
retries or SERVFAIL for perfectly valid NXDOMAIN/NODATA answers. Moreover,
`hasOptOutInProof(nsec3s)` inspects ALL raw NSEC3 records in the authority section, not just the
records actually used (and RRSIG-verified) in the proof, so a single irrelevant Opt-Out NSEC3 in the
response rejects an otherwise clean proof. Fix: the function's contract is "is the denial
cryptographically valid" — an Opt-Out proof is valid, so return success here and let the caller
suppress the AD bit; at minimum, only inspect the verified subset used in the proof.

  		if hasOptOutInProof(nsec3s) {
- 			return false, fmt.Errorf("%w: NSEC3 Opt-Out proof for %s of %s — AD bit suppressed (RFC 5155 §9.2)", ErrBogusSignature, denialType, qname)
+ 			// RFC 5155 §9.2: Opt-Out only suppresses the AD bit; the denial
+ 			// proof itself is cryptographically valid.
+ 			log.Debugf("SECURITY: NSEC3 Opt-Out proof for %s of %s — AD bit suppressed", denialType, qname)
+ 			return true, nil
  		}


─── server/resolver/dnssec/nsec.go:318-320 ───
[bug · medium] Silently capping `iterations` to config.DefaultMaxNSEC3Iterations (150) changes the
hash input: the hash is no longer what the zone actually computed with its declared Iterations, so
`matchNSEC3`/`hasNSEC3Covering` can never match any real NSEC3 owner name. Legitimate zones using
higher iteration counts (RFC 5155 §10.3 permits 500 for 2048-bit and 2500 for 4096-bit keys) are
therefore falsely rejected as bogus. The cap should be an explicit policy decision (e.g. return a
distinct "unsupported NSEC3 parameters" result/error and fail closed), not a silent alteration of
the NSEC3 parameters.

  	if iterations > config.DefaultMaxNSEC3Iterations {
- 		iterations = config.DefaultMaxNSEC3Iterations
+ 		// Do not silently change the hash input: hashing with a different
+ 		// iteration count can never match the zone's NSEC3 owner names.
+ 		// Fail closed on unsupported parameters instead.
+ 		return ""
  	}


─── server/resolver/dnssec/nsec.go:237-237 ───
[bug · medium] RFC 5155 §8.4/§8.5 require that the NSEC3 covering the next-closer name must NOT have
the Opt-Out flag set; if it does, the closest-encloser proof is indeterminate (the name may exist
below an insecure delegation) and NXDOMAIN/NODATA must not be concluded from it.
`hasNSEC3Covering`/`findClosestEncloser` never inspect `Flags`, so a proof whose only next-closer
cover is an Opt-Out NSEC3 is accepted as a normal denial. The only protection today is the later
all-or-nothing rejection in `isDenialOfExistenceValid`, which is stricter than the spec (it also
rejects proofs that never relied on an Opt-Out cover). Filter Opt-Out cover records here so only the
records actually relied upon drive the AD-suppression decision per §9.2.



─── server/resolver/dnssec/nsec.go:66-70 ───
[bug · medium] The NSEC NODATA path only accepts an NSEC whose owner exactly equals QNAME. Per RFC
4035 §5.4 / §3.1.3.4, wildcard-expanded NODATA (QNAME does not exist, `*.zone` exists without QTYPE)
is proven by the NSEC at the wildcard owner `*.zone` whose bitmap lacks QTYPE/CNAME — that NSEC's
owner is not equal to QNAME, so such valid responses are rejected as bogus here. Note the NSEC3 path
already implements the analogous wildcard NODATA case (matchesNSEC3NODATA §8.7), but plain NSEC
responses have no equivalent. Add a wildcard-ancestor case: owner is `*.`+an ancestor of
normalizedQname with qtype and CNAME absent.



─── server/resolver/forward.go:214-230 ───
[bug · high] Multi-tag CIDR filtering in forward.go uses OR semantics via accept-on-first-match,
which is inconsistent with the AND semantics used elsewhere for ! tags. A record inside tagB but
outside tagA with Match ['!tagA','!tagB'] is accepted on the first rule, bypassing the second
negated rule; the negate field is never actually used. Require every pre-filtered tag to be
satisfied (or explicitly evaluate each tag's polarity) so negated tags cannot be short-circuited.

- 		accepted := false
- 		hasIPTag := false
- 		ipStr := ip.String()
+ 		accepted := len(ipTags) == 0
  		for _, t := range ipTags {
- 			hasIPTag = true
  			matched, exists := r.crd.MatchIP(ipStr, t.raw)
  			if !exists {
  				return nil, true
  			}
- 			if matched {
- 				accepted = true
+ 			if !matched {
+ 				accepted = false
  				break
- 			}
  		}
- 		if !hasIPTag {
- 			accepted = true
  		}


─── server/resolver/forward.go:273-273 ───
[bug · low] EDE attribution race: `lastUpstreamEDE` is one atomic shared by all parallel upstream
goroutines. `captureUpstreamEDE` Stores the EDE of the current response, but the winning goroutine
here does `lastEDE.Load()` at send time — between the capture and this Load, a *different* upstream
(e.g. a slower SERVFAIL/DNSSEC-bogus responder) can Store its EDE. The result then carries an EDE
that does not belong to the chosen response, and downstream (`cache_store.go`/client) will misreport
the EDE as coming from `serverDesc`. Same issue on the NXDOMAIN fallback path.

Fix: have `captureUpstreamEDE` return the copied EDE for this response and carry that value directly
into the `QueryResult` (per-goroutine local), instead of reloading the shared atomic.



─── server/resolver/resolver.go:275-278 ───
[bug · medium] concurrencyLimit is non-monotonic at the tier boundaries: concurrencyLimit(12)=8 but
concurrencyLimit(13)=7, and concurrencyLimit(20)=10 but concurrencyLimit(21)=max(21/3,8)=8. Adding a
21st upstream therefore *reduces* the fan-out limit from 10 to 8 (same drop at 12→13). This is
likely an unintended artifact of switching formulas between tiers. Consider using a single
continuous formula, or clamp each tier's result to be at least the value for serverCount-1 (e.g.
cap/floor against the previous tier), so adding servers never lowers concurrency.



─── server/resolver/resolver.go:198-206 ───
[maintainability · low] The guard flags (spoofguard/splitguard/poisonguard/hopguard) and
recursiveProxyURL are written with plain assignments while the server list itself is swapped
atomically via upstreamSet.store(). Today the only production caller is init.go (startup-only, so no
live race), but the atomic server set strongly implies reload support is intended — a reload that
runs while queries are in flight would race with the hot-path reads of these fields in
nameserver.go/recursive.go (r.spoofguard, r.poisonguard, r.recursiveProxyURL). Additionally, the
`r.recursive.x = r.recursive.x || s.X` accumulation means a reload cannot ever disable a previously
enabled guard, and the last recursive server's non-empty proxy silently wins. If reload is not
planned, the atomic server swap is dead complexity; otherwise these fields need atomic/synchronized
updates and the accumulation logic needs to be replaced by plain assignment from the new config.



─── server/resolver/root_hints.go:49-54 ───
[bug · high] sync.Once permanently caches a failed initialization: if `ResolveDataFile` fails (e.g.,
named.root is absent at startup and the download from internic.net transiently fails) or
`os.ReadFile` fails, the `func()` still completes, so every later `loadHints()` call returns the
permanently empty map and recursive resolution silently runs with zero root servers for the rest of
the process lifetime. Note `LoadRootHints` is invoked exactly once during server init and returns no
error, so the failure is invisible and unrecoverable. Use a mutex-guarded load that retries on
failure (as in the suggestion) or surface the error from `LoadRootHints`/`loadHints` so the caller
can react.

+ var (
+ 	rootHints   map[string][]string
+ 	rootHintsMu sync.RWMutex
+ )
+
+ // loadHints returns the root server hints, (re)loading from named.root until
+ // the load succeeds. Returns an empty map on failure; later calls retry.
+ func loadHints() map[string][]string {
+ 	rootHintsMu.RLock()
+ 	hints := rootHints
+ 	rootHintsMu.RUnlock()
+ 	if hints != nil {
+ 		return hints
+ 	}
+
+ 	rootHintsMu.Lock()
+ 	defer rootHintsMu.Unlock()
+ 	if rootHints != nil { // double-checked: another goroutine may have loaded already
+ 		return rootHints
+ 	}
+ 	rootHints = make(map[string][]string)
+
+ 	path := zdnsutil.ResolveDataFile(rootHintsFileName, rootHintsURL)
+ 	if path == "" {
+ 		log.Errorf("RECURSION: cannot determine root hints path — no root hints loaded")
+ 		return rootHints
+ 	}
  		hints, err := loadRootHintsFromFile(path)
  		if err != nil {
  			log.Errorf("RECURSION: failed to load root hints from %s: %v", path, err)
- 			return
+ 		return rootHints
  		}
  		rootHints = hints
+ 	log.Infof("RECURSION: loaded %d root server(s) from %s", len(hints), path)
+ 	return rootHints
+ }


─── server/resolver/root_hints.go:77-80 ───
[maintainability · medium] Lines that fail `dns.New` are skipped silently. A single
malformed/truncated line in named.root drops that root server's records without any diagnostic; if
enough lines are corrupted, resolution degrades to only the generic 'no root servers found' error,
giving operators no hint of the partial corruption. Log skipped lines (at debug level) so partial
data loss is observable.

  		rr, err := dns.New(line)
  		if err != nil {
+ 			log.Debugf("RECURSION: skipping malformed root hints line %q: %v", line, err)
  			continue
  		}


─── server/resolver/root_hints.go:97-102 ───
[maintainability · low] The returned `hints` map keys preserve the original (usually uppercase) case
of the NS targets while every other name key in this file (`aRecords`) and DNS names generally are
lowercased. Today's consumers (`getRootServers`/`allRootAddrs`) only range over the map, so nothing
misses yet, but this is a latent case-sensitivity trap: any case-sensitive index into the returned
map by a lowercased name (or cache entries keyed by these names) will silently miss root servers.
Normalize the keys when building the map so the output contract is case-consistent.

  	for name := range nsNames {
  		key := strings.ToLower(name)
  		if addrs := aRecords[key]; len(addrs) > 0 {
- 			hints[name] = addrs
+ 			hints[key] = addrs
  		}
  	}


─── server/server.go:87-91 ───
[bug · high] After `database.Open` succeeds, every subsequent error return in `New` (initEDNS,
initZoneAndRulesets, initDNSResolver, initProtocolListeners) returns without closing `db` (or the
`cacheStore` that owns it). BadgerDB holds an exclusive directory lock and spawns background
goroutines, so a failed `New` leaks the handle and a retried `New()` will fail to re-open the DB
(directory lock still held). Close `db` on all failure paths before returning, e.g. track success
and `defer func() { if !ok { _ = db.Close() } }()` right after `initDatabase` succeeds.



─── server/server.go:314-317 ───
[maintainability · medium] The doc comment states protocol init errors are non-fatal ('the server
starts with the protocols that initialised successfully'), but the implementation returns each
error, aborting `New()` and startup entirely. Worse, if TLS initializes successfully and a later
protocol (DNSCrypt/TLCP) fails, `s.tls` is already assigned while `New` returns an error — the
partial listener is unreachable for any cleanup and no one can shut it down. Either make these
errors non-fatal as documented (log a warning and continue with the protocols that succeeded) or, if
fail-fast is intended, fix the comment and clean up already-created listeners (and the open DB, see
the `New` leak) before returning.



─── server/server.go:372-377 ───
[bug · medium] The pprof HTTP server is created with a nil Handler, which makes `http.Server` fall
back to `http.DefaultServeMux`. However, neither this file nor any other file in the codebase
imports `net/http/pprof` (or registers `/debug/pprof/` handlers on any mux), so the listener starts
and accepts connections but returns 404 for every path — the feature advertised in `displayExtras`
is silently broken. Add the blank import `_ "net/http/pprof"` (which registers handlers on
`http.DefaultServeMux`) or explicitly register the pprof handlers on a dedicated `http.ServeMux`
assigned to `Handler`.



─── server/resolver/recursive_ns.go:86-95 ───
[bug · medium] If cache or glue provides addresses for even a subset of the delegation's NS names,
`len(result.addrs) > 0` short-circuits `resolveNSAddressesConcurrent`, so NS names that have neither
cached addresses nor glue in this referral are silently dropped. The resolver then queries only a
partial set of the delegation's servers; if all of those happen to be unreachable, resolution fails
even though the remaining NS servers could have been resolved independently (see also audit finding
R3-RES-05, which flagged the same short-circuit in this function). Track the NS names not covered by
cache/glue and resolve only those independently, merging the results.

- 	// Use glue records directly when available; only fall back to independent
- 	// NS resolution when the delegation has no glue.
- 	if len(result.addrs) == 0 {
- 		result.addrs = r.resolveNSAddressesConcurrent(ctx, bestNSRecords, qname, depth, forceTCP)
- 		if len(result.addrs) > 0 {
+ 	// Resolve independently any NS names not covered by cache or glue, so a
+ 	// partial cache/glue hit never drops the remaining delegation targets.
+ 	uncovered := make([]*dns.NS, 0, len(bestNSRecords))
+ 	for _, ns := range bestNSRecords {
+ 		nsName := dnsutil.Fqdn(ns.Ns)
+ 		if cachedNSNames[nsName] || len(result.glue[nsName]) > 0 {
+ 			continue
+ 		}
+ 		uncovered = append(uncovered, ns)
+ 	}
+ 	if len(uncovered) > 0 {
+ 		resolved := r.resolveNSAddressesConcurrent(ctx, uncovered, qname, depth, forceTCP)
+ 		if len(resolved) > 0 {
+ 			result.addrs = append(result.addrs, resolved...)
+ 			if result.source == "" {
  			result.source = "resolution"
  		}
- 	} else if result.source == "" {
+ 		}
+ 	}
+ 	if result.source == "" && len(result.addrs) > 0 {
  		result.source = "glue"
  	}


─── server/resolver/recursive_ns.go:42-45 ───
[performance · low] `bestNSRecords` can contain the same NS target more than once (duplicate NS
records in a response, or the same RRset appearing in both Answer and Authority), and distinct NS
names can share an address. The cache loop appends without any seen-set (`cachedNSNames` is only
consulted by the glue loop below), so `result.addrs` can carry duplicate "ip:port" entries.
Downstream `queryNameserversConcurrent` then issues redundant queries to the same server, which can
crowd out unique servers under `DefaultMaxConcurrentNS`. Skip NS names already satisfied by the
cache in this loop (as the glue loop already does) and optionally de-duplicate the final address
list.

  		nsName := dnsutil.Fqdn(ns.Ns)
+ 		if cachedNSNames[nsName] {
+ 			continue // duplicate NS target — addresses already appended
+ 		}
  		cached := r.lookupNSAddrsFromCache(nsName, nil)
  		if len(cached) > 0 {
  			result.addrs = append(result.addrs, cached...)


─── server/resolver/recursive.go:97-102 ───
[bug · medium] Poison-verdict handling in the root-domain branch is inconsistent with the main loop.
queryNameserversConcurrent can return VerdictPoisoned with err == nil (a winning NOERROR response
while another server's answer was rejected as hijack, nameserver.go:195-198). Here the forced-TCP
restart only fires inside the `err != nil` path, so a successful-but-poisoned UDP response for the
root zone is served and cached as-is, defeating poisonguard at this level. The main loop restarts
the entire resolution via TCP on any VerdictPoisoned regardless of err. Apply the same fallback
(Putting the response) before processing a successful poisoned root response.



─── server/resolver/recursive.go:339-344 ───
[bug · low] Multi-hop CNAME chains in a single answer lose intermediate CNAME records. When an
authoritative server synthesizes a full chain (e.g. CNAME1: name1→name2, CNAME2: name2→name3, plus
the final A/AAAA), the loop breaks on the first iteration because hasTargetType is true, and this
collection predicate only keeps records whose owner equals currentQuestion.Name or whose type equals
question.Qtype — CNAME2 (owner name2) is dropped from allAnswers. The served answer is then
incomplete/non-RFC-compliant. Consider collecting every CNAME record that participates in the chain
(e.g. all CNAMEs in qr.Answer whose owner is an alias being followed), not just those matching the
current owner.



─── server/tasks.go:124-126 ───
[bug · high] Race: the sweep can delete a tcpWriteMu entry that a request goroutine still holds,
breaking per-address write serialization. In bridge.go a writer does LoadOrStore synchronously but
only calls entry.lastAccess.Store() deep inside the async handler goroutine (after ServeDNS
returns). Any freshly-created entry has lastAccess==0, which is always < cutoff, so an in-flight
request whose response hasn't been packed yet is indistinguishable from stale. After Delete, the
next request for the same addr:port LoadOrStores a brand-new entry with a fresh writeMu channel —
both writers then hold different mutexes and can write to the same TCP connection concurrently,
corrupting the DNS stream. Fix by tracking in-flight usage, e.g. an atomic refcount (or per-entry
mutex) incremented before the goroutine starts and decremented on exit, and only deleting entries
with zero refs; or guard the delete with entry-level synchronization re-checking lastAccess/refs.



─── server/tasks.go:86-87 ───
[bug · low] The initial refreshECSOnce() runs before this goroutine ever checks
backgroundCtx.Done(). If shutdown is requested during startup (signal or cancel shortly after New),
this still performs an uncancelled network IP-detection refresh and backgroundGroup.Wait() in
shutdownServer blocks until it completes. Prefer checking cancellation before the first refresh
(e.g. select on backgroundCtx.Done() first) or passing a cancellable context into refreshECSOnce.



─── server/tasks.go:171-172 ───
[maintainability · low] Unlike the TLS/DNSCrypt/pprof/TLCP shutdown paths, a failed or timed-out
plain listener drain is completely unobservable here: plain.Server.Shutdown returns no error and
silently ignores each miekg dns.Server.Shutdown result, so shutdownServer logs neither success nor
failure for the plain listeners. If the 15s shutdownCtx expires while draining idle TCP keepalive
connections, the failure is invisible. Consider having plain.Shutdown return the first listener
error (or log per-listener errors in plain) so the drain result is surfaced consistently with the
other protocol servers.



─── server/resolver/qname_minimise.go:102-115 ───
[bug · low] The proportional phase exposes ALL remaining labels at `stepsTaken ==
minimisationCount-1`, i.e. one step before the documented boundary (`stepsTaken >=
minimisationCount` at line 71). Trace with the defaults (minimisationCount=10, minimiseOneLabel=4,
remainingLabels=9): at stepsTaken=9, stepsInPhase = 9-4+1 = 6 = remainingSteps, so cumPhase becomes
perStep*6 + remainder = labelsLeft, and the function returns 4+5 = 9 = remainingLabels. The
early-return at line 71 therefore never actually introduces full exposure — the full QNAME is sent
to the current (often non-authoritative, e.g. TLD) nameservers one query earlier than RFC 9156
§2.3's growth schedule and this function's own doc comment intend, skipping the last partial-growth
step and slightly weakening QNAME-minimisation privacy. Consider holding back one label in the
proportional phase (e.g. cap cumPhase at labelsLeft-1) so the full QNAME is only exposed once
stepsTaken >= minimisationCount.

  	perStep := labelsLeft / remainingSteps
  	remainder := labelsLeft % remainingSteps

  	// Cumulative exposure: one-label base + proportional share so far.
  	cumPhase := perStep * stepsInPhase
  	// Distribute remainder across the LAST steps (largest steps get +1).
  	if stepsInPhase > remainingSteps-remainder {
  		cumPhase += stepsInPhase - (remainingSteps - remainder)
  	}
- 	if cumPhase > labelsLeft {
- 		cumPhase = labelsLeft
+ 	// Hold back one label so the full QNAME is only exposed once
+ 	// stepsTaken >= minimisationCount (the early-return branch above).
+ 	if cumPhase >= labelsLeft {
+ 		cumPhase = labelsLeft - 1
  	}

  	return minimiseOneLabel + cumPhase


─── server/resolver/qname_minimise.go:24-29 ───
[bug · low] When `labelsToAdd == 0` and this fallback branch is taken (root zone, empty currentZone,
or a zone the QNAME is not below), the loop body never runs, so `offset` stays `len(fqOrig)` and the
function returns `fqOrig[len(fqOrig):]` — an empty string, which is an invalid QNAME (an empty name
would be sent in the query question). Today the only caller (`applyQnameMinimisation`) cannot
produce this input — `labelsToAdd` returns 0 only when the zone has >= labels than the QNAME, which
is handled by the labels-equal branch above — so this is a latent edge case, but the helper's
contract should still return the zone ('.' at root) rather than an empty name. Add a guard before
the Prev loop.

+ 		// No labels beyond the zone: return the zone itself (root returns ".")
+ 		// instead of an invalid empty QNAME.
+ 		if labelsToAdd <= 0 {
+ 			return fqZone
+ 		}
  		// Take the rightmost labelsToAdd labels using Prev
  		offset := len(fqOrig)
  		for range labelsToAdd {
  			offset, _ = dnsutil.Prev(fqOrig, offset) // safe: fqOrig is a valid FQDN, Prev walks backwards from end
  		}
  		return fqOrig[offset:]


─── server/upstream/dnscrypt/cert.go:58-60 ───
[bug · high] Multiple upstream transport paths perform blocking socket I/O (TCP/UDP/DTLS/TLCP/TLS
handshakes, CONNECT, DNS message read/write) without applying the caller's context
deadline/cancellation. A cancel-only context or a stalled peer leaves the goroutine blocked
indefinitely, leaking it and hanging resolution past the configured timeout. Apply deadlines derived
from ctx/c.timeout to all socket operations (or watch ctx.Done() and close the conn) so cancellation
interrupts I/O even without an explicit deadline.

+ 	d := net.Dialer{}
+ 	conn, err := d.DialContext(ctx, "udp", addr)
+ 	if err != nil {
+ 		return nil, fmt.Errorf("dial udp: %w", err)
+ 	}
+ 	defer func() { _ = conn.Close() }()
+
+ 	// Ensure a canceled context interrupts blocking reads even without a deadline.
+ 	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
+ 	defer stop()
+
  	if deadline, ok := ctx.Deadline(); ok {
  		_ = conn.SetDeadline(deadline)
  	}


─── server/upstream/dnscrypt/cert.go:43-45 ───
[bug · medium] When a UDP response is truncated (TC=1) and the TCP fallback fails, the code returns
the truncated UDP response with a nil error, so callers treat it as a complete answer and
serve/cache it. Propagate the TCP fallback error (and discard/pool the truncated response) instead
of silently returning partial data.

- 		// TCP failed but the truncated UDP response is better than nothing.
+ 		// TCP failed and the UDP response is incomplete — do not report success.
  		log.Debugf("UPSTREAM: DNSCrypt cert TCP retry failed: %v", tcpErr)
- 		return resp, nil
+ 		return nil, fmt.Errorf("udp response truncated and tcp retry failed: %w", tcpErr)


─── server/upstream/dnscrypt/cert.go:66-67 ───
[bug · high] Several upstream read paths use a small fixed-size buffer or a single read and then
reject/truncate legitimate large DNS responses: DNSCrypt cert reads use 512 bytes despite
advertising 4096; DTLCP/TLCP and DTLS read once into an 8192-byte pooled buffer. Large DNSSEC/EDNS0
responses are silently truncated or treated as hard errors, forcing unnecessary fallbacks. Size the
buffer to the maximum DNS message size and read the full datagram/frame (looping for stream
transports) before returning.

- 	buf := make([]byte, config.DefaultDNSCryptResponseBuffer)
+ 	buf := make([]byte, config.DefaultDNSCryptUDPSize) // must cover the EDNS0 UDPSize (4096) advertised in the cert query
  	n, err := conn.Read(buf)
+ 	if err != nil {
+ 		return nil, fmt.Errorf("read: %w", err)
+ 	}
+ 	// UDP drops datagram bytes beyond the buffer silently; a full buffer is a
+ 	// possible truncation, so surface it and let the caller retry over TCP.
+ 	if n >= len(buf) {
+ 		return nil, fmt.Errorf("read: possible datagram truncation (%d bytes read of %d buffer)", n, len(buf))
+ 	}


─── server/upstream/plain/client.go:27-36 ───
[maintainability · low] The `timeout` field is stored by New but never read anywhere in the `plain`
package: ExecuteTCP/ExecuteUDP rely entirely on the caller-provided context deadline, and
`executeUDPMultiRead` hardcodes `config.DefaultDNSQueryTimeout` for its `maxDeadline`. A caller
passing a different timeout to plain.New would have it silently ignored, which is misleading API
surface. Either use this value (e.g. derive the multi-read maxDeadline from it) or drop the
parameter/field.

- func New(udpClient, tcpClient *dns.Client, tcpPool *pool.ConnPool, getProxy func(*config.UpstreamServer) *socks5.Dialer, timeout time.Duration) *Client {
- 	return &Client{
- 		udpClient: udpClient,
- 		tcpClient: tcpClient,
- 		tcpPool:   tcpPool,
- 		getProxy:  getProxy,
- 		timeout:   timeout,
- 		hopGuard:  defense.NewHopGuard(),
- 	}
- }
+ 	timeout   time.Duration


─── server/upstream/plain/client.go:27-28 ───
[maintainability · low] New accepts pointer/function dependencies without nil validation, yet the
query paths dereference them unconditionally: ExecuteUDP calls c.getProxy(server) (nil function call
→ panic) and c.udpClient.Exchange (nil pointer dereference), and ExecuteTCP does the same for
c.tcpClient. Today's only call site (upstream.New, server/upstream/client.go:122) always passes
non-nil values, so this is a latent robustness gap rather than an active bug — but note Close() is
nil-guarded while the Execute* methods are not. Consider validating in New (or documenting the
non-nil contract) so a future refactor can't construct a Client that panics on first query.



─── server/upstream/client.go:191-196 ───
[bug · low] Any protocol that is not TCP, secure, or DNSCrypt — including an empty string or a
typo'd value — silently falls through to `ExecuteUDP`, sending plaintext DNS. This dispatch does not
fail closed: config/validate.go only rejects non-empty unknown protocols and there is no
normalization of an empty `protocol` to `ProtoUDP` (config/load.go), so a misconfigured upstream is
silently served over plaintext UDP. Mirror `executeSecureQuery`'s `default` branch and reject
anything other than `ProtoUDP`/`ProtoTCP` here (or explicitly normalize an empty protocol if UDP is
intended).

  	} else {
- 		if protocol == config.ProtoTCP {
+ 		switch protocol {
+ 		case config.ProtoTCP:
  			result.Response, result.Error = c.plainClient.ExecuteTCP(queryCtx, msg, server)
- 		} else {
+ 		case config.ProtoUDP:
  			result.Response, result.Error = c.plainClient.ExecuteUDP(queryCtx, msg, server)
+ 		default:
+ 			result.Error = fmt.Errorf("unsupported protocol: %s", server.Protocol)
+ 			result.Duration = time.Since(start)
+ 			return result
  		}


─── server/upstream/client.go:294-297 ───
[maintainability · low] Unlike plainClient, tlsClient, and dnscryptClient, `c.tlcpClient` is never
closed here. The TLCP client owns an LRU map of per-server `*http.Client` objects with open idle
connections plus two LRU session caches (tlcp/client.go), which are only released on LRU eviction —
so at shutdown those idle connections and sessions stay open. Add a `Close` to the tlcp client
(range the cached clients and call `CloseIdleConnections`) and invoke it here, or close the cached
clients directly from this method.



─── server/upstream/client.go:305-305 ───
[bug · low] `Close()` writes `c.proxyDialers = nil` with no synchronization, while `proxyDialer()`
(warmup.go) reads the field from in-flight `ExecuteQuery` goroutines. The shutdown path in
server/tasks.go only waits for warmup goroutines (`warmWg.Wait()`) and cache-refresh tasks; it does
not join in-flight query handlers, so a query running during shutdown can race on this field
(nil-check + LRU map access). Guard the field with a mutex/atomic or guarantee no queries are in
flight before `Close` is called.



─── server/upstream/client.go:265-266 ───
[bug · low] The DTLS→TLS (and DTLCP→TLCP) fallback reuses the same `ctx`, whose deadline may already
have been exhausted by the failed DTLS attempt (e.g. `context.DeadlineExceeded`), so the fallback
can fail immediately with the same timeout error. The other fallback paths in this file (DNSCrypt
and plain UDP→TCP) deliberately create a fresh `context.WithTimeout(ctx, c.timeout)` for exactly
this reason. Apply the same fresh-context approach here so the fallback actually gets a chance to
complete.



─── server/resolver/zonecut.go:37-43 ───
[bug · high] In-zone records signed by the zone itself are stripped as cross-zone. dnsutil.IsBelow
is a strict-subdomain test: it returns false when the RRSIG signer equals fqZone (equal names). Both
call sites pass currentDomain as `zone`, and in the normal path (recursive_helpers.go:200)
currentDomain is the zone apex that signed the answer, so every validated in-zone record (signer ==
currentDomain) falls into the `else` branch and is removed — the returned Answer ends up containing
only RRSIG records (RRSIGs have no covering RRSIG and pass the `len(sigs)==0` branch). The filter as
written only keeps records signed by a strict subdomain of the zone, i.e. the zone-cut case. Treat a
signer equal to the zone as in-zone as well.

  		inZone := false
  		for _, sig := range sigs {
- 			if dnsutil.IsBelow(fqZone, dnsutil.Fqdn(sig.SignerName)) {
+ 			sigZone := dnsutil.Fqdn(sig.SignerName)
+ 			if dns.EqualName(sigZone, fqZone) || dnsutil.IsBelow(fqZone, sigZone) {
  				inZone = true
  				break
  			}
  		}


─── server/resolver/zonecut.go:156-164 ───
[security · high] The child DNSKEY RRset is never authenticated. VerifyDelegationDS only proves that
ONE KSK in the set matches the parent-verified DS; the remaining dnskeyRecords (extra ZSKs or
injected keys) are then cached via CacheZoneKeys and passed to IsResponseValid with no check of the
DNSKEY RRset's own RRSIG. IsResponseValid (crypto.go:244-260) accepts ANY key in the slice whose
KeyTag matches the answer RRSIG, so an attacker who can inject/spoof the DNSKEY response (e.g. an
off-path answer to the DNSKEY query) can append their own key and use it to validate a forged
answer. CryptoValidator.SelfVerifyDNSKEY already exists and is used in dnssec_chain.go (root /
offline-KSK paths) but is not called here. Verify the DNSKEY RRset self-signature with the
DS-matched key before caching or using the key set.

  	matchedKey, dsMatchErr := crypto.VerifyDelegationDS(verifiedDS, dnskeyRecords)
  	if dsMatchErr != nil {
  		log.Debugf("SECURITY: zone cut — DS→DNSKEY mismatch for %s: %v", childZone, dsMatchErr)
  		chain.lastEDECode = dns.ExtendedErrorDNSBogus
  		return false, nil
  	}
- 	log.Debugf("SECURITY: zone cut — verified DNSKEY for %s (key_tag=%d)", childZone, matchedKey.KeyTag())
+
+ 	allSigs := dnssec.CollectRRSIGs(dnskeyResp.Answer, dnskeyResp.Ns, dnskeyResp.Extra)
+ 	dnskeyRRSIGs := dnssec.FindRRSIGs(allSigs, dnsutil.Fqdn(childZone), dns.TypeDNSKEY)
+ 	if err := crypto.SelfVerifyDNSKEY(dnskeyRecords, dnskeyRRSIGs); err != nil {
+ 		chain.lastEDECode = dns.ExtendedErrorDNSBogus
+ 		return false, nil
+ 	}

+ 	log.Debugf("SECURITY: zone cut — verified DNSKEY for %s (key_tag=%d)", childZone, matchedKey.KeyTag())
  	crypto.CacheZoneKeys(childZone, dnskeyRecords)


─── server/resolver/zonecut.go:96-97 ───
[security · high] DS and child DNSKEY are both queried from the same `nameservers` set, but they
live on different sides of the zone cut: DS must be answered by the PARENT zone's servers, while the
child's DNSKEY must be answered by the CHILD zone's servers (queryNameserversConcurrent sends
directly to the given list and does not chase referrals). At this point in the delegation loop
`nameservers` is the parent side, so the DNSKEY query for childZone returns a referral (no answer) →
dnskeyRecords is empty → resolveZoneCut returns an error, and the caller
(recursive_helpers.go:169-172) treats a signed delegation as insecure and serves the answer
unvalidated. Conversely, if the child servers were used, the DS query would be non-authoritative and
the unsigned NODATA path at lines 105-108 would be accepted as 'no DS' with no authenticated
NSEC/NSEC3 denial — an attacker-controlled child server could downgrade a signed delegation to
insecure. Query DS against the parent-side servers (and require an authenticated denial before
concluding 'no DS'), and query the child DNSKEY against the child zone's servers.



─── server/resolver/zonecut.go:68-71 ───
[bug · medium] getZoneCutSigner returns the FIRST RRSIG whose signer is a strict subdomain of
currentDomain. In a mixed-signer answer (e.g. a CNAME chain with targets in different child zones,
or multiple signers), the first match is not necessarily the actual zone cut for the queried name.
resolveZoneCut then queries DS/DNSKEY for that (possibly wrong/deeper) child zone name and validates
the whole response against those keys, turning a valid answer into a bogus failure or anchoring
trust in the wrong zone. Select the closest (deepest / longest) ancestor signer rather than the
first match.



─── server/resolver/zonecut.go:32-36 ───
[security · medium] Records with no matching RRSIG are appended to the result unconditionally. In a
signed zone an unsigned RRset is anomalous, yet such records survive this filter and, when
resolveZoneCut/IsResponseValid succeeds on the other signed RRsets in the same answer, they are
returned to the client with Validated=true (crypto.isAnswerSectionValid only fails when NO RRset
validates — the permissive anyValidated path). An attacker who can suppress RRSIGs for part of the
answer gets those records served as authenticated data. Reject (or at least keep de-validated)
unsigned records when the zone is signed rather than passing them through.



─── server/upstream/dnscrypt/crypto.go:87-88 ───
[security · low] newNonce silently discards the crypto/rand.Read error. Although crypto/rand.Read is
documented to never fail on supported platforms, if that assumption is ever violated the nonce (and,
in the ephemeral branch, the X25519 seed derived from nonce||secretKey) silently degrades to a
deterministic value — a zero/partial nonce combined with the fixed secretKey reproduces the same
key+nonce pair for every query, which is catastrophic for XChaCha20-Poly1305. Since the check is
nearly free, propagate the error (return it from prepareQuery) or fail loudly instead of proceeding
with a possibly-non-random nonce.



─── server/upstream/dnscrypt/crypto.go:48-49 ───
[bug · medium] This branch writes a per-query derived key into the shared State, and the caller
later derives the PQ resume secret from `state.sharedKey` (client.go:
`PQResumeSecret(state.sharedKey, ...)`) rather than from the key returned by this function. The
mutex held by the caller only serializes the encrypt phase; concurrent in-flight PQ queries against
the same cached State can overwrite `state.sharedKey` before an earlier response's PQControl block
is processed, so `pqResumeSecret` is derived from the wrong query's key and every subsequent resumed
query fails server-side (falling back to full encapsulation). Consider returning the query-specific
key for the resume-secret derivation as well (or deriving it here) instead of relying on the mutable
`state.sharedKey`, which is the same race the returned-sharedKey design was intended to avoid.



─── server/upstream/plain/tcp.go:102-104 ───
[bug · medium] Fresh-connection DNS response paths overwrite response.ID with the request ID instead
of verifying it. A stale, misrouted, or injected datagram/frame with a mismatched ID is silently
accepted as the answer to the query. Validate that response.ID equals msg.ID (and optionally the
question section) before returning, matching the UDP multi-read path.



─── server/upstream/dnscrypt/client.go:29-31 ───
[bug · medium] The TC retry budget is coupled to the initial `minQueryLen` and is off by one for the
64-byte start documented here. Each escalation consumes one loop iteration and sets the value for
the *next* query, so reaching and *sending* at 4096 needs one more iteration than the escalation
count. With start=64 the 6th iteration escalates 2048→4096 and the loop exits — the 4096-byte query
is never sent and the RFC §5.4.2 TCP fallback in executeOnce is unreachable, returning "query still
truncated" even though the protocol could still resolve. It only works today because
`config.DefaultDNSCryptMinQueryLen` happens to be 512 (needs just 4 iterations). Make the bound
derive from the initial value or bump `maxTCRetries` to 7 so the max-padding attempt and TCP
fallback are always reachable.



─── server/upstream/dnscrypt/client.go:147-150 ───
[performance · low] Transient network failures (UDP timeout, connection reset, TCP read error) do
not indicate certificate rotation, yet each one calls `deleteState`, evicting the cached shared
key/client magic and forcing a full certificate re-fetch (FetchCert DNS TXT round trip) on the very
next query. In lossy networks this turns every dropped packet into extra RTTs and load on the
resolver. Only the decrypt/unpack error paths suggest the cached key material is genuinely stale;
consider restricting invalidation to those paths and treating pure I/O errors as transient (keep the
state).



─── server/upstream/dnscrypt/state.go:157-158 ───
[bug · high] `state.ephemeralKeys` is written after `buildState` has already published this State
into the shared cache (`cache.Set` inside `buildState`), and the write does not hold `state.mu`. A
concurrent query that hits the cache in that window observes the default value `true` instead of the
configured `ephemeral_keys`, and the unsynchronized write races with readers in `prepareQuery`
(crypto.go) that read `state.ephemeralKeys` while holding `state.mu`. Note that on cache hits the
per-server `ephemeral_keys`/`pqdnscrypt` knobs are never re-applied either, so a second upstream
sharing `addr|providerName` silently inherits the first config's state. Fix: pass `ephemeralKeys`
into `buildState` and set it before `cache.Set` (or hold `state.mu` and set it before publication).

- 	state.ephemeralKeys = ephemeralKeys
+ 	state, err = c.buildState(addr, providerName, publicKey, cert, preferPQ, explicitPQ, ephemeralKeys)
+ 	if err != nil {
+ 		return nil, err
+ 	}
  	return state, nil


─── server/upstream/dnscrypt/state.go:188-191 ───
[bug · medium] When a server serves only a PQ certificate (`cert.classical == nil`), this block is
skipped and the State is built with all-zero `sharedKey`, `secretKey`, `publicKey`, and
`resolverPK`. The current PQ encrypt path survives only because `EncryptPQ` derives the per-query
key from the X-Wing KEM and never reads these fields, but the cached State then carries zero key
material (zero client public key, zero resolver X25519 key), which is inconsistent and would
silently encrypt with an all-zero key if any path touches them (e.g. `EncryptedQuery.ClientPk =
state.publicKey`, or a fallback/rotation to the classical construction). Derive the client X25519
key pair unconditionally, or reject PQ-only states, so the State always carries real key material.



─── server/upstream/dnscrypt/state.go:212-212 ───
[bug · medium] `State.expires` is set purely from the fixed config TTL and ignores the selected
certificate's own validity window (`selectedCert.NotAfter`). `parseCert` only validates the date at
fetch time, so if the cert is fetched near the end of its window, the cached state is used past
`NotAfter` — queries are then rejected by the resolver (stale client magic) until the TTL lapses and
a refetch happens. This also propagates to the PQ ticket expiry cap in client.go, which bounds
tickets by this same `state.expires`. Cap the expiry at `min(now+TTL, selectedCert.NotAfter)`.

- 		expires:       time.Now().Add(config.DefaultDNSCryptCertificateCacheTTL),
+ 		expires:       minTime(time.Now().Add(config.DefaultDNSCryptCertificateCacheTTL), time.Unix(int64(selectedCert.NotAfter), 0)),


─── server/upstream/dnscrypt/state.go:38-39 ───
[maintainability · low] `ewmaQuerySize` is initialized in `buildState` but never read anywhere in
the codebase — the TC-escalation logic in client.go uses `minQueryLen` directly. This is dead state
left over from an unfinished EWMA feature; either wire it up or remove it to avoid confusion about
which field drives response-size adjustments.



─── server/upstream/tlcp/client.go:70-72 ───
[bug · medium] The DTLCP client config drops both ServerName and CurvePreferences that the TLCP
config sets. The server-side DTLCP listener in this codebase pins `CurvePreferences:
[]dtlcp.CurveID{dtlcp.CurveSM2}`, so the client should mirror that; otherwise a DTLCP upstream may
negotiate a non-SM2 curve. More importantly, `ServerName` is never propagated and
`dialDTLCP`/`dtlcp.Client` do not fill it from the address (unlike the TLCP path), so with
`InsecureSkipVerify=false` (the default under privacy_profile=strict) hostname verification is
either skipped or fails outright even though config validation mandates `server_name` for secure
protocols. Mirror the TLCP config for consistency.

  	return &dtlcp.Config{
  		InsecureSkipVerify: server.SkipTLSVerify,
+ 		ServerName:         server.ServerName,
+ 		CurvePreferences:   []dtlcp.CurveID{dtlcp.CurveSM2},
  		SessionCache:       c.dtlcpSession,


─── server/upstream/tlcp/client.go:49-49 ───
[bug · medium] `smx509.NewCertPool()` returns an always-empty pool and nothing ever adds a trusted
CA to it (config has no CA-file field, and `.Clone()` in tlcp.go/http_tlcp.go only copies it). With
`InsecureSkipVerify=false` — the default and the only mode `privacy_profile=strict` allows — every
TLCP handshake will fail with "x509: certificate signed by unknown authority", so verified TLCP
upstream connections are effectively impossible. Meanwhile the DTLCP config leaves `RootCAs` nil,
silently falling back to the system pool that this very comment says cannot parse SM2 certs, so the
two paths are inconsistent. Either support loading a trusted SM2 CA into the pool (e.g., a config
option), or explicitly document/enforce that TLCP/DTLCP upstreams require `skip_tls_verify=true`.



─── server/upstream/tlcp/client.go:57-62 ───
[security · low] Both `VerifyConnection` callbacks only log the handshake and unconditionally return
nil. When `InsecureSkipVerify` is true (i.e., `SkipTLSVerify`), normal certificate verification is
skipped and this hook is the last gate before the connection is accepted, so returning nil means
zero authentication is enforced — fine if that is the intended semantics, but any future security
check added here expecting to be enforced would be silently bypassed. Return an error on failed
checks and document that this hook is logging-only.



─── server/upstream/plain/udp.go:333-335 ───
[bug · medium] `raw[10]<<8|raw[11]` is the DNS header ARCOUNT, not the presence of an EDNS OPT
record. Any response carrying additional records (glue, TSIG, additional A/AAAA) will set
`hasEDNS=true` even when it has no OPT RR, causing it to skip the non-EDNS gate (`rcode ==
RcodeSuccess && !hasEDNS && queryUDPSize > 0`) and be treated as an EDNS candidate. A GFW-style bare
single-answer A/AAAA response with extra records would then pass the gate and be collected as a
legitimate candidate, weakening the spoofguard heuristic. Prefer determining EDNS presence from the
parsed OPT RR (e.g. `resp.IsEdns0() != nil`) after `Unpack` rather than from ARCOUNT.

  	ad := (raw[3] >> 5) & 1
- 	hasEDNS := uint16(raw[10])<<8|uint16(raw[11]) > 0
  	rcode := int(raw[3] & 0x0F)


─── server/upstream/pool/quic.go:105-108 ───
[bug · medium] Acquire never checks `p.closed` before initiating a dial. After `Shutdown` has set
`p.closed`, a concurrent or subsequent `Acquire` (e.g. from `ExecuteQUIC` or `WarmUp`) will still
start a full QUIC handshake, only to discard the freshly dialed connection once the post-dial `if
p.closed` check runs — a wasted handshake that can also fail with a misleading "no available
connection" error while the in-flight `dialing[key]` counter is still elevated (the counter is only
cleared when the dial completes). Check `p.closed` under the lock before dialing and return a
shutdown error immediately.

+ 	p.mu.Lock()
+ 	if p.closed {
+ 		p.mu.Unlock()
+ 		return nil, fmt.Errorf("client: pool shut down for %s", key)
+ 	}
+ 	live := p.conns[key][:0]
+
  	if len(live)+p.dialing[key] < p.maxConns {
  		p.dialing[key]++
  		p.mu.Unlock()
  		conn, err := dialFunc(ctx, key)


─── server/upstream/pool/quic.go:183-187 ───
[bug · medium] `Put`'s dedup only checks current pool membership, not connection liveness. Because
`Acquire` returns connections without removing them from the pool, the same raw `*quic.Conn` can be
shared by concurrent queries; if one query fails and calls `Remove(pc)` (which closes the
connection) while another succeeds and calls `Put(key, conn)` with the same raw conn, `Put` finds no
matching entry and inserts a `QUICConn` wrapping an already-closed connection into the pool,
consuming a slot until the next `Acquire` filters it out. Check liveness (e.g.
`conn.Context().Done()` or the wrapper's `closed` flag) before re-inserting, or have `Put` accept
the `*QUICConn` so it can reuse the existing liveness tracking.

+ 	if conn.Context().Err() != nil {
+ 		_ = conn.CloseWithError(0, "connection already closed")
+ 		return
+ 	}
  	if len(p.conns[key]) >= p.maxConns {
  		_ = conn.CloseWithError(0, "pool full")
  		return
  	}
  	p.conns[key] = append(p.conns[key], &QUICConn{Conn: conn, addr: key})


─── server/upstream/pool/quic.go:171-174 ───
[performance · low] `Put` calls `conn.CloseWithError` while `p.mu` is held (both the `p.closed` and
"pool full" branches), and `Remove` likewise invokes `pc.close()` → `CloseWithError` under the lock.
If quic-go's close path blocks (e.g. internal session lock contention or a slow packet write), every
pool operation (`Acquire`, `Put`, `Remove`, `Shutdown`) stalls behind the mutex. Close the
connection after releasing the lock, as the post-dial and `Shutdown` paths already do.

  	if p.closed {
- 		_ = conn.CloseWithError(zpool.QUICCodeNoError, "pool closed")
+ 		closedConn := conn
+ 		p.mu.Unlock()
+ 		_ = closedConn.CloseWithError(zpool.QUICCodeNoError, "pool closed")
  		return
  	}


─── server/upstream/tlcp/http_tlcp.go:33-35 ───
[bug · medium] The URL is not validated for scheme/host before the request is issued. url.Parse
accepts both scheme-less strings (treated as a path, leaving parsedURL.Host empty —
net.JoinHostPort("", "9443") then yields :9443, and ExecuteDoHRequest builds "://:9443/..." which
fails later with a confusing unsupported-protocol-scheme error) and http:// URLs, in which case
DialTLSContext is never invoked and the DNS query is sent over plaintext HTTP, silently downgrading
from TLCP. Validate parsedURL.Scheme == "https" and a non-empty parsedURL.Host right after parsing
and return a clear error otherwise.

+ 	if parsedURL.Scheme != "https" || parsedURL.Hostname() == "" {
+ 		return nil, fmt.Errorf("tlcp: upstream address %q must be an https URL with a host", server.Address)
+ 	}
  	if parsedURL.Port() == "" {
  		parsedURL.Host = net.JoinHostPort(parsedURL.Host, config.DefaultHTTPTLCPPort)
  	}


─── server/upstream/tlcp/http_tlcp.go:66-69 ───
[security · high] The http.Client has no CheckRedirect, so Go's default policy follows up to 10
redirects. A compromised or misconfigured DoH endpoint can return a 3xx to an arbitrary host/scheme:
the full DNS query (embedded in the dns= URL) is then re-sent to that destination — leaking query
data and enabling SSRF, and a redirect to an http:// target bypasses TLCP entirely (the transport
dials it plainly since DialTLSContext is only used for TLS connections). Restrict redirects, e.g.
reject them outright or allow only same-host/https redirects.

  		httpClient = &http.Client{
  			Timeout:   c.timeout,
  			Transport: transport,
+ 			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
+ 				return http.ErrUseLastResponse
+ 			},
  		}


─── server/upstream/tlcp/http_tlcp.go:46-46 ───
[performance · low] The cache key is built from the raw server.Address before the default-port
normalization, so upstreams that differ only by the implicit default port (e.g.
https://dns.example.com vs https://dns.example.com:9443) resolve to the same effective endpoint but
get two distinct cached HTTP clients, defeating connection reuse and wasting LRU slots. Use the
normalized endpoint in the key, e.g. parsedURL.String() after the port has been appended.

+ 	b.WriteString(parsedURL.String())
  	key := b.String()


─── server/upstream/socks5/socks5.go:450-450 ───
[bug · medium] BND.ADDR domain resolution here is wasteful and not bound by the Dialer's timeout or
caller context. `skipAddress` (used for TCP CONNECT replies) calls `readAddress` only to discard the
address, so a legal-but-rare domain-typed BND.ADDR triggers a full DNS lookup under a hard-coded
`context.Background()` + 10s deadline that ignores `d.timeout` and the caller's context — an
otherwise successful CONNECT can be stalled or failed by this unrelated lookup. Additionally, only
`ips[0]` is used, which may pick an unreachable address family for the relay. Suggest making
`skipAddress` skip the address bytes without resolving, and threading a context/deadline into
`readAddress` (or reusing the connection's deadline) instead of `context.Background()`.



─── server/upstream/socks5/socks5.go:274-274 ───
[bug · low] This precheck (`len(b) < 10`) rejects valid domain-typed datagrams: a SOCKS5 UDP header
with a 1- or 2-byte domain is only 8–9 bytes (4 prefix + 1 len + 1–2 domain + 2 port), and per RFC
1928 §7 that is not truncated. The per-ATYP bounds checks below (e.g. `len(b) < 4+headerLen` for the
domain case) already handle truncation correctly, so the top-level check only needs to guarantee the
ATYP byte is readable.

- if len(b) < 10 {
+ if len(b) < 4 {


─── server/upstream/socks5/socks5.go:398-398 ───
[bug · medium] For a bracketed IPv6 literal without a port (e.g. `"[::1]"`), `net.SplitHostPort`
fails and `h` keeps the brackets. The resulting `"[::1]"` is later passed to `buildSOCKS5Request`,
where `net.ParseIP` fails, so the address is sent to the proxy as a bogus 5-character domain name
instead of an IPv6 literal. Strip the brackets before falling back to the default port.

  h = addr
+ 		// net.SplitHostPort also fails for bracketed IPv6 without a port
+ 		// (e.g. "[::1]"); strip the brackets so the host stays a valid IP.
+ 		if len(h) > 1 && h[0] == '[' && h[len(h)-1] == ']' {
+ 			h = h[1 : len(h)-1]
+ 		}


─── server/upstream/socks5/socks5.go:386-386 ───
[bug · medium] `byte(len(host))` silently wraps for hostnames longer than 255 bytes, producing a
malformed SOCKS5 request (length byte differs from the actual bytes copied). The port range check
above returns nil for an invalid port, but there is no analogous guard for the domain length — add
one so an oversized host is rejected instead of wrapped.

+ if len(host) > 255 {
+ 		return nil
+ 	}
+ 	buf := make([]byte, 7+len(host)) // 4 + 1 + len(host) + 2
+ 	buf[0], buf[1], buf[2] = socks5Version, cmd, 0x00
+ 	buf[3] = socks5ATYPDomain
  buf[4] = byte(len(host)) //nolint:gosec // G115: SOCKS5 address length — max 255 fits byte


─── server/upstream/tlcp/tlcp.go:25-25 ───
[security · medium] ALPN result is never verified: `NextProtoDOT` ("dot") is offered, but after the
handshake nothing checks `ConnectionState.NegotiatedProtocol`. The `VerifyConnection` closure in
`tlcpClientConfig` only logs the negotiated protocol and always returns nil, so a TLCP server that
silently ignores ALPN (negotiates no protocol, or an unexpected one) is accepted and the query
proceeds without the DoT ALPN guarantee — a silent downgrade. Per RFC 7858 §4.1, the client should
only proceed when "dot" was negotiated (or explicitly accept a fallback). Enforce this by returning
an error from `VerifyConnection` when `cs.NegotiatedProtocol != "dot"`, or by checking the
connection state in `dialTLCPConn` after `HandshakeContext` and failing the dial when it is
empty/unexpected.

  	tlcpCfg.NextProtos = config.NextProtoDOT
+ 	// require the server to negotiate "dot" (see VerifyConnection / post-handshake check)


─── server/upstream/socks5/udp.go:72-75 ───
[bug · high] Both socks5PacketConn and socks5UDPConn read fresh.udpConn without holding fresh.mu
while the monitor goroutine can concurrently run cleanupLocked() and set d.udpConn=nil when the
proxy closes the TCP control connection. The returned wrapper can wrap a nil/already-closed
*net.UDPConn, causing nil-pointer panics or use of a closed connection. Capture the conn under the
lock (or have establishUDPRelay return it) and fail when nil.

+ 	fresh.mu.RLock()
+ 	conn := fresh.udpConn
+ 	fresh.mu.RUnlock()
+ 	if conn == nil {
+ 		return nil, errors.New("socks5: UDP relay torn down before use")
+ 	}
  	return &socks5PacketConn{
- 		conn: fresh.udpConn,
+ 		conn: conn,
  		done: func() { _ = fresh.Close() },
  	}, nil


─── server/upstream/socks5/udp.go:81-84 ───
[bug · medium] Dialer.timeout (documented as "connection + negotiation timeout" and set via New) is
silently ignored here: net.Dialer.Timeout is only assigned when ctx has a deadline. When a caller
passes a deadline-less context (e.g. context.Background(), as in socks5_test.go
TestListenPacketConcurrentRelays), the TCP dial to the proxy has no timeout and — worse —
ctrlConn.SetDeadline is never applied, so the SOCKS5 greeting/ASSOCIATE reads can block forever on a
stalled proxy. Apply d.timeout as the fallback for both the dialer and the negotiation deadline.

  	dialer := net.Dialer{}
  	if hasDeadline {
  		dialer.Timeout = time.Until(deadline)
+ 	} else if d.timeout > 0 {
+ 		dialer.Timeout = d.timeout
  	}


─── server/upstream/socks5/udp.go:137-141 ───
[bug · medium] The v2ray/xray 0.0.0.0 relay fallback breaks for hostname-configured proxies: when
proxyAddr is like "proxy.example.com:1080", net.ParseIP(proxyHost) returns nil, so relay.IP stays
0.0.0.0 (unspecified) and the subsequent UDP dial targets "0.0.0.0:<port>" — i.e. localhost —
instead of the proxy, silently breaking the relay. Resolve proxyHost when it is not an IP literal
(or dial the UDP socket using the proxy hostname directly) before falling back.

  	if relay.IP == nil || relay.IP.IsUnspecified() {
  		if ip := net.ParseIP(proxyHost); ip != nil {
  			relay.IP = ip
+ 		} else if ips, err := net.DefaultResolver.LookupIP(ctx, "ip", proxyHost); err == nil && len(ips) > 0 {
+ 			relay.IP = ips[0]
  		}
  	}


─── server/upstream/socks5/udp.go:244-248 ───
[bug · low] The datagram is already consumed from the socket by the time this check runs, so
returning io.ErrShortBuffer loses it permanently: a caller that grows its buffer and retries will
block reading the *next* datagram (which, for the 1:1 DNS request/response flows here, never
arrives) and time out. This also diverges from net.UDPConn truncation semantics. Either copy the
truncated prefix and return n=len(p), or document that the datagram is dropped; the same pattern
exists in socks5UDPConn.Read.



─── server/upstream/tls/client.go:232-235 ───
[security · high] QUIC pool and QUIC-config cache keys omit the TLS identity. `poolKey` and the
`"doq:"+addr` config key contain only the server address (plus proxy), whereas the DoT/DoH/DoH3
paths key on `transportKey(host, serverName, skipVerify, proxy)`. Two upstreams that share the same
address but differ in ServerName or SkipTLSVerify (e.g. one with verification disabled) will share
the same pooled QUIC connection and the same cached quic.Config — including `Allow0RTT` and the
0-RTT TokenStore, which are fixed by whichever dial populated the cache first. A connection
verified/negotiated for one identity can then be handed to queries intended for another upstream,
crossing trust boundaries (the same issue exists in ExecuteQUIC/quic.go). Build the pool and config
keys with a transportKey-style identity (address|serverName|skipVerify|proxy) and keep it consistent
with the query path.



─── server/upstream/tls/client.go:248-253 ───
[bug · medium] `addr` here is the pool key, not the server address. `quicPool.WarmUp(ctx, poolKey,
…)` forwards `poolKey` to the dial func, so when a proxy is configured `addr` is
`"<address>|<proxy>"`; `net.ResolveUDPAddr("udp", addr)` will fail and the proxied pre-warm can
never succeed. (ExecuteQUIC's dialQUIC explicitly ignores this parameter and dials the real address
`key` instead.) Dial `server.Address`, and derive the QUIC config key from it too, otherwise the
warmed config/token store is also keyed incorrectly.



─── server/upstream/tls/client.go:253-253 ───
[bug · medium] `pconn` is leaked if `quic.Dial` fails: after `proxyDialer.ListenPacket` succeeds,
this error path returns without closing `pconn`. quic-go does not take ownership of a
caller-provided PacketConn on a failed dial, so every failed proxied warm-up leaks a UDP socket.
Capture the dial error and close `pconn` before returning, e.g.:

```go
conn, err := quic.Dial(timeoutCtx, pconn, remoteAddr, dialTLS, cfg)
if err != nil {
    _ = pconn.Close()
    return nil, err
}
return conn, nil
```



─── server/upstream/tls/https.go:33-35 ───
[bug · high] For IPv6 literal upstreams without an explicit port, parsedURL.Host already contains
brackets, and net.JoinHostPort produces malformed destinations like [[2001:db8::1]]:443, breaking
the dial. Use parsedURL.Hostname() (which strips brackets) before joining the port.

  	if parsedURL.Port() == "" {
- 		parsedURL.Host = net.JoinHostPort(parsedURL.Host, config.DefaultHTTPSPort)
+ 		parsedURL.Host = net.JoinHostPort(parsedURL.Hostname(), config.DefaultHTTPSPort)
  	}


─── server/upstream/tls/https.go:40-40 ───
[bug · medium] Client.Close() sets dohTransports/doh3Transports to nil, but
ExecuteHTTPS/ExecuteHTTP3 dereference the map with Get/Delete before any nil guard, so a query
racing with shutdown panics. Add nil checks matching createDOHClient/createDOH3Client before
touching the cache.

- 	client, isCached := c.dohTransports.Get(key)
+ 	var client *http.Client
+ 	var isCached bool
+ 	if c.dohTransports != nil {
+ 		client, isCached = c.dohTransports.Get(key)
+ 	}
+ 	if !isCached {
+ 		client = c.createDOHClient(parsedURL.Host, server.ServerName, server.SkipTLSVerify, server.Proxy, tlsConfig)
+ 	}


─── server/upstream/tls/https.go:52-57 ───
[bug · medium] The eviction sequence `Get(key)` → compare → `Delete(key)` is not atomic:
`lrumap.Map` locks only around each individual call, so another goroutine (ExecuteHTTPS is reachable
concurrently from the query path) can remove/install a new transport for the same key between the
two calls, causing this code to close/evict the just-installed transport and churn the cache. Prefer
an atomic compare-and-delete (e.g. add a `CompareAndDelete(key, value) bool` method to `lrumap.Map`)
so the entry is only removed when it still holds `client`. The same pattern is repeated in the final
error-cleanup block below.

- 			if cached, ok := c.dohTransports.Get(key); ok && cached == client {
+ 			if c.dohTransports.CompareAndDelete(key, client) {
  				if ct, ok := client.Transport.(*eHTTP.CompatableTransport); ok {
  					ct.CloseIdleConnections()
  				}
- 				c.dohTransports.Delete(key)
  			}


─── server/upstream/pool/tcp.go:0-0 ───
[bug · medium] Race between Exchange's ctx-cancellation cleanup and readLoop's response delivery
leaks a pooled *dns.Msg. readLoop can look up the pending (ok=true), then Exchange's deferred
cleanup deletes the pending and drains the (still-empty) resultCh, after which readLoop's send lands
in the now-empty channel and the response is stranded forever — it is never returned to
zpool.DefaultMessage and the buffered channel keeps it reachable. The race window is small but real
under cancellation + late response. Fix: deliver under the RLock so the cleanup's delete/drain
(which needs the write lock) cannot interleave, or re-verify the pending is still registered
immediately before the send.

  		if ok {
+ 			c.mu.RLock()
+ 			pq2, still := c.inflight[resp.ID]
+ 			c.mu.RUnlock()
+ 			if !still || pq2 != pq {
+ 				zpool.DefaultMessage.Put(resp)
+ 			} else {
  			select {
  			case pq.resultCh <- resp:
  			default:
  				zpool.DefaultMessage.Put(resp)
+ 				}
  			}
  		}


─── server/upstream/pool/tcp.go:407-410 ───
[maintainability · low] When the pool is already at maxConns but no dial is currently in flight
(dialing[key]==0, the normal idle case), this guard does not bail: WarmUp proceeds to dialAndAdd,
which then dials a full connection, finds no dead conn to replace, discards the new connection via
c.close(), and returns "client: max conns reached" as an error. So WarmUp both wastes a full
dial/TLS handshake and reports a spurious error in the healthy steady state. Bail as soon as
len(conns) >= maxConns.

- 	if len(p.conns[key]) >= p.maxConns && p.dialing[key] >= p.maxConns {
+ 	if len(p.conns[key]) >= p.maxConns {
  		p.mu.Unlock()
  		return nil // pool already full, don't bother
  	}


─── server/upstream/tls/http3.go:90-98 ───
[bug · high] 0-RTT rejection handling (`resetQUICConfig` + recreate/retry) is gated on `isCached`,
so a first-use client that gets `quic.Err0RTTRejected` never resets the stale token store. The token
store and TLS session cache are shared across transport generations (cached in `quicConfigs` keyed
by "doh3:"+key, and `quicSessionCache` is process-wide), so a freshly created transport can still
attempt 0-RTT with an old token that the server rejects. Since the reset never runs, the final error
path only evicts the transport, leaving the stale token in place — the next request recreates a
client that tries 0-RTT again and fails again, repeatedly. Handle `Err0RTTRejected` (reset config +
retry) regardless of whether the client came from cache, not only inside the `isCached` branch.



─── server/upstream/tls/http3.go:115-122 ───
[bug · high] This final block closes and deletes the shared cached transport on ANY error, including
caller-side context cancellation/deadline and upstream HTTP non-200 responses (`ExecuteDoHRequest`
returns an error for `HTTP status != 200`). That tears down a pooled connection that may be actively
used by concurrent requests, causing collateral failures. Worse, `isQUICRetryable` matches
`os.ErrDeadlineExceeded` (which `errors.Is` also matches for `context.DeadlineExceeded`), so a
caller timeout both runs the retry loop against an already-expired context and then evicts a healthy
transport. Gate eviction on QUIC/connection-level errors only, and avoid evicting when the failure
is a caller-side cancellation or an HTTP-level error.



─── server/upstream/tls/http3.go:40-44 ───
[bug · medium] `RoundTrip` holds `h.mu.RLock()` for the entire network I/O (both the cached-conn
attempt and the fallback dial), so `Close()` (which needs the write lock) blocks until every
in-flight request completes. `Close` is called synchronously on the retry/eviction path in
`ExecuteHTTP3` before creating the new client, and also from `Client.Close()` shutdown and the LRU
`OnEvict` hook (which runs while the lrumap mutex is held). A single stalled request (e.g. waiting
out the QUIC idle timeout on a dead connection) therefore stalls transport eviction, the retry path,
and shutdown. Consider guarding only the `closed` flag with the lock/atomic and releasing it before
the network call, relying on quic-go's own concurrency safety for in-flight requests.



─── server/upstream/tls/dtls.go:91-91 ───
[bug · low] uint16(len(msgData)) silently truncates DNS messages larger than 65535 bytes, making the
on-wire length prefix inconsistent with the payload. Add an explicit size check before converting to
uint16 (and before writing the prefix) instead of suppressing the overflow with nolint.

- 	binary.BigEndian.PutUint16(req[:2], uint16(queryLen)) //nolint:gosec // G115: DNS query length < 65535 (UDP datagram limit)
+ 	if queryLen > 65535 {
+ 		return nil, fmt.Errorf("dtls: query too large (%d bytes)", queryLen)
+ 	}
+ 	binary.BigEndian.PutUint16(req[:2], uint16(queryLen))


─── server/upstream/warmup.go:29-29 ───
[security · medium] Credential leak in logs: `server.Proxy` is a `socks5://[user:pass@]host:port`
URL whose userinfo is parsed into the dialer, so logging the raw value exposes the proxy password.
In addition, the `err` from `socks5.New` wraps the `url.Parse` error, whose message embeds the full
URL string (including userinfo) — so `%v` leaks the credentials even if `server.Proxy` were
redacted. The package already has password-redaction logic (`Dialer.SafeURL()`); use a redacting
helper (strip/mask userinfo, and avoid logging the raw parse error) for this line.

- 		log.Warnf("UPSTREAM: invalid proxy %s for %s: %v", server.Proxy, server.Address, err)
+ 		log.Warnf("UPSTREAM: invalid proxy %s for %s: %v", redactProxyURL(server.Proxy), server.Address, err)


─── server/upstream/warmup.go:30-30 ───
[bug · medium] A failed `socks5.New` is permanently cached as a nil dialer: the next `proxyDialer`
call gets `(nil, true)` from `Get` and returns nil, so the server silently falls back to a direct
(proxy-less) connection for the rest of the process lifetime — no retry, no further diagnostics. For
users whose network requires the proxy to reach the upstream (or who configured it for
privacy/filtering), this silently defeats the configuration; the nil entry also permanently consumes
an LRU slot. Do not cache failures — drop the `Set` and return nil (optionally with a bounded
retry/backoff), so the error is at least re-surfaced/retried on later calls.

- 		c.proxyDialers.Set(server.Proxy, nil)
+ 		return nil


─── server/upstream/warmup.go:48-48 ───
[bug · low] The warm-up goroutines capture `s := &servers[i]`, a pointer into the `servers` backing
array owned by the caller (`server.go` passes `cfg.Upstream`). Because `WarmUpConnections` returns
while these goroutines are still running, any later mutation, append, or re-slice of that backing
array by the caller races with the warm-up reads (and keeps the whole array alive). Copy the element
to a local and take its address so each goroutine owns its data.

- 		s := &servers[i]
+ 		s := servers[i]
+ 		c.warmWg.Go(func() {
+ 			defer zdnsutil.HandlePanic("connection pre-warm")
+ 			warmCtx, cancel := context.WithTimeout(ctx, c.timeout)
+ 			defer cancel()
+ 			c.warmUpConnection(warmCtx, &s, protocol)
+ 		})


─── server/upstream/warmup.go:64-65 ───
[maintainability · low] The HTTPS/HTTP3 branches ignore the derived `warmCtx`:
`WarmUpHTTPS`/`WarmUpHTTP3` take no context, so the per-warmup timeout/cancellation set up here is
dropped for those protocols. Today they only parse the URL and build/cache transports (no blocking
I/O), so the practical impact is limited — but the asymmetry is surprising, and any future dialing
added to these paths would be uncancellable. Thread the warmup context through for consistency with
the TLS/QUIC/DNSCrypt branches.

  	case config.ProtoHTTPS:
- 		c.tlsClient.WarmUpHTTPS(server)
+ 		c.tlsClient.WarmUpHTTPS(ctx, server)


─── stats/stats.go:288-291 ───
[bug · high] Data race: `*c = Collector{}` performs a non-atomic, multi-word struct copy while
`Record()`/`Stats()` are concurrently reading and writing the same atomic fields. `Reset()` is
reachable from DNS request handling (`server/init.go` wires it to the CHAOS
`.stats.clear`/`.cache.clear` zone rules), so it runs in parallel with `Record()` from other
in-flight queries and `Stats()` from `.stats` queries. Under the Go memory model this is a race:
counters can be torn (a concurrent `Stats()` can observe a half-zeroed struct, and a concurrent
`Record()` increment can be lost), and QPS computed from `total`/`startTime` can use mismatched
epochs. Suggest making the state immutable behind an `atomic.Pointer` snapshot and swapping it in
`Reset()`, or at minimum resetting each counter with an atomic `Store(0)` and documenting that
`Reset` must be serialized against `Record`/`Stats`.



─── stats/stats.go:138-140 ───
[bug · medium] Rcodes >= 6 are silently dropped, including the BADCOOKIE (23) rcode this server
itself records. `handler.go` calls `Record(&stats.Request{Result: "badcookie", ..., Rcode:
dns.RcodeBadCookie})`, and `dns.RcodeBadCookie` == 23 (see docs/rfc/GUIDELINE.md), which always
fails `r.Rcode < len(c.rCode)` (6), so badcookie responses never appear in the rcode line even
though they are counted as a result. Zone rules can also be configured with arbitrary `rcode=`
values (zone/parse.go), which are likewise lost. Either widen `rCode` to cover the rcodes actually
produced (e.g. `[24]atomic.Int64` or track only the standard 0–5 and document that BADCOOKIE is
intentionally excluded), or drop `Rcode: dns.RcodeBadCookie` from the caller so the data isn't
silently discarded.



─── stats/stats.go:181-181 ───
[maintainability · low] `Stats()` is not a consistent snapshot: `total` is loaded first, then each
category counter is loaded separately, so under concurrent `Record()` calls the category loads can
overtake the earlier `total` load. This can make a percentage exceed 100%, make the
rcode/protocol/DNSSEC lines disagree with each other, and produce a qps/p50/p95/p99 line whose
latency histogram (`latTotal`, which excludes prefetch) does not share the denominator with `total`.
The package doc says best-effort, so this may be acceptable — but since `.stats` is exposed to
operators via the CHAOS zone, consider documenting the caveat or computing percentages from a single
captured snapshot (e.g. `atomic.Pointer` to an immutable stats struct).



─── stats/stats.go:73-73 ───
[maintainability · low] `totalMS` is incremented for every recorded request (line 73) but never read
anywhere in the codebase — it is dead state, adding a wasted atomic write to the hot path of every
query. Either surface it (e.g. average/mean latency in `Stats()`) or remove the field.



─── zone/parse.go:88-91 ───
[bug · high] A bare "." or "*." header flushes the previous domain but then `continue`s without
resetting `curDomain`/`curRawName`/`curRecords`/`curAuth`/`curAddl`. Any record lines that follow
are appended to the stale slices and, at the next flush/EOF, are stored again (duplicated, since
`store` appends) under the previous domain — silently producing wrong DNS answers. Additionally, a
root header with attributes such as ". rcode=3" does not hit this branch: `fields[0]` becomes
"rcode=3", which is canonicalized into the domain name, so the rcode attribute is lost and records
get bound to a bogus "rcode=3." domain. Reset all parser state (or explicitly special-case the root
domain and parse attributes from `fields` when the domain part is empty/root) before continuing.

  			fields := strings.Fields(curRawName)
  			if len(fields) == 0 {
- 				continue // bare "." or "*." with no following domain
+ 				// bare "." or "*." — do not leave stale state for later record lines
+ 				curDomain = ""
+ 				curRawName = ""
+ 				curRecords = nil
+ 				curAuth = nil
+ 				curAddl = nil
+ 				continue
+ 			}
+ 			if strings.HasPrefix(fields[0], "rcode=") || strings.HasPrefix(fields[0], "match=") {
+ 				// root header with attributes, e.g. ". rcode=3" — handle attributes
+ 				// without treating them as the domain name
  			}


─── zone/parse.go:139-143 ───
[bug · medium] Zone loading can leave partially applied rule state on error: zone/parse.go runs
flush() before checking sc.Err(), so a scanner failure commits partial zone data and then returns an
error; zone/zone.go LoadRules resets evaluator maps before loading completes, so a mid-load failure
leaves partially populated maps and inconsistent ruleCount. Check for scanner errors before
flushing, and build/swap fresh maps atomically only on success (or otherwise make the load
transactional).

- 	flush()
-
  	if err := sc.Err(); err != nil {
  		return 0, fmt.Errorf("read: %w", err)
  	}
+ 	flush()


─── zone/parse.go:0-0 ───
[bug · medium] The quoted-string scanner in `tokenize` stops at the first unescaped `"`, so a
backslash-escaped quote inside quoted content (valid DNS TXT rdata, e.g. `"foo\"bar"`) terminates
the token early: the content is truncated and the remainder is emitted as extra fields, corrupting
the record that `parseRecordLine` builds. Escaped quotes (`\"`) and other backslash escape sequences
must be preserved when scanning (and unescaped consistently downstream), since TXT records routinely
contain them.

  		if line[i] == '"' {
  			// Quoted string.
  			i++ // skip opening quote
  			j := i
- 			for j < len(line) && line[j] != '"' {
+ 			closed := false
+ 			for j < len(line) {
+ 				if line[j] == '\\' && j+1 < len(line) {
+ 					j += 2 // keep escape sequence (incl. \")
+ 					continue
+ 				}
+ 				if line[j] == '"' {
+ 					closed = true
+ 					break
+ 				}
  				j++
  			}
  			tokens = append(tokens, line[i:j])
+ 			if closed {
  			i = j + 1 // skip closing quote
+ 			} else {
+ 				i = len(line)
+ 			}
  		}


─── zone/zone.go:162-169 ───
[bug · high] Wildcard dynamic rules are stored under a key that can never be matched. `e.dynamics`
is keyed by `normalizedName` *before* the `*.` prefix is stripped, so a rule named `*.bind` is
stored as `*.bind.`; `Evaluate` only looks up `e.dynamics[dnsutil.Canonical(qname)]`, which never
contains `*.`. The dynamic `fn()` is therefore never invoked for wildcard names — only the
answer-less rcode sentinel (stored under the stripped suffix) can fire via `wildcardMatch`, silently
serving no dynamic content. Strip the wildcard prefix before keying `e.dynamics` (and match dynamic
wildcards during suffix iteration).

  	if rule.DynamicContent != nil {
- 		e.dynamics[normalizedName] = &dynamicEntry{fn: rule.DynamicContent, configs: rule.Answer}
+ 		isWildcard := strings.HasPrefix(rule.Name, wildcardPrefix)
+ 		key := normalizedName
+ 		if isWildcard {
+ 			key = key[len(wildcardPrefix):]
+ 		}
+ 		e.dynamics[key] = &dynamicEntry{fn: rule.DynamicContent, configs: rule.Answer}
  	}
  	tags := parseMatchTagsText(serializeMatchTags(rule.Match))
  	isWildcard := strings.HasPrefix(rule.Name, wildcardPrefix)
  	if isWildcard {
  		normalizedName = normalizedName[len(wildcardPrefix):]
  	}


─── zone/zone.go:355-360 ───
[bug · high] Dynamic rules drop match tags, rcode, and authority/additional metadata. `dynamicEntry`
stores only `fn`/`configs`, and `evalDynamic` always returns `Rcode: dns.RcodeSuccess` with no
authority/additional and no tag scoring. Combined with `Evaluate` short-circuiting on
`e.dynamics[qname]` before any tag-scored exact/wildcard lookup, a dynamic rule configured with
`Match` restrictions applies to every client regardless of tags, and a configured rcode (e.g.
NXDOMAIN) or authority/additional section is silently ignored. Store the rule metadata (matchTags,
rcode, authority, additional) in `dynamicEntry` and honor it in `evalDynamic`, or route dynamics
through the normal exact/wildcard path.



─── zone/zone.go:341-352 ───
[bug · medium] When `de.configs` is non-empty and no record matches `qtype`/`qclass`, `contents`
stays nil and `evalDynamic` returns an empty non-matched `Result`. Because `Evaluate` already
returned at the `e.dynamics[qname]` lookup, the exact sentinel and wildcard rules for that qname are
never consulted — static answers configured for other types/classes of the same name are masked.
Fall through to the normal exact/wildcard matching when the dynamic filter does not match.



─── zone/zone.go:165-165 ───
[bug · medium] Malformed match tags silently become match-all. `parseMatchTagsText` logs a warning
and returns nil on invalid tags, and `loadInline` never propagates the error, so a typo in a content
rule's `Match` list (e.g. `!` or an empty entry) makes that rule unrestricted — it matches every
client instead of failing closed. Note the bypass path in `LoadRules` propagates tag errors via
`parseMatchTags`, so the two paths are inconsistent. Return the error (or skip the rule with a load
failure) so an invalid tag cannot widen a rule's scope.



─── server/upstream/tls/quic.go:79-85 ───
[bug · medium] On quic.Err0RTTRejected, both the pooled and non-pooled DoQ paths retry the query on
the same QUIC connection. RFC 9250 requires a fresh connection after 0-RTT rejection; relying on
quic-go's internal re-handshake is fragile and can fail or leave an invalidated connection in the
pool. Remove the rejected connection from the pool, dial/acquire a fresh connection, and retry on
it.

  		if errors.Is(err, quic.Err0RTTRejected) {
  			c.resetQUICConfig("doq:" + key)
+ 			c.quicPool.Remove(pc)
+ 			pc, err = c.quicPool.Acquire(ctx, poolKey, dialQUIC)
+ 			if err == nil {
  			response, err = c.doQUICQuery(ctx, pc.Conn, msg, c.timeout)
  			if err == nil {
  				return response, nil
+ 				}
+ 				c.quicPool.Remove(pc)
  			}
  		}


─── zone/wire.go:95-98 ───
[bug · high] This fallback is reachable only when dns.New fails (i.e. record.Content is not valid
presentation data for the declared type), and it then fabricates an RFC3597 RR that is corrupt in
two ways: (1) the RR header `dns.Header{...}` leaves `Rrtype` unset (0), so the packed wire message
carries type 0 / the Header() accessor reports type 0 to middleware; (2) `rdata.RFC3597.Data` must
be wire-format rdata, but `record.Content` is a presentation-format string (e.g. "192.0.2.1",
"ns1.example.com."), which is not valid generic RFC 3597 encoding. Net effect: a misconfigured
record is either silently dropped at Pack time (packRRs returns nil) or served as a malformed type-0
RR with garbage rdata — never surfaced as a config error. Prefer logging the parse error and
skipping the record (return nil from buildRecord is already handled by buildRRs), and if an RFC3597
fallback is kept, set Rrtype and require genuine "\# len hexdata" content.

  	return &dns.RFC3597{
- 		Hdr:     dns.Header{Name: name, Class: class, TTL: ttl},
+ 		Hdr:     dns.Header{Name: name, Rrtype: record.Type, Class: class, TTL: ttl},
  		RFC3597: rdata.RFC3597{RRType: record.Type, Data: record.Content},
  	}


─── zone/wire.go:69-72 ───
[bug · medium] A relative record name is promoted to an absolute root-zone name:
`dnsutil.Fqdn("www")` yields "www." (single label at the root), not "www.example.com.". Zone-file
records support `name=www` under a `.example.com` header (see parse.go `case "name"`), so these
records are stored with owner "www." — they never match a query for www.example.com (the evaluator
keys on the zone domain, not the record owner), and if served via a matching rule the answer owner
no longer matches the question. The name should be joined to the zone domain when it is not already
fully qualified.

  	name := dnsutil.Fqdn(domain)
  	if record.Name != "" {
+ 		if strings.HasSuffix(record.Name, ".") {
  		name = dnsutil.Fqdn(record.Name)
+ 		} else {
+ 			name = dnsutil.Fqdn(record.Name + "." + domain)
+ 		}
  	}


─── zone/wire.go:23-27 ───
[bug · medium] The Pack error is silently discarded and the caller stores a nil section while still
counting the rule as loaded (zone.go/parse.go). Any record that fails to serialize (e.g. the RFC3597
fallback above, or an oversized section) is dropped without any log or error, so the zone serves an
empty answer at query time as if nothing were wrong. At minimum log the error before returning nil.

  	msg := &dns.Msg{Answer: rrs}
  	if err := msg.Pack(); err != nil {
  		return nil
  	}
- 	return msg.Data


─── zone/wire.go:35-39 ───
[bug · low] An Unpack failure on a stored blob silently yields a nil section, indistinguishable from
a legitimately empty zone — the query then receives an empty answer instead of surfacing the
corrupted stored data. Since the blob is produced internally by packRRs this is defensive-only, but
a Warn log would make corruption diagnosable rather than invisible.



─── scripts/install-hook.ps1:9-12 ───
[bug · medium] With `$ErrorActionPreference = "Stop"` set at the top of the script, `Write-Error`
raises a terminating error and execution never reaches the `exit 1` line — the explicit exit-code
handling is dead code. This makes the failure mode dependent on PowerShell's default
terminating-error exit code rather than an intentional value. Use `Write-Host`/`Write-Output`
followed by `exit 1`, or drop the explicit exit and rely on `Write-Error` alone.

  if (-not (Test-Path $hookSource)) {
-     Write-Error "Hook script not found: $hookSource"
+     Write-Host "Hook script not found: $hookSource" -ForegroundColor Red
      exit 1
  }


─── scripts/install-hook.ps1:7-7 ───
[bug · medium] The destination hardcodes `.git\hooks\pre-commit`, which assumes `.git` is a plain
directory directly under the repo root. This breaks in linked worktrees (where `.git` is a file, not
a directory), and `Copy-Item` will also throw if the `hooks` directory doesn't exist yet. Resolve
the real hooks path via `git rev-parse --git-path hooks/pre-commit` (checking `$LASTEXITCODE`) and
ensure the target directory exists before copying.

- $hookDest   = Join-Path (Split-Path $PSScriptRoot -Parent) ".git\hooks\pre-commit"
+ git rev-parse --git-path hooks/pre-commit 2>$null | Out-Null
+ if ($LASTEXITCODE -ne 0) {
+     Write-Host "Not inside a git repository" -ForegroundColor Red
+     exit 1
+ }
+ $hookDest = git rev-parse --git-path hooks/pre-commit
+ $hookDir  = Split-Path $hookDest -Parent
+ if (-not (Test-Path $hookDir)) { New-Item -ItemType Directory -Path $hookDir -Force | Out-Null }


─── scripts/install-hook.ps1:14-14 ───
[bug · medium] `Copy-Item -Force` silently overwrites any existing pre-commit hook without prompting
or keeping a backup, which can destroy a user's custom hook configuration. Check for an existing
destination hook first and either prompt for confirmation or back it up (e.g., to `pre-commit.bak`)
before overwriting.

+ if (Test-Path $hookDest) {
+     $backup = "$hookDest.bak"
+     Copy-Item -Path $hookDest -Destination $backup -Force
+     Write-Host "Existing hook backed up to $backup"
+ }
  Copy-Item -Path $hookSource -Destination $hookDest -Force


─── scripts/bump-version.ps1:14-14 ───
[bug · medium] Fragile current-version extraction: `Select-String 'Version\s*='` takes the first
line that merely *contains* `Version =`, so a comment line such as `// Version = 0.1.0` appearing
before the real declaration would be picked. The greedy regex `.*"(.*)".*` also captures the
**last** quoted string on the line when several quoted strings are present. And if the file/pattern
is missing, `$Current` is empty and `[int]$null` coerces to 0, so the script silently rewrites the
version to `0.0.x` instead of failing. Anchor the pattern to the actual declaration (e.g.
`(?:const|var)?\s*Version\s*=\s*"\d+\.\d+\.\d+"`), validate the parsed value with `^\d+\.\d+\.\d+$`,
and `throw` when it cannot be parsed.



─── scripts/bump-version.ps1:33-33 ───
[bug · medium] `$Current` is interpolated directly into the regex without escaping. The `.` in a
version like `1.2.3` is a regex wildcard, so the pattern can match unintended text, and PowerShell
`-replace` rewrites **every** occurrence in the file. Escape the value with
`[regex]::Escape($Current)` before building the pattern. Also note the replacement hard-codes 5
spaces, which normalizes whatever whitespace the original declaration used (tabs / gofmt alignment)
— consider capturing and reusing the original whitespace.

- $content = $content -replace "Version\s+=\s+`"$Current`"", "Version     = `"$New`""
+ $escaped = [regex]::Escape($Current)
+ $content = $content -replace "Version\s+=\s+`"$escaped`"", "Version     = `"$New`""


─── scripts/bump-version.ps1:34-35 ───
[bug · medium] Silent no-op risk in both file edits: in version.go, if the -replace does not match
(formatting drift, or $Current parsed incorrectly), the file content is unchanged yet the script
still writes the file and prints "Bumped"; in README.md, if the badge doesn't match the hard-coded
Version-x.y.z- shape (different casing, a v prefix, or different badge URL), no replacement occurs
yet the script still reports "Bumped". Compare content before/after replacement and throw if nothing
changed in either file. Also, Set-Content without -Encoding uses the host default (ANSI in Windows
PowerShell 5.1), which can corrupt UTF-8 Go sources and re-encode the README; specify an explicit
encoding (e.g. -Encoding UTF8, or utf8NoBOM in pwsh). -NoNewline with -Raw preserves the original
trailing newline, but make the encoding explicit.

- Set-Content $VersionFile $content -NoNewline
- Write-Host "Bumped $VersionFile"
+ if ($content -notmatch "Version\s+=\s+`"$New`"") { throw "Version pattern not found in $VersionFile" }
+ Set-Content $VersionFile $content -NoNewline -Encoding UTF8


─── scripts/bump-version.ps1:13-13 ───
[maintainability · low] Paths such as `cmd/zjdns/version.go` and `README.md` are resolved against
the caller's current working directory, so running the script from anywhere other than the repo root
fails (or worse, edits the wrong file). Anchor paths to the script location: the repo root is one
level above the `scripts` directory, so use `$PSScriptRoot` to derive absolute paths.

- $VersionFile = "cmd/zjdns/version.go"
+ $RepoRoot = Split-Path $PSScriptRoot -Parent
+ $VersionFile = Join-Path $RepoRoot "cmd\zjdns\version.go"


─── scripts/install-hook.sh:8-8 ───
[bug · medium] Hardcoding `.git/hooks` breaks in Git worktrees and submodules, where `.git` is a
file (not a directory) containing a `gitdir:` pointer — the subsequent `cp` fails with "Not a
directory". It also ignores `core.hooksPath` if the user has customized the hooks location, so the
installed hook would silently never run. Resolve the real hooks directory with Git itself instead.

- hook_dst="$(dirname "$0")/../.git/hooks/pre-commit"
+ hook_dst="$(git rev-parse --git-path hooks/pre-commit)"


─── scripts/install-hook.sh:15-16 ───
[bug · medium] `cp` silently overwrites an existing pre-commit hook, destroying any user
configuration without warning or backup. Before installing, check whether the destination already
exists and preserve it (e.g., move it aside or prompt before overwriting).

+ if [ -e "$hook_dst" ]; then
+     backup="$hook_dst.$(date +%Y%m%d%H%M%S).bak"
+     cp "$hook_dst" "$backup"
+     echo "Existing hook backed up to $backup"
+ fi
  cp "$hook_src" "$hook_dst"
  chmod +x "$hook_dst"


─── scripts/install-hook.sh:10-13 ───
[bug · medium] No preflight validation ensures the script runs inside a Git repository or that the
target hooks directory exists. Outside a repo (or when `.git`/`.git/hooks` is absent), `cp` fails
with a cryptic "No such file or directory" and `set -e` exits without a useful message. Verify the
repo context first (using `git rev-parse --git-path hooks` also naturally fails outside a repo,
which can serve as the check).

  if [ ! -f "$hook_src" ]; then
      echo "ERROR: Hook script not found: $hook_src" >&2
+     exit 1
+ fi
+
+ if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
+     echo "ERROR: Not inside a Git work tree (run from the repo root)" >&2
      exit 1
  fi


─── scripts/bump-version.sh:21-21 ───
[bug · high] `\s` is a GNU regex extension, not POSIX BRE. The script explicitly branches on `uname`
for BSD/macOS elsewhere, but BSD grep (macOS) does not support `\s`, so this grep fails to match the
actual line `Version     = "3.8.16"` and `CURRENT` becomes empty. Use the POSIX `[[:space:]]*` form,
which is already used consistently in the sed patterns below.

- CURRENT=$(grep 'Version\s*=' "$VERSION_FILE" | head -1 | sed 's/.*"\(.*\)".*/\1/')
+ CURRENT=$(grep 'Version[[:space:]]*=' "$VERSION_FILE" | head -1 | sed 's/.*"\(.*\)".*/\1/')


─── scripts/bump-version.sh:24-26 ───
[bug · high] `CURRENT` is used in arithmetic without any format validation. Because the grep
pipeline's failure status is masked by `head`/`sed`, a missing version.go or a regex mismatch yields
an empty `CURRENT`; under `set -e`, empty components evaluate as 0 in `$((...))` and the script
silently writes a wrong version (e.g. "1.0.1"). A version with a `v` prefix or suffix (e.g.
"v1.2.3", "1.2.3-beta") likewise yields non-numeric segments that produce garbage or abort the
script. Validate that `CURRENT` matches `^[0-9]+\.[0-9]+\.[0-9]+$` before doing the arithmetic.

+ printf '%s\n' "$CURRENT" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || { echo "Invalid current version: $CURRENT" >&2; exit 1; }
  MAJOR=$(echo "$CURRENT" | cut -d. -f1)
  MINOR=$(echo "$CURRENT" | cut -d. -f2)
  PATCH=$(echo "$CURRENT" | cut -d. -f3)


─── scripts/bump-version.sh:39-39 ───
[bug · medium] The version.go and README `sed -i` replacements both lack a post-condition check: if
the target pattern is missing, sed exits 0 and the script still reports success although the file
was not updated. For version.go, also escape the dots in `$CURRENT` (`.` matches any character)
before interpolating it into the `s///` pattern, and after the replacement verify the new line is
present (e.g. `grep -q 'Version     = "$NEW"' "$VERSION_FILE"`), failing if absent. For the README
badge, add the `g` flag so every badge on a line is updated, and verify the new `Version-${NEW}-`
badge is present, failing if it is not.

      sed -i '' "s/Version[[:space:]]*=[[:space:]]*\"$CURRENT\"/Version     = \"$NEW\"/" "$VERSION_FILE"
+     grep -q "Version     = \"$NEW\"" "$VERSION_FILE" || { echo "Failed to bump $VERSION_FILE" >&2; exit 1; }


─── docs/debug/routedns/dtls-client.toml:10-10 ───
[security · medium] Trust anchor is placed in /tmp (world-writable). DEBUG.md generates the cert via
`mkdir -p /tmp/zjdns-certs` + `openssl ... -nodes`, so any local user can replace cert.pem (and
key.pem) and then run a fake DTLS server on 127.0.0.1:10434 to intercept/MITM the debug client's DNS
queries. Even for a loopback-only debug setup this defeats the purpose of TLS. Recommend storing the
CA under a root-owned, non-world-writable directory with restrictive permissions (e.g.
/etc/zjdns/certs, mode 0600/0644) and, ideally, pinning the server certificate instead of trusting a
mutable CA file.



─── docs/debug/routedns/dtls-client.toml:8-9 ───
[bug · medium] DTLS handshake will likely fail with the documented certificate. The client dials
127.0.0.1:10434 and only provides `ca` (no `server-name`), so RouteDNS verifies the server cert
against the name "127.0.0.1". However, DEBUG.md generates the cert with only `-subj
"/CN=zjdns-test.local"` and no subjectAltName extension (Go-based verification requires SANs and
does not fall back to CN). Fix: either regenerate the cert with `-addext "subjectAltName =
IP:127.0.0.1"` so the IP SAN matches, or add `server-name` (and ensure the cert has a matching DNS
SAN) to this resolver.



─── docs/debug/routedns/dtls-client.toml:11-11 ───
[maintainability · low] `bootstrap-address` is a bare IP with no port and is redundant here:
`address` is already an IP literal, so RouteDNS has no hostname to bootstrap-resolve and this option
is ignored. If it were ever honored, the missing port would default to 53 (not the DTLS server port
10434), which is misleading. Remove the line, or if bootstrap resolution is genuinely needed, use
the full `host:port` form of the bootstrap resolver.



─── docs/debug/dnscrypt/proxy-classic-ephemeral.toml:9-9 ───
[maintainability · low] The stamp is currently consistent with the server config
(docs/debug/dnscrypt/zjdns-server.json): address 127.0.0.1:12443, public key 1498ACC3...DE53, and
provider name 2.dnscrypt-cert.zjdns-test.local all match, and the header follows the RFC's
proto(1)+props(8) layout. However, this is hand-embedded key material duplicated across
proxy-classic.toml, proxy-pq.toml, and this file. If the server's DNSCrypt key pair or the
certificate domain is ever rotated, all three stamps must be regenerated in lockstep or the proxy
will silently fail the handshake (public-key mismatch). Add a comment referencing the server config
and the project's `--dnsstamp --encode` tooling to regenerate the stamp, to prevent a stale trust
anchor.



─── docs/debug/dnscrypt/proxy-classic-ephemeral.toml:4-4 ───
[maintainability · low] log_level = 2 (Notice) suppresses Info/Debug messages from dnscrypt-proxy.
For a debug profile whose purpose is to observe DNSCrypt handshake/key-exchange behavior
(docs/debug/DEBUG.md relies on log output to confirm which key exchange was used), consider
log_level = 1 (Info) or 0 (Debug) so per-query handshake and certificate-fetch details are visible.
At Notice level a silent handshake failure is much harder to diagnose.



─── docs/debug/dnscrypt/proxy-classic-ephemeral.toml:2-2 ───
[security · low] Binding to 127.0.0.1 only is correct for this debug profile — the endpoint performs
no client authentication beyond DNSCrypt and forwards to localhost. If listen_addresses is ever
widened to 0.0.0.0 or a LAN interface, this becomes an open, unauthenticated DNS resolver usable by
anyone who can reach it. Keep it loopback-only, or add an explicit comment warning against reuse.



─── docs/debug/dnscrypt/proxy-classic-ephemeral.toml:6-6 ───
[performance · low] dnscrypt_ephemeral_keys = true generates a fresh X25519 client key pair and full
shared-secret derivation for every query, and combined with cache = false there is no response
caching either. This is intentionally the purpose of this debug file (per-query forward secrecy),
but the profile is very expensive at scale — flag it clearly so it is not accidentally reused as a
production upstream profile.



─── .github/dependabot.yml:7-10 ───
[maintainability · low] The `"*"` wildcard batches every GitHub Actions update into a single
Dependabot PR. While convenient, this means one failing check, merge conflict, or manual review
delay blocks all action updates at once, and a large PR is harder to review (e.g., mixed minor and
major bumps in one diff). Consider splitting into narrower groups (by action name/scope patterns) or
removing the group so each dependency gets its own independently-mergeable PR.



─── .github/dependabot.yml:3-6 ───
[maintainability · medium] No `allow`/`ignore` constraints are configured, so Dependabot will open
PRs for major-version bumps of GitHub Actions by default. Major releases of actions frequently
contain breaking changes to inputs/outputs and can silently break workflows. Consider ignoring
major-version updates (e.g., `ignore: [{dependency-name: "*", update-types:
["version-update:semver-major"]}]`) or narrowing the scope with `allow`/`versioning-strategy` so
automatic upgrades cannot break CI.



─── .github/workflows/deps.yml:31-34 ───
[security · high] Third-party GitHub Actions are referenced by mutable major-version tags while
running with access to repository secrets, so a retagged or compromised release could hijack the
pipeline and exfiltrate credentials. Pin each action to a full commit SHA and let
Dependabot/Renovate manage pin updates: `peter-evans/create-pull-request@v8` in
`.github/workflows/deps.yml` (used with `secrets.PAT_TOKEN`), and `docker/setup-buildx-action@v4`,
`docker/login-action@v4`, `docker/build-push-action@v7` in `.github/workflows/main.yml` (used with
`DOCKERHUB_TOKEN`/`GHCR_TOKEN`).

        - name: Create Pull Request
-         uses: peter-evans/create-pull-request@v8
+         uses: peter-evans/create-pull-request@<full-commit-sha>
          with:
            token: ${{ secrets.PAT_TOKEN }}


─── .github/workflows/deps.yml:6-8 ───
[security · medium] Several jobs/workflows declare no `permissions` block, so the `GITHUB_TOKEN`
inherits the repository's default (potentially broad) access instead of least-privilege scopes. In
`.github/workflows/deps.yml`, the `update-deps` job only needs to open a pull request, so set
explicit permissions such as `contents: write, pull-requests: write`. In
`.github/workflows/main.yml`, the workflow only reads source and uses the external
`GHCR_TOKEN`/`DOCKERHUB_TOKEN` secrets, so add a workflow-level `permissions: { contents: read }`.

  jobs:
    update-deps:
+     permissions:
+       contents: write
+       pull-requests: write
      runs-on: ubuntu-latest


─── .github/workflows/deps.yml:28-29 ───
[test · medium] Dependencies are bumped to moving branch heads and `go mod tidy` runs, but nothing
is compiled or tested before the PR is opened. A `main`/`develop` commit that doesn't build, fails
tests, or breaks the module graph would still be proposed for merge. Add verification steps (e.g.,
`go build ./...`, `go vet ./...`, `go test ./...`) that gate the PR creation.

            go get -u gitlab.com/go-extension/tls@master
            go mod tidy
+           go build ./...
+           go vet ./...
+           go test ./...


─── .github/workflows/deps.yml:20-21 ───
[security · medium] Resolving every dependency to a moving branch ref (`@main`, `@develop`,
`@master`) makes the update non-reproducible and pulls arbitrary, unreviewed commits directly into
the module graph — a supply-chain risk. Prefer tagged releases (or `@latest` for the current release
line) and delegate automated updates to a dedicated tool (Dependabot/Renovate) that reviews bumps
before they land.

-           go get -u codeberg.org/miekg/dns@main
-           go get -u gitee.com/Trisia/gotlcp@main
+           go get -u codeberg.org/miekg/dns@latest
+           go get -u gitee.com/Trisia/gotlcp@latest


─── .github/workflows/deps.yml:8-10 ───
[other · low] Several jobs have no `timeout-minutes`, so a hung `run:` step (network stall, registry
login, `go get`/`go mod tidy`) could consume GitHub-hosted runner minutes indefinitely. Add explicit
timeouts: e.g. `timeout-minutes: 30` for the `.github/workflows/deps.yml` job, and `timeout-minutes:
60` on `build` / `15` on `merge` in `.github/workflows/main.yml`.

+     timeout-minutes: 30
      runs-on: ubuntu-latest
      steps:
        - name: Checkout code


─── .golangci.yml:51-51 ───
[maintainability · low] Empty `gosec:` and `makezero:` settings blocks parse as YAML null values
(not empty mappings), so they are no-ops: both linters simply run with defaults and the blocks add
no value or documented intent. Either remove the blocks entirely or populate each with the settings
you actually want (e.g. `gosec`: `severity`, `confidence`, `excludes`, `config`, `audit`;
`makezero`: `always`, `skip-make-assertion`).



─── .golangci.yml:48-49 ───
[maintainability · medium] `enable-all: true` turns on every gocritic checker, including
experimental and opinionated ones, and makes lint output implicitly depend on upstream releases: any
new checker introduced by a future gocritic/golangci-lint version will be auto-enabled and can
change lint results or break CI without a deliberate decision. Since no `disabled-checks`/exclusions
are configured here, this is likely to produce noisy or even conflicting diagnostics. Consider an
explicit `enabled-checks` list (or a curated `disabled-checks` list) instead of blanket-enabling
everything.



─── .golangci.yml:64-65 ───
[bug · medium] `default-signifies-exhaustive: true` makes the exhaustive linter treat a `default`
branch as proof of exhaustiveness, so enum members accidentally omitted from a switch will no longer
be reported whenever that switch has a `default` case. This materially weakens the exhaustiveness
guarantee — the primary purpose of the linter. If strict enum coverage is intended, keep the default
(`false`) and use `default-case-required` to force an explicit default instead.



─── .golangci.yml:88-92 ───
[maintainability · low] Enabling all four perfsprint suggestion groups maximizes mechanical churn
across the codebase: `int-conversion` and `errorf` in particular propose many low-value rewrites
(e.g. wrapping/formatting already-fast paths) that can distract from higher-impact issues. If the
goal is to keep the diff focused, enable only the highest-value checks (e.g. `sprintf1`,
`err-error`) and let other conversions be reviewed on their merits, or narrow scope with exclusions.



─── .github/workflows/main.yml:6-8 ───
[other · low] No `concurrency` group is defined. A manual `workflow_dispatch` run overlapping the
twice-daily scheduled run (or two manual runs in a row) will race while pushing the same `latest`
tag and digests, potentially interleaving or invalidating the published manifest. Add `concurrency:
{ group: build-release, cancel-in-progress: true }` to serialize runs.



─── .github/workflows/main.yml:15-15 ───
[maintainability · medium] `CONTAINTER_TAG` is a typo for `CONTAINER_TAG` (it works only because the
same typo is used consistently, but it will confuse maintainers). More importantly, publishing
scheduled builds to the mutable `latest` tag is not reproducible — consumers get whatever code
happened to be checked out at build time. Prefer an explicit version/run-based tag (e.g. `${{
github.run_number }}` or a date) and only add `latest` as an additional alias.



─── .github/workflows/main.yml:19-19 ───
[bug · high] `continue-on-error: true` on the `build` job turns a failed platform build into a
successful job, so the dependent `merge` job still runs when, e.g., only the arm64 leg failed. The
missing platform digest artifact is then skipped (`download-artifact` defaults to
`if-no-files-found: warn`), and `merge` silently publishes a single-platform/incomplete `latest`
manifest — or fails deep inside `imagetools create`. Remove `continue-on-error` so a failed platform
build aborts the workflow before any incomplete manifest can be published.



─── .github/workflows/main.yml:57-57 ───
[performance · low] The scheduled build always rebuilds from scratch on both platforms. Add a build
cache so recurring runs are faster and registry/dependency churn is reduced — e.g. `cache-from:
type=gha` / `cache-to: type=gha,mode=max` on `docker/build-push-action`.



─── .github/workflows/main.yml:121-122 ───
[bug · high] `docker buildx imagetools create -t <name>@sha256:<digest>` is invalid: the `-t/--tag`
option expects a `name:tag` reference, not a digest reference, so this loop will fail. The final
manifest-merge step below also relies on these Docker Hub digest references existing, so the entire
`merge` job is broken. Copy each platform image using a tag (e.g. `:${digest}`) and update the final
`imagetools create` step to reference `:${digest}` accordingly.

            for digest in *; do
-             docker buildx imagetools create -t ${{ env.DOCKERHUB_NAMESPACE }}/${{ matrix.package }}@sha256:${digest} \
+             docker buildx imagetools create -t ${{ env.DOCKERHUB_NAMESPACE }}/${{ matrix.package }}:${digest} \
+               ${{ env.GHCR_NAMESPACE }}/${{ matrix.package }}@sha256:${digest}
+           done


─── .gitignore:32-32 ───
[security · medium] Only the exact filename `.env` is matched by this rule. Variants such as
`.env.local`, `.env.development`, or `.env.production` will NOT be ignored and could be accidentally
committed, leaking credentials/secrets. Consider `/.env*` and explicitly re-include a template file
if one is meant to be committed (e.g. `!.env.example`).

- .env
+ .env*
+ !.env.example


─── .gitignore:2-2 ───
[other · low] Several build-output ignore patterns in `.gitignore` are root-anchored or missing, so
generated artifacts can be committed. `/zjdns` only ignores the binary at the repo root (while
`*.exe` covers Windows binaries anywhere); `/tmp/` and `/dist/` only match at the root and miss
nested outputs such as `cmd/zjdns/dist/`; and common Go output directories `bin/` and `build/` are
absent. Consider using unanchored/recursive patterns (e.g. `zjdns`, `**/tmp/`, `**/dist/`) or
explicitly adding `bin/` and `build/`.



─── .gitignore:35-35 ───
[other · low] `*.db` matches database files anywhere in the repo. If the project intentionally
checks in seed/fixture databases for tests or reference data, this rule will silently exclude them
from version control. Consider scoping the pattern to runtime/volatile paths or adding explicit
exceptions (e.g. `!testdata/*.db`) for intentional fixtures. Also note SQLite variants (`*.sqlite`,
`*.sqlite3`) are not covered.



─── .gitignore:20-20 ───
[other · low] The Go coverage patterns only cover `/coverage.txt` at the root (plus
`*.out`/`*.prof`). Common coverage report outputs such as `coverage.html`, `coverage.xml`, or
`coverage/` directories are not ignored and could be committed as generated artifacts. Consider
`coverage.*` or a dedicated `coverage/` directory rule.

- /coverage.txt
+ coverage.*
+ coverage/


─── LICENSE:3-3 ───
[other · high] The combination of Apache License, Version 2.0 with the Commons Clause is legally
inconsistent and creates compliance ambiguity. The embedded Apache 2.0 text grants a perpetual,
irrevocable license that explicitly includes commercial use, and its section 4 permits recipients to
provide additional or different license terms for their modifications; the Commons Clause denies the
right to Sell the Software, so the terms directly conflict and a downstream licensee could strip the
Commons Clause when redistributing derivative works. The file also appends the Commons Clause after
the unmodified Apache 2.0 text, making it unclear whether this License (which section 4(a) requires
redistributors to give recipients) refers to the ASF-published Apache 2.0 or this modified
combination; standard license scanners will not recognize it as Apache-2.0, and this is neither the
Apache License as published by the ASF nor an OSI-approved license. If the goal is to restrict
commercial resale, use a single coherent custom/source-available license explicitly labeled as
derived from Apache 2.0 instead of relabeling a modified Apache text.



─── Dockerfile:1-1 ───
[maintainability · medium] The Dockerfile relies on floating/mutable version references, making
builds non-reproducible and creating supply-chain risk: `GOLANG_VERSION="1"` resolves to the latest
Go release, and dependencies are fetched via `go get -u` from mutable branches (`@main`, `@develop`,
`@master`), so the same Dockerfile can produce different binaries over time and untested or
malicious upstream changes can be pulled in. Pin the Go toolchain to a specific minor release that
matches go.mod, and pin each dependency to a released tag or immutable commit SHA.

- ARG GOLANG_VERSION="1"
+ ARG GOLANG_VERSION="1.26"


─── Dockerfile:7-7 ───
[security · medium] `ADD . /zjdns` copies the entire build context into the build stage, including
`.git`, local secrets, and leftover build artifacts. There is no `.dockerignore` in the repo, so
nothing is excluded. Additionally, `ADD` auto-extracts local tar archives, which is rarely intended
here. Use `COPY . /zjdns` and add a `.dockerignore` (excluding `.git`, secrets, build outputs) to
shrink the context and keep sensitive files out of the image.

- ADD . /zjdns
+ COPY . /zjdns


─── Dockerfile:13-13 ───
[security · high] The root CA bundle is downloaded from curl.se at build time with no
checksum/signature verification, then installed as the only system trust store in the final image.
If the download is tampered with (compromised CDN/upstream, or a MITM if https is ever downgraded),
every TLS client in the runtime image would trust attacker-controlled roots. Verify the bundle
against a pinned SHA-256 digest after download, or copy `/etc/ssl/certs/ca-certificates.crt` from a
pinned, well-known base image instead of fetching it at build time.



─── Dockerfile:39-39 ───
[security · medium] The final scratch image has no `USER` directive, so `/zjdns` runs as UID 0
inside the container. Since this is a network-facing DNS/TLS service, a vulnerability in the binary
would give an attacker full root privileges in the container. Add a non-root user in the build stage
(including an `/etc/passwd` entry, since scratch has none) and set `USER <uid>` before the
`ENTRYPOINT`; also consider read-only rootfs/dropping capabilities.



─── scripts/pre-commit:24-26 ───
[bug · high] The re-staging check `git diff --quiet -- "$f"` only detects whether the working-tree
version differs from the index — it cannot distinguish formatter changes from pre-existing unstaged
edits. If a staged file already had unstaged modifications before `go fix`/`golangci-lint fmt` ran,
`git add "$f"` will silently sweep those unrelated edits into the commit. To be safe, verify that
all staged files are worktree-clean (no unstaged changes) before running the formatters and abort
with a clear message otherwise, or snapshot/restore the pre-format worktree content so only
formatter-produced changes get re-staged.



─── scripts/pre-commit:23-23 ───
[bug · medium] `for f in $staged` word-splits and glob-expands the captured file names, so any
staged path containing spaces or glob characters (`*`, `?`, `[`) is broken into multiple bogus
entries and never re-staged correctly. Capture the list NUL-separated and iterate safely:
`staged=$(git diff --cached --name-only -z --diff-filter=ACM)` followed by `while IFS= read -r -d ''
f; do ... done`.

- 	for f in $staged; do
+ 	while IFS= read -r -d '' f; do


─── scripts/pre-commit:15-18 ───
[maintainability · medium] The pre-commit hook runs `go fix ./...`, `golangci-lint fmt ./...`, and
`golangci-lint run ./...` on the entire module rather than only the files staged for this commit.
This can rewrite many unrelated files (even when `$staged` is empty, e.g. on `--amend`), and with
`set -e` it will hard-fail the commit if `golangci-lint` is missing (exit 127) or if there are
pre-existing lint failures anywhere in the module. Scope these commands to the staged Go files (e.g.
via `git diff --cached --name-only --diff-filter=ACM -- '*.go'`), and check that the lint binary is
available up front with a clear error message.




──────── Project Summary ────────

### Top Issues

1. **DNSSEC validation can certify unauthenticated or bogus data as valid.** Multiple independent flaws in `server/resolver/dnssec/` combine into a false-sense-of-security posture: `trust_anchor.go` never cross-checks `KeyDigest`/`KeyTag` against the reconstructed DNSKEY and ignores `ValidFrom`; `validate.go` treats mere presence of DNSSEC records (or the upstream AD bit) as proof of validation; `dnssec_chain.go` accepts an unauthenticated CDS/CDNSKEY response as an offline-KSK fallback and uses stale `parentDNSKEYs`; `crypto.go` reports success if *any one* RRset validates; and `nsec.go` rejects Opt-Out proofs as bogus while silently capping NSEC3 iterations so hashes can never match. Any one of these is serious; together they mean a resolver configured for strict validation can serve forged or insecure data while logging "validated".

2. **Widespread data races on shared resolver/server state.** The same pattern repeats across the codebase: mutable fields read on query paths while written by background/control goroutines. Representative paths: `stats/stats.go` (`Reset()` does a non-atomic struct copy racing `Record()`), `server/protocol/dnscrypt/crypto.go` (ticket keys written under `s.mu` but read without it), `server/resolver/dnssec_chain.go` (`Recursive.lastEDECode` plain uint16), `server/tasks.go` + `server/bridge.go` (sweep deletes `tcpWriteMu` entries still in use), `internal/lrumap/lru.go` (unsynchronized `OnEvict` field), and `server/resolver/probe/probe.go` (in-flight dedup keyed only by qname+qtype). These are not theoretical: `stats.Reset()` is reachable from DNS query handling via the CHAOS `.stats.clear` rule.

3. **Systematic error swallowing makes failures indistinguishable from success.** Dozens of comments document discarded errors or results: `cache/lifecycle.go` (View, `ValueCopy`, and `db.Update` errors all dropped — a failed latency write looks like a successful probe), `cmd/zjdns/main.go` (banner `fmt.Print` error ignored, then startup proceeds), `server/protocol/plain/server.go` and `server/protocol/tlcp/tlcp.go` (Shutdown hides all per-server errors and returns nil; TLCP logs and skips `net.Listen` failures so `Start` reports success while serving nothing), `zone/wire.go` (Pack/Unpack failures yield nil sections with no log), and `server/handler/middleware/dns64.go` (secondary A lookup failure returned as NODATA). The net effect is that operators cannot distinguish "working" from "silently degraded".

4. **TLS/TLCP trust is broken in both directions.** Config validation skips TLS/TLCP certificate checks entirely when `IsEnabled()` is false, before checking whether a TLS-based protocol is enabled (`config/config.go`), so partial/missing cert configs pass. Generated certs only set CommonName and never SANs (`server/protocol/tlcp/certs.go`, `server/protocol/tls/certs.go`), failing modern hostname verification. The TLCP client ships an always-empty `smx509.CertPool` with nothing ever added to it (`server/upstream/tlcp/client.go`), and its `VerifyConnection` callbacks unconditionally return nil. On the QUIC side, `server/protocol/tls/addr_validator.go` has inverted return polarity relative to quic-go's `VerifySourceAddress` contract.

5. **Cache layer produces wrong answers, not just misses.** `cache/lifecycle.go` computes reverse-lookup TTLs that are always the stale TTL and has `LatencyLastProbe` return the current time instead of the last probe time (making probe-interval logic dead). `server/handler/response.go` loses NXDOMAIN rcode entirely (negative responses cached as NOERROR). `cache/store.go` interprets the OPT pseudo-record's TTL field as a real TTL (RFC 6891 violation), so common OPT TTL 0 entries expire immediately. `cache/ptr.go` dedup keys are case-sensitive (RFC 4343 violation). And `internal/ttl/ttl.go`'s cyclical wrap resets expired records to a full TTL at exact multiples.

6. **Config loading silently discards user intent.** `config/load.go` unmarshals into a zero-value `ServerConfig{}`, so omitted fields disable DNSSEC enforcement, ECS, DDR, and port defaults; the no-config path skips CHAOS/DDR enrichment entirely. `config/ecs.go` has a marshal→unmarshal round-trip bug where `PreferIPv4: false` becomes `true` (omitzero). And `server/protocol/dnscrypt/generate.go` regenerates *both* DNSCrypt keys whenever either is empty, silently discarding a user-provided public or private key.

7. **Unbounded resource growth and leaked lifetime objects.** `server/server.go` never closes the BadgerDB handle on any post-`database.Open` error path (exclusive dir lock + background goroutines leak), and `srv.Start()` failure abandons the already-open DB. `internal/latency/prober.go` spawns one goroutine per input IP regardless of the semaphore limit. `server/protocol/tls/http3.go` and `server/protocol/tls/tls.go` have no admission cap on connections (only on streams/goroutines). `server/upstream/tls/client.go` leaks the UDP `pconn` when `quic.Dial` fails. `internal/dnsutil/download.go` leaves partial/corrupt trust-material files in place and accepts them on later runs.

8. **Protocol parsers crash or corrupt on malformed input.** `internal/stamp/stamp.go` has out-of-bounds reads and minimum-length guards that are both too strict (rejecting valid short stamps) and too lax (missing padding for length-byte reads). `edns/ecs.go` can panic when a client-supplied `SourcePrefix` exceeds the address length. `internal/dnscryptcrypto/pq.go` slices certificates at fixed offsets without length checks and forwards arbitrary-length inputs to `xwing.Decapsulate`, which panics. `cmd/zjdns/cli/probe.go` panics on `resp.ID >= probePipelineNumQueries` and packs malformed wire messages with `Rrtype` unset.

9. **Upstream transport races and incorrect fallback behavior.** `server/upstream/pool/quic.go` can hand out the same `*quic.Conn` to concurrent queries and closes connections under `p.mu`; `server/upstream/pool/tcp.go` has a ctx-cancellation race that leaks a pooled `*dns.Msg`; `server/upstream/tls/https.go` has a non-atomic Get→compare→Delete eviction race and nil-map panic on Close racing queries; `server/upstream/tls/http3.go` closes the shared cached transport on caller-side context cancellation and HTTP non-200s. The DTLS→TLS fallback in `server/upstream/client.go` reuses the expired `ctx`, so it fails immediately.

10. **CLI and ops tooling fails silently.** `cmd/zjdns/cli/parse.go` never surfaces CLI failures as non-zero exit status, and conflicting special modes (`--version --generate-config`, etc.) are silently resolved by a priority chain. `cmd/zjdns/cli/dnsstamp.go` drops ODoH paths, silently drops `--stamp-addr` for odoh-target, and normalizes empty paths to "/". The `.cache.clear` CHAOS rule (`config/chaos.go` + `server/init.go`) also wipes all stats as a side effect and leaks raw error text into DNS TXT answers.

### Module Hotspots

- **`server/resolver/` and `server/resolver/dnssec/`** — highest severity density. DNSSEC trust/validation, qname minimisation returning an empty QNAME, EDE race, root-hint `sync.Once` caching permanent failure, and multi-hop CNAME chains losing records.
- **`server/upstream/`** — ~30 comments spanning pool races, credential leaks in warmup logs, nil-dialer permanent caching, URL/port mishandling, and protocol fallbacks that reuse dead contexts.
- **`internal/dnscryptcrypto/`** — 16+ comments on PQ certificate validation, packet-bound violations, TCP padding inconsistencies, stale shared-key reuse, and mutable `ResolverMagic`.
- **`cache/` + `internal/ttl/`** — TTL/lifecycle correctness is broken in several independent ways (always-stale reverse TTLs, OPT TTL misinterpretation, negative-rcode loss, case-sensitive dedup).
- **`config/`** — validation gaps that permit partial TLS/TLCP/DNSCrypt configs, defaults silently discarded by zero-value unmarshal, and ECS round-trip corruption.
- **`internal/stamp/`** — parser OOB reads plus encode-side port/path loss and malformed IPv6 handling.
- **`scripts/`** — every shell and PowerShell script has portability, regex-escaping, overwrite-without-backup, or silent no-op issues.

### Cross-Cutting Concerns

- **Discarded errors / nil results treated as success.** Appears in nearly every module: `cache/lifecycle.go`, `zone/wire.go`, `server/protocol/plain/server.go`, `server/protocol/tlcp/tlcp.go`, `server/handler/middleware/dns64.go`, `internal/dnsutil/bind.go`, `internal/ipdetect/ipdetect.go`, `cmd/zjdns/main.go`.
- **Unsafe shared mutable state.** `stats/stats.go` Reset race, `server/protocol/dnscrypt/crypto.go` ticket keys, `server/resolver/dnssec_chain.go` `lastEDECode`, `server/init.go` dynamic CHAOS rules racing `stats.Record`, `internal/lrumap/lru.go` unsynchronized field, `server/upstream/dnscrypt/state.go` post-publish write to `ephemeralKeys`, `server/upstream/warmup.go` pointer capture into caller's backing array.
- **Input validation deferred or absent until panic.** `edns/ecs.go` prefix panic, `internal/stamp/stamp.go` OOB, `internal/dnscryptcrypto/pq.go` fixed-offset slicing, `zone/wire.go` RFC3597 fallback with `Rrtype` 0, `server/handler/middleware/dns64.go` calling `qd.Header()` on a `dns.Question` value, `server/resolver/qname_minimise.go` returning an empty QNAME.
- **TTL/expiry semantics inconsistent.** `internal/ttl/ttl.go` boundary mismatch with `IsExpired` and cyclical wrap to full TTL; `cache/lifecycle.go` always-stale TTL; `cache/store.go` OPT TTL; `server/resolver/dnssec/extract.go` DNSKEY cache cap silently dropped; `database/keys.go` negative TTL conversion.
- **Listener/service shutdown races.** `server/protocol/plain/server.go` (slices appended during Start while Shutdown runs; `wg.Add` vs `wg.Wait`), `server/protocol/dnscrypt/tcp.go` (same WaitGroup pattern), `server/tasks.go` (sweep vs in-flight write), `server/upstream/tls/https.go` (nil-map on Close), `server/upstream/pool/quic.go` (Close under lock).
- **Generated artifacts / configs with trust implications.** Hardcoded DNSCrypt private key in the example config (`cmd/zjdns/cli/generate.go`), /tmp world-writable trust anchor in debug docs (`docs/debug/routedns/dtls-client.toml`), mutable `@main`/`@develop` dependency refs in `Dockerfile` and `.github/workflows/deps.yml`.
- **CLI exit-code and silent-mode bugs.** `cmd/zjdns/cli/parse.go` (exit status never set), conflicting special modes ignored, `cmd/zjdns/cli/probe.go` (misreports idle timeout, no dial timeout, cannot detect reordering).

### Quick Wins

- **Close `db` on every error return in `server/server.go` after `database.Open`** (and add a `Close` method). One-line fix per error path; stops BadgerDB dir-lock/goroutine leaks.
- **Fix `cmd/zjdns/cli/probe.go`**: set `Rrtype: dns.TypeA`/`dns.TypePTR` on constructed RRs and bounds-check `resp.ID` before indexing `seen`. Both are two-line changes that eliminate malformed wire messages and a panic.
- **Fix `config/ecs.go` omitzero round-trip** by making `PreferIPv4` a pointer or adding a custom `MarshalJSON`/`UnmarshalJSON` pair that distinguishes absent from false.
- **Replace `stats.Collector.Reset()`'s `*c = Collector{}` with a mutex or atomic-flag snapshot** so the CHAOS `.stats.clear` path cannot race `Record()`.
- **Fix `cache/lifecycle.go` `LatencyLastProbe`** to return the stored timestamp (or delete the function and its dead call sites in `server/resolver/probe/probe.go`); likewise remove the dead `ewmaQuerySize` field in `server/upstream/dnscrypt/state.go` and the unused `cache` field in `server/handler/middleware/zone.go`.
- **Harden `internal/stamp/stamp.go` parsing**: add length checks for the provider-name/path length-byte reads and correct the over-strict DNSCrypt/relay minimums. Small, contained, prevents OOB panics on untrusted stamps.
- **Set a dial timeout in `cmd/zjdns/cli/probe.go`** (`net.Dialer{Timeout: ...}`) so blackholed targets cannot hang the CLI for minutes.
- **Escape `$Current` with `[regex]::Escape`/`sed`-safe escaping in `scripts/bump-version.*`** and replace GNU `\s` with POSIX `[[:space:]]` in the shell script; both are one-line fixes for silent no-op or wrong-file edits.
- **Pin GitHub Actions to commit SHAs in `.github/workflows/deps.yml`** and add `permissions:` blocks; low effort, removes a supply-chain and credential-exposure risk.
- **Fix `server/protocol/tls/addr_validator.go` return polarity** to match quic-go's `VerifySourceAddress` contract (and its own doc comment), or the source-address whitelist always sends/withholds Retry incorrectly.
