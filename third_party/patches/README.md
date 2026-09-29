# eTLS build-time patches

`gitlab.com/go-extension/tls` (eTLS) is consumed through a build-time patch
flow instead of a vendored copy:

- `go.mod` pins the upstream version and redirects it with
  `replace gitlab.com/go-extension/tls => ./.etls-patched`.
- `sh scripts/prepare-etls.sh` copies the pinned version out of the module
  cache into the gitignored `./.etls-patched/` and applies every
  `NNNN-*.patch` here in numbered order (`git apply`, zero extra tools).
- Every build environment runs the script first: the Dockerfile does it
  before `go get`/`go build`; locally run it once per clone. Until it has
  run, go fails with "replacement directory ./.etls-patched does not exist".

A patch that no longer applies aborts the script — upstream drifted, see
"Re-sync" below.

## Version tracking

The Docker build tracks `gitlab.com/go-extension/tls@master` deliberately:
it drops the replace, `go get`s master, re-adds the replace and re-runs the
prepare script — so a patch that no longer applies to master HEAD **fails
the Docker build loudly**.  That failure is the intended drift signal: it
means the patches need regenerating (or upstream fixed the bugs and the
whole mechanism can be deleted).  A plain `go get` cannot do this dance —
with the replace present it silently no-ops the module.

Local/dev builds stay on whatever pseudo-version go.mod pins (updated by the
same `go mod edit -dropreplace` / `go get` / `go mod edit -replace` /
`sh scripts/prepare-etls.sh` sequence, or by the weekly dependency review).

## Patches

### 0001 — kernel_linux.go: missing `fallthrough` in the >=6.19 capability case

`init()`'s version-capability switch added the `TLS_TX_MAX_PAYLOAD` (>=6.19)
arm without `fallthrough`. Go switches do not fall through implicitly, so on
kernels >= 6.19 the switch exits after that first arm and `kernel.TLS` stays
false — eTLS then silently skips kernel offload for every connection
(`setup()` returns at `if !kernel.TLS`), with no log line and no setsockopt
attempt (strace shows zero `TCP_ULP`).

Isolated A/B proof with a simulated `7.2.8-x64v2-xanmod1` uname: upstream
installs nothing (`TlsTxSw` unchanged); with the fallthrough the install
sequence `TCP_ULP → TLS_RX/TLS_TX` succeeds and `TlsTxSw` increments.

### 0002 — kernel_linux.go: semver.Parse rejects 4-part vendor kernel releases

`init()` parsed `uname.Release` with strict semver. Vendor releases with a
4-part version core (WSL `6.18.33.2-microsoft-standard-WSL2`, BSP kernels)
are invalid semver, so the parse failed and `init()` returned before setting
any capability — same silent KTLS disable, different gate. Fix: on parse
failure, coerce the pre-release base's first three dot segments to
MAJOR.MINOR.PATCH and retry; any other malformed release keeps the upstream
behaviour. Every capability threshold is a minor-version boundary, so the
dropped suffix can never cross one.

Verified on WSL (real `6.18.33.2-microsoft-standard-WSL2`): upstream code
makes zero `TCP_ULP` attempts; with the coercion the shared-port DoT/DoH
install sequence succeeds and `TlsTxSw` increments.

## Re-sync (after upstream fixes these / when bumping the pin)

1. Update the `require` version in `go.mod` (upstream fixed both bugs:
   also delete the patches here, the replace line in `go.mod`, this
   directory, `scripts/prepare-etls.sh`, the `.gitignore` stanza and the
   `.etls-patched/README.md` bootstrap, plus the Dockerfile prepare line).
2. Bump only: `sh scripts/prepare-etls.sh` — if a patch fails to apply,
   regenerate it against the new source (`git diff --no-index` pristine vs
   patched tree, paths relative to the module root) and update the rationale
   above.
