# update-deps.ps1 - refresh the tracked direct dependencies (weekly review).
# Usage:
#   pwsh scripts/update-deps.ps1
#
# The eTLS bump needs the dropreplace / go-get-master / re-replace dance from
# the Dockerfile: with the replace directive active a plain `go get` silently
# no-ops the module (see third_party/patches/README.md "Version tracking").
# A patch that no longer applies to master aborts the second prepare-etls
# loudly - regenerate it per README "Re-sync".
#
# The patch step calls the native PowerShell twin scripts/prepare-etls.ps1
# (the Docker build uses the POSIX twin scripts/prepare-etls.sh instead).

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

function Invoke-Step {
    # ValueFromRemainingArguments is required: without it PowerShell silently
    # swallows dash tokens like `-u` or `-dropreplace=...` (no matching
    # parameter), e.g. "go get -u pkg" became "go get pkg".
    param(
        [Parameter(Position = 0)][string]$Exe,
        [Parameter(Position = 1, ValueFromRemainingArguments)][string[]]$ArgList
    )
    Write-Host "+ $Exe $($ArgList -join ' ')"
    & $Exe @ArgList
    if ($LASTEXITCODE -ne 0) { throw "update-deps: failed: $Exe $($ArgList -join ' ')" }
}

# ./.etls-patched must exist before any go command while the replace is active.
Invoke-Step pwsh scripts/prepare-etls.ps1

Invoke-Step go get -u codeberg.org/miekg/dns@main
Invoke-Step go get -u gitee.com/Trisia/gotlcp@main
Invoke-Step go get -u github.com/cloudflare/circl@main
Invoke-Step go get -u github.com/klauspost/compress@master
Invoke-Step go get -u github.com/pion/dtls/v3@main
Invoke-Step go get -u github.com/quic-go/quic-go@master

# eTLS master dance; on failure re-add the replace so go.mod stays buildable
# against the previously prepared ./.etls-patched tree.
try {
    Invoke-Step go mod edit "-dropreplace=gitlab.com/go-extension/tls"
    Invoke-Step go get -u gitlab.com/go-extension/tls@master
}
catch {
    go mod edit "-replace=gitlab.com/go-extension/tls=./.etls-patched"
    throw
}
Invoke-Step go mod edit "-replace=gitlab.com/go-extension/tls=./.etls-patched"

Invoke-Step pwsh scripts/prepare-etls.ps1
Invoke-Step go mod tidy
Write-Host "update-deps: done - review git diff go.mod go.sum before committing"
