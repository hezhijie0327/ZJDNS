# prepare-etls.ps1 - materialise the ./.etls-patched replacement directory:
# copy the go.mod-pinned gitlab.com/go-extension/tls version out of the module
# cache and apply every patch in third_party/patches/ (numbered order).  Any
# patch that fails to apply aborts the build loudly - that means upstream
# drifted; see third_party/patches/README.md for the re-sync procedure.
#
# Run once per fresh clone and after every eTLS version bump.  Until it has
# run, every go command fails with:
#   "replacement directory ./.etls-patched does not exist"
#
# (POSIX twin: scripts/prepare-etls.sh, used by the Docker build.)

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

$Module = "gitlab.com/go-extension/tls"
$Dest = ".etls-patched"

# go.mod pins the version as a pseudo-version.
$pin = Select-String -Path go.mod -Pattern '^\s*gitlab\.com/go-extension/tls (v\S+)' | Select-Object -First 1
if (-not $pin) { throw "prepare-etls: cannot find $Module version in go.mod" }
$Ver = $pin.Matches[0].Groups[1].Value

# Fetch the pinned version into the module cache WITHOUT loading this repo's
# go.mod: the replace directive points at $Dest, which does not exist yet - a
# plain `go mod download` here would fail on it.  A throwaway module in a
# temp dir has no such replace.
$Tmp = Join-Path ([IO.Path]::GetTempPath()) ("etls-" + [IO.Path]::GetRandomFileName())
New-Item -ItemType Directory (Join-Path $Tmp "m") -Force | Out-Null
try {
    Push-Location (Join-Path $Tmp "m")
    try {
        go mod init tmp *> $null
        if ($LASTEXITCODE -ne 0) { throw "prepare-etls: go mod init failed" }
        go mod edit "-require=$Module@$Ver"
        if ($LASTEXITCODE -ne 0) { throw "prepare-etls: go mod edit failed" }
        $OldGoFlags = $env:GOFLAGS
        $env:GOFLAGS = "-mod=mod"
        try {
            go mod download "$Module@$Ver" *> $null
        }
        finally {
            $env:GOFLAGS = $OldGoFlags
        }
        if ($LASTEXITCODE -ne 0) { throw "prepare-etls: go mod download $Module@$Ver failed" }
    }
    finally {
        Pop-Location
    }

    $Src = Join-Path (go env GOMODCACHE) "$Module@$Ver"
    if (-not (Test-Path $Src)) { throw "prepare-etls: $Src not found after download" }

    # Wipe any previous generation but keep the tracked bootstrap README (it is
    # the only git-visible file in this gitignored directory).
    if (Test-Path $Dest) {
        Get-ChildItem $Dest -Force | Where-Object { $_.Name -ne "README.md" } | Remove-Item -Recurse -Force
    }
    else {
        New-Item -ItemType Directory $Dest | Out-Null
    }
    Copy-Item (Join-Path $Src "*") $Dest -Recurse -Force
    # chmod -R u+w equivalent: the module cache stores files read-only.
    Get-ChildItem $Dest -Recurse -File | ForEach-Object { $_.IsReadOnly = $false }

    Get-ChildItem "third_party/patches/*.patch" | Sort-Object Name | ForEach-Object {
        Write-Host "prepare-etls: applying $($_.Name)"
        git apply "--directory=$Dest" $_.FullName
        if ($LASTEXITCODE -ne 0) { throw "prepare-etls: patch failed to apply: $($_.Name)" }
    }

    Write-Host "prepare-etls: $Module@$Ver + patches -> $Dest/"
}
finally {
    Remove-Item $Tmp -Recurse -Force -ErrorAction SilentlyContinue
}
