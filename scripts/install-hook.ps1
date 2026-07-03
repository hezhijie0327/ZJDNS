# Install the pre-commit hook on Windows.
# Run from the repo root: pwsh scripts/install-hook.ps1

$ErrorActionPreference = "Stop"

$hookSource = Join-Path $PSScriptRoot "pre-commit"
$hookDest   = Join-Path (Split-Path $PSScriptRoot -Parent) ".git\hooks\pre-commit"

if (-not (Test-Path $hookSource)) {
    Write-Error "Hook script not found: $hookSource"
    exit 1
}

Copy-Item -Path $hookSource -Destination $hookDest -Force
Write-Host "Pre-commit hook installed to .git/hooks/pre-commit"
