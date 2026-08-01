# Install the pre-commit hook on Windows.
# Run from the repo root: pwsh scripts/install-hook.ps1

$ErrorActionPreference = "Stop"

$hookSource = Join-Path $PSScriptRoot "pre-commit"

# Pre-flight: must run inside the repository; git-path resolves the hooks
# dir correctly for worktrees.
$hookDir = git rev-parse --git-path hooks 2>$null
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($hookDir)) {
    Write-Host "ERROR: not inside a git repository" -ForegroundColor Red
    exit 1
}
New-Item -ItemType Directory -Path $hookDir -Force | Out-Null
$hookDest = Join-Path $hookDir "pre-commit"

if (-not (Test-Path $hookSource)) {
    Write-Host "ERROR: Hook script not found: $hookSource" -ForegroundColor Red
    exit 1
}

# Back up an existing hook instead of silently overwriting it.
if (Test-Path $hookDest) {
    $same = (Get-FileHash $hookSource).Hash -eq (Get-FileHash $hookDest).Hash
    if (-not $same) {
        $backup = "$hookDest.bak.$(Get-Date -Format yyyyMMddHHmmss)"
        Copy-Item -Path $hookDest -Destination $backup
        Write-Host "Existing hook backed up to $backup"
    }
}

Copy-Item -Path $hookSource -Destination $hookDest -Force
Write-Host "Pre-commit hook installed to $hookDest"
