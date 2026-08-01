# bump-version.ps1 — bump ZJDNS version.
# Usage: pwsh scripts/bump-version.ps1 <patch|minor|major>

param(
    [Parameter(Mandatory)]
    [ValidateSet("patch", "minor", "major")]
    [string]$Bump
)

$ErrorActionPreference = "Stop"

# ── Parse current version from version.go ────────────────────────────────
# Anchor to the actual Version declaration (a comment or other file could
# contain a similar pattern) and fail loudly if it cannot be parsed.
$VersionFile = Join-Path $PSScriptRoot "..\cmd\zjdns\version.go"
$match = Select-String -Path $VersionFile -Pattern '^\s*Version\s+=\s+"([0-9]+\.[0-9]+\.[0-9]+)"' | Select-Object -First 1
if ($null -eq $match) {
    throw "Could not parse a numeric version from $VersionFile"
}
$Current = $match.Matches[0].Groups[1].Value
Write-Host "Current version: $Current"

$parts = $Current -split '\.'
$Major = [int]$parts[0]
$Minor = [int]$parts[1]
$Patch = [int]$parts[2]

switch ($Bump) {
    "major" { $Major++; $Minor = 0; $Patch = 0 }
    "minor" { $Minor++; $Patch = 0 }
    "patch" { $Patch++ }
}

$New = "$Major.$Minor.$Patch"
Write-Host "New version:     $New"

# ── Bump version.go ──────────────────────────────────────────────────────
$content = Get-Content $VersionFile -Raw
$escapedCurrent = [regex]::Escape($Current)
$content = $content -replace "Version\s+=\s+`"$escapedCurrent`"", "Version     = `"$New`""
Set-Content -Path $VersionFile -Value $content -NoNewline -Encoding utf8NoBOM
if (-not (Select-String -Path $VersionFile -Pattern "Version\s+=\s+`"$New`"" -Quiet)) {
    throw "Failed to bump $VersionFile to $New"
}
Write-Host "Bumped $VersionFile"

# ── Bump README version badge ────────────────────────────────────────────
$Readme = Join-Path $PSScriptRoot "..\README.md"
$readmeContent = Get-Content $Readme -Raw
$readmeContent = $readmeContent -replace "Version-\d+\.\d+\.\d+-", "Version-$New-"
Set-Content -Path $Readme -Value $readmeContent -NoNewline -Encoding utf8NoBOM
if (-not ($readmeContent -match "Version-$New-")) {
    throw "Failed to bump README badge to $New"
}
Write-Host "Bumped $Readme"
