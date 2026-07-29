# bump-version.ps1 — bump ZJDNS version.
# Usage: pwsh scripts/bump-version.ps1 <patch|minor|major>

param(
    [Parameter(Mandatory)]
    [ValidateSet("patch", "minor", "major")]
    [string]$Bump
)

$ErrorActionPreference = "Stop"

# ── Parse current version from version.go ────────────────────────────────
$VersionFile = "cmd/zjdns/version.go"
$Current = (Select-String -Path $VersionFile -Pattern 'Version\s*=' | Select-Object -First 1).Line -replace '.*"(.*)".*', '$1'
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
$content = $content -replace "Version\s+=\s+`"$Current`"", "Version     = `"$New`""
Set-Content $VersionFile $content -NoNewline
Write-Host "Bumped $VersionFile"

# ── Bump README version badge ────────────────────────────────────────────
$Readme = "README.md"
$readmeContent = Get-Content $Readme -Raw
$readmeContent = $readmeContent -replace "Version-\d+\.\d+\.\d+-", "Version-$New-"
Set-Content $Readme $readmeContent -NoNewline
Write-Host "Bumped $Readme"
