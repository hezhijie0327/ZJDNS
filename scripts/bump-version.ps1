# bump-version.ps1 — bump ZJDNS version and optionally create a migration skeleton.
# Usage:
#   pwsh scripts/bump-version.ps1 patch   "add indexes"                        # + migration
#   pwsh scripts/bump-version.ps1 patch   "merge files"   -NoMigration         # no SQL file
#   pwsh scripts/bump-version.ps1 minor   "new feature"
#   pwsh scripts/bump-version.ps1 major   "breaking change"
#
# Conventions (see CLAUDE.md §Version Bumping):
#   Z (patch) — bug fixes, perf improvements, refactors, linter fixes
#   Y (minor) — new features, new config options, new protocols
#   X (major) — breaking config/schema/API changes

param(
    [Parameter(Mandatory)]
    [ValidateSet("patch", "minor", "major")]
    [string]$Bump,

    [Parameter(Mandatory)]
    [string]$Slug,

    [Parameter()]
    [switch]$NoMigration
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

# ── Bump README version badge ──────────────────────────────────────────────
$Readme = "README.md"
$readmeContent = Get-Content $Readme -Raw
$readmeContent = $readmeContent -replace "Version-$Current-", "Version-$New-"
Set-Content $Readme $readmeContent -NoNewline
Write-Host "Bumped $Readme"

# ── Create migration SQL archive ─────────────────────────────────────────
if (-not $NoMigration) {
    $MigrationFile = "database/migrations/${New}_${Slug}.sql"
    New-Item -ItemType Directory -Force -Path "database/migrations" | Out-Null
    Set-Content $MigrationFile @"
-- $New : $Slug
-- TODO: add migration SQL here
"@
    Write-Host "Created $MigrationFile"

    $Var = "migrateV${Major}_${Minor}_${Patch}"
    Write-Host ""
    Write-Host "Next steps:"
    Write-Host "  1. Edit $MigrationFile with the actual SQL"
    Write-Host "  2. Add migration entry to database/migration.go:"
    Write-Host "     {`"$New`", `"$Slug`", $Var},"
    Write-Host "  3. Implement the $Var function"
} else {
    Write-Host "(skipped migration SQL — schema unchanged)"
}
