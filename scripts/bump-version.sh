#!/bin/sh
# bump-version.sh — bump ZJDNS version and optionally create a migration skeleton.
# Usage:
#   sh scripts/bump-version.sh patch   "add performance indexes"          # 3.2.1 → 3.2.2 + migration
#   sh scripts/bump-version.sh patch   "merge tiny files"   --no-migration # 3.2.1 → 3.2.2, no SQL file
#   sh scripts/bump-version.sh minor   "new DNSCrypt feature"             # 3.2.1 → 3.3.0
#   sh scripts/bump-version.sh major   "breaking protocol change"         # 3.2.1 → 4.0.0
#
# Conventions (see CLAUDE.md §Version Bumping):
#   Z (patch) — bug fixes, perf improvements, refactors, linter fixes
#   Y (minor) — new features, new config options, new protocols
#   X (major) — breaking config/schema/API changes
#
# When bumping with --no-migration:
#   - Only bumps version.go — no SQL file created
#   - Use for pure code refactors, naming fixes, lint fixes (no schema changes)

set -eu

BUMP="${1:-}"
SLUG="${2:-}"
GEN_MIGRATION=true

if [ "${3:-}" = "--no-migration" ]; then
    GEN_MIGRATION=false
fi

if [ -z "$BUMP" ] || [ -z "$SLUG" ]; then
    echo "Usage: sh scripts/bump-version.sh <patch|minor|major> <slug> [--no-migration]" >&2
    exit 1
fi

case "$BUMP" in
    patch|minor|major) ;;
    *) echo "bump must be patch, minor, or major" >&2; exit 1 ;;
esac

# ── Parse current version from version.go ────────────────────────────────
VERSION_FILE="cmd/zjdns/version.go"
CURRENT=$(grep 'Version\s*=' "$VERSION_FILE" | head -1 | sed 's/.*"\(.*\)".*/\1/')
echo "Current version: $CURRENT"

MAJOR=$(echo "$CURRENT" | cut -d. -f1)
MINOR=$(echo "$CURRENT" | cut -d. -f2)
PATCH=$(echo "$CURRENT" | cut -d. -f3)

case "$BUMP" in
    major) MAJOR=$((MAJOR + 1)); MINOR=0; PATCH=0 ;;
    minor) MINOR=$((MINOR + 1)); PATCH=0 ;;
    patch) PATCH=$((PATCH + 1)) ;;
esac

NEW="$MAJOR.$MINOR.$PATCH"
echo "New version:     $NEW"

# ── Bump version.go ──────────────────────────────────────────────────────
# Use [[:space:]] instead of \s for portability (macOS sed lacks \s).
if [ "$(uname)" = "Darwin" ]; then
    sed -i '' "s/Version[[:space:]]*=[[:space:]]*\"$CURRENT\"/Version     = \"$NEW\"/" "$VERSION_FILE"
else
    sed -i "s/Version[[:space:]]*=[[:space:]]*\"$CURRENT\"/Version     = \"$NEW\"/" "$VERSION_FILE"
fi
echo "Bumped $VERSION_FILE"

# ── Create migration SQL archive ─────────────────────────────────────────
if $GEN_MIGRATION; then
    MIGRATION_FILE="database/migrations/${NEW}_${SLUG}.sql"
    mkdir -p database/migrations
    cat > "$MIGRATION_FILE" <<EOF
-- $NEW: $SLUG
-- TODO: add migration SQL here
EOF
    echo "Created $MIGRATION_FILE"

    echo ""
    echo "Next steps:"
    echo "  1. Edit $MIGRATION_FILE with the actual SQL"
    echo "  2. Add migration entry to database/migration.go:"
    echo "     {\"$NEW\", \"$SLUG\", migrateV${MAJOR}_${MINOR}_${PATCH}},"
    echo "  3. Implement the migrateV${MAJOR}_${MINOR}_${PATCH} function"
else
    echo "(skipped migration SQL — schema unchanged)"
fi
