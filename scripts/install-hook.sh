#!/bin/sh
# Install the pre-commit hook on Linux / macOS.
# Run from the repo root: sh scripts/install-hook.sh

set -e

hook_src="$(dirname "$0")/pre-commit"
hook_dst="$(dirname "$0")/../.git/hooks/pre-commit"

if [ ! -f "$hook_src" ]; then
    echo "ERROR: Hook script not found: $hook_src" >&2
    exit 1
fi

cp "$hook_src" "$hook_dst"
chmod +x "$hook_dst"
echo "Pre-commit hook installed to .git/hooks/pre-commit"
