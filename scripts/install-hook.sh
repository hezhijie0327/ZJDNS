#!/bin/sh
# Install the pre-commit hook on Linux / macOS.
# Run from the repo root: sh scripts/install-hook.sh

set -e

hook_src="$(dirname "$0")/pre-commit"

# Pre-flight: must run inside the repository (worktrees have their own
# .git file, not a directory — git-path resolves the hooks dir correctly).
if ! hook_dir="$(git rev-parse --git-path hooks)"; then
    echo "ERROR: not inside a git repository" >&2
    exit 1
fi
hook_dst="$hook_dir/pre-commit"
mkdir -p "$hook_dir"

if [ ! -f "$hook_src" ]; then
    echo "ERROR: Hook script not found: $hook_src" >&2
    exit 1
fi

# Back up an existing hook instead of silently overwriting it.
if [ -f "$hook_dst" ] && ! cmp -s "$hook_src" "$hook_dst"; then
    backup="$hook_dst.bak.$(date +%s)"
    cp "$hook_dst" "$backup"
    echo "Existing hook backed up to $backup"
fi

cp "$hook_src" "$hook_dst"
chmod +x "$hook_dst"
echo "Pre-commit hook installed to $hook_dst"
