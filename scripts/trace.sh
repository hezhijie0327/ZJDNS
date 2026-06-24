#!/bin/bash
# trace.sh — Minimal recursive DNS diagnostic with hijack protection + DNSSEC enforcement.
#
# Usage:
#   ./scripts/trace.sh <domain> [qtype]
#
# Examples:
#   ./scripts/trace.sh zhijie-online.mail.protection.outlook.com AAAA
#   ./scripts/trace.sh unpkg.luckincoffeecdn.com HTTPS
#
# This script starts a temporary zjdns instance in recursive-only mode with
# debug logging, queries the given domain, captures the resolution trace,
# and then shuts down cleanly.

set -euo pipefail

DOMAIN="${1:-}"
QTYPE="${2:-A}"

if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 <domain> [qtype]"
    echo ""
    echo "Examples:"
    echo "  $0 zhijie-online.mail.protection.outlook.com AAAA"
    echo "  $0 unpkg.luckincoffeecdn.com HTTPS"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ZJDNS_BIN="$PROJECT_DIR/zjdns"

# Build if needed
if [ ! -x "$ZJDNS_BIN" ]; then
    echo "=== Building zjdns ==="
    (cd "$PROJECT_DIR" && go build -o zjdns)
fi

# Create temp directory
TMPDIR="$(mktemp -d)"
trap "rm -rf $TMPDIR" EXIT

# Generate minimal recursive-only config
CONFIG="$TMPDIR/config.json"
cat > "$CONFIG" << EOF
{
  "server": {
    "port": "5353",
    "log_level": "debug",
    "features": {
      "hijack_protection": true,
      "dnssec_enforce": true,
      "query_log": "$TMPDIR/query.jsonl",
      "query_log_rcode": "2"
    }
  },
  "upstream": [
    { "address": "builtin_recursive" }
  ]
}
EOF

echo "=== Config ==="
cat "$CONFIG"
echo ""

# Start zjdns in background
echo "=== Starting zjdns (recursive, hijack=on, dnssec_enforce=on) ==="
"$ZJDNS_BIN" -config "$CONFIG" > "$TMPDIR/zjdns.log" 2>&1 &
ZJDNS_PID=$!
trap "kill $ZJDNS_PID 2>/dev/null; rm -rf $TMPDIR" EXIT

# Wait for server to be ready
sleep 1
if ! kill -0 $ZJDNS_PID 2>/dev/null; then
    echo "ERROR: zjdns failed to start. Log output:"
    cat "$TMPDIR/zjdns.log"
    exit 1
fi

echo "Server PID: $ZJDNS_PID"
echo ""

# Query the domain
echo "=== Querying: $DOMAIN $QTYPE ==="
dig @"127.0.0.1" -p 5353 +tcp "$DOMAIN" "$QTYPE" 2>&1 || true
echo ""

# Wait a moment for logs to flush
sleep 1

# Show recursive resolution trace
echo ""
echo "=== Resolution Trace ==="
grep -E 'RECURSION|SECURITY|UPSTREAM' "$TMPDIR/zjdns.log" | head -100 || echo "(no recursive trace found)"

echo ""
echo "=== SERVFAIL entries in query log ==="
if [ -f "$TMPDIR/query.jsonl" ]; then
    cat "$TMPDIR/query.jsonl" | python3 -m json.tool 2>/dev/null || cat "$TMPDIR/query.jsonl"
else
    echo "(no query log)"
fi

# Cleanup
kill $ZJDNS_PID 2>/dev/null || true
echo ""
echo "=== Done ==="
