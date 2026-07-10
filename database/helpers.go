package database

import zdnsutil "zjdns/internal/dnsutil"

// BoolToInt converts a bool to 0 or 1 (delegates to dnsutil.BoolToInt).
var BoolToInt = zdnsutil.BoolToInt

// JoinPlaceholders joins string parts with a separator (delegates to dnsutil.JoinPlaceholders).
var JoinPlaceholders = zdnsutil.JoinPlaceholders
