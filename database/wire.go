package database

import zdnsutil "zjdns/internal/dnsutil"

// Compress compresses data with zstd (delegates to dnsutil.Compress).
var Compress = zdnsutil.Compress

// Decompress decompresses data with zstd (delegates to dnsutil.Decompress).
var Decompress = zdnsutil.Decompress
