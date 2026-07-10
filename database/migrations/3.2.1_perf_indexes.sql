-- 3.2.1: add performance indexes for eviction and latency cleanup,
-- drop redundant idx_zone_qname (qname is leading PK column).
CREATE INDEX IF NOT EXISTS idx_entries_expires_ts ON entries(expires_at, timestamp);
CREATE INDEX IF NOT EXISTS idx_entries_timestamp ON entries(timestamp);
CREATE INDEX IF NOT EXISTS idx_ip_latency_probe ON ip_latency(last_probe_time);
DROP INDEX IF EXISTS idx_zone_qname;
