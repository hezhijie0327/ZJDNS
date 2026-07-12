-- 3.2.21: Denormalize qname/qtype/qclass into request_log.
-- Stores the query identity directly in the log table so debugging queries
-- no longer need a JOIN with entries. entry_id becomes nullable (no FK) —
-- zone/error/badcookie paths no longer require stub entries.
-- entry_hit_counters retains its FK to entries for cascade cleanup.
--
-- Apply manually:
--   zjdns --sql --rw cache.db "$(cat database/migrations/3.2.21_denormalize\ qname\ into\ request_log.sql)"

CREATE TABLE IF NOT EXISTS request_log_new (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       INTEGER NOT NULL,
    qname           TEXT NOT NULL DEFAULT '',
    qtype           INTEGER NOT NULL DEFAULT 0,
    qclass          INTEGER NOT NULL DEFAULT 1,
    entry_id        INTEGER,
    protocol        TEXT NOT NULL,
    result          TEXT NOT NULL,
    response_time_ms INTEGER NOT NULL DEFAULT 0,
    rcode           INTEGER NOT NULL DEFAULT 0,
    server          TEXT NOT NULL DEFAULT '',
    hijack          INTEGER NOT NULL DEFAULT 0,
    fallback        INTEGER NOT NULL DEFAULT 0,
    dnssec_status   TEXT NOT NULL DEFAULT ''
);

INSERT OR IGNORE INTO request_log_new
    SELECT rl.id, rl.timestamp,
        COALESCE(e.qname, ''), COALESCE(e.qtype, 0), COALESCE(e.qclass, 1),
        rl.entry_id,
        rl.protocol, rl.result, rl.response_time_ms, rl.rcode,
        rl.server, rl.hijack, rl.fallback, rl.dnssec_status
    FROM request_log rl
    LEFT JOIN entries e ON rl.entry_id = e.id;

DROP TABLE request_log;
ALTER TABLE request_log_new RENAME TO request_log;
CREATE INDEX IF NOT EXISTS idx_request_log_ts ON request_log(timestamp);
DROP INDEX IF EXISTS idx_request_log_entry;
