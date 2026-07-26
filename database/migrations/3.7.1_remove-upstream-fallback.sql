-- 3.7.1: remove fallback column from query_stats and query_log

-- query_stats is WITHOUT ROWID with fallback in the PK — rebuild via
-- CREATE-INSERT-DROP-RENAME, merging rows that differ only by fallback.
CREATE TABLE IF NOT EXISTS query_stats_new (
    stat_day    INTEGER NOT NULL,
    result      TEXT NOT NULL,
    protocol    TEXT NOT NULL,
    rcode       INTEGER NOT NULL DEFAULT 0,
    dnssec      TEXT NOT NULL DEFAULT '',
    poisoned    INTEGER NOT NULL DEFAULT 0,
    query_count INTEGER NOT NULL DEFAULT 0,
    total_ms    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (stat_day, result, protocol, rcode, dnssec, poisoned)
) WITHOUT ROWID;

INSERT INTO query_stats_new
    SELECT stat_day, result, protocol, rcode, dnssec, poisoned,
        SUM(query_count), SUM(total_ms)
    FROM query_stats
    GROUP BY stat_day, result, protocol, rcode, dnssec, poisoned;

DROP TABLE query_stats;
ALTER TABLE query_stats_new RENAME TO query_stats;

-- query_log: simple column drop (not in PK).
ALTER TABLE query_log DROP COLUMN fallback;
