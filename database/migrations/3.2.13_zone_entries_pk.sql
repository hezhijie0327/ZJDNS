-- 3.2.13: rebuild zone_entries with is_wildcard in the primary key.
-- This allows the prepared statements' is_wildcard = ? filter to use a
-- direct seek instead of a partial scan within (qname, qtype, qclass).
CREATE TABLE IF NOT EXISTS zone_entries_new (
    qname      TEXT NOT NULL,
    qtype      INTEGER NOT NULL DEFAULT 0,
    qclass     INTEGER NOT NULL DEFAULT 0,
    rcode      INTEGER NOT NULL DEFAULT 0,
    answer     BLOB,
    authority  BLOB,
    additional BLOB,
    match_tags TEXT NOT NULL DEFAULT '',
    is_wildcard INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (qname, qtype, qclass, is_wildcard, match_tags)
);
INSERT OR IGNORE INTO zone_entries_new SELECT * FROM zone_entries;
DROP TABLE zone_entries;
ALTER TABLE zone_entries_new RENAME TO zone_entries;
