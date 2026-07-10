-- 3.2.0: rebuild zone_entries with match_tags in primary key
-- Manual run: zjdns --sql <db> "$(cat 3.2.0_zone_entries_pk.sql)"
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
    PRIMARY KEY (qname, qtype, qclass, match_tags)
);
INSERT OR REPLACE INTO zone_entries_new SELECT * FROM zone_entries;
DROP TABLE zone_entries;
ALTER TABLE zone_entries_new RENAME TO zone_entries;
CREATE INDEX IF NOT EXISTS idx_zone_qname ON zone_entries(qname);
UPDATE version SET version = '3.2.0' WHERE rowid = 1;
