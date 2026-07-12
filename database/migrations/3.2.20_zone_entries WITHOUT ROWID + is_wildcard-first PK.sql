-- 3.2.20: Rebuild zone_entries as WITHOUT ROWID with is_wildcard-first PK.
-- The new PK order makes wildcard IS queries (WHERE is_wildcard=1 AND qname IN (...))
-- use a prefix match on the clustered B-tree instead of filtering after the fact.
-- Exact lookups (WHERE is_wildcard=0 AND qname=? AND qtype=? AND qclass=?) also
-- benefit from perfect PK prefix match. WITHOUT ROWID eliminates the second
-- B-tree traversal incurred by rowid-table secondary index lookups.
--
-- Apply manually:
--   zjdns --sql --rw cache.db "$(cat database/migrations/3.2.20_zone_entries\ WITHOUT\ ROWID\ +\ is_wildcard-first\ PK.sql)"

CREATE TABLE IF NOT EXISTS zone_entries_new (
    is_wildcard INTEGER NOT NULL DEFAULT 0,
    qname      TEXT NOT NULL,
    qtype      INTEGER NOT NULL DEFAULT 0,
    qclass     INTEGER NOT NULL DEFAULT 0,
    rcode      INTEGER NOT NULL DEFAULT 0,
    answer     BLOB,
    authority  BLOB,
    additional BLOB,
    match_tags TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (is_wildcard, qname, qtype, qclass, match_tags)
) WITHOUT ROWID;

INSERT INTO zone_entries_new
    SELECT is_wildcard, qname, qtype, qclass, rcode, answer, authority, additional, match_tags
    FROM zone_entries;

DROP TABLE zone_entries;
ALTER TABLE zone_entries_new RENAME TO zone_entries;
