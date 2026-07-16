-- 3.4.5: reorder ruleset_entries PK to (type, tag, value) for index-seek queries
-- Also adds idx_ruleset_type_value for domain (type, value) lookups.

CREATE TABLE IF NOT EXISTS ruleset_entries_new (
    tag   TEXT NOT NULL,
    type  TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (type, tag, value)
) WITHOUT ROWID;

INSERT OR REPLACE INTO ruleset_entries_new SELECT tag, type, value FROM ruleset_entries;

DROP TABLE ruleset_entries;

ALTER TABLE ruleset_entries_new RENAME TO ruleset_entries;

CREATE INDEX IF NOT EXISTS idx_ruleset_type_value ON ruleset_entries(type, value);
