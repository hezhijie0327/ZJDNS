-- 3.2.8: add nsec_chain table for aggressive NSEC negative caching.
-- Indexes NSEC/NSEC3 records from validated DNSSEC responses so that
-- NXDOMAIN/NODATA can be synthesized directly from cache without
-- re-querying upstream.
CREATE TABLE IF NOT EXISTS nsec_chain (
    zone_name  BLOB NOT NULL,
    owner_name BLOB NOT NULL,
    next_name  BLOB NOT NULL,
    types      BLOB NOT NULL,
    entry_id   INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    PRIMARY KEY (zone_name, owner_name)
);
