-- 3.2.19: Drop redundant idx_entries_expires.
-- idx_entries_expires_ts(expires_at, timestamp) covers all queries that
-- idx_entries_expires(expires_at) could serve, since expires_at is the
-- leading column of the compound index. Removes write overhead per INSERT.
--
-- Apply manually:
--   zjdns --sql --rw cache.db "DROP INDEX IF EXISTS idx_entries_expires"

DROP INDEX IF EXISTS idx_entries_expires;
