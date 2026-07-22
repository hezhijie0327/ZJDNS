-- 3.5.0: rename-hijack-to-poisoned
-- Rename hijack column to poisoned in query_stats and query_log.
-- These statements are idempotent: they will fail safely if the column
-- has already been renamed (already-migrated or fresh database with
-- the new base DDL).

ALTER TABLE query_stats RENAME COLUMN hijack TO poisoned;
ALTER TABLE query_log RENAME COLUMN hijack TO poisoned;
