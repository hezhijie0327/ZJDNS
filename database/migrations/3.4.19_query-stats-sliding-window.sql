-- 3.4.19: query-stats-sliding-window
-- Drop legacy stats/journal tables. The new tables (query_stats, query_log)
-- are created by the base DDL which runs on every startup before migrations.

DROP TABLE IF EXISTS entry_hit_counters;
DROP TABLE IF EXISTS request_log;
DROP TABLE IF EXISTS stats_meta;
