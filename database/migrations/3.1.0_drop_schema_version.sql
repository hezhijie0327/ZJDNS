-- 3.1.0: drop legacy schema_version table (replaced by version)
-- Manual run: zjdns --sql <db> "$(cat 3.1.0_drop_schema_version.sql)"
DROP TABLE IF EXISTS schema_version;
UPDATE version SET version = '3.1.0' WHERE rowid = 1;
