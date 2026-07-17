-- 3.4.18: add last_hit_time to entry_hit_counters for time-based cleanup
ALTER TABLE entry_hit_counters ADD COLUMN last_hit_time INTEGER NOT NULL DEFAULT 0;
