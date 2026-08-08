-- Switch internal canonical form from no-trailing-dot to FQDN with trailing dot.
-- Append '.' to stored domain names that don't already end with one.
UPDATE entries      SET qname = qname || '.' WHERE qname != '' AND qname != '.' AND qname NOT LIKE '%.';
UPDATE query_log    SET qname = qname || '.' WHERE qname != '' AND qname != '.' AND qname NOT LIKE '%.';
UPDATE ptr_map      SET name  = name  || '.' WHERE name  != '' AND name  != '.' AND name  NOT LIKE '%.';
UPDATE zone_entries SET qname = qname || '.' WHERE qname != '' AND qname != '.' AND qname NOT LIKE '%.';
