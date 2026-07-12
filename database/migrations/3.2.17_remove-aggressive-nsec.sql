-- Migration: remove aggressive NSEC negative cache
-- Version: 3.2.17
-- Description: Drops the nsec_chain table. Aggressive NSEC caching (RFC 8198)
--              is removed due to high false-positive rate with NSEC3 zones
--              and parent-zone NSEC record leaks.

DROP TABLE IF EXISTS nsec_chain;
