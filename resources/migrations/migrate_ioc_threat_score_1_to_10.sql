-- Migration: Rescale IOC threat_score from 0-100 to 1-10
-- Applies to ip_cache_ipv4, ip_cache_ipv6, domain_cache, and hash_cache.
--
-- Safe to re-run: rows already on the 1-10 scale (threat_score <= 10) are skipped.
-- Run BEFORE deploying the updated application code.

BEGIN;

-- ip_cache_ipv4
WITH scaled AS (
    SELECT
        ip_address,
        LEAST(10, CAST(CEILING(threat_score * 1.0 / 10) AS INTEGER)) AS new_score
    FROM ip_cache_ipv4
    WHERE threat_score > 10
)
UPDATE ip_cache_ipv4
SET
    threat_score = scaled.new_score,
    threat_level = CASE
        WHEN scaled.new_score < 3 THEN 0
        WHEN scaled.new_score < 5 THEN 1
        WHEN scaled.new_score < 8 THEN 2
        ELSE 3
    END
FROM scaled
WHERE ip_cache_ipv4.ip_address = scaled.ip_address;

-- ip_cache_ipv6
WITH scaled AS (
    SELECT
        ip_address,
        LEAST(10, CAST(CEILING(threat_score * 1.0 / 10) AS INTEGER)) AS new_score
    FROM ip_cache_ipv6
    WHERE threat_score > 10
)
UPDATE ip_cache_ipv6
SET
    threat_score = scaled.new_score,
    threat_level = CASE
        WHEN scaled.new_score < 3 THEN 0
        WHEN scaled.new_score < 5 THEN 1
        WHEN scaled.new_score < 8 THEN 2
        ELSE 3
    END
FROM scaled
WHERE ip_cache_ipv6.ip_address = scaled.ip_address;

-- domain_cache
WITH scaled AS (
    SELECT
        domain_name,
        LEAST(10, CAST(CEILING(threat_score * 1.0 / 10) AS INTEGER)) AS new_score
    FROM domain_cache
    WHERE threat_score > 10
)
UPDATE domain_cache
SET
    threat_score = scaled.new_score,
    threat_level = CASE
        WHEN scaled.new_score < 3 THEN 0
        WHEN scaled.new_score < 5 THEN 1
        WHEN scaled.new_score < 8 THEN 2
        ELSE 3
    END
FROM scaled
WHERE domain_cache.domain_name = scaled.domain_name;

-- hash_cache
WITH scaled AS (
    SELECT
        hash_value,
        hash_type,
        LEAST(10, CAST(CEILING(threat_score * 1.0 / 10) AS INTEGER)) AS new_score
    FROM hash_cache
    WHERE threat_score > 10
)
UPDATE hash_cache
SET
    threat_score = scaled.new_score,
    threat_level = CASE
        WHEN scaled.new_score < 3 THEN 0
        WHEN scaled.new_score < 5 THEN 1
        WHEN scaled.new_score < 8 THEN 2
        ELSE 3
    END
FROM scaled
WHERE hash_cache.hash_value = scaled.hash_value
  AND hash_cache.hash_type  = scaled.hash_type;

COMMIT;
