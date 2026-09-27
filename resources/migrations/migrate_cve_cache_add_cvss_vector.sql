-- Migration: Add cvss_v3_vector_string column to cve_cache
ALTER TABLE public.cve_cache
    ADD COLUMN IF NOT EXISTS cvss_v3_vector_string TEXT;

-- Migration: Change cvss_score from integer (0-100) to numeric (0.0-10.0)
-- First convert existing values (stored as score*10) back to real CVSS scores
UPDATE public.cve_cache
    SET cvss_score = cvss_score / 10.0
    WHERE cvss_score > 10;

ALTER TABLE public.cve_cache
    ALTER COLUMN cvss_score TYPE NUMERIC(4,1) USING cvss_score::numeric(4,1);
