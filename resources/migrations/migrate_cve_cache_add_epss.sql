-- Migration: Add EPSS score columns to cve_cache
ALTER TABLE public.cve_cache
    ADD COLUMN IF NOT EXISTS epss_score NUMERIC(6,5),
    ADD COLUMN IF NOT EXISTS epss_fetched_at TIMESTAMPTZ;
