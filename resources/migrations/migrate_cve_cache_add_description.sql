-- Migration: Add description column to cve_cache
-- Run once on the target database before deploying the updated ingestion service

ALTER TABLE public.cve_cache
    ADD COLUMN IF NOT EXISTS description TEXT;
