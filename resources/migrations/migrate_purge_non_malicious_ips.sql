-- Migration: Purge non-malicious IPs from ip_cache
-- Removes entries where AbuseIPDB reports zero confidence and zero reports,
-- meaning the IP has never been flagged within the 90-day lookup window.
-- Run once after deploying the lookup_service fix that stops ingesting clean IPs.

DELETE FROM public.ip_cache_ipv4
WHERE threat_score = 0
  AND total_reports = 0;

DELETE FROM public.ip_cache_ipv6
WHERE threat_score = 0
  AND total_reports = 0;
