-- Migration: Create cve_cpe junction table for flat CPE string indexing
-- Run once on the target database before deploying the updated ingestion service.
-- The backfill at the end will take a few minutes on a large dataset.

CREATE TABLE IF NOT EXISTS public.cve_cpe (
    cve_id                  VARCHAR NOT NULL REFERENCES public.cve_cache(cve_id) ON DELETE CASCADE,
    cpe_string              TEXT NOT NULL,   -- full criteria string (may contain * for version)
    cpe_base                TEXT NOT NULL,   -- first 5 CPE components: cpe:2.3:<part>:<vendor>:<product>
    vulnerable              BOOLEAN NOT NULL DEFAULT TRUE,
    version_start_including TEXT,
    version_start_excluding TEXT,
    version_end_including   TEXT,
    version_end_excluding   TEXT,
    PRIMARY KEY (cve_id, cpe_string)
);

CREATE INDEX IF NOT EXISTS idx_cve_cpe_cpe_string ON public.cve_cpe (cpe_string);
CREATE INDEX IF NOT EXISTS idx_cve_cpe_base       ON public.cve_cpe (cpe_base);

-- Backfill from existing cve_cache.configurations (stored as JSON text)
INSERT INTO public.cve_cpe (
    cve_id, cpe_string, cpe_base, vulnerable,
    version_start_including, version_start_excluding,
    version_end_including, version_end_excluding
)
SELECT
    c.cve_id,
    cpe_entry->>'criteria'                  AS cpe_string,
    -- base = first 5 colon-delimited components of the criteria string
    array_to_string(
        (string_to_array(cpe_entry->>'criteria', ':'))[1:5], ':'
    )                                        AS cpe_base,
    COALESCE((cpe_entry->>'vulnerable')::boolean, true) AS vulnerable,
    cpe_entry->>'versionStartIncluding'     AS version_start_including,
    cpe_entry->>'versionStartExcluding'     AS version_start_excluding,
    cpe_entry->>'versionEndIncluding'       AS version_end_including,
    cpe_entry->>'versionEndExcluding'       AS version_end_excluding
FROM public.cve_cache c
CROSS JOIN LATERAL jsonb_array_elements(c.configurations::jsonb)   AS config_entry
CROSS JOIN LATERAL jsonb_array_elements(config_entry->'nodes')     AS node_entry
CROSS JOIN LATERAL jsonb_array_elements(node_entry->'cpeMatch')    AS cpe_entry
WHERE c.configurations IS NOT NULL
  AND cpe_entry->>'criteria' IS NOT NULL
ON CONFLICT DO NOTHING;
