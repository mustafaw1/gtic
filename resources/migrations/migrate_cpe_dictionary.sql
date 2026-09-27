CREATE TABLE IF NOT EXISTS public.cpe_dictionary (
    cpe_name        TEXT PRIMARY KEY,
    cpe_name_id     TEXT,
    cpe_base        TEXT NOT NULL,
    version         TEXT,
    update_field    TEXT,
    deprecated      BOOLEAN NOT NULL DEFAULT FALSE,
    last_modified   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cpe_dict_base         ON public.cpe_dictionary (cpe_base);
CREATE INDEX IF NOT EXISTS idx_cpe_dict_base_version ON public.cpe_dictionary (cpe_base, version);
CREATE INDEX IF NOT EXISTS idx_cpe_dict_last_modified ON public.cpe_dictionary (last_modified);

CREATE TABLE IF NOT EXISTS public.cpe_dict_sync_state (
    id              INT PRIMARY KEY DEFAULT 1,
    last_sync_date  TIMESTAMPTZ,
    total_cpes      BIGINT DEFAULT 0,
    CONSTRAINT single_row CHECK (id = 1)
);

INSERT INTO public.cpe_dict_sync_state (id, last_sync_date, total_cpes)
VALUES (1, NULL, 0)
ON CONFLICT (id) DO NOTHING;
