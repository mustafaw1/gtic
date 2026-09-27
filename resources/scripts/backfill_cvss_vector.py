#!/usr/bin/env python3
"""
Backfill cvss_v3_vector_string for existing rows in cve_cache.

Reads the compressed `details` blob already stored per CVE, extracts the
CVSS v3.1 vector string, and writes it back — no NVD API calls needed.

Usage:
    python resources/scripts/backfill_cvss_vector.py
"""

import json
import logging
import os
import sys

import psycopg2
import psycopg2.extras
import zstandard as zstd

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
)
logger = logging.getLogger(__name__)

PG_HOST     = os.environ.get("DB_HOST", "127.0.0.1")
PG_PORT     = int(os.environ.get("DB_PORT", 5432))
PG_DB       = os.environ.get("DB_NAME", "intelligence")
PG_USER     = os.environ.get("DB_USER", "intelligence_app")
PG_PASS     = os.environ.get("DB_PASSWORD", "overpower")

BATCH_SIZE  = 500

decompressor = zstd.ZstdDecompressor()


def extract_vector(raw: dict) -> str | None:
    """Extract CVSS v3.1 vector string from raw NVD cve_obj dict."""
    metrics = raw.get("metrics", {})
    v31 = metrics.get("cvssMetricV31", [])
    if v31:
        return v31[0].get("cvssData", {}).get("vectorString")
    # Fall back to v3.0 if v3.1 not present
    v30 = metrics.get("cvssMetricV30", [])
    if v30:
        return v30[0].get("cvssData", {}).get("vectorString")
    return None


def main():
    conn = psycopg2.connect(
        host=PG_HOST, port=PG_PORT, dbname=PG_DB,
        user=PG_USER, password=PG_PASS,
    )
    conn.autocommit = False
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    cur.execute("SELECT COUNT(*) FROM public.cve_cache WHERE cvss_v3_vector_string IS NULL AND details IS NOT NULL")
    total = cur.fetchone()[0]
    logger.info(f"Rows to backfill: {total}")

    if total == 0:
        logger.info("Nothing to do.")
        return

    processed = updated = skipped = errors = 0

    while True:
        cur.execute(
            """
            SELECT cve_id, details
            FROM public.cve_cache
            WHERE cvss_v3_vector_string IS NULL AND details IS NOT NULL
            ORDER BY cve_id
            LIMIT %s
            """,
            (BATCH_SIZE,),
        )
        rows = cur.fetchall()
        if not rows:
            break

        updates = []
        for row in rows:
            cve_id = row["cve_id"]
            processed += 1
            try:
                raw_bytes = bytes(row["details"])
                decompressed = decompressor.decompress(raw_bytes)
                raw = json.loads(decompressed.decode("utf-8"))
                vector = extract_vector(raw)
                if vector:
                    updates.append((vector, cve_id))
                    updated += 1
                else:
                    skipped += 1
            except Exception as e:
                logger.warning(f"Failed to process {cve_id}: {e}")
                errors += 1

        if updates:
            psycopg2.extras.execute_batch(
                cur,
                "UPDATE public.cve_cache SET cvss_v3_vector_string = %s WHERE cve_id = %s",
                updates,
            )
            conn.commit()

        logger.info(f"Progress: {processed}/{total} | updated={updated} skipped={skipped} errors={errors}")

    conn.close()
    logger.info(f"Done. updated={updated}, skipped={skipped}, errors={errors}")


if __name__ == "__main__":
    sys.exit(main())
