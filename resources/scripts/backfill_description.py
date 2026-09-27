#!/usr/bin/env python3
"""
Backfill description column for existing rows in cve_cache.

Reads the compressed `details` blob already stored per CVE, extracts the
English description from the NVD descriptions array, and writes it back —
no NVD API calls needed.

Usage:
    python resources/scripts/backfill_description.py
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

PG_HOST    = os.environ.get("DB_HOST", "127.0.0.1")
PG_PORT    = int(os.environ.get("DB_PORT", 5432))
PG_DB      = os.environ.get("DB_NAME", "intelligence")
PG_USER    = os.environ.get("DB_USER", "intelligence_app")
PG_PASS    = os.environ.get("DB_PASSWORD", "overpower")

BATCH_SIZE = 500

decompressor = zstd.ZstdDecompressor()


def extract_description(raw: dict) -> str | None:
    """Extract English description from raw NVD cve_obj dict."""
    for entry in raw.get("descriptions", []):
        if entry.get("lang") == "en":
            return entry.get("value")
    return None


def main():
    conn = psycopg2.connect(
        host=PG_HOST, port=PG_PORT, dbname=PG_DB,
        user=PG_USER, password=PG_PASS,
    )
    conn.autocommit = False
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    cur.execute(
        "SELECT COUNT(*) FROM public.cve_cache WHERE description IS NULL AND details IS NOT NULL"
    )
    total = cur.fetchone()[0]
    logger.info(f"Rows to backfill: {total}")

    if total == 0:
        logger.info("Nothing to do.")
        return

    processed = updated = skipped = errors = 0

    while True:
        # Always OFFSET 0: each commit removes updated rows from the WHERE clause,
        # so the next fetch naturally picks up the next unprocessed batch.
        cur.execute(
            """
            SELECT cve_id, details
            FROM public.cve_cache
            WHERE description IS NULL AND details IS NOT NULL
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
                description = extract_description(raw)
                if description:
                    updates.append((description, cve_id))
                    updated += 1
                else:
                    skipped += 1
            except Exception as e:
                logger.warning(f"Failed to process {cve_id}: {e}")
                errors += 1

        if updates:
            psycopg2.extras.execute_batch(
                cur,
                "UPDATE public.cve_cache SET description = %s WHERE cve_id = %s",
                updates,
            )
            conn.commit()

        logger.info(
            f"Progress: {processed}/{total} | updated={updated} skipped={skipped} errors={errors}"
        )

    conn.close()
    logger.info(f"Done. updated={updated}, skipped={skipped}, errors={errors}")


if __name__ == "__main__":
    sys.exit(main())
