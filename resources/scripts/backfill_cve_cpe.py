#!/usr/bin/env python3
"""
One-time backfill script: populate cve_cpe from cve_cache.details
for CVEs that have raw NVD data but no CPE mappings.

Usage:
    python3 scripts/backfill_cve_cpe.py \
        --host 127.0.0.1 --port 5432 \
        --dbname intelligence --user intelligence_app
"""

import argparse
import json
import logging
import sys
import time
from typing import List, Tuple, Optional

import psycopg2
import psycopg2.extras

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

BATCH_SIZE = 500


def parse_args():
    p = argparse.ArgumentParser(description="Backfill cve_cpe from cve_cache.details")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=5432)
    p.add_argument("--dbname", required=True)
    p.add_argument("--user", required=True)
    p.add_argument("--password", default=None)
    p.add_argument("--dry-run", action="store_true", help="Parse only, do not insert")
    return p.parse_args()


def extract_cpe_rows(
    cve_id: str, raw_obj: dict
) -> List[Tuple]:
    """
    Parse NVD configurations from the raw CVE object and return rows
    ready for insertion into cve_cpe.
    Each row: (cve_id, cpe_string, cpe_base, vulnerable,
               version_start_including, version_start_excluding,
               version_end_including, version_end_excluding)
    """
    rows = []
    seen = set()

    configurations = raw_obj.get("configurations", [])
    if not configurations:
        return rows

    for config in configurations:
        for node in config.get("nodes", []):
            # Recurse into nested nodes if present
            nodes_to_process = [node]
            nested = node.get("nodes", [])
            nodes_to_process.extend(nested)

            for n in nodes_to_process:
                for cpe_match in n.get("cpeMatch", []):
                    criteria = cpe_match.get("criteria", "").strip()
                    if not criteria:
                        continue
                    parts = criteria.split(":")
                    cpe_base = ":".join(parts[:5]) if len(parts) >= 5 else criteria

                    key = (cve_id, criteria,
                           cpe_match.get("versionStartIncluding"),
                           cpe_match.get("versionStartExcluding"),
                           cpe_match.get("versionEndIncluding"),
                           cpe_match.get("versionEndExcluding"))
                    if key in seen:
                        continue
                    seen.add(key)

                    rows.append((
                        cve_id,
                        criteria,
                        cpe_base,
                        bool(cpe_match.get("vulnerable", True)),
                        cpe_match.get("versionStartIncluding"),
                        cpe_match.get("versionStartExcluding"),
                        cpe_match.get("versionEndIncluding"),
                        cpe_match.get("versionEndExcluding"),
                    ))
    return rows


def main():
    args = parse_args()

    connect_kwargs = dict(
        host=args.host, port=args.port,
        dbname=args.dbname, user=args.user,
    )
    if args.password:
        connect_kwargs["password"] = args.password

    conn = psycopg2.connect(**connect_kwargs)
    conn.autocommit = False
    cur = conn.cursor()

    logger.info("Counting CVEs to backfill...")
    cur.execute("""
        SELECT COUNT(*)
        FROM cve_cache c
        LEFT JOIN cve_cpe cp ON cp.cve_id = c.cve_id
        WHERE cp.cve_id IS NULL
          AND c.configurations IS NOT NULL
    """)
    total = cur.fetchone()[0]
    logger.info(f"CVEs to process: {total:,}")

    if total == 0:
        logger.info("Nothing to backfill.")
        return

    # Fetch IDs in pages using keyset pagination
    cur.execute("""
        SELECT c.cve_id
        FROM cve_cache c
        LEFT JOIN cve_cpe cp ON cp.cve_id = c.cve_id
        WHERE cp.cve_id IS NULL
          AND c.configurations IS NOT NULL
        ORDER BY c.cve_id
    """)
    all_ids = [row[0] for row in cur.fetchall()]

    processed = 0
    inserted = 0
    skipped_no_config = 0
    errors = 0

    start = time.time()

    for batch_start in range(0, len(all_ids), BATCH_SIZE):
        batch_ids = all_ids[batch_start:batch_start + BATCH_SIZE]

        cur.execute(
            "SELECT cve_id, configurations FROM cve_cache WHERE cve_id = ANY(%s) AND configurations IS NOT NULL",
            (batch_ids,)
        )
        rows_fetched = cur.fetchall()

        cpe_rows: List[Tuple] = []
        for cve_id, configurations_json in rows_fetched:
            processed += 1
            try:
                configurations = configurations_json if isinstance(configurations_json, list) else json.loads(configurations_json)
                raw_obj = {"configurations": configurations}
                rows = extract_cpe_rows(cve_id, raw_obj)
                if not rows:
                    skipped_no_config += 1
                else:
                    cpe_rows.extend(rows)
            except Exception as e:
                logger.warning(f"Failed to process {cve_id}: {e}")
                errors += 1

        if cpe_rows and not args.dry_run:
            try:
                psycopg2.extras.execute_values(
                    cur,
                    """
                    INSERT INTO cve_cpe (
                        cve_id, cpe_string, cpe_base, vulnerable,
                        version_start_including, version_start_excluding,
                        version_end_including, version_end_excluding
                    ) VALUES %s
                    ON CONFLICT DO NOTHING
                    """,
                    cpe_rows,
                    page_size=1000,
                )
                conn.commit()
                inserted += len(cpe_rows)
            except Exception as e:
                conn.rollback()
                logger.error(f"Batch insert failed: {e}")
                errors += len(batch_ids)

        elapsed = time.time() - start
        rate = processed / elapsed if elapsed > 0 else 0
        eta = (total - processed) / rate if rate > 0 else 0
        logger.info(
            f"Progress: {processed:,}/{total:,} | "
            f"Inserted rows: {inserted:,} | "
            f"No-config: {skipped_no_config:,} | "
            f"Errors: {errors} | "
            f"ETA: {eta:.0f}s"
        )

    logger.info(
        f"Done. Processed: {processed:,} | "
        f"CPE rows inserted: {inserted:,} | "
        f"Skipped (no config): {skipped_no_config:,} | "
        f"Errors: {errors}"
    )

    cur.close()
    conn.close()


if __name__ == "__main__":
    main()
