#!/usr/bin/env python3
"""
Backfill epss_score for existing rows in cve_cache.

Fetches EPSS scores from FIRST.org in batches of 100 CVE IDs per request
and writes them back — runs once after applying the migration.

Usage:
    python resources/scripts/backfill_epss.py
"""

import asyncio
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Dict, List

import aiohttp
import psycopg2
import psycopg2.extras

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
)
logger = logging.getLogger(__name__)

PG_HOST = os.environ.get("DB_HOST", "127.0.0.1")
PG_PORT = int(os.environ.get("DB_PORT", 5432))
PG_DB   = os.environ.get("DB_NAME", "intelligence")
PG_USER = os.environ.get("DB_USER", "intelligence_app")
PG_PASS = os.environ.get("DB_PASSWORD", "overpower")

EPSS_API_URL  = "https://api.first.org/data/v1/epss"
BATCH_SIZE    = 100
MAX_CONCURRENT = 5


async def fetch_epss_batch(session: aiohttp.ClientSession, cve_ids: List[str]) -> Dict[str, float]:
    params = {"cve": ",".join(cve_ids)}
    try:
        async with session.get(EPSS_API_URL, params=params) as resp:
            if resp.status != 200:
                logger.warning(f"EPSS API returned {resp.status}")
                return {}
            payload = await resp.json()
            return {
                item["cve"].upper(): float(item["epss"])
                for item in payload.get("data", [])
                if item.get("cve") and item.get("epss") is not None
            }
    except Exception as e:
        logger.error(f"EPSS request failed: {e}")
        return {}


async def fetch_all_scores(cve_ids: List[str]) -> Dict[str, float]:
    batches = [cve_ids[i:i + BATCH_SIZE] for i in range(0, len(cve_ids), BATCH_SIZE)]
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    scores: Dict[str, float] = {}

    async def process(batch):
        async with semaphore:
            result = await fetch_epss_batch(session, batch)
            scores.update(result)

    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=60),
        headers={"User-Agent": "GTIC EPSS Backfill 1.0"},
    ) as session:
        await asyncio.gather(*[process(b) for b in batches])

    return scores


def main():
    conn = psycopg2.connect(
        host=PG_HOST, port=PG_PORT, dbname=PG_DB,
        user=PG_USER, password=PG_PASS,
    )
    conn.autocommit = False
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    cur.execute("SELECT cve_id FROM public.cve_cache ORDER BY cve_id")
    cve_ids = [row["cve_id"] for row in cur.fetchall()]
    total = len(cve_ids)
    logger.info(f"Total CVEs to backfill EPSS: {total}")

    if not total:
        logger.info("Nothing to do.")
        return

    logger.info("Fetching EPSS scores from FIRST.org...")
    scores = asyncio.run(fetch_all_scores(cve_ids))
    logger.info(f"Received EPSS scores for {len(scores)} CVEs")

    fetched_at = datetime.now(timezone.utc)
    updates = [(score, fetched_at, cve_id) for cve_id, score in scores.items()]

    psycopg2.extras.execute_batch(
        cur,
        "UPDATE public.cve_cache SET epss_score = %s, epss_fetched_at = %s WHERE cve_id = %s",
        updates,
        page_size=500,
    )
    conn.commit()
    conn.close()

    skipped = total - len(scores)
    logger.info(f"Done. updated={len(scores)}, skipped={skipped} (no EPSS data)")


if __name__ == "__main__":
    sys.exit(main())
