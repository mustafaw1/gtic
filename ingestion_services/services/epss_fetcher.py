"""
EPSS (Exploit Prediction Scoring System) Fetcher Service

Fetches EPSS scores from FIRST.org for all CVEs stored in cve_cache and
updates the epss_score + epss_fetched_at columns in batch.

FIRST.org API: https://api.first.org/data/v1/epss
  - Accepts up to 100 CVE IDs per request via comma-separated `cve` param
  - Returns probability (0.0–1.0) and percentile
  - Updates daily around 00:00 UTC
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple

import aiohttp

from config import IngestionServiceSettings
from database.connection import IngestionDatabase

logger = logging.getLogger(__name__)

EPSS_API_URL = "https://api.first.org/data/v1/epss"
BATCH_SIZE = 100
MAX_CONCURRENT = 5


class EPSSFetcher:
    """Fetches and stores EPSS scores for CVEs in cve_cache."""

    def __init__(self, settings: IngestionServiceSettings, database: IngestionDatabase):
        self.settings = settings
        self.database = database
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=60),
                headers={"User-Agent": "GTIC EPSS Ingestion Service 1.0"},
            )
        return self._session

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    async def _fetch_epss_batch(self, cve_ids: List[str]) -> Dict[str, float]:
        """Fetch EPSS scores for up to 100 CVE IDs. Returns {cve_id: epss_score}."""
        session = await self._get_session()
        params = {"cve": ",".join(cve_ids)}
        try:
            async with session.get(EPSS_API_URL, params=params) as resp:
                if resp.status != 200:
                    logger.warning(f"EPSS API returned {resp.status} for batch of {len(cve_ids)}")
                    return {}
                payload = await resp.json()
                scores: Dict[str, float] = {}
                for item in payload.get("data", []):
                    cve = item.get("cve", "").upper()
                    epss = item.get("epss")
                    if cve and epss is not None:
                        scores[cve] = float(epss)
                return scores
        except Exception as e:
            logger.error(f"EPSS API request failed: {e}")
            return {}

    async def _get_all_cve_ids(self) -> List[str]:
        """Fetch all cve_ids from cve_cache."""
        if not self.database._pool:
            return []
        try:
            async with self.database._pool.acquire() as conn:
                rows = await conn.fetch("SELECT cve_id FROM public.cve_cache ORDER BY cve_id")
                return [row["cve_id"] for row in rows]
        except Exception as e:
            logger.error(f"Failed to fetch CVE IDs for EPSS: {e}")
            return []

    async def _update_epss_scores(self, scores: Dict[str, float], fetched_at: datetime) -> int:
        """Bulk-update epss_score and epss_fetched_at for a dict of CVE->score. Returns rows updated."""
        if not scores or not self.database._pool:
            return 0
        rows = [(score, fetched_at, cve_id) for cve_id, score in scores.items()]
        try:
            async with self.database._pool.acquire() as conn:
                await conn.executemany(
                    """
                    UPDATE public.cve_cache
                       SET epss_score = $1, epss_fetched_at = $2
                     WHERE cve_id = $3
                    """,
                    rows,
                )
            return len(rows)
        except Exception as e:
            logger.error(f"Failed to update EPSS scores in DB: {e}")
            return 0

    async def run(self) -> Tuple[int, int]:
        """
        Fetch EPSS scores for all CVEs and persist to DB.

        Returns:
            (total_cves, updated_cves)
        """
        logger.info("Starting EPSS score enrichment")
        fetched_at = datetime.now(timezone.utc)

        cve_ids = await self._get_all_cve_ids()
        total = len(cve_ids)
        if not total:
            logger.info("No CVEs found in cve_cache — skipping EPSS run")
            return 0, 0

        logger.info(f"Fetching EPSS scores for {total} CVEs in batches of {BATCH_SIZE}")
        batches = [cve_ids[i:i + BATCH_SIZE] for i in range(0, total, BATCH_SIZE)]
        semaphore = asyncio.Semaphore(MAX_CONCURRENT)
        all_scores: Dict[str, float] = {}

        async def fetch_batch(batch: List[str]):
            async with semaphore:
                result = await self._fetch_epss_batch(batch)
                all_scores.update(result)

        await asyncio.gather(*[fetch_batch(b) for b in batches])

        updated = await self._update_epss_scores(all_scores, fetched_at)

        await self.close()
        logger.info(f"EPSS enrichment complete: {total} CVEs checked, {updated} scores updated")
        return total, updated
