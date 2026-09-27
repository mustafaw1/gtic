"""
NVD CPE Dictionary Fetcher
Fetches the NVD CPE product dictionary and stores it locally.
Used as a gate: only return CVEs for CPE versions registered in the dictionary.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional

import aiohttp

from config import IngestionServiceSettings
from database.connection import IngestionDatabase

logger = logging.getLogger(__name__)

CPE_API_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
RESULTS_PER_PAGE = 10000  # max allowed by NVD CPE API


@dataclass
class CPEDictionaryStats:
    inserted: int = 0
    updated: int = 0
    total_fetched: int = 0
    processing_time_seconds: float = 0.0
    errors: List[str] = field(default_factory=list)

    def model_dump(self) -> Dict[str, Any]:
        return {
            "inserted": self.inserted,
            "updated": self.updated,
            "total_fetched": self.total_fetched,
            "processing_time_seconds": round(self.processing_time_seconds, 2),
            "errors": self.errors,
        }


class CPEDictionaryFetcher:
    """Fetches the NVD CPE dictionary with full and incremental sync support."""

    def __init__(self, settings: IngestionServiceSettings, database: IngestionDatabase):
        self.settings = settings
        self.database = database
        self._session: Optional[aiohttp.ClientSession] = None
        self.rate_limit = 0.67
        self.last_request_time = 0.0
        self._rate_lock = asyncio.Lock()

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(limit=5)
            self._session = aiohttp.ClientSession(
                headers={
                    "apiKey": self.settings.NVD_API_KEY,
                    "User-Agent": "GTIC NVD CPE Dictionary Fetcher 1.0",
                },
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=120),
            )
        return self._session

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    async def _enforce_rate_limit(self):
        async with self._rate_lock:
            elapsed = time.time() - self.last_request_time
            if elapsed < self.rate_limit:
                await asyncio.sleep(self.rate_limit - elapsed)
            self.last_request_time = time.time()

    async def run(self, mode: str = "incremental") -> CPEDictionaryStats:
        start = time.time()
        stats = CPEDictionaryStats()
        try:
            if mode == "full":
                await self._fetch_all(stats)
            else:
                await self._fetch_incremental(stats)
            await self.database.update_cpe_dict_sync_date(datetime.now(timezone.utc), stats.total_fetched)
        except Exception as e:
            logger.error(f"CPE dictionary sync failed: {e}", exc_info=True)
            stats.errors.append(str(e))
        finally:
            stats.processing_time_seconds = time.time() - start
            await self.close()
        logger.info(f"CPE dictionary sync done: {stats.model_dump()}")
        return stats

    async def _fetch_incremental(self, stats: CPEDictionaryStats):
        last_sync = await self.database.get_last_cpe_dict_sync_date()
        if last_sync is None:
            logger.info("No previous CPE dict sync — running full sync instead")
            await self._fetch_all(stats)
            return

        start_date = last_sync.strftime("%Y-%m-%dT%H:%M:%S.000-00:00")
        end_date = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000-00:00")
        logger.info(f"CPE dict incremental sync: {start_date} → {end_date}")
        await self._paginate({"lastModStartDate": start_date, "lastModEndDate": end_date}, stats)

    async def _fetch_all(self, stats: CPEDictionaryStats):
        logger.info("CPE dict full sync starting")
        await self._paginate({}, stats)

    async def _paginate(self, extra_params: Dict[str, Any], stats: CPEDictionaryStats):
        session = await self._get_session()
        start_index = 0
        total_results = None
        retries = 0

        while True:
            await self._enforce_rate_limit()
            params = {"resultsPerPage": RESULTS_PER_PAGE, "startIndex": start_index, **extra_params}

            try:
                async with session.get(CPE_API_URL, params=params) as response:
                    if response.status == 429:
                        wait = min(30 * (2 ** retries), 300)
                        retries += 1
                        logger.warning(f"CPE API rate limit — waiting {wait}s (attempt {retries})")
                        await asyncio.sleep(wait)
                        if retries > 5:
                            logger.error("Max retries exceeded on rate limit")
                            break
                        continue

                    response.raise_for_status()
                    retries = 0
                    data = await response.json()

                    if total_results is None:
                        total_results = data.get("totalResults", 0)
                        logger.info(f"CPE dictionary total entries: {total_results}")

                    products = data.get("products", [])
                    if not products:
                        break

                    batch = self._parse_products(products)
                    inserted, updated = await self.database.store_cpe_dictionary_batch(batch)
                    stats.inserted += inserted
                    stats.updated += updated
                    stats.total_fetched += len(batch)

                    start_index += len(products)
                    logger.info(f"CPE dict progress: {start_index}/{total_results}")

                    if start_index >= total_results:
                        break

                    await asyncio.sleep(0.5)

            except aiohttp.ClientError as e:
                logger.error(f"CPE API request failed at index {start_index}: {e}")
                stats.errors.append(str(e))
                break

    def _parse_products(self, products: List[Dict]) -> List[Dict[str, Any]]:
        rows = []
        for product in products:
            cpe = product.get("cpe", {})
            cpe_name = cpe.get("cpeName")
            if not cpe_name:
                continue
            parts = cpe_name.split(":")
            cpe_base = ":".join(parts[:5]) if len(parts) >= 5 else cpe_name
            version = parts[5] if len(parts) > 5 else None
            update_field = parts[6] if len(parts) > 6 else None
            if version in ("*", "-", ""):
                version = None
            if update_field in ("*", ""):
                update_field = None

            last_mod_str = cpe.get("lastModified")
            last_modified = None
            if last_mod_str:
                try:
                    last_modified = datetime.fromisoformat(last_mod_str.replace("Z", "+00:00"))
                except ValueError:
                    pass

            rows.append({
                "cpe_name": cpe_name,
                "cpe_name_id": cpe.get("cpeNameId"),
                "cpe_base": cpe_base,
                "version": version,
                "update_field": update_field,
                "deprecated": bool(cpe.get("deprecated", False)),
                "last_modified": last_modified,
            })
        return rows
