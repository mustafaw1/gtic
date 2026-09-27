"""
NVD CVE Fetcher Service
Fetches CVE data from NVD API and stores in database
Supports both initial bulk ingestion and incremental updates
"""

import json
import logging
import asyncio
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from pathlib import Path

import aiohttp
import zstandard as zstd

from config import IngestionServiceSettings
from database.connection import IngestionDatabase
from models.iocs_record import ProcessingStats

logger = logging.getLogger(__name__)


class NVDFetcher:
    """NVD CVE fetcher with support for bulk and incremental updates"""
    
    def __init__(self, settings: IngestionServiceSettings, database: IngestionDatabase):
        self.settings = settings
        self.database = database
        
        if not settings.NVD_API_KEY:
            raise ValueError("NVD_API_KEY not found in configuration")
        
        self._session = None
        self._compressor = None
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.rate_limit = 0.67  # ~50 requests per 30 seconds with API key
        self.last_request_time = 0.0
        self._rate_lock = asyncio.Lock()
        
        self.processed_cves_file = Path("nvd_processed_cves.json")
        self.last_sync_file = Path("nvd_last_sync.json")
        self.processed_cves = self._load_processed_cves()
        self.last_sync_date = self._load_last_sync_date()
        
    async def get_session(self):
        """Lazy initialization of aiohttp session"""
        if self._session is None or self._session.closed:
            if self._session and self._session.closed:
                logger.info("Session was closed, creating a new one")
            
            connector = aiohttp.TCPConnector(
                limit=self.settings.http_connection_limit,
                limit_per_host=self.settings.http_per_host_limit,
                keepalive_timeout=30
            )
            headers = {
                'apiKey': self.settings.NVD_API_KEY,
                'User-Agent': 'GTIC NVD Ingestion Service 1.0'
            }
            self._session = aiohttp.ClientSession(
                headers=headers,
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=120)
            )
        return self._session
    
    def get_compressor(self):
        """Lazy initialization of zstd compressor"""
        if self._compressor is None:
            self._compressor = zstd.ZstdCompressor(level=3)
        return self._compressor
    
    async def close_session(self):
        """Properly close the session"""
        if self._session:
            await self._session.close()
            self._session = None
    
    def _load_processed_cves(self) -> Dict[str, datetime]:
        """Load list of already processed CVE IDs with timestamps"""
        if self.processed_cves_file.exists():
            try:
                with open(self.processed_cves_file, 'r') as f:
                    data = json.load(f)
                return {
                    cve_id: datetime.fromisoformat(timestamp)
                    for cve_id, timestamp in data.items()
                }
            except Exception as e:
                logger.warning(f"Could not load processed CVEs: {e}")
        return {}
    
    def _save_processed_cves(self):
        """Save processed CVE IDs to file"""
        try:
            data = {
                cve_id: timestamp.isoformat()
                for cve_id, timestamp in self.processed_cves.items()
            }
            with open(self.processed_cves_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Could not save processed CVEs: {e}")
    
    def _load_last_sync_date(self) -> Optional[datetime]:
        """Load last sync date for incremental updates"""
        if self.last_sync_file.exists():
            try:
                with open(self.last_sync_file, 'r') as f:
                    data = json.load(f)
                    return datetime.fromisoformat(data.get('last_sync_date'))
            except Exception as e:
                logger.warning(f"Could not load last sync date: {e}")
        return None
    
    def _save_last_sync_date(self, sync_date: datetime):
        """Save last sync date"""
        try:
            data = {'last_sync_date': sync_date.isoformat()}
            with open(self.last_sync_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Could not save last sync date: {e}")
    
    async def enforce_rate_limit(self):
        """Enforce rate limiting"""
        import time
        async with self._rate_lock:
            current_time = time.time()
            time_since_last = current_time - self.last_request_time
            
            if time_since_last < self.rate_limit:
                sleep_time = self.rate_limit - time_since_last
                await asyncio.sleep(sleep_time)
            
            self.last_request_time = time.time()
    
    async def run(self, mode: str = "incremental") -> ProcessingStats:
        """
        Main execution method
        
        Args:
            mode: "incremental" (default) - fetch only modified CVEs since last sync
                  "full" - fetch all CVEs (for initial ingestion)
        """
        logger.info(f"Starting NVD CVE ingestion (mode: {mode})")
        start_time = datetime.now()
        stats = ProcessingStats()
        
        try:
            if mode == "full":
                stats = await self._fetch_all_cves()
            else:
                stats = await self._fetch_incremental_cves()
            
            processing_time = (datetime.now() - start_time).total_seconds()
            stats.processing_time_seconds = processing_time
            
            logger.info(f"NVD CVE ingestion completed: {stats.model_dump()}")
            return stats
            
        finally:
            await self.close_session()
    
    async def _fetch_incremental_cves(self) -> ProcessingStats:
        """Fetch only CVEs modified since last sync"""
        stats = ProcessingStats()
        
        # Default to last 24 hours if no last sync date
        if self.last_sync_date:
            start_date = self.last_sync_date
        else:
            start_date = datetime.now(timezone.utc) - timedelta(days=1)
        
        end_date = datetime.now(timezone.utc)
        
        logger.info(f"Fetching CVEs modified between {start_date} and {end_date}")
        
        # Format dates for NVD API (YYYY-MM-DDTHH:MM:SS.FFF-00:00)
        mod_start_date = start_date.strftime("%Y-%m-%dT%H:%M:%S.000-00:00")
        mod_end_date = end_date.strftime("%Y-%m-%dT%H:%M:%S.000-00:00")
        
        return await self._fetch_cves_by_date_range(
            mod_start_date=mod_start_date,
            mod_end_date=mod_end_date,
            stats=stats
        )
    
    async def _fetch_all_cves(self) -> ProcessingStats:
        """Fetch all CVEs year-by-year (for initial ingestion)"""
        stats = ProcessingStats()
        current_year = datetime.now().year
        
        logger.info(f"Starting year-based full CVE ingestion from 2002 to {current_year}")
        
        total_years = current_year - 2002 + 1
        
        for idx, year in enumerate(range(2002, current_year + 1), start=1):
            logger.info(f"Processing year {year} ({idx}/{total_years})")
            
            try:
                await self._fetch_cves_by_year(year, stats)
                logger.info(f"Completed year {year}. Progress: {idx}/{total_years} years ({(idx/total_years)*100:.1f}%)")
                
                # Longer delay between years to respect rate limits
                if idx < total_years:
                    await asyncio.sleep(5)
                    
            except Exception as e:
                logger.error(f"Error processing year {year}: {e}", exc_info=True)
                logger.warning(f"Continuing to next year after error...")
                await asyncio.sleep(10)  # Longer wait after error
                continue
        
        logger.info(f"Year-based ingestion complete!")
        logger.info(f"Total CVEs processed: {stats.total_cves_processed}")
        logger.info(f"CVEs stored: {stats.cves_newly_stored}, Updated: {stats.cves_updated}, Skipped: {stats.cves_skipped}")
        
        return stats
    
    async def _fetch_cves_by_year(
        self,
        year: int,
        stats: ProcessingStats
    ) -> None:
        """Fetch all CVEs for a specific year by splitting into quarters (NVD API limit is 120 days)"""
        # Define 90-day intervals for the year
        intervals = [
            (f"{year}-01-01T00:00:00.000-00:00", f"{year}-03-31T23:59:59.999-00:00"),
            (f"{year}-04-01T00:00:00.000-00:00", f"{year}-06-30T23:59:59.999-00:00"),
            (f"{year}-07-01T00:00:00.000-00:00", f"{year}-09-30T23:59:59.999-00:00"),
            (f"{year}-10-01T00:00:00.000-00:00", f"{year}-12-31T23:59:59.999-00:00"),
        ]
        
        for q_idx, (start_date, end_date) in enumerate(intervals, start=1):
            logger.info(f"Processing year {year} - Quarter {q_idx}")
            await self._fetch_cves_by_date_range(
                pub_start_date=start_date,
                pub_end_date=end_date,
                stats=stats,
                context=f"year {year} Q{q_idx}"
            )
            # Brief pause between quarters to avoid burst limits
            await asyncio.sleep(2)
    
    async def _fetch_cves_by_date_range(
        self,
        mod_start_date: Optional[str] = None,
        mod_end_date: Optional[str] = None,
        pub_start_date: Optional[str] = None,
        pub_end_date: Optional[str] = None,
        stats: Optional[ProcessingStats] = None,
        context: str = ""
    ) -> ProcessingStats:
        """Fetch CVEs by date range with pagination"""
        if stats is None:
            stats = ProcessingStats()
        
        results_per_page = 2000  # Maximum allowed by NVD API
        start_index = 0
        total_results = None
        cves_stored = 0
        cves_updated = 0
        cves_skipped = 0
        
        try:
            while True:
                await self.enforce_rate_limit()
                
                # Get session inside the loop to ensure it's not closed
                session = await self.get_session()
                
                params = {
                    "resultsPerPage": results_per_page,
                    "startIndex": start_index
                }
                
                # Add modification date filters (for incremental updates)
                if mod_start_date:
                    params["lastModStartDate"] = mod_start_date
                if mod_end_date:
                    params["lastModEndDate"] = mod_end_date
                
                # Add publication date filters (for year-based fetching)
                if pub_start_date:
                    params["pubStartDate"] = pub_start_date
                if pub_end_date:
                    params["pubEndDate"] = pub_end_date
                
                context_str = f" ({context})" if context else ""
                
                retry_count = 0
                max_retries = 3
                
                try:
                    async with session.get(self.base_url, params=params) as response:
                        # Handle rate limiting with exponential backoff
                        if response.status == 429:
                            retry_count += 1
                            wait_time = min(30 * (2 ** retry_count), 300)  # Exponential backoff, max 5 minutes
                            logger.warning(f"Rate limit exceeded (attempt {retry_count}/{max_retries}), waiting {wait_time} seconds...")
                            await asyncio.sleep(wait_time)
                            
                            if retry_count >= max_retries:
                                logger.error(f"Max retries reached for rate limiting, moving to next batch")
                                break
                            continue
                        
                        response.raise_for_status()
                        data = await response.json()
                        
                        if total_results is None:
                            total_results = data.get("totalResults", 0)
                            logger.info(f"Total CVEs to fetch: {total_results}")
                        
                        vulnerabilities = data.get("vulnerabilities", [])
                        if not vulnerabilities:
                            break
                        
                        batch_stored, batch_updated, batch_skipped = await self._process_cve_batch(
                            vulnerabilities
                        )
                        
                        cves_stored += batch_stored
                        cves_updated += batch_updated
                        cves_skipped += batch_skipped
                        
                        start_index += results_per_page
                        
                        if start_index >= total_results:
                            break
                        
                        # Small delay between pages
                        await asyncio.sleep(1)
                        
                except aiohttp.ClientError as e:
                    logger.error(f"HTTP error fetching CVEs: {e}")
                    # Handle 404 errors gracefully (e.g., for years with no data in NVD API 2.0)
                    if "404" in str(e):
                        logger.warning("Received 404, skipping batch")
                        break
                    await asyncio.sleep(5)
                    continue
                except Exception as e:
                    logger.error(f"Error fetching CVEs: {e}", exc_info=True)
                    await asyncio.sleep(5)
                    continue
            
            # Update last sync date
            self._save_last_sync_date(datetime.now(timezone.utc))
            
            # Update stats
            stats.total_cves_processed = cves_stored + cves_updated + cves_skipped
            stats.cves_newly_stored = cves_stored
            stats.cves_updated = cves_updated
            stats.cves_skipped = cves_skipped
            
            logger.info(
                f"CVE ingestion complete: {cves_stored} stored, {cves_updated} updated, "
                f"{cves_skipped} skipped"
            )
            
            return stats
            
        except Exception as e:
            logger.error(f"Error in CVE fetch: {e}", exc_info=True)
            return stats
    
    async def _process_cve_batch(
        self,
        vulnerabilities: List[Dict[str, Any]]
    ) -> tuple[int, int, int]:
        """Process a batch of CVE vulnerabilities"""
        stored = 0
        updated = 0
        skipped = 0
        
        batch_records = []
        
        for vuln in vulnerabilities:
            try:
                cve_obj = vuln.get("cve", {})
                cve_id_str = cve_obj.get("id")
                
                if not cve_id_str:
                    skipped += 1
                    continue
                
                # Check if recently processed
                if cve_id_str in self.processed_cves:
                    last_processed = self.processed_cves[cve_id_str]
                    time_since_processed = datetime.now(timezone.utc) - last_processed
                    if time_since_processed < timedelta(hours=2):
                        skipped += 1
                        continue
                
                # Parse CVE data
                cve_record = self._parse_cve_to_record(cve_obj)
                if cve_record:
                    batch_records.append(cve_record)
                    self.processed_cves[cve_id_str] = datetime.now(timezone.utc)
            
            except Exception as e:
                logger.warning(f"Error processing CVE {cve_obj.get('id', 'unknown')}: {e}")
                skipped += 1
                continue
        
        if batch_records:
            # Store batch in database
            stored_count = await self.database.store_cve_batch(batch_records)
            stored = stored_count
            updated = len(batch_records) - stored_count  # Assume rest were updates
        
        # Save processed CVEs periodically
        self._save_processed_cves()
        
        return stored, updated, skipped
    
    def _parse_cve_to_record(self, cve_obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse NVD CVE object to database record format"""
        try:
            cve_id_str = cve_obj.get("id")
            if not cve_id_str:
                return None
            
            # Parse published and lastModified
            published_str = cve_obj.get("published")
            last_modified_str = cve_obj.get("lastModified")
            
            published = datetime.fromisoformat(published_str.replace('Z', '+00:00')) if published_str else datetime.now(timezone.utc)
            last_modified = datetime.fromisoformat(last_modified_str.replace('Z', '+00:00')) if last_modified_str else datetime.now(timezone.utc)
            
            # Parse CVSS v3.1 scores
            score = 0.0
            severity = "NONE"
            vector_string = None
            
            metrics = cve_obj.get("metrics", {})
            cvss_v31_list = metrics.get("cvssMetricV31", [])
            if cvss_v31_list:
                cvss_data = cvss_v31_list[0].get("cvssData", {})
                score = cvss_data.get("baseScore", 0.0)
                severity = cvss_data.get("baseSeverity", "NONE")
                vector_string = cvss_data.get("vectorString")
            else:
                cvss_v30_list = metrics.get("cvssMetricV30", [])
                if cvss_v30_list:
                    cvss_data = cvss_v30_list[0].get("cvssData", {})
                    score = cvss_data.get("baseScore", 0.0)
                    severity = cvss_data.get("baseSeverity", "NONE")
                    vector_string = cvss_data.get("vectorString")
            
            # Parse CVSS v2 (optional)
            cvss_v2_score = None
            cvss_v2_severity = None
            cvss_v2_list = metrics.get("cvssMetricV2", [])
            if cvss_v2_list:
                cvss_v2_data = cvss_v2_list[0].get("cvssData", {})
                cvss_v2_score = cvss_v2_data.get("baseScore")
                cvss_v2_severity = cvss_v2_list[0].get("baseSeverity")
            
            # Parse CISA KEV fields
            cisa_exploit_add = None
            if cve_obj.get("cisaExploitAdd"):
                try:
                    cisa_exploit_add = datetime.strptime(cve_obj["cisaExploitAdd"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
                except:
                    pass
            
            cisa_action_due = None
            if cve_obj.get("cisaActionDue"):
                try:
                    cisa_action_due = datetime.strptime(cve_obj["cisaActionDue"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
                except:
                    pass
            
            # Parse description (English)
            description_en = None
            descriptions = cve_obj.get("descriptions", [])
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description_en = desc.get("value")
                    break
            
            # Get configurations (CPE matching data)
            configurations = cve_obj.get("configurations", [])
            
            # Calculate threat level from severity
            severity_map = {
                "CRITICAL": 3,
                "HIGH": 2,
                "MEDIUM": 1,
                "LOW": 0,
                "NONE": 0
            }
            threat_level = severity_map.get(severity.upper(), 0)
            
            # Calculate expiry based on severity
            now = datetime.now(timezone.utc)
            if severity == "CRITICAL":
                expires_at = now + timedelta(days=30)
            elif severity == "HIGH":
                expires_at = now + timedelta(days=7)
            else:
                expires_at = now + timedelta(days=3)
            
            # Check if KEV
            is_kev = bool(cisa_exploit_add or cve_obj.get("cisaVulnerabilityName"))
            
            # Compress raw data
            compressor = self.get_compressor()
            raw_data_json = json.dumps(cve_obj).encode('utf-8')
            compressed_details = compressor.compress(raw_data_json)
            
            return {
                'cve_id': cve_id_str,
                'configurations': json.dumps(configurations) if configurations else None,
                'cvss_score': int(score * 10),  # Store as integer (0-100)
                'threat_level': threat_level,
                'cve_status': cve_obj.get("vulnStatus"),
                'published': published,
                'last_modified': last_modified,
                'source_name': cve_obj.get("sourceIdentifier", "NVD"),
                'first_seen': now,
                'last_fetched': now,
                'details': compressed_details,
                'expires_at': expires_at,
                'is_kev': is_kev,
                'description': description_en,
                'cvss_v3_vector_string': vector_string,
            }
            
        except Exception as e:
            logger.error(f"Error parsing CVE object: {e}", exc_info=True)
            return None

