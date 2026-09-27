"""
Unified Ingestion Services Scheduler
Handles periodic execution of both OTX and Malware Bazaar services
Alternates between services: OTX at odd hours, Malware Bazaar at even hours
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional, Tuple

from config import IngestionServiceSettings
from database.connection import IngestionDatabase
from services.otx_fetcher import OTXDomainFetcher
from services.malwarebazaar_fetcher import MalwareBazaarFetcher
from services.nvd_fetcher import NVDFetcher
from services.epss_fetcher import EPSSFetcher
from services.cpe_dictionary_fetcher import CPEDictionaryFetcher, CPEDictionaryStats
from models.iocs_record import ProcessingStats

logger = logging.getLogger(__name__)


class IngestionScheduler:
    """Unified background scheduler for OTX and Malware Bazaar ingestion services"""
    
    def __init__(self, settings: IngestionServiceSettings, database: IngestionDatabase):
        self.settings = settings
        self.database = database
        
        # Initialize fetchers
        self.otx_fetcher = OTXDomainFetcher(settings, database) if settings.OTX_API_KEY else None
        self.malwarebazaar_fetcher = MalwareBazaarFetcher(settings, database) if settings.MALWAREBazaar_API_KEY else None
        self.nvd_fetcher = NVDFetcher(settings, database) if settings.NVD_API_KEY else None
        self.cpe_dict_fetcher = CPEDictionaryFetcher(settings, database) if settings.NVD_API_KEY else None
        self.epss_fetcher = EPSSFetcher(settings, database)
        
        self.task: Optional[asyncio.Task] = None
        self.stop_event = asyncio.Event()
        
    async def start(self):
        """Start the unified scheduler"""
        if not self.otx_fetcher and not self.malwarebazaar_fetcher and not self.nvd_fetcher:
            logger.warning("No API keys configured for any ingestion service, skipping scheduler")
            return
            
        if self.task and not self.task.done():
            logger.warning("Scheduler already running")
            return
            
        self.stop_event.clear()
        self.task = asyncio.create_task(self._scheduler_loop())
        
        enabled_services = []
        if self.otx_fetcher:
            enabled_services.append("OTX (odd hours: 1, 3, 5, ...)")
        if self.malwarebazaar_fetcher:
            enabled_services.append("Malware Bazaar (even hours: 2, 4, 6, ...)")
        if self.nvd_fetcher:
            enabled_services.append("NVD CVE (every 2 hours)")
        
        logger.info(f"Unified ingestion scheduler started")
        logger.info(f"Enabled services: {', '.join(enabled_services)}")
        
    async def stop(self):
        """Stop the unified scheduler"""
        if self.task and not self.task.done():
            self.stop_event.set()
            try:
                await asyncio.wait_for(self.task, timeout=30)
            except asyncio.TimeoutError:
                logger.warning("Scheduler shutdown timed out")
                self.task.cancel()
                try:
                    await self.task
                except asyncio.CancelledError:
                    pass
        logger.info("Unified ingestion scheduler stopped")
    
    async def _scheduler_loop(self):
        """Main scheduler loop - alternates between OTX, Malware Bazaar, and NVD"""
        last_nvd_run = None
        last_cpe_dict_run = None
        
        while not self.stop_event.is_set():
            try:
                # Check if NVD should run (every 2 hours)
                now = datetime.now()
                should_run_nvd = False
                if self.nvd_fetcher:
                    if last_nvd_run is None:
                        should_run_nvd = True
                    else:
                        time_since_nvd = (now - last_nvd_run).total_seconds()
                        if time_since_nvd >= 7200:  # 2 hours
                            should_run_nvd = True

                should_run_cpe_dict = False
                if self.cpe_dict_fetcher:
                    if last_cpe_dict_run is None:
                        should_run_cpe_dict = True
                    elif (now - last_cpe_dict_run).total_seconds() >= 86400:
                        should_run_cpe_dict = True

                if should_run_nvd:
                    await self._run_nvd_fetch()
                    last_nvd_run = now

                if should_run_cpe_dict:
                    await self._run_cpe_dict_fetch()
                    last_cpe_dict_run = now
                    # Wait a bit before checking other services
                    try:
                        await asyncio.wait_for(self.stop_event.wait(), timeout=60)
                        if self.stop_event.is_set():
                            break
                    except asyncio.TimeoutError:
                        pass
                
                # Calculate next run for OTX/MalwareBazaar
                next_run, next_service = self._calculate_next_run()
                wait_seconds = (next_run - datetime.now()).total_seconds()
                
                # Don't wait too long if NVD needs to run soon
                if self.nvd_fetcher and last_nvd_run:
                    time_until_nvd = 7200 - (now - last_nvd_run).total_seconds()
                    if time_until_nvd < wait_seconds and time_until_nvd > 0:
                        wait_seconds = min(wait_seconds, time_until_nvd)
                
                service_name = "OTX" if next_service == "otx" else "Malware Bazaar"
                logger.info(f"Scheduler: Next run ({service_name}) at {next_run.strftime('%Y-%m-%d %H:%M:%S')} "
                           f"(in {wait_seconds/3600:.1f} hours)")
                
                try:
                    await asyncio.wait_for(self.stop_event.wait(), timeout=wait_seconds)
                    break
                except asyncio.TimeoutError:
                    if not self.stop_event.is_set():
                        if next_service == "otx" and self.otx_fetcher:
                            await self._run_otx_fetch()
                        elif next_service == "malwarebazaar" and self.malwarebazaar_fetcher:
                            await self._run_malwarebazaar_fetch()
                        
            except Exception as e:
                logger.error(f"Error in scheduler loop: {e}")
                try:
                    await asyncio.wait_for(self.stop_event.wait(), timeout=300)
                    break
                except asyncio.TimeoutError:
                    continue
    
    def _calculate_next_run(self) -> Tuple[datetime, str]:
        """Calculate next run time and which service to run
        Returns:
            Tuple of (next_run_datetime, service_name)
            - OTX runs at odd hours (1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23)
            - Malware Bazaar runs at even hours (2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 0)
        """
        now = datetime.now()
        current_hour = now.hour
        
        # Determine which service should run next
        if current_hour % 2 == 0:
            # Current hour is even, next service is OTX (next odd hour)
            next_hour = (current_hour + 1) % 24
            next_service = "otx"
        else:
            # Current hour is odd, next service is Malware Bazaar (next even hour)
            next_hour = (current_hour + 1) % 24
            next_service = "malwarebazaar"
        
        next_run = now.replace(hour=next_hour, minute=0, second=0, microsecond=0)
        
        # If next_run is in the past (shouldn't happen but safety check), add 1 hour
        if next_run <= now:
            next_run += timedelta(hours=1)
            # Recalculate service based on new hour
            if next_run.hour % 2 == 0:
                next_service = "malwarebazaar"
            else:
                next_service = "otx"
        
        # If the calculated service is not available, skip to the next one
        if next_service == "otx" and not self.otx_fetcher:
            next_hour = (next_hour + 1) % 24
            next_run = now.replace(hour=next_hour, minute=0, second=0, microsecond=0)
            if next_run <= now:
                next_run += timedelta(hours=1)
            next_service = "malwarebazaar"
        
        if next_service == "malwarebazaar" and not self.malwarebazaar_fetcher:
            next_hour = (next_hour + 1) % 24
            next_run = now.replace(hour=next_hour, minute=0, second=0, microsecond=0)
            if next_run <= now:
                next_run += timedelta(hours=1)
            next_service = "otx"
        
        return next_run, next_service

    async def _run_otx_fetch(self):
        """Execute OTX fetch"""
        if not self.otx_fetcher:
            logger.warning("OTX fetcher not available")
            return
            
        operation_start_time = datetime.now()
        try:
            logger.info("Starting scheduled OTX fetch")
            stats = await self.otx_fetcher.run()
            
            operation_duration = (datetime.now() - operation_start_time).total_seconds()
            logger.info(f"OTX fetch completed in {operation_duration:.1f}s")
            logger.info(f"Processing stats: {stats.model_dump()}")
            
            db_stats = await self.database.get_stats()
            logger.info(f"Database stats: {db_stats}")
            
        except Exception as e:
            operation_duration = (datetime.now() - operation_start_time).total_seconds()
            logger.error(f"OTX fetch failed after {operation_duration:.1f}s: {e}")
    
    async def _run_malwarebazaar_fetch(self):
        """Execute Malware Bazaar fetch"""
        if not self.malwarebazaar_fetcher:
            logger.warning("Malware Bazaar fetcher not available")
            return
            
        operation_start_time = datetime.now()
        try:
            logger.info("Starting scheduled Malware Bazaar fetch")
            stats = await self.malwarebazaar_fetcher.run()
            
            operation_duration = (datetime.now() - operation_start_time).total_seconds()
            logger.info(f"Malware Bazaar fetch completed in {operation_duration:.1f}s")
            logger.info(f"Processing stats: {stats.model_dump()}")
            
            db_stats = await self.database.get_stats()
            logger.info(f"Database stats: {db_stats}")
            
        except Exception as e:
            operation_duration = (datetime.now() - operation_start_time).total_seconds()
            logger.error(f"Malware Bazaar fetch failed after {operation_duration:.1f}s: {e}")
    
    async def trigger_manual_otx_run(self) -> ProcessingStats:
        """Manually trigger OTX fetch (for API endpoint)"""
        if not self.otx_fetcher:
            raise ValueError("OTX fetcher not available (OTX_API_KEY not configured)")
        try:
            logger.info("Manual OTX fetch triggered")
            return await self.otx_fetcher.run()
        except Exception as e:
            logger.error(f"Manual OTX fetch failed: {e}")
            raise
    
    async def trigger_manual_malwarebazaar_run(self) -> ProcessingStats:
        """Manually trigger Malware Bazaar fetch (for API endpoint)"""
        if not self.malwarebazaar_fetcher:
            raise ValueError("Malware Bazaar fetcher not available (MALWAREBazaar_API_KEY not configured)")
        try:
            logger.info("Manual Malware Bazaar fetch triggered")
            return await self.malwarebazaar_fetcher.run()
        except Exception as e:
            logger.error(f"Manual Malware Bazaar fetch failed: {e}")
            raise
    
    async def _run_nvd_fetch(self):
        """Execute NVD CVE fetch, followed by EPSS score enrichment."""
        if not self.nvd_fetcher:
            logger.warning("NVD fetcher not available")
            return

        operation_start_time = datetime.now()
        try:
            logger.info("Starting scheduled NVD CVE fetch")
            stats = await self.nvd_fetcher.run(mode="incremental")

            operation_duration = (datetime.now() - operation_start_time).total_seconds()
            logger.info(f"NVD CVE fetch completed in {operation_duration:.1f}s")
            logger.info(f"Processing stats: {stats.model_dump()}")

            db_stats = await self.database.get_stats()
            logger.info(f"Database stats: {db_stats}")

        except Exception as e:
            operation_duration = (datetime.now() - operation_start_time).total_seconds()
            logger.error(f"NVD CVE fetch failed after {operation_duration:.1f}s: {e}")

        await self._run_epss_fetch()

    async def _run_epss_fetch(self):
        """Execute EPSS score enrichment for all CVEs in cve_cache."""
        try:
            logger.info("Starting EPSS score enrichment")
            total, updated = await self.epss_fetcher.run()
            logger.info(f"EPSS enrichment done: {updated}/{total} scores updated")
        except Exception as e:
            logger.error(f"EPSS enrichment failed: {e}")
    
    async def _run_cpe_dict_fetch(self, mode: str = "incremental"):
        """Execute CPE dictionary sync."""
        if not self.cpe_dict_fetcher:
            logger.warning("CPE dictionary fetcher not available")
            return
        try:
            logger.info(f"Starting CPE dictionary sync (mode: {mode})")
            stats = await self.cpe_dict_fetcher.run(mode=mode)
            logger.info(f"CPE dictionary sync complete: {stats.model_dump()}")
        except Exception as e:
            logger.error(f"CPE dictionary sync failed: {e}")

    async def trigger_manual_cpe_dict_run(self, mode: str = "incremental") -> CPEDictionaryStats:
        """Manually trigger CPE dictionary sync (for API endpoint)."""
        if not self.cpe_dict_fetcher:
            raise ValueError("CPE dictionary fetcher not available (NVD_API_KEY not configured)")
        logger.info(f"Manual CPE dictionary sync triggered (mode: {mode})")
        return await self.cpe_dict_fetcher.run(mode=mode)

    async def trigger_manual_nvd_run(self, mode: str = "incremental") -> ProcessingStats:
        """Manually trigger NVD CVE fetch (for API endpoint)
        
        Args:
            mode: "incremental" (default) - fetch only modified CVEs since last sync
                  "full" - fetch all CVEs (for initial ingestion)
        """
        if not self.nvd_fetcher:
            raise ValueError("NVD fetcher not available (NVD_API_KEY not configured)")
        try:
            logger.info(f"Manual NVD CVE fetch triggered (mode: {mode})")
            return await self.nvd_fetcher.run(mode=mode)
        except Exception as e:
            logger.error(f"Manual NVD CVE fetch failed: {e}")
            raise
