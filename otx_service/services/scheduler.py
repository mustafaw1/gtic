"""
OTX Service Scheduler
Handles periodic execution of OTX domain fetching
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional

from config import OTXServiceSettings
from database.connection import OTXDatabase
from services.otx_fetcher import OTXDomainFetcher
from models.iocs_record import ProcessingStats

logger = logging.getLogger(__name__)


class OTXScheduler:
    """Background scheduler for OTX domain fetching"""
    
    def __init__(self, settings: OTXServiceSettings, database: OTXDatabase):
        self.settings = settings
        self.database = database
        self.fetcher = OTXDomainFetcher(settings, database)
        self.task: Optional[asyncio.Task] = None
        self.stop_event = asyncio.Event()
        
    async def start(self):
        """Start the OTX scheduler"""
        if not self.settings.OTX_API_KEY:
            logger.warning("OTX_API_KEY not configured, skipping OTX scheduler")
            return
            
        if self.task and not self.task.done():
            logger.warning("OTX scheduler already running")
            return
            
        self.stop_event.clear()
        self.task = asyncio.create_task(self._scheduler_loop())
        logger.info(f"OTX scheduler started (every {self.settings.schedule_interval_hours} hours)")
        
    async def stop(self):
        """Stop the OTX scheduler"""
        if self.task and not self.task.done():
            self.stop_event.set()
            try:
                await asyncio.wait_for(self.task, timeout=30)
            except asyncio.TimeoutError:
                logger.warning("OTX scheduler shutdown timed out")
                self.task.cancel()
                try:
                    await self.task
                except asyncio.CancelledError:
                    pass
        logger.info("OTX scheduler stopped")
    
    async def _scheduler_loop(self):
        """Main scheduler loop"""
        while not self.stop_event.is_set():
            try:
                next_run = self._calculate_next_run()
                wait_seconds = (next_run - datetime.now()).total_seconds()
                
                logger.info(f"OTX scheduler: Next run at {next_run.strftime('%Y-%m-%d %H:%M:%S')} "
                           f"(in {wait_seconds/3600:.1f} hours)")
                
                try:
                    await asyncio.wait_for(self.stop_event.wait(), timeout=wait_seconds)
                    break
                except asyncio.TimeoutError:
                    if not self.stop_event.is_set():
                        await self._run_otx_fetch()
                        
            except Exception as e:
                logger.error(f"Error in OTX scheduler loop: {e}")
                try:
                    await asyncio.wait_for(self.stop_event.wait(), timeout=300)
                    break
                except asyncio.TimeoutError:
                    continue
    
    def _calculate_next_run(self) -> datetime:
        """Return the next run time based on configured interval"""
        now = datetime.now()
        next_run = now + timedelta(hours=self.settings.schedule_interval_hours)
        next_run = next_run.replace(minute=0, second=0, microsecond=0)
        return next_run

    async def _run_otx_fetch(self):
        """Execute OTX domain fetch"""
        operation_start_time = datetime.now()
        try:
            logger.info("Starting scheduled OTX domain fetch")
            stats = await self.fetcher.run()
            
            operation_duration = (datetime.now() - operation_start_time).total_seconds()
            logger.info(f"OTX fetch completed in {operation_duration:.1f}s")
            logger.info(f"Processing stats: {stats.model_dump()}")
            
            db_stats = await self.database.get_stats()
            logger.info(f"Database stats: {db_stats}")
            
        except Exception as e:
            operation_duration = (datetime.now() - operation_start_time).total_seconds()
            logger.error(f"OTX fetch failed after {operation_duration:.1f}s: {e}")
    
    async def trigger_manual_run(self) -> ProcessingStats:
        """Manually trigger OTX fetch (for API endpoint)"""
        try:
            logger.info("Manual OTX domain fetch triggered")
            return await self.fetcher.run()
        except Exception as e:
            logger.error(f"Manual OTX fetch failed: {e}")
            raise
