"""
Data consistency management for IP lookup services.

This module provides mechanisms to ensure data consistency between cache and database,
including per-IP locking and synchronized updates.
"""

import asyncio
import logging
import time
from typing import Dict, Optional, Any
from datetime import datetime, timezone, timedelta
from contextlib import asynccontextmanager
from app.services.utils import gtic_threat_score
from .interfaces.cache import CacheInterface
from .interfaces.database import DatabaseRepositoryInterface
from .models.threat_data import ThreatData, IPAddress
from .resource_manager import get_resource_manager, ResourceType

logger = logging.getLogger(__name__)


class ConsistencyManager:
    """
    Manages data consistency between cache and database for IP lookup operations.
    
    Features:
    - Per-IP locking to prevent race conditions
    - Synchronized cache-database updates
    - Atomic operations for data integrity
    """
    
    def __init__(self, cache: CacheInterface, database: DatabaseRepositoryInterface):
        self.cache = cache
        self.database = database
        self._ip_locks: Dict[str, asyncio.Lock] = {}
        self._locks_lock = asyncio.Lock()
        self._resource_manager = get_resource_manager()
        
        self._lock_cleanup_threshold = 1000
        self._last_lock_cleanup = time.time()
    
    async def _get_ip_lock(self, ip: str) -> asyncio.Lock:
        """Get or create a lock for specific IP address to prevent race conditions."""
        async with self._locks_lock:
            if ip not in self._ip_locks:
                lock = asyncio.Lock()
                self._ip_locks[ip] = lock
                
                self._resource_manager.register_resource(
                    resource_id=f"ip_lock:{ip}",
                    resource_type=ResourceType.IP_LOCK,
                    resource_obj=lock,
                    metadata={"ip_address": ip, "created_at": time.time()}
                )
                
                await self._maybe_cleanup_old_locks()
                
            return self._ip_locks[ip]
    
    async def _cleanup_lock(self, ip: str) -> None:
        """Cleanup lock for IP to prevent memory leaks."""
        async with self._locks_lock:
            lock = self._ip_locks.get(ip)
            if lock and not lock.locked():
                resource_id = f"ip_lock:{ip}"
                await self._resource_manager.unregister_resource(resource_id, force_cleanup=False)
                self._ip_locks.pop(ip, None)
                logger.debug(f"Cleaned up lock for IP: {ip}")
    
    async def _maybe_cleanup_old_locks(self) -> None:
        """Periodically cleanup old IP locks to prevent memory leaks."""
        current_time = time.time()
        
        if (len(self._ip_locks) >= self._lock_cleanup_threshold or 
            current_time - self._last_lock_cleanup > 300):  # 5 minutes
            
            stale_ips = []
            stale_threshold = current_time - 1800  # 30 minutes

            for ip, lock in self._ip_locks.items():
                if not lock.locked():
                    resource_id = f"ip_lock:{ip}"
                    if resource_id in self._resource_manager._resources:
                        resource_info = self._resource_manager._resources[resource_id]
                        if resource_info.metadata.get("created_at", 0) < stale_threshold:
                            stale_ips.append(ip)
            
            for ip in stale_ips:
                await self._cleanup_lock(ip)
            
            self._last_lock_cleanup = current_time
            
            if stale_ips:
                logger.info(f"Cleaned up {len(stale_ips)} stale IP locks")
    
    @asynccontextmanager
    async def ip_operation_lock(self, ip: str):
        """Context manager for per-IP locking."""
        ip_lock = await self._get_ip_lock(ip)
        async with ip_lock:
            try:
                yield
            finally:
                asyncio.create_task(self._cleanup_lock(ip))
    
    async def update_threat_data_consistently(
        self, 
        threat_data: ThreatData, 
        update_database: bool = True,
        update_cache: bool = True
    ) -> bool:
        """
        Update threat data in both cache and database consistently.
        
        Args:
            threat_data: The threat data to update
            update_database: Whether to update database record
            update_cache: Whether to update cache record
            
        Returns:
            bool: True if all updates succeeded, False otherwise
        """
        ip_str = str(threat_data.ip_address)
        
        async with self.ip_operation_lock(ip_str):
            success = True
            
            try:
                if update_database:
                    db_success = await self._update_database_record(threat_data)
                    if not db_success:
                        logger.error(f"Failed to update database for IP {ip_str}")
                        success = False
                
                if update_cache and (success or not update_database):
                    cache_success = await self._update_cache_record(threat_data)
                    if not cache_success:
                        logger.error(f"Failed to update cache for IP {ip_str}")
                        success = False
                
                if success:
                    logger.debug(f"Successfully updated IP {ip_str} (DB: {update_database}, Cache: {update_cache})")
                
                return success
                
            except Exception as e:
                logger.error(f"Error updating threat data for IP {ip_str}: {e}")
                return False
    
    async def _update_database_record(self, threat_data: ThreatData) -> bool:
        """Update database record with threat data."""
        try:
            if threat_data.expires_at is None:
                threat_data.expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
                logger.debug(f"Set default expires_at for IP {threat_data.ip_address}")
            
            db_dict = threat_data.to_db_dict()
            return await self.database.save(db_dict)
        except Exception as e:
            logger.error(f"Database update failed for IP {threat_data.ip_address}: {e}")
            return False
    
    async def _update_cache_record(self, threat_data: ThreatData) -> bool:
        """Update cache record with threat data."""
        try:
            if threat_data.expires_at:
                ttl = int((threat_data.expires_at - datetime.now(timezone.utc)).total_seconds())
                ttl = max(1, ttl)
            else:
                ttl = 3600
            
            cache_dict = threat_data.to_dict()
            return await self.cache.set(str(threat_data.ip_address), cache_dict, ttl)
        except Exception as e:
            logger.error(f"Cache update failed for IP {threat_data.ip_address}: {e}")
            return False
    
    async def get_threat_data_consistently(self, ip_address: IPAddress) -> Optional[ThreatData]:
        """
        Get threat data with consistency checks between cache and database.
        
        This method ensures cache and database are in sync and handles
        any inconsistencies found.
        """
        ip_str = str(ip_address)
        
        async with self.ip_operation_lock(ip_str):
            cache_data = await self._get_cache_data(ip_address)
            db_data = await self._get_database_data(ip_address)
            
            if cache_data and db_data:
                return await self._reconcile_data(cache_data, db_data, ip_address)
            elif cache_data and not db_data:
                logger.warning(f"Cache hit but no database record for IP {ip_str}")
                await self._update_database_record(cache_data)
                return cache_data
            elif db_data and not cache_data:
                await self._update_cache_record(db_data)
                return db_data
            else:
                return None
    
    async def _get_cache_data(self, ip_address: IPAddress) -> Optional[ThreatData]:
        """Get threat data from cache."""
        try:
            cache_dict = await self.cache.get(str(ip_address))
            if cache_dict:
                return self._cache_dict_to_threat_data(ip_address, cache_dict)
            return None
        except Exception as e:
            logger.error(f"Error getting cache data for IP {ip_address}: {e}")
            return None
    
    async def _get_database_data(self, ip_address: IPAddress) -> Optional[ThreatData]:
        """Get threat data from database."""
        try:
            db_dict = await self.database.find_by_ip(str(ip_address))
            if db_dict:
                return self._db_dict_to_threat_data(ip_address, db_dict)
            return None
        except Exception as e:
            logger.error(f"Error getting database data for IP {ip_address}: {e}")
            return None
    
    async def _reconcile_data(
        self, 
        cache_data: ThreatData, 
        db_data: ThreatData, 
        ip_address: IPAddress
    ) -> ThreatData:
        """
        Reconcile differences between cache and database data.
        Database is considered source of truth.
        """
        if (cache_data.last_fetched == db_data.last_fetched and 
            cache_data.threat_score == db_data.threat_score and
            cache_data.threat_level == db_data.threat_level):
            return cache_data
        
        logger.info(f"Data inconsistency detected for IP {ip_address}, using database as source of truth")
        
        await self._update_cache_record(db_data)
        return db_data
    
    def _cache_dict_to_threat_data(self, ip_address: IPAddress, cache_dict: Dict[str, Any]) -> ThreatData:
        """Convert cache dictionary to ThreatData object."""
        return ThreatData(
            ip_address=ip_address,
            log_id=cache_dict.get('log_id', ''),
            threat_score=gtic_threat_score.normalize_cached_score(cache_dict.get('threat_score', 0)),
            threat_level=cache_dict.get('threat_level', 0),
            threat_categories=cache_dict.get('threat_categories', ''),
            source_name=cache_dict.get('source_name', ''),
            country_code=cache_dict.get('country_code'),
            total_reports=cache_dict.get('total_reports', 0),
            first_seen=datetime.fromisoformat(cache_dict['first_seen']) if cache_dict.get('first_seen') else None,
            last_fetched=datetime.fromisoformat(cache_dict['last_fetched']) if cache_dict.get('last_fetched') else None,
            expires_at=datetime.fromisoformat(cache_dict['expires_at']) if cache_dict.get('expires_at') else None,
            raw_data=cache_dict.get('raw_data'),
            from_redis=True
        )
    
    def _db_dict_to_threat_data(self, ip_address: IPAddress, db_dict: Dict[str, Any]) -> ThreatData:
        """Convert database dictionary to ThreatData object."""
        return ThreatData(
            ip_address=ip_address,
            log_id=db_dict.get('log_id', ''),
            threat_score=gtic_threat_score.normalize_cached_score(db_dict.get('threat_score', 0)),
            threat_level=db_dict.get('threat_level', 0),
            threat_categories=db_dict.get('threat_categories', ''),
            source_name=db_dict.get('source_name', ''),
            country_code=db_dict.get('country_code'),
            total_reports=db_dict.get('total_reports', 0),
            first_seen=db_dict.get('first_seen'),
            last_fetched=db_dict.get('last_fetched'),
            expires_at=db_dict.get('expires_at'),
            raw_data=db_dict.get('raw_data'),
            from_db=True
        )
    
    async def cleanup(self) -> None:
        """Cleanup resources."""
        logger.info("Starting ConsistencyManager cleanup...")
        async with self._locks_lock:
            remaining_ips = list(self._ip_locks.keys())
            
            for ip in remaining_ips:
                try:
                    await self._cleanup_lock(ip)
                except Exception as e:
                    logger.error(f"Error cleaning up lock for IP {ip}: {e}")
            
            self._ip_locks.clear()
        logger.info("ConsistencyManager cleanup completed")