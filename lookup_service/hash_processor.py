"""
Hash processor that orchestrates file hash threat intelligence workflow.
This is the orchestrator that coordinates between cache, database, and threat providers for hashes.
"""

import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from app.services.utils import gtic_threat_score
from .interfaces.cache import CacheInterface
from .interfaces.database import DatabaseRepositoryInterface
from .interfaces.providers import ThreatProviderInterface
from .models.threat_data import HashValue, HashThreatData, HashProcessingResult
from .consistency import ConsistencyManager
from .resource_manager import get_resource_manager, ResourceType
from .resource_contexts import resource_contexts
from .metrics import metrics_collector

logger = logging.getLogger(__name__)

NEGATIVE = 0
MODERATE = 1
HIGH = 2
CRITICAL = 3


class HashProcessor:
    """
    Main orchestrator for file hash threat intelligence processing.
    Coordinates workflow between cache, database, and external providers.
    """
    
    def __init__(
        self,
        cache: CacheInterface,
        database: DatabaseRepositoryInterface,
        providers: List[ThreatProviderInterface],
        max_workers: int = 20
    ):
        self.cache = cache
        self.database = database
        self.providers = {provider.get_provider_name(): provider for provider in providers}
        self.max_workers = max_workers

        self.consistency_manager = ConsistencyManager(cache, database)
        self._resource_manager = get_resource_manager()
        
        self._batch_rate_limited = False
        
        self.stats = {
            'processed_count': 0,
            'error_count': 0,
            'skipped_invalid_count': 0,
            'cache_hits': 0,
            'db_hits': 0,
            'external_api_calls': 0
        }
    
    async def start(self) -> None:
        """Initialize the hash processor and start resource manager."""
        logger.info("Starting Hash Processor...")
        await self._resource_manager.start()
        logger.info("Hash Processor started successfully")
    
    async def process_hashes(self, hash_entries: List[Dict[str, str]]) -> HashProcessingResult:
        """
        Main entry point for processing file hashes using batch Redis operations.
        
        Args:
            hash_entries: List of dicts with 'hash_value', 'hash_type', and 'log_id'
            
        Returns:
            HashProcessingResult with cached hashes, not found hashes, and statistics
        """
        if not hash_entries:
            return HashProcessingResult()
        
        logger.info(f"Processing {len(hash_entries)} file hashes")
        
        self._reset_stats()
        self._batch_rate_limited = False
        result = HashProcessingResult()
        valid_entries = []
        cache_keys = []
        
        for entry in hash_entries:
            hash_str = entry.get('hash_value', '').strip()
            hash_type = entry.get('hash_type', 'sha256').strip()
            log_id = entry.get('log_id', '').strip()
            
            if not hash_str or not log_id:
                logger.warning(f"Missing hash_value or log_id in entry: {entry}")
                continue
                
            try:
                hash_value = HashValue(hash_str, hash_type)
                
                valid_entries.append({
                    'hash_value': hash_str,
                    'hash_type': hash_type,
                    'log_id': log_id,
                    'hash_obj': hash_value
                })
                cache_keys.append(f"{hash_type}:{hash_str}")
                
            except ValueError as e:
                logger.warning(f"Invalid hash {hash_str}: {e}")
                self.stats['skipped_invalid_count'] += 1
                continue

        if not valid_entries:
            return result

        logger.info(f"Batch checking {len(cache_keys)} hashes in Redis cache")
        try:
            cached_data = await self.cache.mget(cache_keys)
        except Exception as e:
            logger.warning(f"Redis batch operation failed: {e}, skipping Redis cache")
            cached_data = [None] * len(cache_keys)
        
        cache_hits = []
        cache_misses = []
        
        for i, (entry, cached_item) in enumerate(zip(valid_entries, cached_data)):
            if cached_item:
                try:
                    threat_data = self._cache_dict_to_threat_data(cached_item, entry['hash_obj'])
                    if threat_data:
                        threat_data.log_id = entry['log_id']
                        threat_data.from_redis = True
                        
                        if not threat_data.is_expired:
                            threat_data.last_fetched = datetime.now(timezone.utc)
                            threat_data.expires_at = self._calculate_expiry_time(
                                threat_data.threat_level, 
                                threat_data.threat_categories
                            )
                            cache_hits.append(threat_data)
                            self.stats['cache_hits'] += 1
                        else:
                            logger.debug(f"Data expired for {entry['hash_value']}, refreshing without API call")
                            threat_data.last_fetched = datetime.now(timezone.utc)
                            threat_data.expires_at = self._calculate_expiry_time(
                                threat_data.threat_level, 
                                threat_data.threat_categories
                            )
                            cache_hits.append(threat_data)
                            self.stats['cache_hits'] += 1
                        continue
                except Exception as e:
                    logger.error(f"Error converting cached data for {entry['hash_value']}: {e}")
            
            cache_misses.append(entry)

        logger.info(f"Redis batch results: {len(cache_hits)} hits, {len(cache_misses)} misses")
        
        result.cached_hashes.extend(cache_hits)

        if cache_misses:
            async with resource_contexts.concurrent_operations(
                max_concurrency=self.max_workers,
                operation_name="hash_processing_misses",
                metadata={"total_hashes": len(cache_misses)}
            ) as semaphore:
                
                async def process_cache_miss(entry: Dict[str, Any], index: int) -> Optional[HashThreatData]:
                    async with semaphore:
                        return await self._process_cache_miss(entry, index, len(cache_misses))

                tasks = [
                    process_cache_miss(entry, i) 
                    for i, entry in enumerate(cache_misses)
                ]

                miss_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for i, res in enumerate(miss_results):
                    if isinstance(res, Exception):
                        logger.error(f"Error processing hash miss at index {i}: {res}")
                        result.add_error(str(res))
                        self.stats['error_count'] += 1
                        continue
                    
                    if res is None:
                        miss_entry = cache_misses[i]
                        result.not_found_hashes.append({
                            'hash_value': miss_entry['hash_value'],
                            'hash_type': miss_entry['hash_type'],
                            'log_id': miss_entry['log_id']
                        })
                        continue

                    result.cached_hashes.append(res)

        result.redis_hits = self.stats['cache_hits']
        result.postgresql_hits = self.stats['db_hits'] 
        result.external_api_calls = self.stats['external_api_calls']
        
        logger.info(
            f"Hash processing complete. "
            f"Cached: {len(result.cached_hashes)}, "
            f"Not found: {len(result.not_found_hashes)}, "
            f"Redis hits: {result.redis_hits}, "
            f"DB hits: {result.postgresql_hits}, "
            f"API calls: {result.external_api_calls}"
        )
        
        return result
    
    async def _process_cache_miss(
        self, 
        entry: Dict[str, Any], 
        index: int, 
        total_count: int
    ) -> Optional[HashThreatData]:
        """Process cache miss by checking database and external APIs."""
        hash_value = entry['hash_obj']
        log_id = entry['log_id']
        
        try:
            db_dict = await self.database.find_by_hash(str(hash_value), hash_value.hash_type)
            existing_result = None
            if db_dict:
                existing_result = self._db_dict_to_threat_data(hash_value, db_dict)
                if existing_result:
                    existing_result.from_db = True
            
            if existing_result:
                existing_result.log_id = log_id

                if existing_result.from_db:
                    self.stats['db_hits'] += 1

                if not existing_result.is_expired:
                    existing_result.last_fetched = datetime.now(timezone.utc)
                    existing_result.expires_at = self._calculate_expiry_time(
                        existing_result.threat_level, 
                        existing_result.threat_categories
                    )

                    try:
                        cache_dict = existing_result.to_dict()
                        cache_key = f"{hash_value.hash_type}:{str(hash_value)}"
                        await self.cache.set(cache_key, cache_dict, 86400)  # 24 hours
                    except:
                        pass
                    
                    return existing_result
                else:
                    logger.debug(f"Data expired for {hash_value.value}, refreshing without API call")
                    existing_result.last_fetched = datetime.now(timezone.utc)
                    existing_result.expires_at = self._calculate_expiry_time(
                        existing_result.threat_level, 
                        existing_result.threat_categories
                    )
                    
                    try:
                        db_dict = existing_result.to_db_dict()
                        await self.database.save(db_dict)
                        cache_dict = existing_result.to_dict()
                        cache_key = f"{hash_value.hash_type}:{str(hash_value)}"
                        await self.cache.set(cache_key, cache_dict, 86400)
                    except Exception as e:
                        logger.error(f"Failed to update hash data: {e}")
                    
                    return existing_result
            
            # api_result = await self._query_providers(hash_value, index, total_count)
            # if api_result:
            #     api_result.log_id = log_id
            #     self.stats['external_api_calls'] += 1

            #     if api_result.expires_at is None:
            #         api_result.expires_at = self._calculate_expiry_time(
            #             api_result.threat_level,
            #             api_result.threat_categories
            #         )

            #     try:
            #         db_dict = api_result.to_db_dict()
            #         await self.database.save(db_dict)
            #         cache_dict = api_result.to_dict()
            #         cache_key = f"{hash_value.hash_type}:{str(hash_value)}"
            #         await self.cache.set(cache_key, cache_dict, 86400)
            #     except Exception as save_error:
            #         logger.error(f"Failed to save API result for {hash_value.value}: {save_error}")
            #     return api_result
            
            logger.debug(f"No threat data found for hash: {hash_value.value}")
            return None
            
        except Exception as e:
            logger.error(f"Error processing cache miss for hash {hash_value.value}: {e}")
            self.stats['error_count'] += 1
            return None
    
    async def _query_providers(
        self, 
        hash_value: HashValue, 
        index: int, 
        total_count: int
    ) -> Optional[HashThreatData]:
        """Query external threat intelligence providers for hash data"""
        try:
            if self._batch_rate_limited:
                logger.debug(f"Batch rate limited, skipping API call for hash {hash_value}")
                return None

            provider_name = "VirusTotal"
            provider = self.providers.get(provider_name)
            
            if not provider:
                logger.error(f"Provider {provider_name} not available")
                return None

            result = await provider.query_hash(str(hash_value), hash_value.hash_type)
            if result:
                threat_data = self._provider_result_to_threat_data(hash_value, result)
                threat_data.from_api = True
                logger.debug(f"API hit for hash {hash_value} from {provider_name}")
                return threat_data
            
            return None
            
        except Exception as e:
            logger.error(f"Error querying providers for hash {hash_value}: {e}")
            return None
    
    def _calculate_expiry_time(self, threat_level: int, categories: str = "") -> datetime:
        """Calculate expiry time based on threat level and categories"""
        now = datetime.now(timezone.utc)
        
        if categories:
            category_list = categories.lower().split(",")
            if "malware" in category_list or "trojan" in category_list:
                return now + timedelta(days=90)
            if "ransomware" in category_list:
                return now + timedelta(days=180)
        
        if threat_level == NEGATIVE:
            return now + timedelta(days=7)
        elif threat_level == MODERATE:
            return now + timedelta(days=30)
        elif threat_level == HIGH:
            return now + timedelta(days=60)
        elif threat_level == CRITICAL:
            return now + timedelta(days=90)
        else:
            return now + timedelta(days=7)
    
    def _cache_dict_to_threat_data(self, cache_dict: Dict[str, Any], hash_value: HashValue) -> Optional[HashThreatData]:
        """Convert cache dictionary to HashThreatData object."""
        try:
            return HashThreatData(
                hash_value=hash_value,
                log_id=cache_dict.get('log_id', ''),
                threat_score=gtic_threat_score.normalize_cached_score(cache_dict.get('threat_score', 0)),
                threat_level=cache_dict.get('threat_level', 0),
                threat_categories=cache_dict.get('threat_categories', ''),
                source_name=cache_dict.get('source_name', ''),
                total_reports=cache_dict.get('total_reports', 0),
                first_seen=datetime.fromisoformat(cache_dict['first_seen']) if cache_dict.get('first_seen') else None,
                last_fetched=datetime.fromisoformat(cache_dict['last_fetched']) if cache_dict.get('last_fetched') else None,
                expires_at=datetime.fromisoformat(cache_dict['expires_at']) if cache_dict.get('expires_at') else None,
                raw_data=cache_dict.get('raw_data'),
                from_redis=True
            )
        except Exception as e:
            logger.error(f"Error converting cache dict to HashThreatData: {e}")
            return None
    
    def _db_dict_to_threat_data(self, hash_value: HashValue, db_dict: Dict[str, Any]) -> Optional[HashThreatData]:
        """Convert database dictionary to HashThreatData object."""
        try:
            return HashThreatData(
                hash_value=hash_value,
                log_id=db_dict.get('log_id', ''),
                threat_score=gtic_threat_score.normalize_cached_score(db_dict.get('threat_score', 0)),
                threat_level=db_dict.get('threat_level', 0),
                threat_categories=db_dict.get('threat_categories', ''),
                source_name=db_dict.get('source_name', ''),
                total_reports=db_dict.get('total_reports', 0),
                first_seen=db_dict.get('first_seen'),
                last_fetched=db_dict.get('last_fetched'),
                expires_at=db_dict.get('expires_at'),
                raw_data=db_dict.get('raw_data'),
                from_db=True
            )
        except Exception as e:
            logger.error(f"Error converting DB dict to HashThreatData: {e}")
            return None
    
    def _provider_result_to_threat_data(self, hash_value: HashValue, provider_result) -> HashThreatData:
        """Convert provider result to HashThreatData object"""
        return HashThreatData(
            hash_value=hash_value,
            log_id="",
            threat_score=provider_result.threat_score,
            threat_level=provider_result.threat_level,
            threat_categories=provider_result.threat_categories,
            source_name=provider_result.source_name,
            total_reports=provider_result.total_reports,
            first_seen=provider_result.fetched_at,
            last_fetched=provider_result.fetched_at,
            expires_at=None,
            raw_data=provider_result.raw_data
        )

    def set_batch_rate_limited(self, provider_name: str, hash_value: str) -> None:
        """Callback for providers to set batch rate limit flag"""
        if not self._batch_rate_limited:
            self._batch_rate_limited = True
            logger.warning(f"Batch rate limited by {provider_name} for hash {hash_value}")
    
    def _reset_stats(self) -> None:
        """Reset processing statistics"""
        for key in self.stats:
            self.stats[key] = 0
    
    async def health_check(self) -> Dict[str, bool]:
        """Check health of all components"""
        health_status = {}
        
        try:
            health_status['cache'] = await self.cache.health_check()
        except Exception:
            health_status['cache'] = False
        
        try:
            health_status['database'] = await self.database.health_check()
        except Exception:
            health_status['database'] = False
        
        for name, provider in self.providers.items():
            try:
                health_status[f'provider_{name.lower()}'] = await provider.health_check()
            except Exception:
                health_status[f'provider_{name.lower()}'] = False
        
        return health_status
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get comprehensive metrics from the metrics collector."""
        return metrics_collector.get_comprehensive_metrics(self.stats)
    
    def get_performance_trends(self, minutes: int = 30) -> Dict[str, Any]:
        """Get performance trends over the specified time window."""
        return metrics_collector.get_performance_trends(minutes)
    
    def get_health_score(self) -> Dict[str, Any]:
        """Get system health score and recommendations."""
        return metrics_collector.get_health_score()
    
    def get_detailed_resource_status(self) -> Dict[str, Any]:
        """Get detailed status of all tracked resources."""
        return {
            "tracked_resources": self._resource_manager.get_resource_details(),
            "resource_summary": self._resource_manager.get_metrics(),
            "processor_stats": self.stats.copy(),
            "hash_locks": {
                "active_count": len(self.consistency_manager._ip_locks),
                "lock_ids": list(self.consistency_manager._ip_locks.keys())
            },
            "health": self.get_health_score()
        }
    
    async def close(self) -> None:
        """Close all connections"""
        logger.info("Closing hash processor connections")
        
        try:
            await self.cache.close()
        except Exception as e:
            logger.error(f"Error closing cache: {e}")
        
        try:
            await self.database.close()
        except Exception as e:
            logger.error(f"Error closing database: {e}")
        
        for name, provider in self.providers.items():
            try:
                await provider.close()
            except Exception as e:
                logger.error(f"Error closing provider {name}: {e}")
        
        try:
            await self.consistency_manager.cleanup()
        except Exception as e:
            logger.error(f"Error closing consistency manager: {e}")
        
        try:
            await self._resource_manager.stop()
        except Exception as e:
            logger.error(f"Error stopping resource manager: {e}")
        
        logger.info("Hash processor connections closed")

