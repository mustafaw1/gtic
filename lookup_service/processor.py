"""
Main IP processor that orchestrates threat intelligence workflow.
This is the orchestrator that coordinates between cache, database, and threat providers.
"""

import asyncio
import gc
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Tuple
import ipaddress
from app.services.utils import gtic_threat_score
from .interfaces.cache import CacheInterface
from .interfaces.database import DatabaseRepositoryInterface
from .interfaces.providers import ThreatProviderInterface
from .models.threat_data import IPAddress, ThreatData, ProcessingResult
from .consistency import ConsistencyManager
from .resource_manager import get_resource_manager, ResourceType
from .resource_contexts import resource_contexts
from .metrics import metrics_collector
from .config import get_settings

logger = logging.getLogger(__name__)

NEGATIVE = 0
MODERATE = 1
HIGH = 2
CRITICAL = 3


class IPProcessor:
    """
    Main orchestrator for IP threat intelligence processing.
    
    Coordinates workflow between cache, database, and external providers.
    """
    
    def __init__(
        self,
        cache: CacheInterface,
        database: DatabaseRepositoryInterface,
        providers: List[ThreatProviderInterface],
        max_workers: int = 20,
        abuseipdb_limit: int = 50000
    ):
        self.settings = get_settings()
        self.cache = cache
        self.database = database
        self.providers = {provider.get_provider_name(): provider for provider in providers}
        self.max_workers = max_workers
        self.abuseipdb_limit = abuseipdb_limit

        self.consistency_manager = ConsistencyManager(cache, database)
        self._resource_manager = get_resource_manager()
        
        self._batch_rate_limited = False
        self.chunk_size = getattr(self.settings, 'batch_processing_chunk_size', 2000)
        
        self.stats = {
            'processed_count': 0,
            'error_count': 0,
            'skipped_private_count': 0,
            'cache_hits': 0,
            'db_hits': 0,
            'external_api_calls': 0
        }
    
    async def start(self) -> None:
        """Initialize the IP processor and start resource manager."""
        logger.info("Starting IP Processor...")
        await self._resource_manager.start()
        logger.info("IP Processor started successfully")
    
    async def process_ips(self, ip_entries: List[Dict[str, str]]) -> ProcessingResult:
        """
        Main entry point for processing IP addresses using batch Redis operations.
        
        Args:
            ip_entries: List of dicts with 'ip_address' and 'log_id'
            
        Returns:
            ProcessingResult with cached IPs, not found IPs, and statistics
        """
        if not ip_entries:
            return ProcessingResult()
        
        logger.info(f"Processing {len(ip_entries)} IP addresses in chunks of {self.chunk_size}")
        
        self._reset_stats()
        self._batch_rate_limited = False
        overall_result = ProcessingResult()
        
        for chunk_start in range(0, len(ip_entries), self.chunk_size):
            chunk_end = min(chunk_start + self.chunk_size, len(ip_entries))
            chunk = ip_entries[chunk_start:chunk_end]
            
            logger.debug(f"Processing chunk {chunk_start}-{chunk_end} ({len(chunk)} IPs)")
            
            chunk_result = await self._process_chunk(chunk)
            
            overall_result.cached_ips.extend(chunk_result.cached_ips)
            overall_result.not_found_ips.extend(chunk_result.not_found_ips)
            overall_result.errors.extend(chunk_result.errors)
            overall_result.redis_hits += chunk_result.redis_hits
            overall_result.postgresql_hits += chunk_result.postgresql_hits
            overall_result.external_api_calls += chunk_result.external_api_calls
            
            del chunk
            del chunk_result
            
            # Trigger garbage collection every 5 chunks to manage memory
            if (chunk_start // self.chunk_size) % 5 == 0:
                gc.collect()
                logger.debug(f"Memory cleanup performed at chunk {chunk_start // self.chunk_size}")
            
            if chunk_end < len(ip_entries):
                await asyncio.sleep(0.05)
        
        logger.info(
            f"Processing complete. "
            f"Cached: {len(overall_result.cached_ips)}, "
            f"Not found: {len(overall_result.not_found_ips)}, "
            f"Redis hits: {overall_result.redis_hits}, "
            f"DB hits: {overall_result.postgresql_hits}, "
            f"API calls: {overall_result.external_api_calls}"
        )
        
        return overall_result

    async def _process_chunk(self, ip_entries: List[Dict[str, str]]) -> ProcessingResult:
        """Process a chunk of IP addresses using the original logic"""
        result = ProcessingResult()
        valid_entries = []
        cache_keys = []
        
        for entry in ip_entries:
            ip_str = entry.get('ip_address', '').strip()
            log_id = entry.get('log_id', '').strip()
            
            if not ip_str or not log_id:
                logger.warning(f"Missing ip_address or log_id in entry: {entry}")
                continue
                
            try:
                ip_address = IPAddress(ip_str)
                if self._should_skip_ip(ip_address):
                    self.stats['skipped_private_count'] += 1
                    logger.debug(f"Skipped private IP: {ip_str}")
                    continue
                    
                valid_entries.append({
                    'ip_address': ip_str,
                    'log_id': log_id,
                    'ip_obj': ip_address
                })
                cache_keys.append(ip_str)
                
            except ValueError as e:
                logger.warning(f"Invalid IP address {ip_str}: {e}")
                continue

        if not valid_entries:
            return result

        logger.info(f"Batch checking {len(cache_keys)} IPs in Redis cache")
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
                    threat_data = self._cache_dict_to_threat_data(cached_item, entry['ip_obj'])
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
                            logger.debug(f"Data expired for {entry['ip_address']}, refreshing without API call")
                            threat_data.last_fetched = datetime.now(timezone.utc)
                            threat_data.expires_at = self._calculate_expiry_time(
                                threat_data.threat_level, 
                                threat_data.threat_categories
                            )
                            cache_hits.append(threat_data)
                            self.stats['cache_hits'] += 1
                        continue
                except Exception as e:
                    logger.error(f"Error converting cached data for {entry['ip_address']}: {e}")
            
            cache_misses.append(entry)

        logger.info(f"Redis batch results: {len(cache_hits)} hits, {len(cache_misses)} misses")
        
        result.cached_ips.extend(cache_hits)

        if cache_misses:
            async with resource_contexts.concurrent_operations(
                max_concurrency=self.max_workers,
                operation_name="ip_processing_misses",
                metadata={"total_ips": len(cache_misses)}
            ) as semaphore:
                
                async def process_cache_miss(entry: Dict[str, Any], index: int) -> Optional[ThreatData]:
                    async with semaphore:
                        return await self._process_cache_miss(entry, index, len(cache_misses))

                tasks = [
                    process_cache_miss(entry, i) 
                    for i, entry in enumerate(cache_misses)
                ]

                miss_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for i, res in enumerate(miss_results):
                    if isinstance(res, Exception):
                        logger.error(f"Error processing IP miss at index {i}: {res}")
                        result.add_error(str(res))
                        self.stats['error_count'] += 1
                        continue
                    
                    if res is None:
                        miss_entry = cache_misses[i]
                        result.not_found_ips.append({
                            'ip_address': miss_entry['ip_address'],
                            'log_id': miss_entry['log_id']
                        })
                        continue

                    result.cached_ips.append(res)

        result.redis_hits = self.stats['cache_hits']
        result.postgresql_hits = self.stats['db_hits'] 
        result.external_api_calls = self.stats['external_api_calls']
        
        return result
    
    async def _process_single_ip(
        self, 
        entry: Dict[str, str], 
        index: int, 
        total_count: int
    ) -> Optional[ThreatData]:
        """Process a single IP address through the workflow."""
        ip_str = entry.get('ip_address', '').strip()
        log_id = entry.get('log_id', '').strip()
        
        if not ip_str or not log_id:
            logger.warning(f"Missing ip_address or log_id in entry: {entry}")
            return None
        
        try:
            ip_address = IPAddress(ip_str)

            if self._should_skip_ip(ip_address):
                self.stats['skipped_private_count'] += 1
                logger.debug(f"Skipped private IP: {ip_str}")
                return None
            
            existing_result = await self.consistency_manager.get_threat_data_consistently(ip_address)
            if existing_result:
                existing_result.log_id = log_id

                if existing_result.from_redis:
                    self.stats['cache_hits'] += 1
                elif existing_result.from_db:
                    self.stats['db_hits'] += 1

                if not existing_result.is_expired:
                    existing_result.last_fetched = datetime.now(timezone.utc)
                    existing_result.expires_at = self._calculate_expiry_time(
                        existing_result.threat_level, 
                        existing_result.threat_categories
                    )

                    try:
                        cache_dict = existing_result.to_dict()
                        await self.cache.set(str(ip_address), cache_dict, 3600)
                    except:
                        pass
                    
                    return existing_result
                else:
                    logger.debug(f"Data expired for {ip_str}, refreshing without API call")

                    existing_result.last_fetched = datetime.now(timezone.utc)
                    existing_result.expires_at = self._calculate_expiry_time(
                        existing_result.threat_level, 
                        existing_result.threat_categories
                    )

                    await self.consistency_manager.update_threat_data_consistently(
                        existing_result,
                        update_database=True, 
                        update_cache=True
                    )
                    
                    return existing_result
            
            api_result = await self._query_providers(ip_address, index, total_count)
            if api_result:
                api_result.log_id = log_id
                self.stats['external_api_calls'] += 1

                if api_result.expires_at is None:
                    api_result.expires_at = self._calculate_expiry_time(
                        api_result.threat_level,
                        api_result.threat_categories
                    )

                try:
                    if api_result.threat_score > 0 or api_result.total_reports > 0:
                        db_dict = api_result.to_db_dict()
                        await self.database.save(db_dict)
                    cache_dict = api_result.to_dict()
                    await self.cache.set(str(ip_address), cache_dict, 3600)
                except Exception as save_error:
                    logger.error(f"Failed to save API result for {ip_address.value}: {save_error}")
                return api_result

            logger.debug(f"No threat data found for IP: {ip_str}")
            return None
            
        except ValueError as e:
            logger.warning(f"Invalid IP address {ip_str}: {e}")
            return None
        except Exception as e:
            logger.error(f"Error processing IP {ip_str}: {e}")
            self.stats['error_count'] += 1
            return None
    
    def _should_skip_ip(self, ip_address: IPAddress) -> bool:
        """Check if IP should be skipped (private ranges, etc.)"""
        if not ip_address.is_private:
            return False

        ip_obj = ip_address.ip_obj
        
        if ip_obj.version == 4:
            private_ranges = [
                ipaddress.IPv4Network('10.0.0.0/8'),
                ipaddress.IPv4Network('172.16.0.0/12'),
                ipaddress.IPv4Network('192.168.0.0/16')
            ]
            return any(ip_obj in network for network in private_ranges)
        
        elif ip_obj.version == 6:
            return ip_obj in ipaddress.IPv6Network('fc00::/7')
        
        return False
    
    async def _check_cache(self, ip_address: IPAddress) -> Optional[ThreatData]:
        """Check Redis cache for IP data"""
        try:
            cache_data = await self.cache.get(str(ip_address))
            if cache_data:
                threat_data = self._cache_data_to_threat_data(ip_address, cache_data)
                threat_data.from_redis = True
                logger.debug(f"Cache hit for IP: {ip_address}")
                return threat_data
            
            return None
            
        except Exception as e:
            logger.error(f"Error checking cache for IP {ip_address}: {e}")
            return None
    
    async def _check_database(self, ip_address: IPAddress) -> Optional[ThreatData]:
        """Check database for IP data"""
        try:
            db_data = await self.database.find_by_ip(str(ip_address))
            if db_data:
                # Convert database data to ThreatData object
                threat_data = self._db_data_to_threat_data(ip_address, db_data)
                threat_data.from_db = True
                logger.debug(f"Database hit for IP: {ip_address}")
                return threat_data
            
            return None
            
        except Exception as e:
            logger.error(f"Error checking database for IP {ip_address}: {e}")
            return None
    
    async def _query_providers(
        self, 
        ip_address: IPAddress, 
        index: int, 
        total_count: int
    ) -> Optional[ThreatData]:
        """Query external threat intelligence providers with rate limit handling"""
        try:
            if self._batch_rate_limited:
                logger.debug(f"Batch rate limited, skipping API call for IP {ip_address}")
                return None

            # Select provider based on configuration
            provider_name = self._select_provider(index, total_count)
            provider = self.providers.get(provider_name)
            
            if not provider:
                logger.error(f"Provider {provider_name} not available")
                return None

            result = await provider.query_ip(str(ip_address))
            if result:
                # Convert provider result to ThreatData
                threat_data = self._provider_result_to_threat_data(ip_address, result)
                threat_data.from_api = True
                logger.debug(f"API hit for IP {ip_address} from {provider_name}")
                return threat_data
            
            # Try backup provider if primary fails
            backup_provider = self._get_backup_provider(provider_name)
            if backup_provider and backup_provider != provider:
                result = await backup_provider.query_ip(str(ip_address))
                if result:
                    threat_data = self._provider_result_to_threat_data(ip_address, result)
                    threat_data.from_api = True
                    logger.debug(f"Backup API hit for IP {ip_address} from {backup_provider.get_provider_name()}")
                    return threat_data
            
            return None
            
        except Exception as e:
            logger.error(f"Error querying providers for IP {ip_address}: {e}")
            return None
    
    def _select_provider(self, index: int, total_count: int) -> str:
        """Select threat intelligence provider based on index"""
        # Use AbuseIPDB for first N requests, then VirusTotal
        if index < self.abuseipdb_limit and "AbusedIPDB" in self.providers:
            return "AbusedIPDB"
        elif "VirusTotal" in self.providers:
            return "VirusTotal"
        else:
            return next(iter(self.providers.keys()), "")
    
    def _get_backup_provider(self, primary_provider: str) -> Optional[ThreatProviderInterface]:
        """Get backup provider if primary fails"""
        if primary_provider == "AbusedIPDB" and "VirusTotal" in self.providers:
            return self.providers["VirusTotal"]
        elif primary_provider == "VirusTotal" and "AbusedIPDB" in self.providers:
            return self.providers["AbusedIPDB"]
        return None

    def set_batch_rate_limited(self, provider_name: str, ip_address: str) -> None:
        """Callback for providers to set batch rate limit flag"""
        if not self._batch_rate_limited:
            self._batch_rate_limited = True
    
    async def _update_cache(self, threat_data: ThreatData) -> None:
        """Update Redis cache with threat data"""
        try:
            if not threat_data.expires_at:
                # Calculate expiry time
                threat_data.expires_at = self._calculate_expiry_time(
                    threat_data.threat_level,
                    threat_data.threat_categories
                )
            
            # Calculate TTL in seconds
            ttl = int((threat_data.expires_at - datetime.now(timezone.utc)).total_seconds())
            ttl = max(1, ttl)
            
            cache_data = threat_data.to_dict()
            await self.cache.set(str(threat_data.ip_address), cache_data, ttl)
            
            logger.debug(f"Updated cache for IP {threat_data.ip_address} with TTL {ttl}s")
            
        except Exception as e:
            logger.error(f"Error updating cache for IP {threat_data.ip_address}: {e}")
    
    def _calculate_expiry_time(self, threat_level: int, categories: str = "") -> datetime:
        """Calculate expiry time based on threat level and categories"""
        now = datetime.now(timezone.utc)
        
        # Category-based expiry (overrides level-based)
        if categories:
            category_list = categories.lower().split(",")
            if "hacking" in category_list or "malware" in category_list:
                return now + timedelta(days=30)
            if "ddos attack" in category_list:
                return now + timedelta(hours=12)
            if "ssh" in category_list or "brute-force" in category_list:
                return now + timedelta(days=7)
        
        # Level-based expiry
        if threat_level == NEGATIVE:
            return now + timedelta(hours=1)
        elif threat_level == MODERATE:
            return now + timedelta(days=3)
        elif threat_level == HIGH:
            return now + timedelta(days=7)
        elif threat_level == CRITICAL:
            return now + timedelta(days=30)
        else:
            return now + timedelta(hours=1)
    
    def _cache_data_to_threat_data(self, ip_address: IPAddress, cache_data: Dict[str, Any]) -> ThreatData:
        """Convert cache data to ThreatData object"""
        return ThreatData(
            ip_address=ip_address,
            log_id="",
            threat_score=gtic_threat_score.normalize_cached_score(cache_data.get('threat_score', 0)),
            threat_level=cache_data.get('threat_level', 0),
            threat_categories=self._normalize_threat_categories(cache_data.get('threat_categories', '')),
            source_name=cache_data.get('source_name', ''),
            country_code=cache_data.get('country_code'),
            total_reports=cache_data.get('total_reports', 0),
            first_seen=datetime.fromisoformat(cache_data['first_seen']) if cache_data.get('first_seen') else None,
            last_fetched=datetime.fromisoformat(cache_data['last_fetched']) if cache_data.get('last_fetched') else None,
            expires_at=datetime.fromisoformat(cache_data['expires_at']) if cache_data.get('expires_at') else None,
            raw_data=cache_data.get('raw_data')
        )
    
    def _db_data_to_threat_data(self, ip_address: IPAddress, db_data: Dict[str, Any]) -> ThreatData:
        """Convert database data to ThreatData object"""
        return ThreatData(
            ip_address=ip_address,
            log_id="",
            threat_score=gtic_threat_score.normalize_cached_score(db_data.get('threat_score', 0)),
            threat_level=db_data.get('threat_level', 0),
            threat_categories=self._normalize_threat_categories(db_data.get('threat_categories', '')),
            source_name=db_data.get('source_name', ''),
            country_code=db_data.get('country_code'),
            total_reports=db_data.get('total_reports', 0),
            first_seen=db_data.get('first_seen'),
            last_fetched=db_data.get('last_fetched'),
            expires_at=db_data.get('expires_at'),
            raw_data=db_data.get('raw_data')
        )
    
    def _provider_result_to_threat_data(self, ip_address: IPAddress, provider_result) -> ThreatData:
        """Convert provider result to ThreatData object"""
        return ThreatData(
            ip_address=ip_address,
            log_id="",
            threat_score=provider_result.threat_score,
            threat_level=provider_result.threat_level,
            threat_categories=self._normalize_threat_categories(provider_result.threat_categories),
            source_name=provider_result.source_name,
            country_code=provider_result.country_code,
            total_reports=provider_result.total_reports,
            first_seen=provider_result.fetched_at,
            last_fetched=provider_result.fetched_at,
            expires_at=None,
            raw_data=provider_result.raw_data
        )

    def _normalize_threat_categories(self, categories: str) -> str:
        """Normalize threat categories by removing duplicates and sorting"""
        if not categories or not categories.strip():
            return ""

        category_list = [cat.strip() for cat in categories.split(",") if cat.strip()]
        unique_categories = sorted(list(set(category_list)))
        
        return ", ".join(unique_categories)

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
            "ip_locks": {
                "active_count": len(self.consistency_manager._ip_locks),
                "lock_ids": list(self.consistency_manager._ip_locks.keys())
            },
            "health": self.get_health_score()
        }
    
    async def close(self) -> None:
        """Close all connections"""
        logger.info("Closing IP processor connections")
        
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
        
        logger.info("IP processor connections closed")
    
    def _cache_dict_to_threat_data(self, cache_dict: Dict[str, Any], ip_address: IPAddress) -> Optional[ThreatData]:
        """Convert cache dictionary to ThreatData object."""
        try:
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
        except Exception as e:
            logger.error(f"Error converting cache dict to ThreatData: {e}")
            return None
    
    async def _process_cache_miss(
        self, 
        entry: Dict[str, Any], 
        index: int, 
        total_count: int
    ) -> Optional[ThreatData]:
        """Process cache miss by checking database and external APIs."""
        ip_address = entry['ip_obj']
        log_id = entry['log_id']
        
        try:
            db_dict = await self.database.find_by_ip(str(ip_address))
            existing_result = None
            if db_dict:
                existing_result = self._db_dict_to_threat_data(ip_address, db_dict)
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
                        await self.cache.set(str(ip_address), cache_dict, 3600)
                    except:
                        pass
                    
                    return existing_result
                else:
                    logger.debug(f"Data expired for {ip_address.value}, refreshing without API call")
                    existing_result.last_fetched = datetime.now(timezone.utc)
                    existing_result.expires_at = self._calculate_expiry_time(
                        existing_result.threat_level, 
                        existing_result.threat_categories
                    )

                    await self.consistency_manager.update_threat_data_consistently(
                        existing_result,
                        update_database=True, 
                        update_cache=True
                    )
                    
                    return existing_result
            
            api_result = await self._query_providers(ip_address, index, total_count)
            if api_result:
                api_result.log_id = log_id
                self.stats['external_api_calls'] += 1

                if api_result.expires_at is None:
                    api_result.expires_at = self._calculate_expiry_time(
                        api_result.threat_level,
                        api_result.threat_categories
                    )

                try:
                    if api_result.threat_score > 0 or api_result.total_reports > 0:
                        db_dict = api_result.to_db_dict()
                        await self.database.save(db_dict)
                    cache_dict = api_result.to_dict()
                    await self.cache.set(str(ip_address), cache_dict, 3600)
                except Exception as save_error:
                    logger.error(f"Failed to save API result for {ip_address.value}: {save_error}")
                return api_result

            logger.debug(f"No threat data found for IP: {ip_address.value}")
            return None
            
        except Exception as e:
            logger.error(f"Error processing cache miss for IP {ip_address.value}: {e}")
            self.stats['error_count'] += 1
            return None
    
    def _db_dict_to_threat_data(self, ip_address: IPAddress, db_dict: Dict[str, Any]) -> Optional[ThreatData]:
        """Convert database dictionary to ThreatData object."""
        try:
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
        except Exception as e:
            logger.error(f"Error converting DB dict to ThreatData: {e}")
            return None