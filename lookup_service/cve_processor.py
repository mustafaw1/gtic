"""
Main CVE processor that orchestrates CVE vulnerability workflow.
This orchestrator coordinates between cache, database, and NVD provider.
"""

import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
import json

from .interfaces.cache import CacheInterface
from .interfaces.database import DatabaseRepositoryInterface
from .interfaces.providers import ThreatProviderInterface
from .models.cve_data import CVEData, CVEId, CVEProcessingResult
from .resource_manager import get_resource_manager, ResourceType
from .metrics import metrics_collector

logger = logging.getLogger(__name__)


class CVEProcessor:
    """
    Main orchestrator for CVE vulnerability processing.
    
    Coordinates workflow between cache, database, and external NVD provider.
    Implements 3-tier cache: Redis → PostgreSQL → NVD API
    """
    
    def __init__(
        self,
        cache: CacheInterface,
        database: DatabaseRepositoryInterface,
        provider: Optional[ThreatProviderInterface],
        max_workers: int = 10
    ):
        self.cache = cache
        self.database = database
        self.provider = provider
        self.max_workers = max_workers
        
        self._resource_manager = get_resource_manager()
        
        self.stats = {
            'processed_count': 0,
            'error_count': 0,
            'cache_hits': 0,
            'db_hits': 0,
            'external_api_calls': 0
        }
    
    async def start(self) -> None:
        """Initialize the CVE processor"""
        logger.info("Starting CVE Processor...")
        await self._resource_manager.start()
        logger.info("CVE Processor started successfully")
    
    async def process_cpes(
        self,
        cpe_entries: List[Dict[str, str]],
    ) -> CVEProcessingResult:
        """
        Process CPE strings against the database.

        Args:
            cpe_entries: List of dicts with 'cpe_string' and optional 'log_id'

        Returns:
            CVEProcessingResult with matched CVEs, not found CPEs, and statistics
        """
        if not cpe_entries:
            return CVEProcessingResult()

        logger.debug(f"Processing {len(cpe_entries)} CPE strings")
        self._reset_stats()
        result = CVEProcessingResult()

        valid_entries = []
        for entry in cpe_entries:
            cpe_string = entry.get('cpe_string', '').strip()
            if not cpe_string:
                logger.warning(f"Missing cpe_string in entry: {entry}")
                continue
            valid_entries.append({
                'cpe_string': cpe_string,
                'log_id': entry.get('log_id', '').strip(),
            })

        if not valid_entries:
            return result

        seen_cpes: set = set()
        unique_entries = []
        for e in valid_entries:
            if e['cpe_string'] not in seen_cpes:
                seen_cpes.add(e['cpe_string'])
                unique_entries.append(e)

        cpe_strings = [e['cpe_string'] for e in unique_entries]
        log_id_map = {e['cpe_string']: e['log_id'] for e in unique_entries}
        logger.debug(f"Bulk DB query for {len(cpe_strings)} CPEs ({len(valid_entries) - len(unique_entries)} duplicates removed)")
        try:
            batch_results = await self.database.find_by_cpe_batch(cpe_strings)
        except Exception as e:
            logger.error(f"Bulk DB query failed: {e}")
            batch_results = {cpe: [] for cpe in cpe_strings}

        db_hits = []
        db_misses = []
        for entry in unique_entries:
            cpe = entry['cpe_string']
            rows = batch_results.get(cpe, [])
            if rows:
                cve_data_list = self._db_data_to_cve_data_list(rows, cpe)
                passed = []
                for cve_data in cve_data_list:
                    cve_data.log_id = log_id_map.get(cpe)
                    cve_data.from_db = True
                    if self._evaluate_nvd_config(cve_data.configurations or [], cpe_strings):
                        cve_data.confirmed_vulnerable = (cve_data.match_type != 'wildcard')
                        passed.append(cve_data)
                db_hits.extend(passed)
                self.stats['db_hits'] += len(passed)
            else:
                db_misses.append(entry)

        api_hits = []
        if self.provider and db_misses:
            logger.info(f"NVD API fallback for {len(db_misses)} CPE misses")
            semaphore = asyncio.Semaphore(3)

            async def query_cpe(entry):
                async with semaphore:
                    cpe = entry['cpe_string']
                    try:
                        cve_list = await self.provider.query_cves_by_cpe(cpe)
                        passed = []
                        for cve_data in cve_list:
                            cve_data.log_id = log_id_map.get(cpe)
                            cve_data.from_api = True
                            configs = getattr(cve_data, 'configurations', None) or []
                            if self._evaluate_nvd_config(configs, cpe_strings):
                                cve_data.confirmed_vulnerable = True
                                passed.append(cve_data)
                        for cve_data in passed:
                            if hasattr(self.database, 'save_with_cpe_mappings'):
                                await self.database.save_with_cpe_mappings(cve_data)
                            else:
                                await self.database.save(cve_data)
                        if passed and hasattr(self.database, 'save_queried_cpe_mappings'):
                            cve_ids = [str(c.cve_id) for c in passed]
                            await self.database.save_queried_cpe_mappings(cpe, cve_ids)
                        self.stats['external_api_calls'] += 1
                        return cpe, passed
                    except Exception as e:
                        logger.error(f"NVD API fallback failed for CPE {cpe}: {e}")
                        return cpe, []

            api_results = await asyncio.gather(
                *[query_cpe(e) for e in db_misses], return_exceptions=True
            )

            found_cpes = set()
            for r in api_results:
                if isinstance(r, tuple):
                    cpe, cve_list = r
                    if cve_list:
                        found_cpes.add(cpe)
                        api_hits.extend(cve_list)

            db_misses = [e for e in db_misses if e['cpe_string'] not in found_cpes]

        result.matched_cves = db_hits + api_hits
        result.not_found_cpes = [e['cpe_string'] for e in db_misses]
        result.redis_hits = 0
        result.postgresql_hits = self.stats['db_hits']
        result.external_api_calls = self.stats['external_api_calls']
        self.stats['processed_count'] = len(unique_entries)

        logger.debug(
            f"CVE processing complete: {len(result.matched_cves)} matched, "
            f"{len(result.not_found_cpes)} not found, "
            f"DB hits: {result.postgresql_hits}, API calls: {result.external_api_calls}"
        )
        return result

    async def process_cve_ids(self, cve_id_entries: List[Dict[str, str]]) -> CVEProcessingResult:
        """
        Process CVE IDs directly (for specific CVE lookups).
        
        Args:
            cve_id_entries: List of dicts with 'cve_id' and optional 'log_id'
            
        Returns:
            CVEProcessingResult with matched CVEs
        """
        if not cve_id_entries:
            return CVEProcessingResult()
        
        logger.info(f"Processing {len(cve_id_entries)} CVE IDs")
        
        self._reset_stats()
        result = CVEProcessingResult()
        valid_entries = []
        cache_keys = []
        
        for entry in cve_id_entries:
            cve_id_str = entry.get('cve_id', '').strip().upper()
            log_id = entry.get('log_id', '').strip()
            
            if not cve_id_str:
                logger.warning(f"Missing cve_id in entry: {entry}")
                continue
            
            try:
                cve_id = CVEId(cve_id_str)
                valid_entries.append({
                    'cve_id': str(cve_id),
                    'log_id': log_id
                })
                cache_keys.append(f"cve:id:{str(cve_id)}")
            except ValueError as e:
                logger.warning(f"Invalid CVE ID {cve_id_str}: {e}")
                continue
        
        if not valid_entries:
            return result
        
        # Step 1: Check Redis cache
        logger.info(f"Batch checking {len(cache_keys)} CVE IDs in Redis cache")
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
                    cve_data = self._cache_dict_to_cve_data(cached_item, entry['cve_id'])
                    if cve_data:
                        cve_data.log_id = entry.get('log_id')
                        cve_data.from_redis = True
                        
                        if not cve_data.is_expired:
                            if cve_data.affected_cpes is None and hasattr(self.database, 'find_cpes_by_cve_id'):
                                try:
                                    cve_data.affected_cpes = await self.database.find_cpes_by_cve_id(entry['cve_id'])
                                    await self._cache_cve_data(entry['cve_id'], cve_data)
                                except Exception as e:
                                    logger.warning(f"Failed to backfill CPEs for {entry['cve_id']}: {e}")
                            cache_hits.append(cve_data)
                            self.stats['cache_hits'] += 1
                        else:
                            logger.debug(f"CVE data expired for {entry['cve_id']}, will refresh")
                            cache_misses.append(entry)
                        continue
                except Exception as e:
                    logger.warning(f"Error processing cached CVE data for {entry['cve_id']}: {e}")
            
            cache_misses.append(entry)
        
        # Step 2: Check PostgreSQL database
        db_hits = []
        db_misses = []
        
        for entry in cache_misses:
            try:
                db_data = await self.database.find_by_cve_id(entry['cve_id'])
                if db_data:
                    cve_data = self._db_data_to_cve_data(db_data, entry['cve_id'])
                    if cve_data:
                        cve_data.log_id = entry.get('log_id')
                        cve_data.from_db = True
                        db_hits.append(cve_data)
                        self.stats['db_hits'] += 1
                        
                        await self._cache_cve_data(entry['cve_id'], cve_data)
                        continue
            except Exception as e:
                logger.error(f"Error querying database for CVE {entry['cve_id']}: {e}")
            
            db_misses.append(entry)
        
        # Step 3: Query external NVD API
        api_results = []
        if self.provider and db_misses:
            logger.info(f"Querying NVD API for {len(db_misses)} CVE IDs")
            
            semaphore = asyncio.Semaphore(self.max_workers)
            
            async def query_cve_id(entry):
                async with semaphore:
                    try:
                        if hasattr(self.provider, 'query_cve'):
                            cve_data = await self.provider.query_cve(entry['cve_id'])
                            if cve_data:
                                cve_data.log_id = entry.get('log_id')
                                cve_data.from_api = True

                                if hasattr(self.database, 'save_with_cpe_mappings'):
                                    await self.database.save_with_cpe_mappings(cve_data)
                                else:
                                    await self.database.save(cve_data)
                                await self._cache_cve_data(entry['cve_id'], cve_data)

                                self.stats['external_api_calls'] += 1
                                return cve_data
                    except Exception as e:
                        logger.error(f"Error querying NVD API for CVE {entry['cve_id']}: {e}")
                    return None
            
            tasks = [query_cve_id(entry) for entry in db_misses]
            api_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            api_results = [r for r in api_results if r is not None and not isinstance(r, Exception)]

        result.matched_cves = cache_hits + db_hits + api_results
        result.not_found_cpes = [entry['cve_id'] for entry in db_misses if entry['cve_id'] not in [r.cve_id.value for r in api_results if r]]
        
        result.redis_hits = self.stats['cache_hits']
        result.postgresql_hits = self.stats['db_hits']
        result.external_api_calls = self.stats['external_api_calls']
        
        self.stats['processed_count'] = len(valid_entries)
        
        logger.info(
            f"CVE ID processing complete: {len(result.matched_cves)} matched, "
            f"{len(result.not_found_cpes)} not found, "
            f"cache hits: {result.redis_hits}, "
            f"DB hits: {result.postgresql_hits}, "
            f"API calls: {result.external_api_calls}"
        )
        
        return result
    
    def _cache_dict_to_cve_data(self, cache_dict: Dict[str, Any], cve_id_str: str) -> Optional[CVEData]:
        """Convert cached dictionary to CVEData object"""
        try:
            cve_id = CVEId(cve_id_str)

            published = datetime.fromisoformat(cache_dict['published'].replace('Z', '+00:00')) if cache_dict.get('published') else datetime.now(timezone.utc)
            last_modified = datetime.fromisoformat(cache_dict['last_modified'].replace('Z', '+00:00')) if cache_dict.get('last_modified') else datetime.now(timezone.utc)
            expires_at = datetime.fromtimestamp(cache_dict['expires_at_ts'], tz=timezone.utc) if cache_dict.get('expires_at_ts') else None
            
            cve_data = CVEData(
                cve_id=cve_id,
                score=cache_dict.get('score', 0.0),
                severity=cache_dict.get('severity', 'NONE'),
                published=published,
                last_modified=last_modified,
                source_identifier=cache_dict.get('source_identifier'),
                vuln_status=cache_dict.get('vuln_status'),
                description_en=cache_dict.get('description_en'),
                cvss_v3_vector_string=cache_dict.get('cvss_v3_vector_string'),
                epss_score=cache_dict.get('epss_score'),
                cvss_v2_base_score=cache_dict.get('cvss_v2_base_score'),
                cvss_v2_severity=cache_dict.get('cvss_v2_severity'),
                is_kev=bool(cache_dict.get('is_kev', False)),
                cisa_exploit_add=datetime.fromisoformat(cache_dict['cisa_exploit_add'].replace('Z', '+00:00')) if cache_dict.get('cisa_exploit_add') else None,
                cisa_action_due=datetime.fromisoformat(cache_dict['cisa_action_due'].replace('Z', '+00:00')) if cache_dict.get('cisa_action_due') else None,
                cisa_required_action=cache_dict.get('cisa_required_action'),
                cisa_vulnerability_name=cache_dict.get('cisa_vulnerability_name'),
                weaknesses=cache_dict.get('weaknesses'),
                references=cache_dict.get('references'),
                raw_data=cache_dict.get('raw_data'),
                expires_at=expires_at,
                from_redis=True,
                affected_cpes=cache_dict.get('affected_cpes'),
            )
            
            return cve_data
        except Exception as e:
            logger.error(f"Error converting cache dict to CVEData: {e}")
            return None
    
    def _cache_dict_to_cve_data_list(self, cache_dict: Dict[str, Any], cpe_string: str) -> List[CVEData]:
        """Convert cached dictionary (containing list of CVEs) to list of CVEData objects"""
        cve_list = cache_dict.get('cves', [])
        result = []
        
        for cve_dict in cve_list:
            try:
                cve_id_str = cve_dict.get('id') or cve_dict.get('cve_id')
                if not cve_id_str:
                    continue
                
                cve_data = self._cache_dict_to_cve_data(cve_dict, cve_id_str)
                if cve_data:
                    result.append(cve_data)
            except Exception as e:
                logger.warning(f"Error converting CVE dict to CVEData: {e}")
                continue
        
        return result
    
    def _db_data_to_cve_data(self, db_data: Dict[str, Any], cve_id_str: str) -> Optional[CVEData]:
        """Convert database data to CVEData object"""
        try:
            cve_id = CVEId(cve_id_str)
            
            published = db_data.get('published')
            if isinstance(published, datetime):
                published = published.replace(tzinfo=timezone.utc) if published.tzinfo is None else published
            elif isinstance(published, str):
                published = datetime.fromisoformat(published.replace('Z', '+00:00'))
            else:
                published = datetime.now(timezone.utc)
            
            last_modified = db_data.get('last_modified')
            if isinstance(last_modified, datetime):
                last_modified = last_modified.replace(tzinfo=timezone.utc) if last_modified.tzinfo is None else last_modified
            elif isinstance(last_modified, str):
                last_modified = datetime.fromisoformat(last_modified.replace('Z', '+00:00'))
            else:
                last_modified = datetime.now(timezone.utc)
            
            expires_at = db_data.get('expires_at')
            if isinstance(expires_at, datetime):
                expires_at = expires_at.replace(tzinfo=timezone.utc) if expires_at.tzinfo is None else expires_at
            
            cve_data = CVEData(
                cve_id=cve_id,
                score=db_data.get('score', 0.0),
                severity=db_data.get('severity', 'NONE'),
                published=published,
                last_modified=last_modified,
                source_identifier=db_data.get('source_identifier'),
                vuln_status=db_data.get('vuln_status'),
                description_en=db_data.get('description_en'),
                cvss_v3_vector_string=db_data.get('cvss_v3_vector_string'),
                epss_score=db_data.get('epss_score'),
                cvss_v2_base_score=db_data.get('cvss_v2_base_score'),
                cvss_v2_severity=db_data.get('cvss_v2_severity'),
                cisa_exploit_add=db_data.get('cisa_exploit_add'),
                cisa_action_due=db_data.get('cisa_action_due'),
                cisa_required_action=db_data.get('cisa_required_action'),
                cisa_vulnerability_name=db_data.get('cisa_vulnerability_name'),
                is_kev=bool(db_data.get('is_kev', False)),
                weaknesses=db_data.get('weaknesses'),
                references=db_data.get('references'),
                raw_data=db_data.get('raw_data'),
                expires_at=expires_at,
                from_db=True,
                criteria=db_data.get('criteria'),
                affected_cpes=db_data.get('affected_cpes'),
                configurations=db_data.get('configurations'),
                match_type=db_data.get('match_type', ''),
            )
            
            return cve_data
        except Exception as e:
            logger.error(f"Error converting DB data to CVEData: {e}", exc_info=True)
            return None
    
    def _db_data_to_cve_data_list(self, db_data_list: List[Dict[str, Any]], cpe_string: str) -> List[CVEData]:
        """Convert list of database data to list of CVEData objects"""
        result = []
        
        for db_data in db_data_list:
            cve_id_str = db_data.get('id') or db_data.get('cve_id')
            if not cve_id_str:
                continue
            
            cve_data = self._db_data_to_cve_data(db_data, cve_id_str)
            if cve_data:
                result.append(cve_data)
        
        return result
    
    async def _cache_cve_data(self, cve_id: str, cve_data: CVEData) -> None:
        """Cache CVE data in Redis"""
        try:
            cache_key = f"cve:id:{cve_id}"
            cache_dict = cve_data.to_dict()
            if cve_data.weaknesses is not None:
                cache_dict['weaknesses'] = cve_data.weaknesses
            if cve_data.references is not None:
                cache_dict['references'] = cve_data.references

            ttl = None
            if cve_data.expires_at:
                ttl_seconds = int((cve_data.expires_at - datetime.now(timezone.utc)).total_seconds())
                if ttl_seconds > 0:
                    ttl = ttl_seconds

            await self.cache.set(cache_key, cache_dict, ttl=ttl)
        except Exception as e:
            logger.warning(f"Failed to cache CVE data for {cve_id}: {e}")
    
    async def _cache_cve_results(self, cpe_string: str, cve_data_list: List[CVEData]) -> None:
        """Cache CVE results for a CPE string in Redis"""
        try:
            cache_key = f"cve:cpe:{cpe_string}"
            cache_dict = {
                'cpe_string': cpe_string,
                'cves': [cve.to_dict() for cve in cve_data_list],
                'count': len(cve_data_list)
            }
            
            min_expires_at = min([cve.expires_at for cve in cve_data_list if cve.expires_at], default=None)
            ttl = None
            if min_expires_at:
                ttl_seconds = int((min_expires_at - datetime.now(timezone.utc)).total_seconds())
                if ttl_seconds > 0:
                    ttl = ttl_seconds
            
            await self.cache.set(cache_key, cache_dict, ttl=ttl)
        except Exception as e:
            logger.warning(f"Failed to cache CVE results for CPE {cpe_string}: {e}")
    
    @staticmethod
    def _cpe_matches_criteria(
        asset_cpe: str,
        criteria: str,
        vsi: Optional[str] = None,
        vse: Optional[str] = None,
        vei: Optional[str] = None,
        vee: Optional[str] = None,
    ) -> bool:
        """Return True if asset_cpe satisfies a single NVD cpeMatch entry."""
        from packaging.version import Version, InvalidVersion
        import re

        asset_parts = asset_cpe.split(':')
        crit_parts = criteria.split(':')

        # Match part / vendor / product (indices 2-4); '*' on either side is a wildcard
        for i in range(2, 5):
            a = asset_parts[i] if len(asset_parts) > i else '*'
            c = crit_parts[i] if len(crit_parts) > i else '*'
            if c != '*' and a != '*' and c.lower() != a.lower():
                return False

        # Match identity fields 6-12 (update, edition, language, sw_edition, target_sw, target_hw, other)
        for i in range(6, 13):
            a = asset_parts[i] if len(asset_parts) > i else '*'
            c = crit_parts[i] if len(crit_parts) > i else '*'
            if c != '*' and a != '*' and c.lower() != a.lower():
                return False

        asset_ver = asset_parts[5] if len(asset_parts) > 5 else '*'
        crit_ver  = crit_parts[5]  if len(crit_parts) > 5  else '*'

        if vsi or vse or vei or vee:
            if asset_ver in ('*', '-', ''):
                return True  # version unknown — assume in range

            def _parse(v: str) -> Version:
                try:
                    return Version(v)
                except InvalidVersion:
                    v = re.sub(r'[-_]beta\.?(\d*)', lambda m: f'b{m.group(1) or "0"}', v, flags=re.IGNORECASE)
                    v = re.sub(r'[-_]alpha\.?(\d*)', lambda m: f'a{m.group(1) or "0"}', v, flags=re.IGNORECASE)
                    v = re.sub(r'[-_]rc\.?(\d*)', lambda m: f'rc{m.group(1) or "0"}', v, flags=re.IGNORECASE)
                    v = re.sub(r'^(\d+(?:\.\d+)*)([a-z])$',
                               lambda m: f"{m.group(1)}.{ord(m.group(2)) - ord('a') + 1}", v)
                    return Version(v)

            try:
                v = _parse(asset_ver)
                if vsi and v < _parse(vsi): return False
                if vse and v <= _parse(vse): return False
                if vei and v > _parse(vei): return False
                if vee and v >= _parse(vee): return False
                return True
            except Exception:
                return False

        # Point-version check
        if crit_ver != '*' and asset_ver != '*' and crit_ver != asset_ver:
            return False
        return True

    @staticmethod
    def _node_satisfied(node: Dict[str, Any], asset_cpes: List[str]) -> bool:
        """Return True if all/any cpeMatch entries in the node are satisfied (per operator)."""
        operator = node.get('operator', 'OR')
        negate   = node.get('negate', False)
        results  = []

        for cm in node.get('cpeMatch', []):
            criteria = cm.get('criteria', '')
            if not criteria:
                continue
            matched = any(
                CVEProcessor._cpe_matches_criteria(
                    acpe, criteria,
                    cm.get('versionStartIncluding'),
                    cm.get('versionStartExcluding'),
                    cm.get('versionEndIncluding'),
                    cm.get('versionEndExcluding'),
                )
                for acpe in asset_cpes
            )
            results.append(matched)

        for child in node.get('nodes', []):
            results.append(CVEProcessor._node_satisfied(child, asset_cpes))

        if not results:
            return True

        outcome = all(results) if operator == 'AND' else any(results)
        return not outcome if negate else outcome

    @staticmethod
    def _evaluate_nvd_config(configurations: List[Dict[str, Any]], asset_cpes: List[str]) -> bool:
        """
        Evaluate NVD AND/OR configuration logic against the full set of asset CPEs.
        Returns True if any top-level configuration group is fully satisfied.
        An empty/missing configurations list means the CVE applies universally.
        """
        if not configurations:
            return True
        if not asset_cpes:
            return False

        for config in configurations:
            nodes    = config.get('nodes', [])
            operator = config.get('operator', 'OR')
            if not nodes:
                continue
            if operator == 'AND':
                satisfied = all(CVEProcessor._node_satisfied(n, asset_cpes) for n in nodes)
            else:
                satisfied = any(CVEProcessor._node_satisfied(n, asset_cpes) for n in nodes)
            if satisfied:
                return True

        return False

    def _reset_stats(self) -> None:
        """Reset processing statistics"""
        self.stats = {
            'processed_count': 0,
            'error_count': 0,
            'cache_hits': 0,
            'db_hits': 0,
            'external_api_calls': 0
        }
