"""
Database connection management for ingestion services
"""

import json
import logging
from typing import Optional, Set, List, Dict, Any
import asyncpg
from config import IngestionServiceSettings
from models.iocs_record import DomainCacheRecord, IPCacheRecord, HashCacheRecord

logger = logging.getLogger(__name__)


class IngestionDatabase:
    """Database operations for ingestion services (OTX, Malware Bazaar)"""
    
    def __init__(self, settings: IngestionServiceSettings):
        self.settings = settings
        self._pool: Optional[asyncpg.Pool] = None
    
    async def connect(self) -> bool:
        """Initialize database connection pool"""
        try:
            self._pool = await asyncpg.create_pool(
                host=self.settings.DB_HOST,
                port=self.settings.DB_PORT,
                database=self.settings.DB_NAME,
                user=self.settings.DB_USER,
                password=self.settings.DB_PASSWORD,
                command_timeout=60,
                min_size=self.settings.db_pool_min_size,
                max_size=self.settings.db_pool_max_size,
                max_inactive_connection_lifetime=300,
                server_settings={'jit': 'off'}
            )
            logger.info(f"Database pool created with {self.settings.db_pool_min_size}-{self.settings.db_pool_max_size} connections")
            return True
        except Exception as e:
            logger.error(f"Failed to create database pool: {e}")
            return False
    
    async def disconnect(self):
        """Close database connection pool"""
        if self._pool:
            await self._pool.close()
            self._pool = None
            logger.info("Database pool closed")
    
    async def get_existing_domains(self, domains: List[str]) -> Set[str]:
        """Check which domains already exist in database"""
        if not domains or not self._pool:
            return set()
        
        try:
            async with self._pool.acquire() as conn:
                query = "SELECT domain_name FROM public.domain_cache WHERE domain_name = ANY($1)"
                results = await conn.fetch(query, domains)
                return {row['domain_name'] for row in results}
        except Exception as e:
            logger.error(f"Error checking existing domains: {e}")
            return set()
    
    async def store_batch(self, records: List[DomainCacheRecord]) -> int:
        """Store batch of domain records with conflict resolution"""
        if not records or not self._pool:
            return 0
        
        try:
            async with self._pool.acquire() as conn:
                query = """
                    INSERT INTO public.domain_cache 
                    (domain_name, threat_score, threat_level, threat_categories,
                     source_name, first_seen, last_fetched, details, expires_at, total_reports)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                    ON CONFLICT (domain_name) DO UPDATE SET
                        threat_score = EXCLUDED.threat_score,
                        threat_level = EXCLUDED.threat_level,
                        threat_categories = EXCLUDED.threat_categories,
                        last_fetched = EXCLUDED.last_fetched,
                        details = EXCLUDED.details,
                        expires_at = EXCLUDED.expires_at,
                        total_reports = EXCLUDED.total_reports
                """
                
                batch_tuples = [record.to_tuple() for record in records]
                
                await conn.executemany(query, batch_tuples)
                logger.debug(f"Stored batch of {len(batch_tuples)} domain records")
                return len(batch_tuples)
                
        except Exception as e:
            logger.error(f"Error storing batch: {e}")
            return 0
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get database statistics for monitoring"""
        if not self._pool:
            return {}
        
        try:
            async with self._pool.acquire() as conn:
                total_otx = await conn.fetchval(
                    "SELECT COUNT(*) FROM public.domain_cache WHERE source_name = 'AlienVault_OTX'"
                )
                
                recent_otx = await conn.fetchval(
                    "SELECT COUNT(*) FROM public.domain_cache WHERE source_name = 'AlienVault_OTX' AND last_fetched >= NOW() - INTERVAL '24 hours'"
                )
                
                total_mb = await conn.fetchval(
                    "SELECT COUNT(*) FROM public.hash_cache WHERE source_name = 'MalwareBazaar'"
                )
                
                recent_mb = await conn.fetchval(
                    "SELECT COUNT(*) FROM public.hash_cache WHERE source_name = 'MalwareBazaar' AND last_fetched >= NOW() - INTERVAL '24 hours'"
                )
                
                total_cves = await conn.fetchval(
                    "SELECT COUNT(*) FROM public.cve_cache"
                )
                
                recent_cves = await conn.fetchval(
                    "SELECT COUNT(*) FROM public.cve_cache WHERE last_fetched >= NOW() - INTERVAL '24 hours'"
                )
                
                kev_cves = await conn.fetchval(
                    "SELECT COUNT(*) FROM public.cve_cache WHERE is_kev = true"
                )
                
                return {
                    'total_otx_domains': total_otx,
                    'recent_otx_domains': recent_otx,
                    'total_malwarebazaar_hashes': total_mb,
                    'recent_malwarebazaar_hashes': recent_mb,
                    'total_cves': total_cves,
                    'recent_cves': recent_cves,
                    'kev_cves': kev_cves,
                    'pool_size': self._pool.get_size(),
                    'pool_idle': self._pool.get_idle_size(),
                }
        except Exception as e:
            logger.error(f"Error getting database stats: {e}")
            return {}
    
    async def get_existing_ips(self, ips: List[str]) -> Set[str]:
        """Check which IPs already exist in database"""
        if not ips or not self._pool:
            return set()
        
        try:
            ipv4_ips = []
            ipv6_ips = []
            
            for ip in ips:
                if ':' in ip:
                    ipv6_ips.append(ip)
                else:
                    ipv4_ips.append(ip)
            
            existing_ips = set()
            
            async with self._pool.acquire() as conn:
                if ipv4_ips:
                    ipv4_query = "SELECT ip_address FROM public.ip_cache_ipv4 WHERE ip_address = ANY($1)"
                    ipv4_results = await conn.fetch(ipv4_query, ipv4_ips)
                    existing_ips.update(row['ip_address'] for row in ipv4_results)
                
                if ipv6_ips:
                    ipv6_query = "SELECT ip_address FROM public.ip_cache_ipv6 WHERE ip_address = ANY($1)"
                    ipv6_results = await conn.fetch(ipv6_query, ipv6_ips)
                    existing_ips.update(row['ip_address'] for row in ipv6_results)
                
                return existing_ips
                
        except Exception as e:
            logger.error(f"Error checking existing IPs: {e}")
            return set()
    
    async def store_ip_batch(self, records: List[IPCacheRecord]) -> int:
        """Store batch of IP records with conflict resolution"""
        if not records or not self._pool:
            return 0
        
        ipv4_records = []
        ipv6_records = []
        
        for record in records:
            if ':' in record.ip_address:
                ipv6_records.append(record)
            else:
                ipv4_records.append(record)
        
        stored_count = 0
        
        try:
            if ipv4_records:
                stored_count += await self._store_ip_table_batch(ipv4_records, 'ip_cache_ipv4')
            
            if ipv6_records:
                stored_count += await self._store_ip_table_batch(ipv6_records, 'ip_cache_ipv6')
                
            return stored_count
            
        except Exception as e:
            logger.error(f"Error storing IP batch: {e}")
            return 0
    
    async def _store_ip_table_batch(self, records: List[IPCacheRecord], table_name: str) -> int:
        """Store IP records to specific table (ipv4 or ipv6)"""
        if not records:
            return 0
        
        try:
            async with self._pool.acquire() as conn:
                query = f"""
                    INSERT INTO public.{table_name}
                    (ip_address, threat_score, threat_level, threat_categories,
                     source_name, first_seen, last_fetched, details, expires_at, 
                     country_code, total_reports)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                    ON CONFLICT (ip_address) DO UPDATE SET
                        threat_score = EXCLUDED.threat_score,
                        threat_level = EXCLUDED.threat_level,
                        threat_categories = EXCLUDED.threat_categories,
                        last_fetched = EXCLUDED.last_fetched,
                        details = EXCLUDED.details,
                        expires_at = EXCLUDED.expires_at,
                        country_code = EXCLUDED.country_code,
                        total_reports = EXCLUDED.total_reports
                """
                
                batch_tuples = [record.to_tuple() for record in records]
                
                await conn.executemany(query, batch_tuples)
                logger.debug(f"Stored batch of {len(batch_tuples)} IP records to {table_name}")
                return len(batch_tuples)
                
        except Exception as e:
            logger.error(f"Error storing IP batch to {table_name}: {e}")
            return 0
    
    async def get_existing_hashes(self, hashes: List[tuple]) -> Set[tuple]:
        """Check which hashes already exist in database
        Args:
            hashes: List of (hash_value, hash_type) tuples
        Returns:
            Set of existing (hash_value, hash_type) tuples
        """
        if not hashes or not self._pool:
            return set()
        
        try:
            existing_hashes = set()
            
            async with self._pool.acquire() as conn:
                hash_groups = {}
                for hash_value, hash_type in hashes:
                    if hash_type not in hash_groups:
                        hash_groups[hash_type] = []
                    hash_groups[hash_type].append(hash_value)
                
                for hash_type, hash_values in hash_groups.items():
                    query = "SELECT hash_value FROM public.hash_cache WHERE hash_type = $1 AND hash_value = ANY($2)"
                    results = await conn.fetch(query, hash_type, hash_values)
                    for row in results:
                        existing_hashes.add((row['hash_value'], hash_type))
                
                return existing_hashes
                
        except Exception as e:
            logger.error(f"Error checking existing hashes: {e}")
            return set()
    
    async def store_hash_batch(self, records: List[HashCacheRecord]) -> int:
        """Store batch of hash records with conflict resolution"""
        if not records or not self._pool:
            return 0
        
        try:
            async with self._pool.acquire() as conn:
                query = """
                    INSERT INTO public.hash_cache
                    (hash_value, hash_type, threat_score, threat_level, threat_categories,
                     source_name, first_seen, last_fetched, details, expires_at, total_reports)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                    ON CONFLICT (hash_value, hash_type) DO UPDATE SET
                        threat_score = EXCLUDED.threat_score,
                        threat_level = EXCLUDED.threat_level,
                        threat_categories = EXCLUDED.threat_categories,
                        last_fetched = EXCLUDED.last_fetched,
                        details = EXCLUDED.details,
                        expires_at = EXCLUDED.expires_at,
                        total_reports = EXCLUDED.total_reports
                """
                
                batch_tuples = [record.to_tuple() for record in records]
                
                await conn.executemany(query, batch_tuples)
                logger.debug(f"Stored batch of {len(batch_tuples)} hash records")
                return len(batch_tuples)
                
        except Exception as e:
            logger.error(f"Error storing hash batch: {e}")
            return 0
    
    async def store_cve_batch(self, records: List[Dict[str, Any]]) -> int:
        """Store batch of CVE records with conflict resolution"""
        if not records or not self._pool:
            return 0
        
        try:
            async with self._pool.acquire() as conn:
                query = """
                    INSERT INTO public.cve_cache
                    (cve_id, configurations, cvss_score, threat_level, cve_status, published, last_modified,
                     source_name, first_seen, last_fetched, details, expires_at, is_kev, description,
                     cvss_v3_vector_string)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
                    ON CONFLICT (cve_id) DO UPDATE SET
                        configurations = EXCLUDED.configurations,
                        cvss_score = CASE
                            WHEN EXCLUDED.cvss_score IS NOT NULL AND EXCLUDED.cvss_score > 0
                            THEN EXCLUDED.cvss_score
                            ELSE COALESCE(public.cve_cache.cvss_score, EXCLUDED.cvss_score)
                        END,
                        threat_level = CASE
                            WHEN EXCLUDED.cvss_score IS NOT NULL AND EXCLUDED.cvss_score > 0
                            THEN EXCLUDED.threat_level
                            ELSE COALESCE(public.cve_cache.threat_level, EXCLUDED.threat_level)
                        END,
                        cve_status = EXCLUDED.cve_status,
                        published = EXCLUDED.published,
                        last_modified = EXCLUDED.last_modified,
                        source_name = EXCLUDED.source_name,
                        first_seen = COALESCE(public.cve_cache.first_seen, EXCLUDED.first_seen),
                        last_fetched = EXCLUDED.last_fetched,
                        details = COALESCE(EXCLUDED.details, public.cve_cache.details),
                        expires_at = EXCLUDED.expires_at,
                        is_kev = EXCLUDED.is_kev,
                        description = COALESCE(EXCLUDED.description, public.cve_cache.description),
                        cvss_v3_vector_string = COALESCE(EXCLUDED.cvss_v3_vector_string, public.cve_cache.cvss_v3_vector_string)
                """

                batch_tuples = []
                for record in records:
                    batch_tuples.append((
                        record.get('cve_id'),
                        record.get('configurations'),
                        record.get('cvss_score'),
                        record.get('threat_level'),
                        record.get('cve_status'),
                        record.get('published'),
                        record.get('last_modified'),
                        record.get('source_name'),
                        record.get('first_seen'),
                        record.get('last_fetched'),
                        record.get('details'),
                        record.get('expires_at'),
                        record.get('is_kev', False),
                        record.get('description'),
                        record.get('cvss_v3_vector_string'),
                    ))
                
                await conn.executemany(query, batch_tuples)
                logger.debug(f"Stored batch of {len(batch_tuples)} CVE records")

                cpe_tuples = []
                for record in records:
                    cve_id = record.get('cve_id')
                    raw_configs = record.get('configurations')
                    if not cve_id or not raw_configs:
                        continue
                    try:
                        configs = json.loads(raw_configs) if isinstance(raw_configs, str) else raw_configs
                        seen_cpe_keys = set()
                        for config in configs:
                            for node in config.get('nodes', []):
                                nodes_to_process = [node] + node.get('nodes', [])
                                for n in nodes_to_process:
                                    for cpe_match in n.get('cpeMatch', []):
                                        criteria = cpe_match.get('criteria')
                                        if not criteria:
                                            continue
                                        vsi = cpe_match.get('versionStartIncluding')
                                        vse = cpe_match.get('versionStartExcluding')
                                        vei = cpe_match.get('versionEndIncluding')
                                        vee = cpe_match.get('versionEndExcluding')
                                        key = (cve_id, criteria, vsi, vse, vei, vee)
                                        if key in seen_cpe_keys:
                                            continue
                                        seen_cpe_keys.add(key)
                                        parts = criteria.split(':')
                                        cpe_base = ':'.join(parts[:5]) if len(parts) >= 5 else criteria
                                        cpe_tuples.append((
                                            cve_id,
                                            criteria,
                                            cpe_base,
                                            bool(cpe_match.get('vulnerable', True)),
                                            vsi,
                                            vse,
                                            vei,
                                            vee,
                                        ))
                    except Exception:
                        pass

                if cpe_tuples:
                    cpe_query = """
                        INSERT INTO public.cve_cpe (
                            cve_id, cpe_string, cpe_base, vulnerable,
                            version_start_including, version_start_excluding,
                            version_end_including, version_end_excluding
                        )
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                        ON CONFLICT (cve_id, cpe_string) DO UPDATE SET
                            vulnerable              = EXCLUDED.vulnerable,
                            version_start_including = EXCLUDED.version_start_including,
                            version_start_excluding = EXCLUDED.version_start_excluding,
                            version_end_including   = EXCLUDED.version_end_including,
                            version_end_excluding   = EXCLUDED.version_end_excluding
                    """
                    await conn.executemany(cpe_query, cpe_tuples)
                    logger.debug(f"Upserted {len(cpe_tuples)} CPE entries")

                    batch_cve_ids = [t[0] for t in cpe_tuples]
                    batch_cpe_strings = [t[1] for t in cpe_tuples]
                    deleted = await conn.execute(
                        """
                        DELETE FROM public.cve_cpe
                        WHERE cve_id = ANY($1::text[])
                          AND NOT EXISTS (
                              SELECT 1
                              FROM unnest($2::text[], $3::text[]) AS current(cve_id, cpe_string)
                              WHERE current.cve_id    = cve_cpe.cve_id
                                AND current.cpe_string = cve_cpe.cpe_string
                          )
                        """,
                        list(set(batch_cve_ids)),
                        batch_cve_ids,
                        batch_cpe_strings,
                    )
                    logger.debug(f"Removed stale CPE entries: {deleted}")

                return len(batch_tuples)

        except Exception as e:
            logger.error(f"Error storing CVE batch: {e}", exc_info=True)
            return 0

    async def store_cpe_dictionary_batch(self, records: List[Dict[str, Any]]) -> tuple[int, int]:
        """Upsert a batch of CPE dictionary entries. Returns (inserted, updated)."""
        if not records or not self._pool:
            return 0, 0
        try:
            async with self._pool.acquire() as conn:
                inserted = updated = 0
                for rec in records:
                    result = await conn.fetchval(
                        """
                        INSERT INTO public.cpe_dictionary
                            (cpe_name, cpe_name_id, cpe_base, version, update_field, deprecated, last_modified)
                        VALUES ($1, $2, $3, $4, $5, $6, $7)
                        ON CONFLICT (cpe_name) DO UPDATE SET
                            cpe_name_id  = EXCLUDED.cpe_name_id,
                            cpe_base     = EXCLUDED.cpe_base,
                            version      = EXCLUDED.version,
                            update_field = EXCLUDED.update_field,
                            deprecated   = EXCLUDED.deprecated,
                            last_modified = EXCLUDED.last_modified
                        RETURNING (xmax = 0)
                        """,
                        rec["cpe_name"], rec["cpe_name_id"], rec["cpe_base"],
                        rec["version"], rec["update_field"], rec["deprecated"], rec["last_modified"],
                    )
                    if result:
                        inserted += 1
                    else:
                        updated += 1
                return inserted, updated
        except Exception as e:
            logger.error(f"Error storing CPE dictionary batch: {e}", exc_info=True)
            return 0, 0

    async def get_last_cpe_dict_sync_date(self):
        """Return the last CPE dictionary sync timestamp, or None if never synced."""
        if not self._pool:
            return None
        try:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow("SELECT last_sync_date FROM public.cpe_dict_sync_state WHERE id = 1")
                return row["last_sync_date"] if row else None
        except Exception as e:
            logger.error(f"Error getting CPE dict sync date: {e}")
            return None

    async def update_cpe_dict_sync_date(self, sync_date, total_cpes: int = 0):
        """Persist the last successful CPE dictionary sync timestamp."""
        if not self._pool:
            return
        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO public.cpe_dict_sync_state (id, last_sync_date, total_cpes)
                    VALUES (1, $1, $2)
                    ON CONFLICT (id) DO UPDATE SET last_sync_date = EXCLUDED.last_sync_date,
                                                   total_cpes = EXCLUDED.total_cpes
                    """,
                    sync_date, total_cpes,
                )
        except Exception as e:
            logger.error(f"Error updating CPE dict sync date: {e}")