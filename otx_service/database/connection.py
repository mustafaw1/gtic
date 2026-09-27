"""
Database connection management for OTX service
"""

import logging
from typing import Optional, Set, List, Dict, Any
import asyncpg
from config import OTXServiceSettings
from models.iocs_record import DomainCacheRecord, IPCacheRecord, HashCacheRecord

logger = logging.getLogger(__name__)


class OTXDatabase:
    """Database operations for OTX ingestion service"""
    
    def __init__(self, settings: OTXServiceSettings):
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
                
                return {
                    'total_otx_domains': total_otx,
                    'recent_otx_domains': recent_otx,
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