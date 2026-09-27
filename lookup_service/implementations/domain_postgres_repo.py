"""PostgreSQL repository implementation for domain threat intelligence data."""

import json
import logging
from typing import Optional, List, Dict, Any
import asyncio
import time

import asyncpg
import zstandard as zstd

from ..interfaces.database import DatabaseRepositoryInterface
from ..resource_manager import get_resource_manager, ResourceType

logger = logging.getLogger(__name__)


class DomainPostgreSQLRepository(DatabaseRepositoryInterface):
    """PostgreSQL implementation of domain database repository interface"""
    
    def __init__(self, db_pool: Optional[asyncpg.Pool] = None, connection_params: Optional[Dict] = None):
        self.db_pool = db_pool
        self.connection_params = connection_params or {}
        self.schema = 'public'
        self.table_name = 'domain_cache'
        self._lock = asyncio.Lock()
        self._resource_manager = get_resource_manager()
        self._connection_timeout = 30.0
        self._max_retries = 3
        self._retry_delay = 1.0
        
        self.zstd_compressor = zstd.ZstdCompressor(level=3)
        self.zstd_decompressor = zstd.ZstdDecompressor()
    
    async def _acquire_connection_with_retry(self):
        """Acquire database connection with retry logic and pool exhaustion handling."""
        for attempt in range(self._max_retries):
            try:
                connection_id = f"domain_db_conn_{time.time()}_{attempt}"
                connection = await asyncio.wait_for(
                    self.db_pool.acquire(),
                    timeout=self._connection_timeout
                )
                
                self._resource_manager.register_resource(
                    resource_id=connection_id,
                    resource_type=ResourceType.DATABASE_CONNECTION,
                    metadata={
                        "pool_size": len(self.db_pool._holders),
                        "pool_max": self.db_pool._maxsize,
                        "acquired_at": time.time(),
                        "table": self.table_name
                    }
                )
                
                return connection, connection_id
                
            except asyncio.TimeoutError:
                logger.warning(f"Domain database connection timeout on attempt {attempt + 1}/{self._max_retries}")
                if attempt == self._max_retries - 1:
                    raise RuntimeError("Domain database connection pool exhausted - all connections in use")
                    
            except Exception as e:
                logger.error(f"Domain database connection error on attempt {attempt + 1}/{self._max_retries}: {e}")
                if attempt == self._max_retries - 1:
                    raise
                    
            await asyncio.sleep(self._retry_delay * (2 ** attempt))
        
        raise RuntimeError("Failed to acquire domain database connection after all retries")
    
    async def _release_connection(self, connection, connection_id: str):
        """Release database connection and unregister from resource manager."""
        try:
            if connection:
                await self.db_pool.release(connection)
                await self._resource_manager.unregister_resource(connection_id)
        except Exception as e:
            logger.error(f"Error releasing domain database connection {connection_id}: {e}")
    
    async def find_by_ip(self, domain_name: str) -> Optional[Dict[str, Any]]:
        """Find domain threat data by domain name"""
        if not self.db_pool:
            raise RuntimeError("Database pool not available")
        
        connection = None
        connection_id = None
        try:
            connection, connection_id = await self._acquire_connection_with_retry()
            
            query = f"""
                SELECT 
                    domain_name, threat_score, threat_level, threat_categories,
                    source_name, first_seen, last_fetched, details,
                    expires_at, total_reports
                FROM {self.schema}.{self.table_name}
                WHERE domain_name = $1
            """
            
            result = await connection.fetchrow(query, domain_name)
            
            if result:
                data = dict(result)
                
                for col in ['expires_at', 'first_seen', 'last_fetched']:
                    dt = data.get(col)
                    if dt and dt.tzinfo is None:
                        from datetime import timezone
                        data[col] = dt.replace(tzinfo=timezone.utc)
                
                if data.get('details'):
                    try:
                        decompressed = self.zstd_decompressor.decompress(data['details'])
                        raw_data = json.loads(decompressed.decode('utf-8'))
                        data['raw_data'] = raw_data
                        logger.debug(f"Decompressed raw_data for domain {domain_name}")
                    except Exception as e:
                        logger.warning(f"Failed to decompress details for domain {domain_name}: {e}")
                        data['raw_data'] = None
                else:
                    data['raw_data'] = None
                
                logger.debug(f"Found domain data in database: {domain_name}")
                return data
            
            logger.debug(f"Domain not found in database: {domain_name}")
            return None
                
        except Exception as e:
            logger.error(f"Error finding domain {domain_name} in database: {e}")
            return None
        finally:
            if connection and connection_id:
                await self._release_connection(connection, connection_id)
    
    async def find_by_ips(self, domain_names: List[str]) -> List[Dict[str, Any]]:
        """Find threat data for multiple domain names"""
        if not self.db_pool:
            raise RuntimeError("Database pool not available")
        
        if not domain_names:
            return []
        
        connection = None
        connection_id = None
        try:
            connection, connection_id = await self._acquire_connection_with_retry()
            
            query = f"""
                SELECT 
                    domain_name, threat_score, threat_level, threat_categories,
                    source_name, first_seen, last_fetched, details,
                    expires_at, total_reports
                FROM {self.schema}.{self.table_name}
                WHERE domain_name = ANY($1)
            """
            
            results = await connection.fetch(query, domain_names)
            
            processed_results = []
            for result in results:
                data = dict(result)
                
                for col in ['expires_at', 'first_seen', 'last_fetched']:
                    dt = data.get(col)
                    if dt and dt.tzinfo is None:
                        from datetime import timezone
                        data[col] = dt.replace(tzinfo=timezone.utc)
                
                if data.get('details'):
                    try:
                        decompressed = self.zstd_decompressor.decompress(data['details'])
                        raw_data = json.loads(decompressed.decode('utf-8'))
                        data['raw_data'] = raw_data
                    except Exception as e:
                        logger.warning(f"Failed to decompress details for domain {data.get('domain_name')}: {e}")
                        data['raw_data'] = None
                else:
                    data['raw_data'] = None
                
                processed_results.append(data)
            
            logger.debug(f"Found {len(processed_results)} domains in database from {len(domain_names)} requested")
            return processed_results
                
        except Exception as e:
            logger.error(f"Error finding multiple domains in database: {e}")
            return []
        finally:
            if connection and connection_id:
                await self._release_connection(connection, connection_id)
    
    async def save(self, threat_data: Dict[str, Any]) -> bool:
        """Save single domain threat data record"""
        return await self.save_batch([threat_data])
    
    async def save_batch(self, threat_data_list: List[Dict[str, Any]]) -> bool:
        """Save multiple domain threat data records"""
        if not self.db_pool:
            raise RuntimeError("Database pool not available")
        
        if not threat_data_list:
            return True
        
        columns = [
            'domain_name', 'threat_score', 'threat_level', 'threat_categories',
            'source_name', 'first_seen', 'last_fetched', 'details',
            'expires_at', 'total_reports'
        ]
        
        prepared_records = []
        for record in threat_data_list:
            raw_data = record.get('raw_data')
            compressed_data = None
            if raw_data:
                sanitized_data = self._sanitize_for_db_json(raw_data)
                json_str = json.dumps(sanitized_data).encode('utf-8')
                compressed_data = self.zstd_compressor.compress(json_str)
                logger.debug(f"Compressing raw_data for domain {record.get('domain_name')}: {len(json_str)} bytes")
            else:
                logger.warning(f"No raw_data found for domain {record.get('domain_name')} from source {record.get('source_name')}")
            
            record_tuple = (
                record.get('domain_name'),
                record.get('threat_score', 0),
                record.get('threat_level', 0),
                record.get('threat_categories', ''),
                record.get('source_name', ''),
                record.get('first_seen'),
                record.get('last_fetched'),
                compressed_data,
                record.get('expires_at'),
                record.get('total_reports', 0)
            )
            prepared_records.append(record_tuple)
        
        placeholders = ', '.join([f'${i+1}' for i in range(len(columns))])
        update_cols = [f"{col} = EXCLUDED.{col}" for col in columns if col not in ['domain_name', 'first_seen']]
        
        upsert_query = f"""
            INSERT INTO {self.schema}.{self.table_name} ({', '.join(columns)}) 
            VALUES ({placeholders})
            ON CONFLICT (domain_name) DO UPDATE SET
                {', '.join(update_cols)}
        """
        
        connection = None
        connection_id = None
        try:
            async with self._lock:
                connection, connection_id = await self._acquire_connection_with_retry()
                
                if len(prepared_records) == 1:
                    await connection.execute(upsert_query, *prepared_records[0])
                else:
                    await connection.executemany(upsert_query, prepared_records)
            
            logger.debug(f"Saved {len(prepared_records)} domain records to {self.table_name}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving domain records to {self.table_name}: {e}")
            return False
        finally:
            if connection and connection_id:
                await self._release_connection(connection, connection_id)
    
    def _sanitize_for_db_json(self, data: Any) -> Any:
        """Recursively remove NULL bytes from JSON data"""
        if isinstance(data, dict):
            return {k: self._sanitize_for_db_json(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._sanitize_for_db_json(e) for e in data]
        elif isinstance(data, str):
            return data.translate({0: None})
        return data
    
    async def health_check(self) -> bool:
        """Check database health"""
        if not self.db_pool:
            return False
        
        connection = None
        connection_id = None
        try:
            connection, connection_id = await self._acquire_connection_with_retry()
            await connection.fetchval("SELECT 1")
            return True
        except Exception as e:
            logger.error(f"Domain database health check failed: {e}")
            return False
        finally:
            if connection and connection_id:
                await self._release_connection(connection, connection_id)
    
    async def find_by_cpe_batch(self, cpe_strings: List[str]) -> Dict[str, List[Dict[str, Any]]]:
        """Not applicable for domain repository."""
        return {}

    async def close(self) -> None:
        """Close database connections"""
        # Note: We don't close the pool here since it's shared
        # The pool is managed by the application lifecycle
        logger.debug("Domain PostgreSQL repository cleanup completed")
    
    async def find_by_hash(self, hash_value: str, hash_type: str = "sha256") -> Optional[Dict[str, Any]]:
        """Not implemented for domain repository"""
        raise NotImplementedError("Domain repository doesn't handle hash lookups")
    
    async def find_by_hashes(self, hash_list: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        """Not implemented for domain repository"""
        raise NotImplementedError("Domain repository doesn't handle hash lookups")
    