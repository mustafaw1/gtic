"""PostgreSQL repository implementation for threat intelligence data."""

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


class PostgreSQLRepository(DatabaseRepositoryInterface):
    """PostgreSQL implementation of database repository interface"""
    
    def __init__(self, db_pool: Optional[asyncpg.Pool] = None, connection_params: Optional[Dict] = None):
        self.db_pool = db_pool
        self.connection_params = connection_params or {}
        self.schema = 'public'
        self.table_name = 'ip_cache'
        self._lock = asyncio.Lock()
        self._resource_manager = get_resource_manager()
        self._connection_timeout = 30.0  # seconds
        self._max_retries = 3
        self._retry_delay = 1.0  # seconds
        
        self.zstd_compressor = zstd.ZstdCompressor(level=3)
        self.zstd_decompressor = zstd.ZstdDecompressor()
    
    async def _acquire_connection_with_retry(self):
        """Acquire database connection with retry logic and pool exhaustion handling."""
        for attempt in range(self._max_retries):
            try:
                connection_id = f"db_conn_{time.time()}_{attempt}"
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
                        "acquired_at": time.time()
                    }
                )
                
                return connection, connection_id
                
            except asyncio.TimeoutError:
                logger.warning(f"Database connection timeout on attempt {attempt + 1}/{self._max_retries}")
                if attempt == self._max_retries - 1:
                    raise RuntimeError("Database connection pool exhausted - all connections in use")
                    
            except Exception as e:
                logger.error(f"Database connection error on attempt {attempt + 1}/{self._max_retries}: {e}")
                if attempt == self._max_retries - 1:
                    raise
                    
            await asyncio.sleep(self._retry_delay * (2 ** attempt))
        
        raise RuntimeError("Failed to acquire database connection after all retries")
    
    async def _release_connection(self, connection, connection_id: str):
        """Release database connection and unregister from resource manager."""
        try:
            if connection:
                await self.db_pool.release(connection)
                await self._resource_manager.unregister_resource(connection_id)
        except Exception as e:
            logger.error(f"Error releasing database connection {connection_id}: {e}")
    
    async def find_by_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Find threat data by IP address"""
        if not self.db_pool:
            raise RuntimeError("Database pool not available")
        
        connection = None
        connection_id = None
        try:
            connection, connection_id = await self._acquire_connection_with_retry()
            
            if ':' in ip_address:
                table_to_query = 'ip_cache_ipv6'
            else:
                table_to_query = 'ip_cache_ipv4'
            
            query = f"""
                SELECT 
                    ip_address, threat_score, threat_level, threat_categories,
                    source_name, first_seen, last_fetched, details,
                    expires_at, country_code, total_reports
                FROM {self.schema}.{table_to_query}
                WHERE ip_address = $1
            """
            
            result = await connection.fetchrow(query, ip_address)
            
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
                        logger.debug(f"Decompressed raw_data for IP {ip_address}")
                    except Exception as e:
                        logger.warning(f"Failed to decompress details for IP {ip_address}: {e}")
                        data['raw_data'] = None
                else:
                    data['raw_data'] = None
                
                logger.debug(f"Found IP data in database: {ip_address}")
                return data
            
            logger.debug(f"IP not found in database: {ip_address}")
            return None
                
        except Exception as e:
            logger.error(f"Error finding IP {ip_address} in database: {e}")
            return None
        finally:
            if connection and connection_id:
                await self._release_connection(connection, connection_id)
    
    async def find_by_ips(self, ip_addresses: List[str]) -> List[Dict[str, Any]]:
        """Find threat data for multiple IP addresses"""
        if not self.db_pool:
            raise RuntimeError("Database pool not available")
        
        if not ip_addresses:
            return []
        
        connection = None
        connection_id = None
        try:
            connection, connection_id = await self._acquire_connection_with_retry()
            
            ipv4_addresses = [ip for ip in ip_addresses if ':' not in ip]
            ipv6_addresses = [ip for ip in ip_addresses if ':' in ip]

            results = []

            if ipv4_addresses:
                ipv4_query = f"""
                    SELECT 
                        ip_address, threat_score, threat_level, threat_categories,
                        source_name, first_seen, last_fetched, details,
                        expires_at, country_code, total_reports
                    FROM {self.schema}.ip_cache_ipv4
                    WHERE ip_address = ANY($1)
                """
                ipv4_results = await connection.fetch(ipv4_query, ipv4_addresses)
                results.extend(ipv4_results)

            if ipv6_addresses:
                ipv6_query = f"""
                    SELECT 
                        ip_address, threat_score, threat_level, threat_categories,
                        source_name, first_seen, last_fetched, details,
                        expires_at, country_code, total_reports
                    FROM {self.schema}.ip_cache_ipv6
                    WHERE ip_address = ANY($1)
                """
                ipv6_results = await connection.fetch(ipv6_query, ipv6_addresses)
                results.extend(ipv6_results)
            
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
                        logger.warning(f"Failed to decompress details for IP {data.get('ip_address')}: {e}")
                        data['raw_data'] = None
                else:
                    data['raw_data'] = None
                
                processed_results.append(data)
            
            logger.debug(f"Found {len(processed_results)} IPs in database from {len(ip_addresses)} requested")
            return processed_results
                
        except Exception as e:
            logger.error(f"Error finding multiple IPs in database: {e}")
            return []
        finally:
            if connection and connection_id:
                await self._release_connection(connection, connection_id)
    
    async def save(self, threat_data: Dict[str, Any]) -> bool:
        """Save single threat data record"""
        return await self.save_batch([threat_data])
    
    async def save_batch(self, threat_data_list: List[Dict[str, Any]]) -> bool:
        """Save multiple threat data records (IPs or hashes)"""
        if not self.db_pool:
            raise RuntimeError("Database pool not available")
        
        if not threat_data_list:
            return True
        
        first_record = threat_data_list[0]
        if 'hash_value' in first_record and 'hash_type' in first_record:
            return await self._save_hash_to_table(threat_data_list)
        
        ipv4_records = []
        ipv6_records = []
        
        for data in threat_data_list:
            ip_address = data.get('ip_address')
            if ':' in ip_address:
                ipv6_records.append(data)
            else:
                ipv4_records.append(data)
        
        success = True
        
        if ipv4_records:
            success &= await self._save_to_table(ipv4_records, 'ip_cache_ipv4')
        
        if ipv6_records:
            success &= await self._save_to_table(ipv6_records, 'ip_cache_ipv6')
        
        return success
    
    async def _save_to_table(self, records: List[Dict[str, Any]], table_name: str) -> bool:
        """Save records to specific table"""
        if not records:
            return True
        
        columns = [
            'ip_address', 'threat_score', 'threat_level', 'threat_categories',
            'source_name', 'first_seen', 'last_fetched', 'details',
            'expires_at', 'country_code', 'total_reports'
        ]
        
        prepared_records = []
        for record in records:
            raw_data = record.get('raw_data')
            compressed_data = None
            if raw_data:
                sanitized_data = self._sanitize_for_db_json(raw_data)
                json_str = json.dumps(sanitized_data).encode('utf-8')
                compressed_data = self.zstd_compressor.compress(json_str)
                logger.debug(f"Compressing raw_data for IP {record.get('ip_address')}: {len(json_str)} bytes")
            else:
                logger.warning(f"No raw_data found for IP {record.get('ip_address')} from source {record.get('source_name')}")
            
            record_tuple = (
                record.get('ip_address'),
                record.get('threat_score', 0),
                record.get('threat_level', 0),
                record.get('threat_categories', ''),
                record.get('source_name', ''),
                record.get('first_seen'),
                record.get('last_fetched'),
                compressed_data,
                record.get('expires_at'),
                record.get('country_code'),
                record.get('total_reports', 0)
            )
            prepared_records.append(record_tuple)
        
        placeholders = ', '.join([f'${i+1}' for i in range(len(columns))])
        update_cols = [f"{col} = EXCLUDED.{col}" for col in columns if col not in ['ip_address', 'first_seen']]
        
        upsert_query = f"""
            INSERT INTO {self.schema}.{table_name} ({', '.join(columns)}) 
            VALUES ({placeholders})
            ON CONFLICT (ip_address) DO UPDATE SET
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
            
            logger.debug(f"Saved {len(prepared_records)} records to {table_name}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving records to {table_name}: {e}")
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
    
    async def _save_hash_to_table(self, records: List[Dict[str, Any]]) -> bool:
        """Save hash records to partitioned hash_cache tables based on hash type"""
        if not records:
            return True
        
        md5_records = []
        sha1_records = []
        sha256_records = []
        
        for record in records:
            hash_type = record.get('hash_type', 'sha256').lower()
            if hash_type == 'md5':
                md5_records.append(record)
            elif hash_type == 'sha1':
                sha1_records.append(record)
            else:  # sha256 is default
                sha256_records.append(record)
        
        success = True
        
        if md5_records:
            success &= await self._save_hash_records_to_table(md5_records, 'hash_cache_md5')
        
        if sha1_records:
            success &= await self._save_hash_records_to_table(sha1_records, 'hash_cache_sha1')
        
        if sha256_records:
            success &= await self._save_hash_records_to_table(sha256_records, 'hash_cache_sha256')
        
        return success
    
    async def _save_hash_records_to_table(self, records: List[Dict[str, Any]], table_name: str) -> bool:
        """Save hash records to specific partitioned table"""
        if not records:
            return True
        
        columns = [
            'hash_value', 'hash_type', 'threat_score', 'threat_level', 'threat_categories',
            'source_name', 'first_seen', 'last_fetched', 'details',
            'expires_at', 'total_reports'
        ]
        
        prepared_records = []
        for record in records:
            raw_data = record.get('raw_data')
            compressed_data = None
            if raw_data:
                sanitized_data = self._sanitize_for_db_json(raw_data)
                json_str = json.dumps(sanitized_data).encode('utf-8')
                compressed_data = self.zstd_compressor.compress(json_str)
                logger.debug(f"Compressing raw_data for hash {record.get('hash_value')}: {len(json_str)} bytes")
            
            record_tuple = (
                record.get('hash_value'),
                record.get('hash_type', 'sha256'),
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
        update_cols = [f"{col} = EXCLUDED.{col}" for col in columns if col not in ['hash_value', 'hash_type', 'first_seen']]
        
        upsert_query = f"""
            INSERT INTO {self.schema}.{table_name} ({', '.join(columns)}) 
            VALUES ({placeholders})
            ON CONFLICT (hash_value, hash_type) DO UPDATE SET
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
            
            logger.debug(f"Saved {len(prepared_records)} hash records to {table_name}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving hash records to {table_name}: {e}")
            return False
        finally:
            if connection and connection_id:
                await self._release_connection(connection, connection_id)
    
    def _get_hash_table_name(self, hash_type: str) -> str:
        """Get the partitioned table name based on hash type"""
        hash_type_lower = hash_type.lower()
        if hash_type_lower == 'md5':
            return 'hash_cache_md5'
        elif hash_type_lower == 'sha1':
            return 'hash_cache_sha1'
        else:
            return 'hash_cache_sha256'
    
    async def find_by_hash(self, hash_value: str, hash_type: str = "sha256") -> Optional[Dict[str, Any]]:
        """Find threat data by file hash from partitioned table"""
        if not self.db_pool:
            raise RuntimeError("Database pool not available")
        
        connection = None
        connection_id = None
        try:
            connection, connection_id = await self._acquire_connection_with_retry()
            
            table_name = self._get_hash_table_name(hash_type)
            
            query = f"""
                SELECT 
                    hash_value, hash_type, threat_score, threat_level, threat_categories,
                    source_name, first_seen, last_fetched, details,
                    expires_at, total_reports
                FROM {self.schema}.{table_name}
                WHERE hash_value = $1 AND hash_type = $2
                AND expires_at > NOW()
            """
            
            row = await connection.fetchrow(query, hash_value, hash_type)
            
            if row:
                result = {
                    'hash_value': row['hash_value'],
                    'hash_type': row['hash_type'],
                    'threat_score': row['threat_score'],
                    'threat_level': row['threat_level'],
                    'threat_categories': row['threat_categories'],
                    'source_name': row['source_name'],
                    'first_seen': row['first_seen'],
                    'last_fetched': row['last_fetched'],
                    'expires_at': row['expires_at'],
                    'total_reports': row['total_reports'],
                    'raw_data': None
                }
                
                if row['details']:
                    try:
                        decompressed = self.zstd_decompressor.decompress(row['details'])
                        result['raw_data'] = json.loads(decompressed.decode('utf-8'))
                    except Exception as e:
                        logger.warning(f"Failed to decompress details for hash {hash_value}: {e}")
                
                logger.debug(f"Found hash {hash_value} ({hash_type}) in {table_name}")
                return result
            
            logger.debug(f"Hash {hash_value} ({hash_type}) not found in {table_name}")
            return None
            
        except Exception as e:
            logger.error(f"Error finding hash {hash_value}: {e}")
            return None
        finally:
            if connection and connection_id:
                await self._release_connection(connection, connection_id)
    
    async def save_hash_to_table(self, record: Dict[str, Any], hash_type: str) -> bool:
        """Save a single hash record to the appropriate partitioned table"""
        return await self._save_hash_to_table([record])
    
    async def find_by_hashes(self, hash_list: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        """Find threat data for multiple hashes from partitioned tables"""
        if not self.db_pool or not hash_list:
            return []
        
        md5_hashes = []
        sha1_hashes = []
        sha256_hashes = []
        
        for h in hash_list:
            hash_type = h.get('hash_type', 'sha256').lower()
            if hash_type == 'md5':
                md5_hashes.append(h['hash_value'])
            elif hash_type == 'sha1':
                sha1_hashes.append(h['hash_value'])
            else:  # sha256 is default
                sha256_hashes.append(h['hash_value'])
        
        connection = None
        connection_id = None
        results = []
        
        try:
            connection, connection_id = await self._acquire_connection_with_retry()
            
            if md5_hashes:
                md5_query = f"""
                    SELECT 
                        hash_value, hash_type, threat_score, threat_level, threat_categories,
                        source_name, first_seen, last_fetched, details,
                        expires_at, total_reports
                    FROM {self.schema}.hash_cache_md5
                    WHERE hash_value = ANY($1)
                    AND expires_at > NOW()
                """
                md5_results = await connection.fetch(md5_query, md5_hashes)
                results.extend(md5_results)
            
            if sha1_hashes:
                sha1_query = f"""
                    SELECT 
                        hash_value, hash_type, threat_score, threat_level, threat_categories,
                        source_name, first_seen, last_fetched, details,
                        expires_at, total_reports
                    FROM {self.schema}.hash_cache_sha1
                    WHERE hash_value = ANY($1)
                    AND expires_at > NOW()
                """
                sha1_results = await connection.fetch(sha1_query, sha1_hashes)
                results.extend(sha1_results)
            
            if sha256_hashes:
                sha256_query = f"""
                    SELECT 
                        hash_value, hash_type, threat_score, threat_level, threat_categories,
                        source_name, first_seen, last_fetched, details,
                        expires_at, total_reports
                    FROM {self.schema}.hash_cache_sha256
                    WHERE hash_value = ANY($1)
                    AND expires_at > NOW()
                """
                sha256_results = await connection.fetch(sha256_query, sha256_hashes)
                results.extend(sha256_results)
            
            # Process results
            processed_results = []
            for row in results:
                result = {
                    'hash_value': row['hash_value'],
                    'hash_type': row['hash_type'],
                    'threat_score': row['threat_score'],
                    'threat_level': row['threat_level'],
                    'threat_categories': row['threat_categories'],
                    'source_name': row['source_name'],
                    'first_seen': row['first_seen'],
                    'last_fetched': row['last_fetched'],
                    'expires_at': row['expires_at'],
                    'total_reports': row['total_reports'],
                    'raw_data': None
                }
                
                if row['details']:
                    try:
                        decompressed = self.zstd_decompressor.decompress(row['details'])
                        result['raw_data'] = json.loads(decompressed.decode('utf-8'))
                    except Exception as e:
                        logger.warning(f"Failed to decompress details for hash {row['hash_value']}: {e}")
                
                processed_results.append(result)
            
            logger.debug(f"Found {len(processed_results)} hashes out of {len(hash_list)} requested (MD5: {len(md5_hashes)}, SHA1: {len(sha1_hashes)}, SHA256: {len(sha256_hashes)})")
            return processed_results
            
        except Exception as e:
            logger.error(f"Error finding hashes batch: {e}")
            return []
        finally:
            if connection and connection_id:
                await self._release_connection(connection, connection_id)
    
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
            logger.error(f"Database health check failed: {e}")
            return False
        finally:
            if connection and connection_id:
                await self._release_connection(connection, connection_id)
    
    async def find_by_cpe_batch(self, cpe_strings: List[str]) -> Dict[str, List[Dict[str, Any]]]:
        """Not applicable for IP/domain/hash repository."""
        return {}

    async def close(self) -> None:
        """Close database connections"""
        # Note: We don't close the pool here since it's shared
        # The pool is managed by the application lifecycle
        logger.debug("PostgreSQL repository cleanup completed")