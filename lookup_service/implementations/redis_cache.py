"""Redis cache implementation for threat intelligence data."""

import json
import logging
import asyncio
import time
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone

import redis.asyncio as aioredis

from ..interfaces.cache import CacheInterface
from ..resource_manager import get_resource_manager, ResourceType
from ..config import get_settings

logger = logging.getLogger(__name__)


class RedisCache(CacheInterface):
    """Redis implementation of cache interface"""
    
    def __init__(self, host: str = "localhost", port: int = 6379, prefix: str = "", **kwargs):
        self.settings = get_settings()
        self.host = host
        self.port = port
        self.prefix = prefix
        self.client: Optional[aioredis.Redis] = None
        self.connection_kwargs = kwargs
        self._resource_manager = get_resource_manager()
        self._max_retries = 3
        self._retry_delay = 1.0
        self._operation_timeout = 5.0
    
    async def _execute_with_retry(self, operation_name: str, operation_func):
        """Execute Redis operation with retry logic and connection exhaustion handling."""
        for attempt in range(self._max_retries):
            try:
                if not self.client:
                    await self.connect()

                operation_id = f"redis_op_{operation_name}_{time.time()}_{attempt}"
                self._resource_manager.register_resource(
                    resource_id=operation_id,
                    resource_type=ResourceType.REDIS_CONNECTION,
                    metadata={
                        "operation": operation_name,
                        "started_at": time.time(),
                        "attempt": attempt + 1
                    }
                )
                
                result = await asyncio.wait_for(
                    operation_func(),
                    timeout=self._operation_timeout
                )

                await self._resource_manager.unregister_resource(operation_id)
                return result
                
            except (aioredis.ConnectionError, aioredis.TimeoutError, asyncio.TimeoutError) as e:
                logger.warning(f"Redis {operation_name} connection/timeout error on attempt {attempt + 1}/{self._max_retries}: {e}")
                self.client = None
                
                try:
                    await self._resource_manager.unregister_resource(operation_id, force_cleanup=True)
                except:
                    pass
                
                if attempt == self._max_retries - 1:
                    raise RuntimeError(f"Redis operation {operation_name} failed after {self._max_retries} attempts: {e}")
                    
            except Exception as e:
                logger.error(f"Redis {operation_name} error on attempt {attempt + 1}/{self._max_retries}: {e}")
                
                try:
                    await self._resource_manager.unregister_resource(operation_id, force_cleanup=True)
                except:
                    pass
                    
                if attempt == self._max_retries - 1:
                    raise

            await asyncio.sleep(self._retry_delay * (2 ** attempt))  # Exponential backoff
        
        raise RuntimeError(f"Redis operation {operation_name} failed after all retries")
    
    async def connect(self) -> None:
        """Establish Redis connection with connection pooling"""
        try:
            max_connections = getattr(self.settings, 'redis_max_connections', 25)
            socket_keepalive = getattr(self.settings, 'redis_socket_keepalive', True)
            connection_timeout = getattr(self.settings, 'redis_connection_pool_timeout', 30)
            self.client = aioredis.from_url(
                f"redis://{self.host}:{self.port}",
                decode_responses=True,
                max_connections=max_connections,
                retry_on_timeout=True,
                socket_keepalive=socket_keepalive,
                socket_keepalive_options={},
                health_check_interval=connection_timeout,
                socket_connect_timeout=10,
                **self.connection_kwargs
            )
            await self.client.ping()
            logger.info(f"Connected to Redis at {self.host}:{self.port} with connection pooling")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise
    
    def _get_key(self, key: str) -> str:
        """Get prefixed key"""
        return f"{self.prefix}{key}" if self.prefix else key
    
    async def get(self, key: str) -> Optional[Dict[str, Any]]:
        """Get cached data by key"""
        
        async def _get_operation():
            prefixed_key = self._get_key(key)
            data_str = await self.client.get(prefixed_key)
            if data_str:
                data = json.loads(data_str)
                
                expires_at_ts = data.get('expires_at_ts')
                if expires_at_ts and expires_at_ts < datetime.now(timezone.utc).timestamp():
                    logger.debug(f"Cache entry expired for key: {prefixed_key}")
                    return None
                
                logger.debug(f"Cache hit for key: {prefixed_key}")
                return data
            
            logger.debug(f"Cache miss for key: {prefixed_key}")
            return None
        
        try:
            return await self._execute_with_retry("get", _get_operation)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to decode cached data for key {key}: {e}")
            return None
        except Exception as e:
            logger.error(f"Error getting cached data for key {key}: {e}")
            return None
    
    async def set(self, key: str, value: Dict[str, Any], ttl: int = None) -> bool:
        """Set cached data with optional TTL"""
        
        async def _set_operation():
            prefixed_key = self._get_key(key)
            value_with_ts = value.copy()
            if ttl and 'expires_at' in value:
                expires_at = datetime.fromisoformat(value['expires_at'])
                value_with_ts['expires_at_ts'] = expires_at.timestamp()

            data_str = json.dumps(value_with_ts)

            if ttl:
                await self.client.set(prefixed_key, data_str, ex=ttl)
            else:
                await self.client.set(prefixed_key, data_str)

            logger.debug(f"Cached data for key: {prefixed_key} (TTL: {ttl})")
            return True
        
        try:
            return await self._execute_with_retry("set", _set_operation)
        except Exception as e:
            logger.error(f"Error setting cached data for key {key}: {e}")
            return False
    
    async def delete(self, key: str) -> bool:
        """Delete cached data by key"""
        
        async def _delete_operation():
            prefixed_key = self._get_key(key)
            result = await self.client.delete(prefixed_key)
            logger.debug(f"Deleted cache key: {prefixed_key}")
            return result > 0

        try:
            return await self._execute_with_retry("delete", _delete_operation)
        except Exception as e:
            logger.error(f"Error deleting cached data for key {key}: {e}")
            return False
    
    async def exists(self, key: str) -> bool:
        """Check if key exists in cache"""
        
        async def _exists_operation():
            prefixed_key = self._get_key(key)
            result = await self.client.exists(prefixed_key)
            return result > 0
        
        try:
            return await self._execute_with_retry("exists", _exists_operation)
        except Exception as e:
            logger.error(f"Error checking existence of key {key}: {e}")
            return False
    
    async def health_check(self) -> bool:
        """Check cache health"""
        
        async def _health_check_operation():
            await self.client.ping()
            return True
        
        try:
            return await self._execute_with_retry("health_check", _health_check_operation)
        except Exception as e:
            logger.error(f"Redis health check failed: {e}")
            return False
    
    async def mget(self, keys: List[str]) -> List[Optional[Dict[str, Any]]]:
        """Get multiple cached data by keys"""
        
        async def _mget_operation():
            prefixed_keys = [self._get_key(key) for key in keys]
            data_list = await self.client.mget(prefixed_keys)
            results = []
            
            for i, data_str in enumerate(data_list):
                if data_str:
                    try:
                        data = json.loads(data_str)
                        
                        expires_at_ts = data.get('expires_at_ts')
                        if expires_at_ts and expires_at_ts < datetime.now(timezone.utc).timestamp():
                            logger.debug(f"Cache entry expired for key: {prefixed_keys[i]}")
                            results.append(None)
                        else:
                            logger.debug(f"Cache hit for key: {prefixed_keys[i]}")
                            results.append(data)
                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to decode cached data for key {prefixed_keys[i]}: {e}")
                        results.append(None)
                else:
                    logger.debug(f"Cache miss for key: {prefixed_keys[i]}")
                    results.append(None)
            
            return results
        
        try:
            return await self._execute_with_retry("mget", _mget_operation)
        except Exception as e:
            logger.error(f"Error getting multiple cached data: {e}")
            return [None] * len(keys)

    async def close(self) -> None:
        """Close cache connections"""
        if self.client:
            await self.client.close()
            logger.info("Redis connection closed")
            self.client = None