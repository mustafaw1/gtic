"""
Resource cleanup context managers for automatic resource lifecycle management.

This module provides context managers for common resources used in the IP lookup service,
ensuring proper cleanup and preventing resource leaks.
"""

import asyncio
import logging
import time
from typing import Optional, Any, Dict, AsyncContextManager
from contextlib import asynccontextmanager

from .resource_manager import get_resource_manager, ResourceType
from .implementations.postgres_repo import PostgreSQLRepository
from .implementations.redis_cache import RedisCache

logger = logging.getLogger(__name__)


@asynccontextmanager
async def managed_database_connection(
    repository: PostgreSQLRepository,
    operation_name: str = "database_operation",
    metadata: Optional[Dict[str, Any]] = None
) -> AsyncContextManager[Any]:
    """
    Context manager for database connections with automatic cleanup.
    
    Args:
        repository: PostgreSQL repository instance
        operation_name: Name of the operation for tracking
        metadata: Additional metadata for the resource
        
    Yields:
        Database connection object
    """
    resource_manager = get_resource_manager()
    connection = None
    connection_id = None
    
    try:
        # Acquire connection
        connection, connection_id = await repository._acquire_connection_with_retry()
        
        # Update metadata with operation info
        operation_metadata = {
            "operation_name": operation_name,
            "started_at": time.time(),
            **(metadata or {})
        }
        
        # Access the resource to update metadata
        resource_manager.access_resource(connection_id)
        if connection_id in resource_manager._resources:
            resource_manager._resources[connection_id].metadata.update(operation_metadata)
        
        logger.debug(f"Acquired database connection for {operation_name}")
        yield connection
        
    except Exception as e:
        logger.error(f"Error in database operation {operation_name}: {e}")
        raise
    finally:
        if connection and connection_id:
            try:
                await repository._release_connection(connection, connection_id)
                logger.debug(f"Released database connection for {operation_name}")
            except Exception as e:
                logger.error(f"Error releasing database connection for {operation_name}: {e}")


@asynccontextmanager 
async def managed_redis_operation(
    cache: RedisCache,
    operation_name: str,
    metadata: Optional[Dict[str, Any]] = None
) -> AsyncContextManager[Any]:
    """
    Context manager for Redis operations with automatic cleanup and monitoring.
    
    Args:
        cache: Redis cache instance
        operation_name: Name of the operation for tracking
        metadata: Additional metadata for the resource
        
    Yields:
        Redis client object
    """
    resource_manager = get_resource_manager()
    
    # Register operation start
    operation_id = f"redis_ctx_{operation_name}_{time.time()}"
    operation_metadata = {
        "operation_name": operation_name,
        "started_at": time.time(),
        "context_managed": True,
        **(metadata or {})
    }
    
    try:
        # Ensure connection is available
        if not cache.client:
            await cache.connect()
        
        # Register the operation
        resource_manager.register_resource(
            resource_id=operation_id,
            resource_type=ResourceType.REDIS_CONNECTION,
            resource_obj=cache.client,
            metadata=operation_metadata
        )
        
        logger.debug(f"Started managed Redis operation: {operation_name}")
        yield cache.client
        
    except Exception as e:
        logger.error(f"Error in Redis operation {operation_name}: {e}")
        raise
    finally:
        try:
            await resource_manager.unregister_resource(operation_id)
            logger.debug(f"Completed managed Redis operation: {operation_name}")
        except Exception as e:
            logger.error(f"Error cleaning up Redis operation {operation_name}: {e}")


@asynccontextmanager
async def managed_ip_processing_batch(
    batch_size: int,
    timeout: float = 180.0,
    metadata: Optional[Dict[str, Any]] = None
) -> AsyncContextManager[Dict[str, Any]]:
    """
    Context manager for IP processing batches with resource monitoring.
    
    Args:
        batch_size: Number of IPs in the batch
        timeout: Maximum processing time in seconds
        metadata: Additional metadata for tracking
        
    Yields:
        Dict with batch context information
    """
    resource_manager = get_resource_manager()
    
    batch_id = f"ip_batch_{time.time()}"
    batch_metadata = {
        "batch_size": batch_size,
        "started_at": time.time(),
        "timeout": timeout,
        **(metadata or {})
    }
    
    try:
        # Register batch processing
        resource_manager.register_resource(
            resource_id=batch_id,
            resource_type=ResourceType.MEMORY_CACHE,  # Using this for batch tracking
            metadata=batch_metadata
        )
        
        batch_context = {
            "batch_id": batch_id,
            "batch_size": batch_size,
            "started_at": time.time(),
            "timeout": timeout
        }
        
        logger.info(f"Started IP processing batch {batch_id} with {batch_size} IPs")
        
        # Execute with timeout
        try:
            async with asyncio.timeout(timeout):
                yield batch_context
        except asyncio.TimeoutError:
            logger.error(f"IP processing batch {batch_id} timed out after {timeout}s")
            raise
        
        logger.info(f"Completed IP processing batch {batch_id}")
        
    except Exception as e:
        logger.error(f"Error in IP processing batch {batch_id}: {e}")
        raise
    finally:
        try:
            await resource_manager.unregister_resource(batch_id)
        except Exception as e:
            logger.error(f"Error cleaning up batch {batch_id}: {e}")


@asynccontextmanager
async def managed_concurrent_operations(
    max_concurrency: int,
    operation_name: str = "concurrent_ops",
    metadata: Optional[Dict[str, Any]] = None
) -> AsyncContextManager[asyncio.Semaphore]:
    """
    Context manager for controlling concurrency with resource monitoring.
    
    Args:
        max_concurrency: Maximum number of concurrent operations
        operation_name: Name for tracking purposes
        metadata: Additional metadata
        
    Yields:
        asyncio.Semaphore for controlling concurrency
    """
    resource_manager = get_resource_manager()
    
    semaphore_id = f"semaphore_{operation_name}_{time.time()}"
    semaphore_metadata = {
        "max_concurrency": max_concurrency,
        "operation_name": operation_name,
        "created_at": time.time(),
        **(metadata or {})
    }
    
    semaphore = asyncio.Semaphore(max_concurrency)
    
    try:
        # Register semaphore
        resource_manager.register_resource(
            resource_id=semaphore_id,
            resource_type=ResourceType.THREAD_POOL,  # Using this for concurrency control
            resource_obj=semaphore,
            metadata=semaphore_metadata
        )
        
        logger.debug(f"Created semaphore for {operation_name} with max_concurrency={max_concurrency}")
        yield semaphore
        
    except Exception as e:
        logger.error(f"Error in concurrent operations {operation_name}: {e}")
        raise
    finally:
        try:
            await resource_manager.unregister_resource(semaphore_id)
            logger.debug(f"Cleaned up semaphore for {operation_name}")
        except Exception as e:
            logger.error(f"Error cleaning up semaphore {semaphore_id}: {e}")


@asynccontextmanager
async def managed_memory_pool(
    initial_size: int = 100,
    max_size: int = 1000,
    cleanup_threshold: int = 500,
    operation_name: str = "memory_pool"
) -> AsyncContextManager[Dict[str, Any]]:
    """
    Context manager for memory pools with automatic cleanup.
    
    Args:
        initial_size: Initial pool size
        max_size: Maximum pool size
        cleanup_threshold: Size threshold for cleanup
        operation_name: Name for tracking
        
    Yields:
        Dict representing a memory pool context
    """
    resource_manager = get_resource_manager()
    
    pool_id = f"memory_pool_{operation_name}_{time.time()}"
    pool_metadata = {
        "initial_size": initial_size,
        "max_size": max_size,
        "cleanup_threshold": cleanup_threshold,
        "operation_name": operation_name,
        "current_size": 0,
        "created_at": time.time()
    }
    
    memory_pool = {
        "pool_id": pool_id,
        "data": {},
        "size": 0,
        "max_size": max_size,
        "cleanup_threshold": cleanup_threshold
    }
    
    try:
        # Register memory pool
        resource_manager.register_resource(
            resource_id=pool_id,
            resource_type=ResourceType.MEMORY_CACHE,
            resource_obj=memory_pool,
            metadata=pool_metadata
        )
        
        logger.debug(f"Created memory pool {pool_id} with max_size={max_size}")
        yield memory_pool
        
    except Exception as e:
        logger.error(f"Error in memory pool {operation_name}: {e}")
        raise
    finally:
        try:
            # Clear pool data
            if "data" in memory_pool:
                memory_pool["data"].clear()
            
            await resource_manager.unregister_resource(pool_id)
            logger.debug(f"Cleaned up memory pool {pool_id}")
        except Exception as e:
            logger.error(f"Error cleaning up memory pool {pool_id}: {e}")


class ResourceContexts:
    """
    Collection of resource context managers for the IP lookup service.
    
    This class provides a centralized way to access all resource context managers
    and ensures consistent resource management across the application.
    """
    
    @staticmethod
    def database_connection(repository: PostgreSQLRepository, operation_name: str = "db_op", **kwargs):
        """Get a managed database connection context."""
        return managed_database_connection(repository, operation_name, kwargs)
    
    @staticmethod  
    def redis_operation(cache: RedisCache, operation_name: str, **kwargs):
        """Get a managed Redis operation context."""
        return managed_redis_operation(cache, operation_name, kwargs)
    
    @staticmethod
    def ip_batch_processing(batch_size: int, **kwargs):
        """Get a managed IP processing batch context."""
        return managed_ip_processing_batch(batch_size, **kwargs)
    
    @staticmethod
    def concurrent_operations(max_concurrency: int, **kwargs):
        """Get a managed concurrency control context."""
        return managed_concurrent_operations(max_concurrency, **kwargs)
    
    @staticmethod
    def memory_pool(**kwargs):
        """Get a managed memory pool context."""
        return managed_memory_pool(**kwargs)


# Global instance for easy access
resource_contexts = ResourceContexts()