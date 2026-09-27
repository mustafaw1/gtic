"""
Resource management system for IP lookup services.

This module provides comprehensive resource tracking, leak detection,
and automatic cleanup to prevent memory and connection leaks.
"""

import asyncio
import logging
import weakref
import gc
import time
import psutil
from typing import Dict, List, Optional, Set, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from enum import Enum

logger = logging.getLogger(__name__)


class ResourceType(Enum):
    """Types of resources being managed."""
    DATABASE_CONNECTION = "database_connection"
    REDIS_CONNECTION = "redis_connection"
    HTTP_CONNECTION = "http_connection"
    IP_LOCK = "ip_lock"
    MEMORY_CACHE = "memory_cache"
    THREAD_POOL = "thread_pool"


@dataclass
class ResourceMetrics:
    """Resource usage metrics."""
    total_created: int = 0
    total_destroyed: int = 0
    currently_active: int = 0
    peak_usage: int = 0
    last_cleanup: Optional[datetime] = None
    leak_count: int = 0
    
    @property
    def active_count(self) -> int:
        """Current active resource count."""
        return self.total_created - self.total_destroyed
    
    @property
    def potential_leaks(self) -> int:
        """Resources that might be leaked."""
        return max(0, self.active_count - self.currently_active)


@dataclass
class ResourceInfo:
    """Information about a managed resource."""
    resource_id: str
    resource_type: ResourceType
    created_at: datetime
    last_accessed: datetime
    stack_trace: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def age_seconds(self) -> float:
        """Age of resource in seconds."""
        return (datetime.now(timezone.utc) - self.created_at).total_seconds()
    
    @property
    def idle_seconds(self) -> float:
        """Seconds since last access."""
        return (datetime.now(timezone.utc) - self.last_accessed).total_seconds()


class ResourceManager:
    """
    Comprehensive resource management system.
    
    Features:
    - Resource tracking and leak detection
    - Automatic cleanup of stale resources
    - Connection pool monitoring
    - Memory usage tracking
    - Resource usage metrics
    """
    
    def __init__(self, 
                 cleanup_interval: int = 300,  # 5 minutes
                 max_resource_age: int = 3600,  # 1 hour
                 max_idle_time: int = 1800,     # 30 minutes
                 enable_gc_monitoring: bool = True):
        self.cleanup_interval = cleanup_interval
        self.max_resource_age = max_resource_age
        self.max_idle_time = max_idle_time
        self.enable_gc_monitoring = enable_gc_monitoring
        
        # Resource tracking
        self._resources: Dict[str, ResourceInfo] = {}
        self._metrics: Dict[ResourceType, ResourceMetrics] = {
            rt: ResourceMetrics() for rt in ResourceType
        }
        self._cleanup_callbacks: Dict[str, Callable] = {}
        self._weak_refs: Dict[str, weakref.ref] = {}
        
        # Cleanup task
        self._cleanup_task: Optional[asyncio.Task] = None
        self._shutdown_event = asyncio.Event()
        
        # System monitoring
        self._process = psutil.Process()
        self._initial_memory = self._process.memory_info().rss
        
        logger.info(f"ResourceManager initialized with cleanup_interval={cleanup_interval}s")
    
    async def start(self) -> None:
        """Start the resource manager."""
        if self._cleanup_task and not self._cleanup_task.done():
            logger.warning("ResourceManager already started")
            return
        
        self._shutdown_event.clear()
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        logger.info("ResourceManager started")
    
    async def stop(self) -> None:
        """Stop the resource manager and cleanup all resources."""
        logger.info("Stopping ResourceManager...")
        
        # Signal shutdown
        self._shutdown_event.set()
        
        # Wait for cleanup task to finish
        if self._cleanup_task:
            try:
                await asyncio.wait_for(self._cleanup_task, timeout=30)
            except asyncio.TimeoutError:
                logger.warning("ResourceManager cleanup task timeout, cancelling")
                self._cleanup_task.cancel()
        
        # Force cleanup all remaining resources
        await self._force_cleanup_all()
        
        logger.info("ResourceManager stopped")
    
    def register_resource(self, 
                         resource_id: str,
                         resource_type: ResourceType,
                         resource_obj: Any = None,
                         cleanup_callback: Optional[Callable] = None,
                         metadata: Dict[str, Any] = None) -> None:
        """
        Register a resource for tracking.
        
        Args:
            resource_id: Unique identifier for the resource
            resource_type: Type of resource
            resource_obj: Actual resource object (for weak references)
            cleanup_callback: Function to call when cleaning up
            metadata: Additional metadata about the resource
        """
        import traceback
        
        now = datetime.now(timezone.utc)
        
        resource_info = ResourceInfo(
            resource_id=resource_id,
            resource_type=resource_type,
            created_at=now,
            last_accessed=now,
            stack_trace=traceback.format_stack()[-3],  # Skip current frame
            metadata=metadata or {}
        )
        
        self._resources[resource_id] = resource_info
        self._metrics[resource_type].total_created += 1
        self._metrics[resource_type].currently_active += 1
        
        # Update peak usage
        current_active = self._metrics[resource_type].currently_active
        if current_active > self._metrics[resource_type].peak_usage:
            self._metrics[resource_type].peak_usage = current_active
        
        # Store cleanup callback
        if cleanup_callback:
            self._cleanup_callbacks[resource_id] = cleanup_callback
        
        # Create weak reference for automatic cleanup detection
        if resource_obj is not None:
            def cleanup_on_gc(ref):
                asyncio.create_task(self._handle_gc_cleanup(resource_id))
            
            self._weak_refs[resource_id] = weakref.ref(resource_obj, cleanup_on_gc)
        
        logger.debug(f"Registered resource {resource_id} of type {resource_type.value}")
    
    def access_resource(self, resource_id: str) -> None:
        """Mark a resource as accessed (updates last_accessed timestamp)."""
        if resource_id in self._resources:
            self._resources[resource_id].last_accessed = datetime.now(timezone.utc)
    
    async def unregister_resource(self, resource_id: str, 
                                force_cleanup: bool = False) -> bool:
        """
        Unregister a resource and optionally clean it up.
        
        Args:
            resource_id: Resource to unregister
            force_cleanup: Whether to force cleanup even if callback fails
            
        Returns:
            True if successfully unregistered, False otherwise
        """
        if resource_id not in self._resources:
            logger.warning(f"Attempted to unregister unknown resource: {resource_id}")
            return False
        
        resource_info = self._resources[resource_id]
        success = True
        
        # Run cleanup callback if available
        if resource_id in self._cleanup_callbacks:
            try:
                cleanup_func = self._cleanup_callbacks[resource_id]
                if asyncio.iscoroutinefunction(cleanup_func):
                    await cleanup_func()
                else:
                    cleanup_func()
            except Exception as e:
                logger.error(f"Error cleaning up resource {resource_id}: {e}")
                success = False
                
                if not force_cleanup:
                    return False
        
        # Remove from tracking
        del self._resources[resource_id]
        self._cleanup_callbacks.pop(resource_id, None)
        self._weak_refs.pop(resource_id, None)
        
        # Update metrics
        self._metrics[resource_info.resource_type].total_destroyed += 1
        self._metrics[resource_info.resource_type].currently_active -= 1
        
        logger.debug(f"Unregistered resource {resource_id}")
        return success
    
    async def _handle_gc_cleanup(self, resource_id: str) -> None:
        """Handle automatic cleanup when resource is garbage collected."""
        if resource_id in self._resources:
            logger.warning(f"Resource {resource_id} was garbage collected without proper cleanup")
            resource_info = self._resources[resource_id]
            self._metrics[resource_info.resource_type].leak_count += 1
            await self.unregister_resource(resource_id, force_cleanup=True)
    
    async def _cleanup_loop(self) -> None:
        """Background cleanup loop."""
        while not self._shutdown_event.is_set():
            try:
                await self._perform_cleanup()
                await asyncio.wait_for(
                    self._shutdown_event.wait(), 
                    timeout=self.cleanup_interval
                )
            except asyncio.TimeoutError:
                continue  # Normal timeout, continue cleanup
            except Exception as e:
                logger.error(f"Error in resource cleanup loop: {e}")
                await asyncio.sleep(60)  # Wait before retrying
    
    async def _perform_cleanup(self) -> None:
        """Perform periodic resource cleanup."""
        now = datetime.now(timezone.utc)
        stale_resources = []
        
        # Find stale resources
        for resource_id, resource_info in self._resources.items():
            if (resource_info.age_seconds > self.max_resource_age or 
                resource_info.idle_seconds > self.max_idle_time):
                stale_resources.append(resource_id)
        
        # Clean up stale resources
        if stale_resources:
            logger.info(f"Cleaning up {len(stale_resources)} stale resources")
            
            for resource_id in stale_resources:
                try:
                    await self.unregister_resource(resource_id, force_cleanup=True)
                except Exception as e:
                    logger.error(f"Failed to cleanup stale resource {resource_id}: {e}")
        
        # Update cleanup metrics
        for metrics in self._metrics.values():
            metrics.last_cleanup = now
        
        # Force garbage collection if enabled
        if self.enable_gc_monitoring:
            gc.collect()
        
        # Log resource status
        await self._log_resource_status()
    
    async def _force_cleanup_all(self) -> None:
        """Force cleanup of all registered resources."""
        logger.info(f"Force cleaning up {len(self._resources)} remaining resources")
        
        # Copy keys to avoid dictionary change during iteration
        resource_ids = list(self._resources.keys())
        
        for resource_id in resource_ids:
            try:
                await self.unregister_resource(resource_id, force_cleanup=True)
            except Exception as e:
                logger.error(f"Failed to force cleanup resource {resource_id}: {e}")
    
    async def _log_resource_status(self) -> None:
        """Log current resource status."""
        total_resources = len(self._resources)
        memory_usage = self._process.memory_info().rss
        memory_growth = memory_usage - self._initial_memory
        
        logger.debug(
            f"Resource status: {total_resources} tracked, "
            f"Memory: {memory_usage / 1024 / 1024:.1f}MB "
            f"({memory_growth / 1024 / 1024:+.1f}MB growth)"
        )
        
        # Log metrics for each resource type
        for resource_type, metrics in self._metrics.items():
            if metrics.total_created > 0:
                logger.debug(
                    f"{resource_type.value}: "
                    f"active={metrics.currently_active}, "
                    f"peak={metrics.peak_usage}, "
                    f"leaks={metrics.leak_count}"
                )
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get comprehensive resource metrics."""
        memory_info = self._process.memory_info()
        
        return {
            "total_tracked_resources": len(self._resources),
            "memory_usage_mb": memory_info.rss / 1024 / 1024,
            "memory_growth_mb": (memory_info.rss - self._initial_memory) / 1024 / 1024,
            "resource_metrics": {
                rt.value: {
                    "active": metrics.currently_active,
                    "total_created": metrics.total_created,
                    "total_destroyed": metrics.total_destroyed,
                    "peak_usage": metrics.peak_usage,
                    "leak_count": metrics.leak_count,
                    "potential_leaks": metrics.potential_leaks
                }
                for rt, metrics in self._metrics.items()
            },
            "last_cleanup": max(
                (m.last_cleanup for m in self._metrics.values() if m.last_cleanup),
                default=None
            )
        }
    
    def get_resource_details(self) -> List[Dict[str, Any]]:
        """Get detailed information about all tracked resources."""
        return [
            {
                "resource_id": resource_id,
                "type": info.resource_type.value,
                "age_seconds": info.age_seconds,
                "idle_seconds": info.idle_seconds,
                "created_at": info.created_at.isoformat(),
                "last_accessed": info.last_accessed.isoformat(),
                "metadata": info.metadata
            }
            for resource_id, info in self._resources.items()
        ]
    
    @asynccontextmanager
    async def managed_resource(self, 
                              resource_id: str,
                              resource_type: ResourceType,
                              resource_factory: Callable,
                              cleanup_callback: Optional[Callable] = None,
                              metadata: Dict[str, Any] = None):
        """
        Context manager for automatic resource lifecycle management.
        
        Args:
            resource_id: Unique identifier for the resource
            resource_type: Type of resource
            resource_factory: Function to create the resource
            cleanup_callback: Function to cleanup the resource
            metadata: Additional metadata
        """
        resource = None
        try:
            # Create resource
            if asyncio.iscoroutinefunction(resource_factory):
                resource = await resource_factory()
            else:
                resource = resource_factory()
            
            # Register resource
            self.register_resource(
                resource_id=resource_id,
                resource_type=resource_type,
                resource_obj=resource,
                cleanup_callback=cleanup_callback,
                metadata=metadata
            )
            
            yield resource
            
        finally:
            # Cleanup resource
            await self.unregister_resource(resource_id)


# Global resource manager instance
_resource_manager: Optional[ResourceManager] = None


def get_resource_manager() -> ResourceManager:
    """Get the global resource manager instance."""
    global _resource_manager
    if _resource_manager is None:
        _resource_manager = ResourceManager()
    return _resource_manager


async def start_resource_manager() -> None:
    """Start the global resource manager."""
    manager = get_resource_manager()
    await manager.start()


async def stop_resource_manager() -> None:
    """Stop the global resource manager."""
    global _resource_manager
    if _resource_manager:
        await _resource_manager.stop()
        _resource_manager = None