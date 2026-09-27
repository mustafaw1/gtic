"""Cache interface for threat intelligence data."""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List
from datetime import datetime


class CacheInterface(ABC):
    """Interface for cache operations"""

    @abstractmethod
    async def get(self, key: str) -> Optional[Dict[str, Any]]:
        """Get cached data by key"""
        pass

    @abstractmethod
    async def set(self, key: str, value: Dict[str, Any], ttl: int = None) -> bool:
        """Set cached data with optional TTL"""
        pass

    @abstractmethod
    async def delete(self, key: str) -> bool:
        """Delete cached data by key"""
        pass

    @abstractmethod
    async def exists(self, key: str) -> bool:
        """Check if key exists in cache"""
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """Check cache health"""
        pass

    @abstractmethod
    async def mget(self, keys: List[str]) -> List[Optional[Dict[str, Any]]]:
        """Get multiple cached data by keys"""
        pass

    @abstractmethod
    async def close(self) -> None:
        """Close cache connections"""
        pass