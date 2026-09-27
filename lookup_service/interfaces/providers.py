"""Threat intelligence provider interfaces."""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from dataclasses import dataclass
from datetime import datetime


@dataclass
class ThreatResult:
    """Standard threat intelligence result"""
    ip_address: str
    threat_score: int
    threat_level: int
    threat_categories: str
    source_name: str
    country_code: Optional[str] = None
    total_reports: int = 0
    raw_data: Optional[Dict[str, Any]] = None
    fetched_at: Optional[datetime] = None


class ThreatProviderInterface(ABC):
    """Interface for threat intelligence providers"""

    @abstractmethod
    async def query_ip(self, ip_address: str) -> Optional[ThreatResult]:
        """Query threat intelligence for an IP address"""
        pass

    async def query_hash(self, hash_value: str, hash_type: str = "sha256") -> Optional[ThreatResult]:
        """
        Query threat intelligence for a file hash
        Default implementation returns None (not all providers support hashes)
        """
        return None

    async def query_domain(self, domain: str) -> Optional[ThreatResult]:
        """
        Query threat intelligence for a domain
        Default implementation returns None (not all providers support domains)
        """
        return None

    @abstractmethod
    async def health_check(self) -> bool:
        """Check provider health/availability"""
        pass

    @abstractmethod
    def get_provider_name(self) -> str:
        """Get provider name"""
        pass

    @abstractmethod
    async def close(self) -> None:
        """Close provider connections"""
        pass


class RateLimitedProviderInterface(ThreatProviderInterface):
    """Interface for providers with rate limiting"""

    @abstractmethod
    async def enforce_rate_limit(self) -> None:
        """Enforce rate limiting before making requests"""
        pass

    @abstractmethod
    def get_rate_limit_info(self) -> Dict[str, Any]:
        """Get current rate limit status"""
        pass
    
    def is_rate_limited(self) -> bool:
        """Check if provider is currently rate limited"""
        # Default implementation returns False for backward compatibility
        return False