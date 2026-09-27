"""Database repository interface for threat intelligence data."""

from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any


class DatabaseRepositoryInterface(ABC):
    """Interface for database operations"""

    @abstractmethod
    async def find_by_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Find threat data by IP address"""
        pass

    @abstractmethod
    async def find_by_ips(self, ip_addresses: List[str]) -> List[Dict[str, Any]]:
        """Find threat data for multiple IP addresses"""
        pass

    @abstractmethod
    async def save(self, threat_data: Dict[str, Any]) -> bool:
        """Save single threat data record"""
        pass

    @abstractmethod
    async def save_batch(self, threat_data_list: List[Dict[str, Any]]) -> bool:
        """Save multiple threat data records"""
        pass

    @abstractmethod
    async def find_by_hash(self, hash_value: str, hash_type: str = "sha256") -> Optional[Dict[str, Any]]:
        """Find threat data by file hash"""
        pass

    @abstractmethod
    async def find_by_hashes(self, hash_list: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        """Find threat data for multiple hashes"""
        pass

    @abstractmethod
    async def find_by_cpe_batch(self, cpe_strings: List[str]) -> Dict[str, List[Dict[str, Any]]]:
        """Bulk CVE lookup for N CPE strings — returns {cpe_string: [CVE dicts]}"""
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """Check database health"""
        pass

    @abstractmethod
    async def close(self) -> None:
        """Close database connections"""
        pass