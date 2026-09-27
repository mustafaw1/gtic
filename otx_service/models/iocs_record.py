"""
IOCs (Indicators of Compromise) record models for OTX service
Includes domains and IPs with threat intelligence data
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel
import pickle


class DomainCacheRecord(BaseModel):
    """Optimized domain cache record with custom serialization"""
    
    domain_name: str
    threat_score: int
    threat_level: int
    threat_categories: str
    source_name: str
    first_seen: datetime
    last_fetched: datetime
    details: bytes
    expires_at: datetime
    total_reports: int

    def __reduce_ex__(self, protocol):
        """Custom serialization to reduce memory usage in cache"""
        return (
            DomainCacheRecord, 
            (
                self.domain_name,
                self.threat_score,
                self.threat_level,
                self.threat_categories,
                self.source_name,
                self.first_seen,
                self.last_fetched,
                self.details,
                self.expires_at,
                self.total_reports
            )
        )

    @classmethod
    def from_dict(cls, data: dict) -> 'DomainCacheRecord':
        """Create record from dictionary with validation"""
        return cls(**data)

    def to_tuple(self) -> tuple:
        """Convert to tuple for efficient database operations"""
        return (
            self.domain_name,
            self.threat_score,
            self.threat_level,
            self.threat_categories,
            self.source_name,
            self.first_seen,
            self.last_fetched,
            self.details,
            self.expires_at,
            self.total_reports
        )

    model_config = {
        "extra": "forbid",
        "arbitrary_types_allowed": True
    }


class IPCacheRecord(BaseModel):
    """Optimized IP cache record with custom serialization"""
    
    ip_address: str
    threat_score: int
    threat_level: int
    threat_categories: str
    source_name: str
    first_seen: datetime
    last_fetched: datetime
    details: bytes
    expires_at: datetime
    country_code: Optional[str]
    total_reports: int

    def __reduce_ex__(self, protocol):
        """Custom serialization to reduce memory usage in cache"""
        return (
            IPCacheRecord, 
            (
                self.ip_address,
                self.threat_score,
                self.threat_level,
                self.threat_categories,
                self.source_name,
                self.first_seen,
                self.last_fetched,
                self.details,
                self.expires_at,
                self.country_code,
                self.total_reports
            )
        )

    @classmethod
    def from_dict(cls, data: dict) -> 'IPCacheRecord':
        """Create record from dictionary with validation"""
        return cls(**data)

    def to_tuple(self) -> tuple:
        """Convert to tuple for efficient database operations"""
        return (
            self.ip_address,
            self.threat_score,
            self.threat_level,
            self.threat_categories,
            self.source_name,
            self.first_seen,
            self.last_fetched,
            self.details,
            self.expires_at,
            self.country_code,
            self.total_reports
        )

    model_config = {
        "extra": "forbid",
        "arbitrary_types_allowed": True
    }


class HashCacheRecord(BaseModel):
    """Optimized hash cache record with custom serialization"""
    
    hash_value: str
    hash_type: str
    threat_score: int
    threat_level: int
    threat_categories: str
    source_name: str
    first_seen: datetime
    last_fetched: datetime
    details: bytes
    expires_at: Optional[datetime]
    total_reports: int

    def __reduce_ex__(self, protocol):
        """Custom serialization to reduce memory usage in cache"""
        return (
            HashCacheRecord, 
            (
                self.hash_value,
                self.hash_type,
                self.threat_score,
                self.threat_level,
                self.threat_categories,
                self.source_name,
                self.first_seen,
                self.last_fetched,
                self.details,
                self.expires_at,
                self.total_reports
            )
        )

    @classmethod
    def from_dict(cls, data: dict) -> 'HashCacheRecord':
        """Create record from dictionary with validation"""
        return cls(**data)

    def to_tuple(self) -> tuple:
        """Convert to tuple for efficient database operations"""
        return (
            self.hash_value,
            self.hash_type,
            self.threat_score,
            self.threat_level,
            self.threat_categories,
            self.source_name,
            self.first_seen,
            self.last_fetched,
            self.details,
            self.expires_at,
            self.total_reports
        )

    model_config = {
        "extra": "forbid",
        "arbitrary_types_allowed": True
    }


class ProcessingStats(BaseModel):
    """Statistics for OTX processing run"""
    pulses_processed: int = 0
    pulses_skipped: int = 0
    pulses_failed: int = 0
    total_domains_processed: int = 0
    domains_newly_stored: int = 0
    domains_already_existed: int = 0
    total_ips_processed: int = 0
    ips_newly_stored: int = 0
    ips_already_existed: int = 0
    total_hashes_processed: int = 0
    hashes_newly_stored: int = 0
    hashes_already_existed: int = 0
    processing_time_seconds: float = 0
    memory_peak_mb: float = 0