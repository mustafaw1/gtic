"""Domain models for threat intelligence processing."""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone, timedelta
import ipaddress
import re


@dataclass
class IPAddress:
    """Value object for IP addresses with validation"""
    
    value: str
    
    def __post_init__(self):
        """Validate IP address on creation"""
        try:
            self.ip_obj = ipaddress.ip_address(self.value)
        except ValueError as e:
            raise ValueError(f"Invalid IP address: {self.value}") from e
    
    @property
    def version(self) -> int:
        """Get IP version (4 or 6)"""
        return self.ip_obj.version
    
    @property
    def is_private(self) -> bool:
        """Check if IP is private"""
        return self.ip_obj.is_private
    
    @property
    def is_multicast(self) -> bool:
        """Check if IP is multicast"""
        return self.ip_obj.is_multicast
    
    @property
    def is_reserved(self) -> bool:
        """Check if IP is reserved"""
        return self.ip_obj.is_reserved
    
    def __str__(self) -> str:
        return self.value


@dataclass
class DomainName:
    """Value object for domain names with validation"""
    
    value: str
    
    def __post_init__(self):
        """Validate domain name on creation"""
        self.value = self.value.strip().lower()
        if not self._is_valid_domain():
            raise ValueError(f"Invalid domain name: {self.value}")
    
    def _is_valid_domain(self) -> bool:
        """Validate domain name format"""
        if not self.value or len(self.value) > 253:
            return False
        
        if self.value.endswith('.'):
            self.value = self.value[:-1]
        
        domain_pattern = re.compile(
            r'^(?=.{1,253}$)'  # Total length check
            r'(?!-)'  # Cannot start with hyphen
            r'(?:[a-zA-Z0-9-]{1,63}(?<!-)\.)*'  # Subdomains
            r'[a-zA-Z0-9-]{1,63}(?<!-)$'  # Final domain
        )
        
        return bool(domain_pattern.match(self.value))
    
    @property
    def is_subdomain(self) -> bool:
        """Check if this is a subdomain"""
        return len(self.value.split('.')) > 2
    
    @property
    def root_domain(self) -> str:
        """Get the root domain (last two parts)"""
        parts = self.value.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return self.value
    
    def __str__(self) -> str:
        return self.value


@dataclass
class ThreatData:
    """Domain model for threat intelligence data"""
    
    ip_address: IPAddress
    log_id: str
    threat_score: int = 0
    threat_level: int = 0
    threat_categories: str = ""
    source_name: str = ""
    country_code: Optional[str] = None
    total_reports: int = 0
    first_seen: Optional[datetime] = None
    last_fetched: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    raw_data: Optional[Dict[str, Any]] = None
    
    from_redis: bool = False
    from_db: bool = False
    from_db_recache: bool = False
    from_api: bool = False
    
    def __post_init__(self):
        """Validate fields and set default timestamps."""
        if not (0 <= self.threat_score <= 10):
            raise ValueError(f"threat_score must be 0-10, got {self.threat_score}")
        if self.last_fetched is None:
            self.last_fetched = datetime.now(timezone.utc)
        if self.first_seen is None:
            self.first_seen = self.last_fetched

    @property
    def is_expired(self) -> bool:
        """Check if threat data is expired"""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization (ISO strings for datetimes)"""
        return {
            'ip_address': str(self.ip_address),
            'log_id': self.log_id,
            'threat_score': self.threat_score,
            'threat_level': self.threat_level,
            'threat_categories': self.threat_categories,
            'source_name': self.source_name,
            'country_code': self.country_code,
            'total_reports': self.total_reports,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_fetched': self.last_fetched.isoformat() if self.last_fetched else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'raw_data': self.raw_data,
            'from_redis': self.from_redis,
            'from_db': self.from_db,
            'from_db_recache': self.from_db_recache,
            'from_api': self.from_api
        }
    
    def to_db_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for database storage (datetime objects preserved)"""
        expires_at = self.expires_at
        if expires_at is None:
            expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        return {
            'ip_address': str(self.ip_address),
            'threat_score': self.threat_score,
            'threat_level': self.threat_level,
            'threat_categories': self.threat_categories,
            'source_name': self.source_name,
            'country_code': self.country_code,
            'total_reports': self.total_reports,
            'first_seen': self.first_seen,
            'last_fetched': self.last_fetched,
            'expires_at': expires_at,
            'raw_data': self.raw_data
        }


@dataclass
class DomainThreatData:
    """Domain model for domain threat intelligence data"""
    
    domain_name: DomainName
    log_id: str
    threat_score: int = 0
    threat_level: int = 0
    threat_categories: str = ""
    source_name: str = ""
    total_reports: int = 0
    first_seen: Optional[datetime] = None
    last_fetched: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    raw_data: Optional[Dict[str, Any]] = None
    
    from_redis: bool = False
    from_db: bool = False
    from_db_recache: bool = False
    from_api: bool = False
    
    def __post_init__(self):
        """Validate fields and set default timestamps."""
        if not (0 <= self.threat_score <= 10):
            raise ValueError(f"threat_score must be 0-10, got {self.threat_score}")
        if self.last_fetched is None:
            self.last_fetched = datetime.now(timezone.utc)
        if self.first_seen is None:
            self.first_seen = self.last_fetched

    @property
    def is_expired(self) -> bool:
        """Check if domain threat data is expired"""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization (ISO strings for datetimes)"""
        return {
            'domain_name': str(self.domain_name),
            'log_id': self.log_id,
            'threat_score': self.threat_score,
            'threat_level': self.threat_level,
            'threat_categories': self.threat_categories,
            'source_name': self.source_name,
            'total_reports': self.total_reports,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_fetched': self.last_fetched.isoformat() if self.last_fetched else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'raw_data': self.raw_data,
            'from_redis': self.from_redis,
            'from_db': self.from_db,
            'from_db_recache': self.from_db_recache,
            'from_api': self.from_api
        }
    
    def to_db_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for database storage (datetime objects preserved)"""
        expires_at = self.expires_at
        if expires_at is None:
            expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        return {
            'domain_name': str(self.domain_name),
            'threat_score': self.threat_score,
            'threat_level': self.threat_level,
            'threat_categories': self.threat_categories,
            'source_name': self.source_name,
            'total_reports': self.total_reports,
            'first_seen': self.first_seen,
            'last_fetched': self.last_fetched,
            'expires_at': expires_at,
            'raw_data': self.raw_data
        }


@dataclass
class HashValue:
    """Value object for file hashes with validation"""
    
    value: str
    hash_type: str = "sha256"
    
    def __post_init__(self):
        """Validate hash on creation"""
        self.value = self.value.strip().lower()
        self.hash_type = self.hash_type.strip().lower()
        
        if not self._is_valid_hash():
            raise ValueError(f"Invalid hash: {self.value}")
    
    def _is_valid_hash(self) -> bool:
        """Validate hash format"""
        if not self.value:
            return False
        
        if not re.match(r'^[a-f0-9]+$', self.value):
            return False
        
        valid_lengths = {
            'md5': 32,
            'sha1': 40,
            'sha256': 64
        }
        
        expected_length = valid_lengths.get(self.hash_type)
        if expected_length is None:
            return False
        
        return len(self.value) == expected_length
    
    def __str__(self) -> str:
        return self.value


@dataclass
class HashThreatData:
    """Domain model for file hash threat intelligence data"""
    
    hash_value: HashValue
    log_id: str
    threat_score: int = 0
    threat_level: int = 0
    threat_categories: str = ""
    source_name: str = ""
    total_reports: int = 0
    first_seen: Optional[datetime] = None
    last_fetched: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    raw_data: Optional[Dict[str, Any]] = None
    
    from_redis: bool = False
    from_db: bool = False
    from_db_recache: bool = False
    from_api: bool = False
    
    def __post_init__(self):
        """Validate fields and set default timestamps."""
        if not (0 <= self.threat_score <= 10):
            raise ValueError(f"threat_score must be 0-10, got {self.threat_score}")
        if self.last_fetched is None:
            self.last_fetched = datetime.now(timezone.utc)
        if self.first_seen is None:
            self.first_seen = self.last_fetched

    @property
    def is_expired(self) -> bool:
        """Check if hash threat data is expired"""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization (ISO strings for datetimes)"""
        return {
            'hash_value': str(self.hash_value),
            'hash_type': self.hash_value.hash_type,
            'log_id': self.log_id,
            'threat_score': self.threat_score,
            'threat_level': self.threat_level,
            'threat_categories': self.threat_categories,
            'source_name': self.source_name,
            'total_reports': self.total_reports,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_fetched': self.last_fetched.isoformat() if self.last_fetched else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'raw_data': self.raw_data,
            'from_redis': self.from_redis,
            'from_db': self.from_db,
            'from_db_recache': self.from_db_recache,
            'from_api': self.from_api
        }
    
    def to_db_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for database storage (datetime objects preserved)"""
        expires_at = self.expires_at
        if expires_at is None:
            expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
        
        return {
            'hash_value': str(self.hash_value),
            'hash_type': self.hash_value.hash_type,
            'threat_score': self.threat_score,
            'threat_level': self.threat_level,
            'threat_categories': self.threat_categories,
            'source_name': self.source_name,
            'total_reports': self.total_reports,
            'first_seen': self.first_seen,
            'last_fetched': self.last_fetched,
            'expires_at': expires_at,
            'raw_data': self.raw_data
        }


@dataclass
class HashProcessingResult:
    """Result of hash processing operation"""
    
    cached_hashes: List[HashThreatData] = field(default_factory=list)
    not_found_hashes: List[Dict[str, str]] = field(default_factory=list)
    
    redis_hits: int = 0
    postgresql_hits: int = 0
    external_api_calls: int = 0
    errors: List[str] = field(default_factory=list)
    
    @property
    def total_processed(self) -> int:
        """Total number of hashes processed"""
        return len(self.cached_hashes) + len(self.not_found_hashes)
    
    @property
    def cache_hit_rate(self) -> float:
        """Calculate cache hit rate percentage"""
        if self.total_processed == 0:
            return 0.0
        cache_hits = self.redis_hits + self.postgresql_hits
        return (cache_hits / self.total_processed) * 100
    
    def add_error(self, error: str) -> None:
        """Add an error to the result"""
        self.errors.append(error)
    
    def to_stats_dict(self) -> Dict[str, int]:
        """Get statistics as dictionary"""
        return {
            'redis_hits': self.redis_hits,
            'postgresql_hits': self.postgresql_hits,
            'external_api_calls': self.external_api_calls
        }


@dataclass
class DomainProcessingResult:
    """Result of domain processing operation"""
    
    cached_domains: List[DomainThreatData] = field(default_factory=list)
    not_found_domains: List[Dict[str, str]] = field(default_factory=list)
    
    redis_hits: int = 0
    postgresql_hits: int = 0
    external_api_calls: int = 0
    errors: List[str] = field(default_factory=list)
    
    @property
    def total_processed(self) -> int:
        """Total number of domains processed"""
        return len(self.cached_domains) + len(self.not_found_domains)
    
    @property
    def cache_hit_rate(self) -> float:
        """Calculate cache hit rate percentage"""
        if self.total_processed == 0:
            return 0.0
        cache_hits = self.redis_hits + self.postgresql_hits
        return (cache_hits / self.total_processed) * 100
    
    def add_error(self, error: str) -> None:
        """Add an error to the result"""
        self.errors.append(error)
    
    def to_stats_dict(self) -> Dict[str, int]:
        """Get statistics as dictionary"""
        return {
            'redis_hits': self.redis_hits,
            'postgresql_hits': self.postgresql_hits,
            'external_api_calls': self.external_api_calls
        }


@dataclass
class ProcessingResult:
    """Result of IP processing operation"""
    
    cached_ips: List[ThreatData] = field(default_factory=list)
    not_found_ips: List[Dict[str, str]] = field(default_factory=list)
    
    redis_hits: int = 0
    postgresql_hits: int = 0
    external_api_calls: int = 0
    errors: List[str] = field(default_factory=list)
    
    @property
    def total_processed(self) -> int:
        """Total number of IPs processed"""
        return len(self.cached_ips) + len(self.not_found_ips)
    
    @property
    def cache_hit_rate(self) -> float:
        """Calculate cache hit rate percentage"""
        if self.total_processed == 0:
            return 0.0
        cache_hits = self.redis_hits + self.postgresql_hits
        return (cache_hits / self.total_processed) * 100
    
    def add_error(self, error: str) -> None:
        """Add an error to the result"""
        self.errors.append(error)
    
    def to_stats_dict(self) -> Dict[str, int]:
        """Get statistics as dictionary"""
        return {
            'redis_hits': self.redis_hits,
            'postgresql_hits': self.postgresql_hits,
            'external_api_calls': self.external_api_calls
        }