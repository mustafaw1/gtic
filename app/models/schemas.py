from pydantic import BaseModel, Field, field_validator
from typing import List, Optional, Any, Dict
from datetime import datetime, timezone
import ipaddress
import re

_CVE_ID_PATTERN = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)


class IPData(BaseModel):
    """Single IP address with its log ID"""
    ip_address: str
    log_id: str
    rule_tier: Optional[int] = Field(
        default=None,
        ge=0,
        le=3,
        description=(
            "Behavioral detection severity (0=Low, 1=Medium, 2=High, 3=Critical). "
            "When provided and >= 2, the IP is automatically promoted to malicious "
            "status in the GTIC if no external source classifies it."
        ),
    )
    agent_id: Optional[str] = None
    threat_categories: Optional[str] = None

    @field_validator('ip_address')
    @classmethod
    def validate_ip(cls, v: str) -> str:
        """Validate IP address format"""
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            raise ValueError(f"Invalid IP address format: {v}")


class DomainData(BaseModel):
    """Single domain with its log ID"""
    domain_name: str
    log_id: str
    
    @field_validator('domain_name')
    @classmethod
    def validate_domain(cls, v: str) -> str:
        """Basic domain validation"""
        if not v or not v.strip():
            raise ValueError("Domain name cannot be empty")
        
        domain = v.strip().lower()
        if len(domain) > 253:
            raise ValueError("Domain name too long")
        
        if '.' not in domain or domain.startswith('.') or domain.endswith('.'):
            raise ValueError(f"Invalid domain format: {v}")
            
        return domain


class HashData(BaseModel):
    """Single hash with its log ID and auto-detected type"""
    hash_value: str
    log_id: str
    hash_type: Optional[str] = None
    
    def __init__(self, **data):
        if 'hash_value' in data and ('hash_type' not in data or data['hash_type'] is None):
            hash_value = data['hash_value'].strip().lower()
            data['hash_type'] = self._detect_hash_type(hash_value)
        super().__init__(**data)
    
    @staticmethod
    def _detect_hash_type(hash_value: str) -> str:
        """Auto-detect hash type from hash value length"""
        length_to_type = {
            32: "md5",
            40: "sha1", 
            64: "sha256"
        }
        return length_to_type.get(len(hash_value), "unknown")
    
    @field_validator('hash_value')
    @classmethod
    def validate_hash(cls, v: str) -> str:
        """Validate hash format"""
        if not v or not v.strip():
            raise ValueError("Hash value cannot be empty")
        
        hash_value = v.strip().lower()
        
        if not re.match(r'^[a-f0-9]+$', hash_value):
            raise ValueError(f"Hash must contain only hexadecimal characters: {v}")
        
        valid_lengths = {32, 40, 64}
        
        if len(hash_value) not in valid_lengths:
            raise ValueError(
                f"Invalid hash length: {len(hash_value)}. "
                f"Expected lengths: 32 (MD5), 40 (SHA1), 64 (SHA256)"
            )
        
        return hash_value


class CheckIOCsRequest(BaseModel):
    """Request payload for checking IOCs (IPs, domains, and hashes)"""
    generated_at: datetime
    total_ips: Optional[int] = 0
    total_domains: Optional[int] = 0
    total_hashes: Optional[int] = 0
    ip_data: Optional[List[IPData]] = []
    domains_data: Optional[List[DomainData]] = []
    hashes_data: Optional[List[HashData]] = []

    @field_validator('ip_data')
    @classmethod
    def validate_ip_count(cls, v: Optional[List[IPData]], info) -> List[IPData]:
        """Ensure total_ips matches actual IP count"""
        if v is None:
            v = []
        total_ips = info.data.get('total_ips', 0)
        if total_ips is not None and len(v) != total_ips:
            raise ValueError(f"total_ips ({total_ips}) doesn't match actual IP count ({len(v)})")
        return v

    @field_validator('domains_data')
    @classmethod
    def validate_domain_count(cls, v: Optional[List[DomainData]], info) -> List[DomainData]:
        """Ensure total_domains matches actual domain count"""
        if v is None:
            v = []
        total_domains = info.data.get('total_domains', 0)
        if total_domains is not None and len(v) != total_domains:
            raise ValueError(f"total_domains ({total_domains}) doesn't match actual domain count ({len(v)})")
        return v

    @field_validator('hashes_data')
    @classmethod
    def validate_hash_count(cls, v: Optional[List[HashData]], info) -> List[HashData]:
        """Ensure total_hashes matches actual hash count"""
        if v is None:
            v = []
        total_hashes = info.data.get('total_hashes', 0)
        if total_hashes is not None and len(v) != total_hashes:
            raise ValueError(f"total_hashes ({total_hashes}) doesn't match actual hash count ({len(v)})")
        return v


class CachedIPResult(BaseModel):
    """IP found in cache with threat data"""
    ip_address: str
    log_id: str
    threat_score: int = Field(ge=0, le=10)
    threat_level: int
    threat_categories: str
    source_name: str
    country_code: Optional[str] = None
    total_reports: int
    last_fetched: datetime
    expires_at: Optional[datetime] = None
    details: Optional[dict] = None


class NotFoundIP(BaseModel):
    """IP not found in cache"""
    ip_address: str
    log_id: str


class CheckIOCsResponse(BaseModel):
    """Response with cached and not found IOCs (IPs, domains, and hashes)"""
    processed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    total_requested: int
    cache_hits: int
    cache_misses: int
    redis_hits: int
    postgresql_hits: int
    external_api_calls: int
    cached_ips: List[dict]
    not_found_ips: List[dict]
    cached_domains: Optional[List[dict]] = []
    not_found_domains: Optional[List[dict]] = []
    cached_hashes: Optional[List[dict]] = []
    not_found_hashes: Optional[List[dict]] = []
    cve_correlation: Optional[dict] = None
    correlation_metadata: Optional[dict] = None


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    database: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AffectedDevice(BaseModel):
    """A single device affected by a software CPE"""
    device_id: str
    asset_name: str
    mac_level: Optional[str] = None
    env_vector: Optional[str] = None
    cpe_confidence: Optional[int] = None


class CPECollectorMeta(BaseModel):
    """Asset metadata attached to each CPE entry from cpe_collector.

    OS items supply flat device fields (asset_name, device_id, …).
    Software items supply software fields and an affected_devices list.
    All fields are passed through to the response unchanged.
    """
    asset_name: Optional[str] = None
    device_id: Optional[str] = None
    mac_level: Optional[str] = None
    env_vector: Optional[str] = None
    cpe_confidence: Optional[int] = None
    catalog_id: Optional[str] = None
    software_name: Optional[str] = None
    software_version: Optional[str] = None
    vendor: Optional[str] = None
    affected_devices: Optional[List[AffectedDevice]] = None


class CPECollectorItem(BaseModel):
    """Single CPE entry as sent by cpe_collector"""
    cpe_string: str
    type: str
    meta: CPECollectorMeta

    @field_validator('cpe_string')
    @classmethod
    def validate_cpe(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("cpe_string cannot be empty")
        v = v.strip()
        if not v.startswith('cpe:'):
            raise ValueError(f"Invalid CPE format (must start with 'cpe:'): {v}")
        return v

    @field_validator('type')
    @classmethod
    def validate_type(cls, v: str) -> str:
        if v not in ('os', 'software'):
            raise ValueError(f"Invalid item type '{v}': expected 'os' or 'software'")
        return v


class CPECollectorRequest(BaseModel):
    """Payload sent by cpe_collector for bulk asset CVE lookup"""
    ioc_type: str
    items: List[CPECollectorItem]

    @field_validator('ioc_type')
    @classmethod
    def validate_ioc_type(cls, v: str) -> str:
        if v != 'cve':
            raise ValueError(f"Unsupported ioc_type '{v}': expected 'cve'")
        return v


class CPECollectorResponse(BaseModel):
    """Response for bulk asset CPE lookup"""
    processed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    total_cves_found: int
    results: List[Dict[str, Any]]


class CVELookupRequest(BaseModel):
    """Request for bulk CVE lookup by CVE identifier"""
    cve_ids: List[str] = Field(..., min_length=1)

    @field_validator('cve_ids')
    @classmethod
    def validate_cve_ids(cls, v: List[str]) -> List[str]:
        normalized = []
        for cve_id in v:
            cve_id = cve_id.strip().upper()
            if not _CVE_ID_PATTERN.match(cve_id):
                raise ValueError(f"Invalid CVE ID format (expected CVE-YYYY-NNNN): {cve_id}")
            normalized.append(cve_id)
        return normalized


class CVELookupStats(BaseModel):
    """Cache and API hit statistics for CVE lookup"""
    redis_hits: int = 0
    postgresql_hits: int = 0
    external_api_calls: int = 0


class CVELookupResponse(BaseModel):
    """Response for bulk CVE lookup by CVE identifier"""
    processed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    total_requested: int
    total_matched: int
    matched_cves: List[Dict[str, Any]]
    not_found_cve_ids: List[str]
    stats: CVELookupStats


class BehavioralPromotionRequest(BaseModel):
    """Request to promote a behaviorally-detected IP to malicious status in the GTIC."""
    ip_address: str
    log_id: str
    rule_tier: int = Field(ge=0, le=3, description="Detection severity tier (0=Low,1=Medium,2=High,3=Critical)")
    threat_categories: Optional[str] = None
    agent_id: Optional[str] = None

    @field_validator('ip_address')
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            raise ValueError(f"Invalid IP address format: {v}")


class BehavioralPromotionResponse(BaseModel):
    """Response after promoting a behaviorally-detected IP to the GTIC."""
    ip_address: str
    promoted: bool
    threat_score: int = 0
    threat_level: int = 0
    threat_categories: str = ""
    source_api: str = ""
    message: str
