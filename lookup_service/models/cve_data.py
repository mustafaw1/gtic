"""Domain models for CVE vulnerability data processing."""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone, timedelta
import re


@dataclass
class CVEId:
    """Value object for CVE identifiers with validation"""
    
    value: str
    
    def __post_init__(self):
        """Validate CVE ID format"""
        self.value = self.value.strip().upper()
        if not self._is_valid_cve():
            raise ValueError(f"Invalid CVE ID format: {self.value}")
    
    def _is_valid_cve(self) -> bool:
        """Validate CVE ID format: CVE-YYYY-NNNN"""
        pattern = re.compile(r'^CVE-\d{4}-\d{4,}$')
        return bool(pattern.match(self.value))
    
    def __str__(self) -> str:
        return self.value


@dataclass
class CVEData:
    """Domain model for CVE vulnerability data"""
    
    cve_id: CVEId
    score: float
    severity: str
    published: datetime
    last_modified: datetime
    
    source_identifier: Optional[str] = None
    vuln_status: Optional[str] = None
    description_en: Optional[str] = None
    cvss_v3_vector_string: Optional[str] = None
    epss_score: Optional[float] = None
    cvss_v2_base_score: Optional[float] = None
    cvss_v2_severity: Optional[str] = None
    cisa_exploit_add: Optional[datetime] = None
    cisa_action_due: Optional[datetime] = None
    cisa_required_action: Optional[str] = None
    cisa_vulnerability_name: Optional[str] = None
    is_kev: bool = False
    weaknesses: Optional[Dict[str, Any]] = None
    references: Optional[Dict[str, Any]] = None
    raw_data: Optional[Dict[str, Any]] = None
    first_fetched: Optional[datetime] = None
    last_fetched: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    from_redis: bool = False
    from_db: bool = False
    from_api: bool = False
    log_id: Optional[str] = None
    criteria: Optional[Dict[str, Any]] = None
    affected_cpes: Optional[List[str]] = None
    configurations: Optional[List] = None
    confirmed_vulnerable: bool = False
    match_type: str = ""
    
    def __post_init__(self):
        """Set default timestamps"""
        if self.last_fetched is None:
            self.last_fetched = datetime.now(timezone.utc)
        if self.first_fetched is None:
            self.first_fetched = self.last_fetched
    
    @property
    def is_expired(self) -> bool:
        """Check if CVE data is expired"""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at
    
    @property
    def normalized_score(self) -> int:
        """Convert CVSS score (0-10) to normalized score (0-100)"""
        return int(self.score * 10)
    
    @property
    def threat_level(self) -> int:
        """Convert severity to threat level (0-3)"""
        severity_map = {
            "CRITICAL": 3,
            "HIGH": 2,
            "MEDIUM": 1,
            "LOW": 0,
            "NONE": 0
        }
        return severity_map.get(self.severity.upper(), 0)
    
    def _extract_remediation_urls(self, *tags: str) -> List[str]:
        """Return deduplicated URLs from references whose tags include any of the given tags."""
        if not self.references:
            return []
        seen = set()
        urls = []
        refs = self.references if isinstance(self.references, list) else []
        for ref in refs:
            url = ref.get('url', '')
            ref_tags = ref.get('tags', [])
            if url and any(t in ref_tags for t in tags) and url not in seen:
                seen.add(url)
                urls.append(url)
        return urls

    def _extract_cwe_ids(self) -> List[str]:
        """Extract CWE identifiers from the weaknesses structure returned by NVD.
        NVD returns weaknesses as a list of objects, each with a description array.
        """
        if not self.weaknesses:
            return []
        weaknesses_list = self.weaknesses if isinstance(self.weaknesses, list) else [self.weaknesses]
        seen = set()
        ids = []
        for weakness in weaknesses_list:
            for entry in weakness.get('description', []):
                val = entry.get('value', '')
                if val.startswith('CWE-') and val not in seen:
                    seen.add(val)
                    ids.append(val)
        return ids

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'id': str(self.cve_id),
            'source_api': 'NVD',
            'score': self.score,
            'severity': self.severity,
            'published': self.published.isoformat() if self.published else None,
            'last_modified': self.last_modified.isoformat() if self.last_modified else None,
            'source_identifier': self.source_identifier,
            'vuln_status': self.vuln_status,
            'cvss_v3_vector_string': self.cvss_v3_vector_string,
            'epss_score': self.epss_score,
            'description_en': self.description_en,
            'is_kev': self.is_kev or bool(self.cisa_exploit_add or self.cisa_vulnerability_name),
            'cwe_ids': self._extract_cwe_ids(),
            'cisa_required_action': self.cisa_required_action,
            'cisa_exploit_add': self.cisa_exploit_add.isoformat() if self.cisa_exploit_add else None,
            'cisa_action_due': self.cisa_action_due.isoformat() if self.cisa_action_due else None,
            'patch_urls': self._extract_remediation_urls('Patch'),
            'vendor_advisories': self._extract_remediation_urls('Vendor Advisory'),
            'first_fetched': self.first_fetched.isoformat() if self.first_fetched else None,
            'last_fetched': self.last_fetched.isoformat() if self.last_fetched else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'from_redis': self.from_redis,
            'from_db': self.from_db,
            'from_api': self.from_api,
            'log_id': self.log_id,
            'criteria': self.criteria,
            'affected_cpes': self.affected_cpes,
            'confirmed_vulnerable': self.confirmed_vulnerable,
            'match_type': self.match_type,
        }
    
    def to_db_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for database storage"""
        expires_at = self.expires_at
        if expires_at is None:
            if self.severity == "CRITICAL":
                expires_at = datetime.now(timezone.utc) + timedelta(days=30)
            elif self.severity == "HIGH":
                expires_at = datetime.now(timezone.utc) + timedelta(days=7)
            else:
                expires_at = datetime.now(timezone.utc) + timedelta(days=3)
        
        return {
            'id': str(self.cve_id),
            'configurations': self.configurations,
            'score': self.score,
            'severity': self.severity,
            'published': self.published,
            'last_modified': self.last_modified,
            'source_identifier': self.source_identifier,
            'vuln_status': self.vuln_status,
            'description_en': self.description_en,
            'cvss_v3_vector_string': self.cvss_v3_vector_string,
            'cvss_v2_base_score': self.cvss_v2_base_score,
            'cvss_v2_severity': self.cvss_v2_severity,
            'cisa_exploit_add': self.cisa_exploit_add.date() if self.cisa_exploit_add else None,
            'cisa_action_due': self.cisa_action_due.date() if self.cisa_action_due else None,
            'cisa_required_action': self.cisa_required_action,
            'cisa_vulnerability_name': self.cisa_vulnerability_name,
            'weaknesses': self.weaknesses,
            'references': self.references,
            'raw_data': self.raw_data,
            'first_fetched': self.first_fetched,
            'last_fetched': self.last_fetched,
            'expires_at': expires_at
        }


@dataclass
class CVEProcessingResult:
    """Result of CVE processing operation"""
    
    matched_cves: List[CVEData] = field(default_factory=list)
    not_found_cpes: List[str] = field(default_factory=list)
    
    redis_hits: int = 0
    postgresql_hits: int = 0
    external_api_calls: int = 0
    errors: List[str] = field(default_factory=list)
    
    @property
    def total_processed(self) -> int:
        """Total number of CPEs processed"""
        return len(self.matched_cves) + len(self.not_found_cpes)
    
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
