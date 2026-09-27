"""NVD (National Vulnerability Database) API client implementation."""

import asyncio
import logging
import time
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List
import json

import httpx

from ..interfaces.providers import RateLimitedProviderInterface, ThreatResult
from ..models.cve_data import CVEId, CVEData

logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)


class NVDProvider(RateLimitedProviderInterface):
    """NVD API threat intelligence provider for CVE data"""
    
    def __init__(self, api_key: Optional[str] = None, mock_mode: bool = False, rate_limit: float = 0.67):
        """
        Initialize NVD provider
        
        Args:
            api_key: NVD API key (optional, but recommended for higher rate limits)
            mock_mode: Whether to use mock responses for testing
            rate_limit: Rate limit in seconds between requests (default: 0.67s = ~50 req/30s with API key)
        """
        self.api_key = api_key
        self.mock_mode = mock_mode
        self.rate_limit = rate_limit
        self.last_request_time = 0.0
        self._rate_limit_callback = None
        self._rate_lock = asyncio.Lock()
        
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cpe_url = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
        self.client: Optional[httpx.AsyncClient] = None
        
        self.mock_template = self._create_mock_template()
    
    async def connect(self) -> None:
        """Initialize HTTP client"""
        if not self.client:
            self.client = httpx.AsyncClient(timeout=30.0)
    
    async def query_cve(self, cve_id: str) -> Optional[CVEData]:
        """Query NVD API for a specific CVE"""
        if not self.client:
            await self.connect()
        
        await self.enforce_rate_limit()
        
        if self.mock_mode:
            return await self._query_mock(cve_id)
        else:
            return await self._query_real(cve_id)
    
    async def query_cves_by_cpe(self, cpe_string: str) -> List[CVEData]:
        """
        Query NVD API for CVEs affecting a specific CPE
        
        Args:
            cpe_string: CPE string (e.g., "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
            
        Returns:
            List of CVEData objects matching the CPE
        """
        if not self.client:
            await self.connect()
        
        await self.enforce_rate_limit()
        
        if self.mock_mode:
            return await self._query_cpe_mock(cpe_string)
        else:
            return await self._query_cpe_real(cpe_string)
    
    async def _query_real(self, cve_id: str) -> Optional[CVEData]:
        """Query real NVD API for specific CVE"""
        try:
            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key
            
            params = {"cveId": cve_id}
            response = await self.client.get(self.base_url, headers=headers, params=params)
            
            if response.status_code == 429:
                # Rate limit exceeded
                if self._rate_limit_callback:
                    self._rate_limit_callback("NVD", cve_id)
                logger.warning(f"NVD rate limit exceeded for {cve_id}")
                return None
            
            response.raise_for_status()
            data = response.json()
            
            return self._parse_nvd_response(data)
            
        except httpx.RequestError as e:
            logger.error(f"NVD API request error for {cve_id}: {e}")
            return None
        except Exception as e:
            logger.error(f"NVD API error for {cve_id}: {e}", exc_info=True)
            return None

    async def _fetch_registered_cpes(self, cpe_match_string: str) -> List[str]:
        """
        Query NVD CPE dictionary to resolve a CPE match string
        (with wildcards) into registered CPE names, including deprecated ones.
        """
        if not self.client:
            await self.connect()

        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        registered = []
        start_index = 0

        while True:
            await self.enforce_rate_limit()
            params = {
                "cpeMatchString": cpe_match_string,
                "resultsPerPage": 10000,
                "startIndex": start_index,
            }
            response = await self.client.get(self.cpe_url, params=params, headers=headers)

            if response.status_code == 429:
                logger.warning(f"NVD rate limit hit fetching CPEs for {cpe_match_string}")
                break

            response.raise_for_status()
            data = response.json()

            for product in data.get("products", []):
                cpe_name = product.get("cpe", {}).get("cpeName")
                if cpe_name:
                    registered.append(cpe_name)

            total_results = data.get("totalResults", 0)
            start_index += len(data.get("products", []))
            if start_index >= total_results or not data.get("products"):
                break

        logger.info(f"Resolved {len(registered)} registered CPEs for match string: {cpe_match_string}")
        return registered

    @staticmethod
    def _extract_criteria(configurations: list, registered_cpe: str) -> Optional[Dict[str, Any]]:
        """Find the cpeMatch entry in NVD configurations that matches the registered CPE."""
        parts = registered_cpe.split(':')
        cpe_base = ':'.join(parts[:5]) if len(parts) >= 5 else registered_cpe

        for config in (configurations or []):
            for node in config.get('nodes', []):
                for cpe_match in node.get('cpeMatch', []):
                    criteria = cpe_match.get('criteria', '')
                    if criteria == registered_cpe or criteria.startswith(cpe_base + ':'):
                        return cpe_match
        return None

    async def _query_cpe_real(self, cpe_string: str) -> List[CVEData]:
        """
        Query NVD CVEs API directly using cpeName — identical to how the NVD
        website searches. NVD performs internal version-range matching, so this
        returns every CVE where the given CPE version falls within any configured
        vulnerable range, regardless of whether the exact CPE is registered in
        the CPE dictionary.
        """
        if not self.client:
            await self.connect()

        try:
            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key

            seen_cve_ids: set = set()
            cve_list: List[CVEData] = []
            start_index = 0
            results_per_page = 2000

            while True:
                await self.enforce_rate_limit()
                params = {
                    "cpeName": cpe_string,
                    "resultsPerPage": results_per_page,
                    "startIndex": start_index,
                }
                response = await self.client.get(
                    self.base_url, params=params, headers=headers
                )

                if response.status_code == 429:
                    logger.warning(f"NVD rate limit hit for CPE {cpe_string}")
                    break

                response.raise_for_status()
                data = response.json()

                vulnerabilities = data.get("vulnerabilities", [])
                for vuln in vulnerabilities:
                    cve_data = self._parse_single_vulnerability(vuln)
                    if cve_data and str(cve_data.cve_id) not in seen_cve_ids:
                        seen_cve_ids.add(str(cve_data.cve_id))
                        cve_data.criteria = self._extract_criteria(
                            cve_data.configurations, cpe_string
                        )
                        cve_list.append(cve_data)

                total_results = data.get("totalResults", 0)
                start_index += len(vulnerabilities)
                if start_index >= total_results or not vulnerabilities:
                    break

            logger.info(f"Found {len(cve_list)} CVEs for CPE: {cpe_string}")
            return cve_list

        except Exception as e:
            logger.error(f"Error querying NVD API for CPE {cpe_string}: {e}", exc_info=True)
            return []
    
    def _parse_nvd_response(self, nvd_json: Dict[str, Any]) -> Optional[CVEData]:
        """Parse NVD API JSON response into CVEData object"""
        try:
            vulnerabilities = nvd_json.get("vulnerabilities", [])
            if not vulnerabilities:
                return None
            
            cve_obj = vulnerabilities[0].get("cve", {})
            cve_id_str = cve_obj.get("id")

            if not cve_id_str:
                return None

            cve_id = CVEId(cve_id_str)

            # Parse published and lastModified
            published_str = cve_obj.get("published")
            last_modified_str = cve_obj.get("lastModified")
            
            published = datetime.fromisoformat(published_str.replace('Z', '+00:00')) if published_str else datetime.now(timezone.utc)
            last_modified = datetime.fromisoformat(last_modified_str.replace('Z', '+00:00')) if last_modified_str else datetime.now(timezone.utc)
            
            # Parse CVSS v3.1 scores
            score = 0.0
            severity = "NONE"
            vector_string = None
            
            metrics = cve_obj.get("metrics", {})
            cvss_v31_list = metrics.get("cvssMetricV31", [])
            if cvss_v31_list:
                cvss_data = cvss_v31_list[0].get("cvssData", {})
                score = cvss_data.get("baseScore", 0.0)
                severity = cvss_data.get("baseSeverity", "NONE")
                vector_string = cvss_data.get("vectorString")
            else:
                cvss_v30_list = metrics.get("cvssMetricV30", [])
                if cvss_v30_list:
                    cvss_data = cvss_v30_list[0].get("cvssData", {})
                    score = cvss_data.get("baseScore", 0.0)
                    severity = cvss_data.get("baseSeverity", "NONE")
                    vector_string = cvss_data.get("vectorString")

            # Parse CVSS v2 (optional)
            cvss_v2_score = None
            cvss_v2_severity = None
            cvss_v2_list = metrics.get("cvssMetricV2", [])
            if cvss_v2_list:
                cvss_v2_data = cvss_v2_list[0].get("cvssData", {})
                cvss_v2_score = cvss_v2_data.get("baseScore")
                cvss_v2_severity = cvss_v2_list[0].get("baseSeverity")
            
            # Parse CISA KEV fields
            cisa_exploit_add = None
            if cve_obj.get("cisaExploitAdd"):
                try:
                    cisa_exploit_add = datetime.strptime(cve_obj["cisaExploitAdd"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
                except:
                    pass
            
            cisa_action_due = None
            if cve_obj.get("cisaActionDue"):
                try:
                    cisa_action_due = datetime.strptime(cve_obj["cisaActionDue"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
                except:
                    pass
            
            # Parse description (English)
            description_en = None
            descriptions = cve_obj.get("descriptions", [])
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description_en = desc.get("value")
                    break
            
            cve_data = CVEData(
                cve_id=cve_id,
                score=score,
                severity=severity,
                published=published,
                last_modified=last_modified,
                source_identifier=cve_obj.get("sourceIdentifier"),
                vuln_status=cve_obj.get("vulnStatus"),
                description_en=description_en,
                cvss_v3_vector_string=vector_string,
                cvss_v2_base_score=cvss_v2_score,
                cvss_v2_severity=cvss_v2_severity,
                cisa_exploit_add=cisa_exploit_add,
                cisa_action_due=cisa_action_due,
                cisa_required_action=cve_obj.get("cisaRequiredAction"),
                cisa_vulnerability_name=cve_obj.get("cisaVulnerabilityName"),
                weaknesses=cve_obj.get("weaknesses"),
                references=cve_obj.get("references"),
                raw_data=cve_obj,
                from_api=True
            )
            cve_data.configurations = cve_obj.get("configurations", [])
            if severity == "CRITICAL":
                cve_data.expires_at = datetime.now(timezone.utc) + timedelta(days=30)
            elif severity == "HIGH":
                cve_data.expires_at = datetime.now(timezone.utc) + timedelta(days=7)
            else:
                cve_data.expires_at = datetime.now(timezone.utc) + timedelta(days=3)
            logger.debug(f"NVD query successful for {cve_id_str}: score={score}, severity={severity}")
            return cve_data

        except Exception as e:
            logger.error(f"Error parsing NVD response: {e}", exc_info=True)
            return None
    
    async def _query_mock(self, cve_id: str) -> Optional[CVEData]:
        """Mock query for testing"""
        await asyncio.sleep(0.01)
        
        mock_data = self.mock_template.copy()
        mock_data["cve"]["id"] = cve_id
        
        return self._parse_nvd_response({"vulnerabilities": [mock_data]})
    
    async def _query_cpe_mock(self, cpe_string: str) -> List[CVEData]:
        """Mock CPE query for testing"""
        await asyncio.sleep(0.01)
        return []
    
    def _parse_single_vulnerability(self, vuln_obj: Dict[str, Any]) -> Optional[CVEData]:
        """Parse a single vulnerability object from NVD API response"""
        try:
            if isinstance(vuln_obj, list):
                if not vuln_obj:
                    return None
                vuln_obj = vuln_obj[0]
            
            if not isinstance(vuln_obj, dict):
                logger.error(f"Expected dict for vulnerability object, got {type(vuln_obj)}")
                return None
                
            cve_obj = vuln_obj.get("cve", {})
            cve_id_str = cve_obj.get("id")

            if not cve_id_str:
                return None

            if cve_obj.get("vulnStatus") in ("Rejected", "Deferred"):
                return None

            cve_id = CVEId(cve_id_str)
            published_str = cve_obj.get("published")
            last_modified_str = cve_obj.get("lastModified")
            
            published = datetime.fromisoformat(published_str.replace('Z', '+00:00')) if published_str else datetime.now(timezone.utc)
            last_modified = datetime.fromisoformat(last_modified_str.replace('Z', '+00:00')) if last_modified_str else datetime.now(timezone.utc)
            
            score = 0.0
            severity = "NONE"
            vector_string = None
            
            metrics = cve_obj.get("metrics", {})
            cvss_v31_list = metrics.get("cvssMetricV31", [])
            if cvss_v31_list:
                cvss_data = cvss_v31_list[0].get("cvssData", {})
                score = cvss_data.get("baseScore", 0.0)
                severity = cvss_data.get("baseSeverity", "NONE")
                vector_string = cvss_data.get("vectorString")
            else:
                cvss_v30_list = metrics.get("cvssMetricV30", [])
                if cvss_v30_list:
                    cvss_data = cvss_v30_list[0].get("cvssData", {})
                    score = cvss_data.get("baseScore", 0.0)
                    severity = cvss_data.get("baseSeverity", "NONE")
                    vector_string = cvss_data.get("vectorString")

            cvss_v2_score = None
            cvss_v2_severity = None
            cvss_v2_list = metrics.get("cvssMetricV2", [])
            if cvss_v2_list:
                cvss_v2_data = cvss_v2_list[0].get("cvssData", {})
                cvss_v2_score = cvss_v2_data.get("baseScore")
                cvss_v2_severity = cvss_v2_list[0].get("baseSeverity")
            
            cisa_exploit_add = None
            if cve_obj.get("cisaExploitAdd"):
                try:
                    cisa_exploit_add = datetime.strptime(cve_obj["cisaExploitAdd"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
                except:
                    pass
            
            cisa_action_due = None
            if cve_obj.get("cisaActionDue"):
                try:
                    cisa_action_due = datetime.strptime(cve_obj["cisaActionDue"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
                except:
                    pass
            
            description_en = None
            descriptions = cve_obj.get("descriptions", [])
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description_en = desc.get("value")
                    break
            
            cve_data = CVEData(
                cve_id=cve_id,
                score=score,
                severity=severity,
                published=published,
                last_modified=last_modified,
                source_identifier=cve_obj.get("sourceIdentifier"),
                vuln_status=cve_obj.get("vulnStatus"),
                description_en=description_en,
                cvss_v3_vector_string=vector_string,
                cvss_v2_base_score=cvss_v2_score,
                cvss_v2_severity=cvss_v2_severity,
                cisa_exploit_add=cisa_exploit_add,
                cisa_action_due=cisa_action_due,
                cisa_required_action=cve_obj.get("cisaRequiredAction"),
                cisa_vulnerability_name=cve_obj.get("cisaVulnerabilityName"),
                weaknesses=cve_obj.get("weaknesses"),
                references=cve_obj.get("references"),
                raw_data=cve_obj,
                from_api=True
            )
            cve_data.configurations = cve_obj.get("configurations", [])
            if severity == "CRITICAL":
                cve_data.expires_at = datetime.now(timezone.utc) + timedelta(days=30)
            elif severity == "HIGH":
                cve_data.expires_at = datetime.now(timezone.utc) + timedelta(days=7)
            else:
                cve_data.expires_at = datetime.now(timezone.utc) + timedelta(days=3)
            logger.debug(f"Parsed individual vulnerability: {cve_id_str}")
            return cve_data

        except Exception as e:
            logger.error(f"Error parsing individual vulnerability: {e}", exc_info=True)
            return None
    
    def _create_mock_template(self) -> Dict[str, Any]:
        """Create mock NVD response template"""
        return {
            "cve": {
                "id": "CVE-2021-44228",
                "sourceIdentifier": "security@apache.org",
                "published": "2021-12-10T10:15:09.143",
                "lastModified": "2025-10-27T17:40:33.680",
                "vulnStatus": "Analyzed",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Apache Log4j2 remote code execution vulnerability"
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 10.0,
                                "baseSeverity": "CRITICAL",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
                            }
                        }
                    ]
                },
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
        }
    
    async def enforce_rate_limit(self) -> None:
        """Enforce rate limiting"""
        async with self._rate_lock:
            current_time = time.time()
            time_since_last = current_time - self.last_request_time
            
            if time_since_last < self.rate_limit:
                sleep_time = self.rate_limit - time_since_last
                await asyncio.sleep(sleep_time)
            
            self.last_request_time = time.time()
    
    def set_rate_limit_callback(self, callback) -> None:
        """Set callback for rate limit notifications"""
        self._rate_limit_callback = callback
    
    def get_provider_name(self) -> str:
        """Get provider name"""
        return "NVD"
    
    async def close(self) -> None:
        """Close HTTP client"""
        if self.client:
            await self.client.aclose()
            self.client = None

    async def query_ip(self, ip_address: str) -> Optional[ThreatResult]:
        """Not implemented for NVD provider"""
        raise NotImplementedError("NVD provider doesn't handle IP lookups")
    
    async def health_check(self) -> bool:
        """Check NVD API connectivity"""
        try:
            if not self.client:
                await self.connect()
            
            response = await self.client.get("https://services.nvd.nist.gov/rest/json/cves/2.0", 
                                           params={"resultsPerPage": 1})
            return response.status_code == 200
        except Exception as e:
            logger.error(f"NVD health check failed: {e}")
            return False
    
    def get_rate_limit_info(self) -> Dict[str, Any]:
        """Get current rate limit information"""
        return {
            "rate_limit": self.rate_limit,
            "last_request_time": self.last_request_time,
            "api_key_configured": bool(self.api_key)
        }
