"""VirusTotal threat intelligence provider implementation."""

import asyncio
import logging
import random
import time
from datetime import datetime, timezone
from typing import Optional, Dict, Any
import httpx
from app.services.utils import gtic_threat_score
from ..interfaces.providers import RateLimitedProviderInterface, ThreatResult

logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)


class VirusTotalProvider(RateLimitedProviderInterface):
    """VirusTotal threat intelligence provider"""
    
    def __init__(self, api_key: str, mock_mode: bool = False, rate_limit: float = 0.001):
        self.api_key = api_key
        self.mock_mode = mock_mode
        self.rate_limit = rate_limit
        self.last_request_time = 0.0
        self._rate_limit_callback = None
        self._rate_lock = asyncio.Lock()
        
        self.base_url = "https://www.virustotal.com/api/v3"
        self.client: Optional[httpx.AsyncClient] = None
        
        self.mock_template = self._create_mock_template()
    
    async def connect(self) -> None:
        """Initialize HTTP client"""
        if not self.client:
            self.client = httpx.AsyncClient(timeout=30.0)
    
    async def query_ip(self, ip_address: str) -> Optional[ThreatResult]:
        """Query threat intelligence for an IP address"""
        if not self.client:
            await self.connect()
        
        await self.enforce_rate_limit()
        
        if self.mock_mode:
            return await self._query_mock(ip_address)
        else:
            return await self._query_real(ip_address)
    
    async def _query_real(self, ip_address: str) -> Optional[ThreatResult]:
        """Query real VirusTotal API"""
        try:
            headers = {
                "x-apikey": self.api_key
            }
            
            url = f"{self.base_url}/ip_addresses/{ip_address}"
            response = await self.client.get(url, headers=headers)

            if response.status_code in [429, 403]:
                # Notify processor to stop all API calls for this batch
                if self._rate_limit_callback:
                    self._rate_limit_callback("VirusTotal", ip_address)
                return None
            
            response.raise_for_status()
            
            data = response.json().get("data", {})
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total_engines = sum(stats.values())
            score = min(100, int((malicious * 3 + suspicious) * 100 / (total_engines or 1)))
            threat_level = self._determine_threat_level(score)
            
            country_code = attributes.get("country", "ZZ")
            tags = attributes.get("tags", [])
            unique_tags = sorted(list(set(map(str, tags)))) if tags else []
            category_names = ", ".join(unique_tags) if unique_tags else "None"
            reports = malicious + suspicious
            
            result = ThreatResult(
                ip_address=ip_address,
                threat_score=gtic_threat_score.normalize_score(score),
                threat_level=threat_level,
                threat_categories=category_names,
                source_name="VirusTotal",
                country_code=country_code,
                total_reports=reports,
                raw_data=data,
                fetched_at=datetime.now(timezone.utc)
            )
            
            logger.debug(f"VirusTotal query successful for {ip_address}: score={score}")
            return result
            
        except httpx.RequestError as e:
            logger.error(f"VirusTotal API request failed for {ip_address}: {e}")
            return None
        except Exception as e:
            logger.error(f"VirusTotal response parsing error for {ip_address}: {e}")
            return None
    
    async def _query_mock(self, ip_address: str) -> Optional[ThreatResult]:
        """Generate mock response for testing"""
        await asyncio.sleep(0.1)
        
        mock_data = self.mock_template.copy()
        mock_data["id"] = ip_address
        
        malicious = random.randint(1, 8)
        suspicious = random.randint(1, 5)
        stats = mock_data['attributes']['last_analysis_stats']
        
        stats['malicious'] = malicious
        stats['suspicious'] = suspicious
        
        total_engines = sum(stats.values())
        score = min(100, int((malicious * 3 + suspicious) * 100 / (total_engines or 1)))
        threat_level = self._determine_threat_level(score)
        
        categories = mock_data['attributes'].get("tags", ["None"])
        unique_categories = sorted(list(set(map(str, categories))))
        category_names = ", ".join(unique_categories)
        reports = malicious + suspicious
        country_code = mock_data['attributes'].get("country", "ZZ")
        
        result = ThreatResult(
            ip_address=ip_address,
            threat_score=gtic_threat_score.normalize_score(score),
            threat_level=threat_level,
            threat_categories=category_names,
            source_name="VirusTotal",
            country_code=country_code,
            total_reports=reports,
            raw_data=mock_data,
            fetched_at=datetime.now(timezone.utc)
        )
        
        logger.debug(f"VirusTotal mock query for {ip_address}: score={score}")
        return result
    
    def _create_mock_template(self) -> Dict[str, Any]:
        """Create mock response template"""
        engine_names = [f"MockEngine_{i}" for i in range(1, 51)]  # 50 engines
        engine_results = ["clean", "unrated", "malicious", "suspicious"]
        
        analysis_results = {}
        for name in engine_names:
            analysis_results[name] = {
                "method": "blacklist",
                "engine_name": name,
                "category": random.choice(["harmless", "malicious", "suspicious", "undetected"]),
                "result": random.choice(engine_results)
            }
        
        virustotal_tags = [
            ["malware", "botnet"],
            ["trojan", "backdoor"],
            ["phishing", "scam"],
            ["scanner", "reconnaissance"],
            ["spam", "malware"],
            ["c2", "command-and-control"],
            ["mining", "cryptocurrency"],
            ["proxy", "vpn"],
            ["tor-exit-node"],
            ["malicious", "suspicious"]
        ]
        selected_tags = random.choice(virustotal_tags)
        
        return {
            "id": "{ip}",
            "type": "ip_address",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 5,
                    "suspicious": 2,
                    "undetected": 50,
                    "harmless": 43,
                    "timeout": 0
                },
                "as_owner": "MOCK-CLOUD-PLATFORM",
                "country": "US",
                "tags": selected_tags,
                "last_analysis_results": analysis_results,
                "whois": ("inetnum: {ip} - 35.255.255.255\\n" + 
                         "netname: MOCK-NON-RIPE-NCC-MANAGED-ADDRESS-BLOCK\\n" * 5)
            }
        }
    
    def _determine_threat_level(self, score: int) -> int:
        """Determine threat level from score"""
        if score < 25:
            return 0
        elif score < 50:
            return 1
        elif score < 75:
            return 2
        else:
            return 3
    
    async def enforce_rate_limit(self) -> None:
        """Enforce rate limiting before making requests"""
        async with self._rate_lock:
            now = time.time()
            elapsed = now - self.last_request_time
            
            if elapsed < self.rate_limit:
                sleep_time = self.rate_limit - elapsed
                await asyncio.sleep(sleep_time)
            
            self.last_request_time = time.time()
    
    def get_rate_limit_info(self) -> Dict[str, Any]:
        """Get current rate limit status"""
        return {
            "provider": "VirusTotal",
            "rate_limit": self.rate_limit,
            "last_request_time": self.last_request_time,
            "time_since_last": time.time() - self.last_request_time
        }
    
    async def query_hash(self, hash_value: str, hash_type: str = "sha256") -> Optional[ThreatResult]:
        """Query VirusTotal for file hash threat intelligence"""
        if not self.client:
            await self.connect()
        
        await self.enforce_rate_limit()
        
        if self.mock_mode:
            return await self._query_hash_mock(hash_value, hash_type)
        else:
            return await self._query_hash_real(hash_value, hash_type)
    
    async def _query_hash_real(self, hash_value: str, hash_type: str) -> Optional[ThreatResult]:
        """Query real VirusTotal API for hash"""
        try:
            headers = {"x-apikey": self.api_key}
            url = f"{self.base_url}/files/{hash_value}"
            
            response = await self.client.get(url, headers=headers)
            
            if response.status_code == 404:
                logger.debug(f"Hash {hash_value} not found in VirusTotal")
                return None
            
            if response.status_code in [429, 403]:
                if self._rate_limit_callback:
                    self._rate_limit_callback("VirusTotal", hash_value)
                return None
            
            response.raise_for_status()
            
            data = response.json().get("data", {})
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            
            total_engines = sum(stats.values())
            score = min(100, int((malicious * 3 + suspicious) * 100 / (total_engines or 1)))
            threat_level = self._determine_threat_level(score)
            
            tags = attributes.get("tags", [])
            threat_label = attributes.get("popular_threat_classification", {}).get("suggested_threat_label", "")
            
            categories = []
            if threat_label:
                categories.append(threat_label)
            if tags:
                categories.extend(tags[:3])
            
            category_names = ", ".join(categories) if categories else "None"
            reports = malicious + suspicious
            
            result = ThreatResult(
                ip_address=hash_value,
                threat_score=gtic_threat_score.normalize_score(score),
                threat_level=threat_level,
                threat_categories=category_names,
                source_name="VirusTotal",
                country_code=None,
                total_reports=reports,
                raw_data={
                    "hash_type": hash_type,
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                    "file_type": attributes.get("type_description"),
                    "file_size": attributes.get("size"),
                    "md5": attributes.get("md5"),
                    "sha1": attributes.get("sha1"),
                    "sha256": attributes.get("sha256"),
                    "last_analysis_date": attributes.get("last_analysis_date")
                },
                fetched_at=datetime.now(timezone.utc)
            )
            
            logger.debug(f"VirusTotal hash query successful for {hash_value}: score={score}")
            return result
            
        except httpx.RequestError as e:
            logger.error(f"Request error querying VirusTotal for hash {hash_value}: {e}")
            return None
        except Exception as e:
            logger.error(f"Error querying VirusTotal for hash {hash_value}: {e}")
            return None
    
    async def _query_hash_mock(self, hash_value: str, hash_type: str) -> Optional[ThreatResult]:
        """Mock hash query for testing"""
        await asyncio.sleep(0.01)
        
        hash_int = int(hash_value[:8], 16) if len(hash_value) >= 8 else 0
        score = (hash_int % 100)
        threat_level = self._determine_threat_level(score)
        
        categories = ["malware", "trojan", "clean", "suspicious"]
        category = categories[hash_int % len(categories)]
        
        return ThreatResult(
            ip_address=hash_value,
            threat_score=gtic_threat_score.normalize_score(score),
            threat_level=threat_level,
            threat_categories=category,
            source_name="VirusTotal",
            country_code=None,
            total_reports=score // 10,
            raw_data={
                "hash_type": hash_type,
                "mock": True,
                "malicious": score // 10,
                "suspicious": max(0, (score // 10) - 2),
                "harmless": 50 - (score // 10),
                "undetected": 10
            },
            fetched_at=datetime.now(timezone.utc)
        )
    
    async def health_check(self) -> bool:
        """Check provider health/availability"""
        if self.mock_mode:
            return True
        
        try:
            if not self.client:
                await self.connect()
            
            headers = {"x-apikey": self.api_key}
            response = await self.client.get(f"{self.base_url}/user", headers=headers)
            return response.status_code in [200, 401]
        except Exception as e:
            logger.error(f"VirusTotal health check failed: {e}")
            return False
    
    def get_provider_name(self) -> str:
        """Get provider name"""
        return "VirusTotal"
    
    def set_rate_limit_callback(self, callback) -> None:
        """Set callback function to notify when rate limit is hit"""
        self._rate_limit_callback = callback
    
    async def close(self) -> None:
        """Close provider connections"""
        if self.client:
            await self.client.aclose()
            self.client = None
            logger.debug("VirusTotal provider connections closed")
