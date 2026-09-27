"""VirusTotal domain threat intelligence provider implementation."""

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


class VirusTotalDomainProvider(RateLimitedProviderInterface):
    """VirusTotal domain threat intelligence provider"""
    
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
    
    async def query_ip(self, domain_name: str) -> Optional[ThreatResult]:
        """Query threat intelligence for a domain name"""
        if not self.client:
            await self.connect()
        
        await self.enforce_rate_limit()
        
        if self.mock_mode:
            return await self._query_mock(domain_name)
        else:
            return await self._query_real(domain_name)
    
    async def _query_real(self, domain_name: str) -> Optional[ThreatResult]:
        """Query real VirusTotal API for domain"""
        try:
            headers = {
                "x-apikey": self.api_key
            }
            
            url = f"{self.base_url}/domains/{domain_name}"
            response = await self.client.get(url, headers=headers)

            if response.status_code in [429, 403]:
                if self._rate_limit_callback:
                    self._rate_limit_callback("VirusTotal", domain_name)
                return None
            
            if response.status_code == 404:
                return ThreatResult(
                    ip_address=domain_name,  # Using ip_address field for domain compatibility
                    threat_score=0,
                    threat_level=0,
                    threat_categories="Clean",
                    source_name="VirusTotal",
                    country_code=None,
                    total_reports=0,
                    raw_data={"not_found": True},
                    fetched_at=datetime.now(timezone.utc)
                )
            
            response.raise_for_status()
            
            data = response.json().get("data", {})
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total_engines = sum(stats.values())
            
            # Calculate threat score for domains
            if total_engines > 0:
                score = min(100, int((malicious * 3 + suspicious) * 100 / (total_engines or 1)))
            else:
                score = 0
                
            threat_level = self._determine_threat_level(score)
            
            # Extract categories from analysis results
            categories = []
            analysis_results = attributes.get("last_analysis_results", {})
            for engine, result in analysis_results.items():
                if result.get("category") in ["malicious", "suspicious"]:
                    result_text = result.get("result", "")
                    if result_text and result_text.lower() != "clean":
                        categories.append(result_text)
            
            unique_categories = sorted(list(set(categories)))
            category_names = ", ".join(unique_categories) if unique_categories else "Clean"
            
            whois_data = attributes.get("whois", "")
            creation_date = attributes.get("creation_date")
            
            reports = malicious + suspicious
            
            result = ThreatResult(
                ip_address=domain_name,  # Using ip_address field for domain compatibility
                threat_score=gtic_threat_score.normalize_score(score),
                threat_level=threat_level,
                threat_categories=category_names,
                source_name="VirusTotal",
                country_code=self._extract_country_from_whois(whois_data),
                total_reports=reports,
                raw_data={
                    **data,
                    "creation_date": creation_date,
                    "whois_snippet": whois_data[:500] if whois_data else None
                },
                fetched_at=datetime.now(timezone.utc)
            )
            
            logger.debug(f"VirusTotal domain query successful for {domain_name}: score={score}")
            return result
            
        except httpx.RequestError as e:
            logger.error(f"VirusTotal domain API request failed for {domain_name}: {e}")
            return None
        except Exception as e:
            logger.error(f"VirusTotal domain response parsing error for {domain_name}: {e}")
            return None
    
    def _extract_country_from_whois(self, whois_data: str) -> Optional[str]:
        """Extract country code from WHOIS data"""
        if not whois_data:
            return None
        
        import re
        country_pattern = r'Country:\s*([A-Z]{2})'
        match = re.search(country_pattern, whois_data, re.IGNORECASE)
        if match:
            return match.group(1).upper()
        
        return None
    
    async def _query_mock(self, domain_name: str) -> Optional[ThreatResult]:
        """Generate mock response for testing"""
        await asyncio.sleep(0.1)
        
        mock_data = self.mock_template.copy()
        mock_data["id"] = domain_name
        
        malicious = random.randint(0, 5)
        suspicious = random.randint(0, 3)
        stats = mock_data['attributes']['last_analysis_stats']
        
        stats['malicious'] = malicious
        stats['suspicious'] = suspicious
        
        total_engines = sum(stats.values())
        if total_engines > 0:
            score = min(100, int((malicious * 3 + suspicious) * 100 / (total_engines or 1)))
        else:
            score = 0
            
        threat_level = self._determine_threat_level(score)
        
        categories = ["phishing", "malware", "suspicious", "clean"][0:random.randint(1, 3)]
        category_names = ", ".join(categories)
        reports = malicious + suspicious
        
        result = ThreatResult(
            ip_address=domain_name,  # Using ip_address field for domain compatibility
            threat_score=gtic_threat_score.normalize_score(score),
            threat_level=threat_level,
            threat_categories=category_names,
            source_name="VirusTotal",
            country_code=random.choice(["US", "DE", "CN", "RU", "NL"]),
            total_reports=reports,
            raw_data=mock_data,
            fetched_at=datetime.now(timezone.utc)
        )
        
        logger.debug(f"VirusTotal domain mock query for {domain_name}: score={score}")
        return result
    
    def _create_mock_template(self) -> Dict[str, Any]:
        """Create mock response template for domains"""
        engine_names = [f"MockEngine_{i}" for i in range(1, 51)]  # 50 engines
        engine_results = ["clean", "unrated", "malicious", "suspicious", "phishing", "malware"]
        
        analysis_results = {}
        for name in engine_names:
            category = random.choice(["harmless", "malicious", "suspicious", "undetected"])
            result = random.choice(engine_results) if category != "harmless" else "clean"
            
            analysis_results[name] = {
                "method": "blacklist",
                "engine_name": name,
                "category": category,
                "result": result
            }
        
        domain_categories = [
            ["phishing"],
            ["malware", "trojan"],
            ["suspicious", "potentially unwanted"],
            ["clean"],
            ["spam", "malicious"],
            ["c2", "command-and-control"],
            ["cryptocurrency", "mining"],
            ["proxy", "anonymizer"]
        ]
        
        selected_categories = random.choice(domain_categories)
        
        return {
            "id": "{domain}",
            "type": "domain",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 2,
                    "suspicious": 1,
                    "undetected": 45,
                    "harmless": 40,
                    "timeout": 2
                },
                "categories": {
                    "Forcepoint ThreatSeeker": "phishing",
                    "sophos": "malware"
                },
                "creation_date": int((datetime.now(timezone.utc).timestamp() - random.randint(86400, 86400*365*5))),
                "last_analysis_results": analysis_results,
                "whois": f"Domain Name: {{domain}}\\nRegistrar: MOCK REGISTRAR\\nCreation Date: 2020-01-01T00:00:00Z\\nCountry: US\\n",
                "reputation": random.randint(-10, 10),
                "tags": selected_categories
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
            logger.error(f"VirusTotal domain health check failed: {e}")
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
            logger.debug("VirusTotal domain provider connections closed")