"""AbuseIPDB threat intelligence provider implementation."""

import asyncio
import logging
import random
import time
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any
import httpx
from app.services.utils import gtic_threat_score
from ..interfaces.providers import RateLimitedProviderInterface, ThreatResult

logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)

ABUSEIPDB_CATEGORIES = {
    3: "Fraud Orders",
    4: "DDoS Attack", 
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted"
}


class AbuseIPDBProvider(RateLimitedProviderInterface):
    """AbuseIPDB threat intelligence provider"""
    
    def __init__(self, api_key: str, mock_mode: bool = False, rate_limit: float = 0.001):
        self.api_key = api_key
        self.mock_mode = mock_mode
        self.rate_limit = rate_limit
        self.last_request_time = 0.0
        self._rate_lock = asyncio.Lock()
        self._rate_limit_callback = None
        
        self.base_url = "https://api.abuseipdb.com/api/v2"
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
        """Query real AbuseIPDB API"""
        try:
            headers = {
                "Accept": "application/json",
                "Key": self.api_key
            }
            
            params = {
                "ipAddress": ip_address,
                "maxAgeInDays": "90",
                "verbose": "true"
            }
            
            url = f"{self.base_url}/check"
            response = await self.client.get(url, headers=headers, params=params)

            if response.status_code in [429, 403]:
                # Notify processor to stop all API calls for this batch
                if self._rate_limit_callback:
                    self._rate_limit_callback("AbuseIPDB", ip_address)
                return None
            
            response.raise_for_status()
            
            data = response.json().get("data", {})
            
            score = data.get("abuseConfidenceScore", 0)
            threat_level = self._determine_threat_level(score)
            country_code = data.get("countryCode")
            total_reports = data.get("totalReports", 0)
            
            categories = data.get("categories", [])
            report_categories = [r.get('categories', []) for r in data.get("reports", [])]
            all_categories = categories + [cat for sublist in report_categories for cat in sublist]
            category_names = self._convert_category_ids_to_names(all_categories)
            
            result = ThreatResult(
                ip_address=ip_address,
                threat_score=gtic_threat_score.normalize_score(score),
                threat_level=threat_level,
                threat_categories=category_names,
                source_name="AbusedIPDB",
                country_code=country_code,
                total_reports=total_reports,
                raw_data=data,
                fetched_at=datetime.now(timezone.utc)
            )
            
            logger.debug(f"AbuseIPDB query successful for {ip_address}: score={score}")
            return result
            
        except httpx.RequestError as e:
            logger.error(f"AbuseIPDB API request failed for {ip_address}: {e}")
            return None
        except Exception as e:
            logger.error(f"AbuseIPDB response parsing error for {ip_address}: {e}")
            return None
    
    async def _query_mock(self, ip_address: str) -> Optional[ThreatResult]:
        """Generate mock response for testing"""
        await asyncio.sleep(0.1)
        
        mock_data = self.mock_template.copy()
        mock_data["ipAddress"] = ip_address
        
        score = random.randint(10, 100)
        reports_count = len(mock_data["reports"])
        threat_level = self._determine_threat_level(score)
        
        mock_data["abuseConfidenceScore"] = score
        mock_data["totalReports"] = reports_count * 3
        
        categories = [str(c) for sublist in [r['categories'] for r in mock_data["reports"]] for c in sublist]
        categories = list(set(categories))
        category_names = self._convert_category_ids_to_names(categories)
        
        result = ThreatResult(
            ip_address=ip_address,
            threat_score=gtic_threat_score.normalize_score(score),
            threat_level=threat_level,
            threat_categories=category_names,
            source_name="AbusedIPDB",
            country_code=mock_data["countryCode"],
            total_reports=reports_count,
            raw_data=mock_data,
            fetched_at=datetime.now(timezone.utc)
        )
        
        logger.debug(f"AbuseIPDB mock query for {ip_address}: score={score}")
        return result
    
    def _create_mock_template(self) -> Dict[str, Any]:
        """Create mock response template"""
        now = datetime.now(timezone.utc)
        reports_list = []
        
        for _ in range(50):
            reported_at = now - timedelta(
                days=random.uniform(0, 7), 
                seconds=random.randint(0, 3600)
            )
            reports_list.append({
                "reportedAt": reported_at.isoformat().replace('+00:00', 'Z'),
                "comment": random.choice([
                    "tcp port scan (multiple attempts)",
                    "SSH unauthorized login attempt", 
                    "Honeypot hit"
                ]),
                "categories": random.choice([[14], [18, 22], [15, 19]]),
                "reporterId": random.randint(10000, 300000),
                "reporterCountryCode": random.choice(["US", "DE", "CN", "IT", "KR"]),
                "reporterCountryName": random.choice([
                    "United States of America", 
                    "Germany", 
                    "China", 
                    "Italy", 
                    "Korea (the Republic of)"
                ])
            })
        
        return {
            "ipAddress": "{ip}",
            "isPublic": True,
            "ipVersion": 4,
            "isWhitelisted": False,
            "abuseConfidenceScore": 50,
            "countryCode": "US",
            "usageType": "Data Center/Web Hosting/Transit",
            "isp": "Mock Threat Intelligence, Inc.",
            "reports": reports_list
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
    
    def _convert_category_ids_to_names(self, category_ids: list) -> str:
        """Convert numeric category IDs to human-readable names"""
        if not category_ids:
            return ""
        
        try:
            if isinstance(category_ids, str):
                ids = [int(x.strip()) for x in category_ids.split(",") if x.strip()]
            else:
                ids = [int(x) for x in category_ids if str(x).isdigit()]
        except (ValueError, TypeError):
            return str(category_ids) if category_ids else ""
        
        unique_ids = list(set(ids))
        names = [
            ABUSEIPDB_CATEGORIES.get(cat_id, f"Unknown({cat_id})") 
            for cat_id in unique_ids
        ]
        return ", ".join(sorted(names))
    
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
            "provider": "AbuseIPDB",
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
            
            headers = {"Accept": "application/json", "Key": self.api_key}
            response = await self.client.get(f"{self.base_url}/check-block", headers=headers)
            return response.status_code in [200, 401]
        except Exception as e:
            logger.error(f"AbuseIPDB health check failed: {e}")
            return False
    
    def get_provider_name(self) -> str:
        """Get provider name"""
        return "AbusedIPDB"
    
    def set_rate_limit_callback(self, callback) -> None:
        """Set callback function to notify when rate limit is hit"""
        self._rate_limit_callback = callback
    
    async def close(self) -> None:
        """Close provider connections"""
        if self.client:
            await self.client.aclose()
            self.client = None
            logger.debug("AbuseIPDB provider connections closed")
