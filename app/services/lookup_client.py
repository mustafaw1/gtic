"""
Client for communicating with the Lookup Service
"""

import asyncio
import logging
from typing import List, Dict, Any, Optional
import httpx

from app.config import get_settings

logger = logging.getLogger(__name__)


class LookupServiceClient:
    """Client for communicating with the independent Lookup Service"""
    
    def __init__(self):
        self.settings = get_settings()
        self.base_url = getattr(self.settings, 'lookup_service_url', 'http://localhost:8001')
        self.client: Optional[httpx.AsyncClient] = None
        self.timeout = 180.0
    
    async def connect(self):
        """Initialize HTTP client"""
        if not self.client:
            self.client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout, pool=self.timeout),
                limits=httpx.Limits(max_keepalive_connections=20, max_connections=100),
            )
    
    async def close(self):
        """Close HTTP client"""
        if self.client:
            await self.client.aclose()
            self.client = None
    
    async def lookup_ips_and_domains(
        self, 
        ips: List[str] = None, 
        domains: List[str] = None,
        hashes: List[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Perform lookup for IPs, domains, and/or hashes via the Lookup Service
        
        Args:
            ips: List of IP addresses to lookup
            domains: List of domains to lookup
            hashes: List of hash dictionaries with 'hash_value' and 'hash_type'
            
        Returns:
            Dictionary with lookup results and stats
        """
        if not self.client:
            await self.connect()
        
        try:
            request_data = {
                "ips": ips or [],
                "domains": domains or [],
                "hashes": hashes or []
            }
            
            response = await self.client.post(
                f"{self.base_url}/lookup",
                json=request_data
            )
            response.raise_for_status()
            
            return response.json()
            
        except httpx.TimeoutException as e:
            logger.error(f"Lookup service timeout: {e}")
            raise
        except httpx.RequestError as e:
            logger.error(f"Lookup service request failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Lookup service error: {e}")
            raise
    
    async def promote_behavioral_ioc(self, threat_record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Promote a behaviorally-detected IP directly into the GTIC cache.

        Calls the lookup service's /promote endpoint, which writes the record
        only when the new threat_score exceeds any existing cached score for
        that IP (no-downgrade guarantee).

        Args:
            threat_record: Pre-computed threat dict with keys ip_address,
                           threat_score, threat_level, threat_categories,
                           source_name, expires_at, raw_data, etc.

        Returns:
            Dict with keys: stored (bool), message, ip_address, threat_score,
            previous_threat_score.
        """
        if not self.client:
            await self.connect()

        try:
            response = await self.client.post(
                f"{self.base_url}/promote",
                json=threat_record
            )
            response.raise_for_status()
            return response.json()
        except httpx.TimeoutException as e:
            logger.error(f"Lookup service /promote timeout: {e}")
            raise
        except httpx.RequestError as e:
            logger.error(f"Lookup service /promote request failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Lookup service /promote error: {e}")
            raise

    async def health_check(self) -> bool:
        """Check if the Lookup Service is healthy"""
        if not self.client:
            await self.connect()
        
        try:
            response = await self.client.get(f"{self.base_url}/health", timeout=5.0)
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Lookup service health check failed: {e}")
            return False


_lookup_client: Optional[LookupServiceClient] = None


async def get_lookup_client() -> LookupServiceClient:
    """Get lookup service client instance"""
    global _lookup_client
    if _lookup_client is None:
        _lookup_client = LookupServiceClient()
        await _lookup_client.connect()
    return _lookup_client


async def close_lookup_client():
    """Close lookup service client"""
    global _lookup_client
    if _lookup_client:
        await _lookup_client.close()
        _lookup_client = None