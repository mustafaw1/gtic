"""
Client for communicating with the CVE Lookup Service
"""

import asyncio
import logging
from typing import List, Dict, Any, Optional
import httpx

from app.config import get_settings

logger = logging.getLogger(__name__)


class CVELookupServiceClient:
    """Client for communicating with the CVE Lookup Service"""
    
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
    
    async def lookup_cves_by_cpe(
        self,
        cpe_entries: List[Dict[str, str]],
    ) -> Dict[str, Any]:
        """
        Perform CVE lookup for CPE strings via the CVE Lookup Service

        Args:
            cpe_entries: List of dicts with 'cpe_string' and optional fields

        Returns:
            Dictionary with CVE lookup results and stats
        """
        if not self.client:
            await self.connect()

        try:
            request_data = {
                "cpe_entries": cpe_entries,
            }
            
            response = await self.client.post(
                f"{self.base_url}/lookup/cve/by-cpe",
                json=request_data
            )
            response.raise_for_status()
            
            return response.json()
            
        except httpx.TimeoutException as e:
            logger.error(f"CVE lookup service timeout: {e}")
            raise
        except httpx.RequestError as e:
            logger.error(f"CVE lookup service request failed: {e}")
            raise
        except Exception as e:
            logger.error(f"CVE lookup service error: {e}")
            raise
    
    async def lookup_cves_by_id(
        self,
        cve_entries: List[Dict[str, str]]
    ) -> Dict[str, Any]:
        """
        Perform CVE lookup for CVE IDs via the CVE Lookup Service
        
        Args:
            cve_entries: List of dicts with 'cve_id' and optional 'log_id'
            
        Returns:
            Dictionary with CVE lookup results and stats
        """
        if not self.client:
            await self.connect()
        
        try:
            request_data = {
                "cve_entries": cve_entries
            }
            
            response = await self.client.post(
                f"{self.base_url}/lookup/cve/by-id",
                json=request_data
            )
            response.raise_for_status()
            
            return response.json()
            
        except httpx.TimeoutException as e:
            logger.error(f"CVE lookup service timeout: {e}")
            raise
        except httpx.RequestError as e:
            logger.error(f"CVE lookup service request failed: {e}")
            raise
        except Exception as e:
            logger.error(f"CVE lookup service error: {e}")
            raise
    
    async def health_check(self) -> bool:
        """Check if the CVE Lookup Service is healthy"""
        if not self.client:
            await self.connect()
        
        try:
            response = await self.client.get(f"{self.base_url}/health", timeout=5.0)
            return response.status_code == 200
        except Exception as e:
            logger.error(f"CVE lookup service health check failed: {e}")
            return False


_cve_client: Optional[CVELookupServiceClient] = None


async def get_cve_client() -> CVELookupServiceClient:
    """Get CVE lookup service client instance"""
    global _cve_client
    if _cve_client is None:
        _cve_client = CVELookupServiceClient()
        await _cve_client.connect()
    return _cve_client


async def close_cve_client():
    """Close CVE lookup service client"""
    global _cve_client
    if _cve_client:
        await _cve_client.close()
        _cve_client = None
