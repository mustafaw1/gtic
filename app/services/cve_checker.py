"""Service for checking CVEs (Common Vulnerabilities and Exposures) against the Lookup Service."""

import logging
from typing import List, Dict, Tuple, Any, Optional
import asyncio
from app.services.cve_lookup_client import get_cve_client
from app.config import settings

logger = logging.getLogger(__name__)


class CVECheckerService:
    """Service for checking CVEs using the Lookup Service."""
    
    @staticmethod
    async def check_cves_by_cpe(
        cpe_list: List[str],
        log_ids: Optional[List[str]] = None,
        ioc_data: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[List[Dict[str, Any]], List[str], Dict[str, Any]]:
        """
        Check CVEs for a list of CPE strings.
        
        Args:
            cpe_list: List of CPE strings to check
            log_ids: Optional list of log IDs corresponding to each CPE
            ioc_data: Optional list of dicts with IOC info (hash, ioc_type, etc.)
            
        Returns:
            Tuple of (matched_cves, not_found_cpes, stats)
        """
        if not cpe_list:
            return [], [], {
                "redis_hits": 0,
                "postgresql_hits": 0,
                "external_api_calls": 0
            }
        
        logger.debug(f"Checking {len(cpe_list)} CPE strings via CVE Lookup Service.")
        
        try:
            cve_client = await get_cve_client()
            
            cpe_entries = []
            for i, cpe_string in enumerate(cpe_list):
                entry = {"cpe_string": cpe_string}
                if log_ids and i < len(log_ids):
                    entry["log_id"] = log_ids[i]
                
                if ioc_data and i < len(ioc_data):
                    entry.update(ioc_data[i])
                    
                cpe_entries.append(entry)
            
            response = await cve_client.lookup_cves_by_cpe(cpe_entries=cpe_entries)
            
            results = response.get("results", {})
            stats = response.get("stats", {})
            
            matched_cves = results.get("matched_cves", [])
            not_found_cpes = results.get("not_found_cpes", [])
            
            for cve in matched_cves:
                fields_to_remove = ['raw_data', 'from_redis', 'from_db', 'from_api']
                for field in fields_to_remove:
                    if field in cve:
                        del cve[field]
            
            final_stats = {
                "redis_hits": stats.get("redis_hits", 0),
                "postgresql_hits": stats.get("postgresql_hits", 0),
                "external_api_calls": stats.get("external_api_calls", 0)
            }
            
            logger.debug(
                f"CVE check complete: {len(matched_cves)} matched CVEs, "
                f"{len(not_found_cpes)} CPEs not found, "
                f"Cache hits: {final_stats['redis_hits']}, "
                f"DB hits: {final_stats['postgresql_hits']}, "
                f"API calls: {final_stats['external_api_calls']}"
            )
            
            return matched_cves, not_found_cpes, final_stats
            
        except Exception as e:
            logger.error(f"Error checking CVEs via CVE Lookup Service: {e}", exc_info=True)
            raise
    
    @staticmethod
    async def check_cves_by_id(
        cve_id_list: List[str],
        log_ids: Optional[List[str]] = None
    ) -> Tuple[List[Dict[str, Any]], List[str], Dict[str, Any]]:
        """
        Check specific CVE IDs.
        
        Args:
            cve_id_list: List of CVE IDs to check (e.g., ["CVE-2021-44228"])
            log_ids: Optional list of log IDs corresponding to each CVE ID
            
        Returns:
            Tuple of (matched_cves, not_found_cve_ids, stats)
        """
        if not cve_id_list:
            return [], [], {
                "redis_hits": 0,
                "postgresql_hits": 0,
                "external_api_calls": 0
            }
        
        logger.info(f"Checking {len(cve_id_list)} CVE IDs via CVE Lookup Service.")
        
        try:
            cve_client = await get_cve_client()
            
            cve_entries = []
            for i, cve_id in enumerate(cve_id_list):
                entry = {"cve_id": cve_id}
                if log_ids and i < len(log_ids):
                    entry["log_id"] = log_ids[i]
                cve_entries.append(entry)
            
            response = await cve_client.lookup_cves_by_id(cve_entries=cve_entries)
            
            results = response.get("results", {})
            stats = response.get("stats", {})
            
            matched_cves = results.get("matched_cves", [])
            not_found_cve_ids = results.get("not_found_cve_ids", [])
            
            for cve in matched_cves:
                fields_to_remove = ['raw_data', 'from_redis', 'from_db', 'from_api']
                for field in fields_to_remove:
                    if field in cve:
                        del cve[field]
            
            final_stats = {
                "redis_hits": stats.get("redis_hits", 0),
                "postgresql_hits": stats.get("postgresql_hits", 0),
                "external_api_calls": stats.get("external_api_calls", 0)
            }
            
            logger.info(
                f"CVE ID check complete: {len(matched_cves)} matched CVEs, "
                f"{len(not_found_cve_ids)} CVE IDs not found, "
                f"Cache hits: {final_stats['redis_hits']}, "
                f"DB hits: {final_stats['postgresql_hits']}, "
                f"API calls: {final_stats['external_api_calls']}"
            )
            
            return matched_cves, not_found_cve_ids, final_stats
            
        except Exception as e:
            logger.error(f"Error checking CVE IDs via CVE Lookup Service: {e}", exc_info=True)
            raise
