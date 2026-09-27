import logging
from typing import List, Dict, Tuple, Any
from app.models.schemas import IPData, DomainData, HashData, NotFoundIP
import asyncio
from app.services.lookup_client import get_lookup_client
from app.config import settings

logger = logging.getLogger(__name__)

def _normalize_threat_categories(categories: str) -> str:
    """Normalize threat categories by removing duplicates and sorting"""
    if not categories or not categories.strip():
        return ""

    category_list = [cat.strip() for cat in categories.split(",") if cat.strip()]
    unique_categories = sorted(list(set(category_list)))
    
    return ", ".join(unique_categories)

class IOCCheckerService:
    """Service for checking IOCs (IPs, domains, and hashes) against the Lookup Service."""
    
    @staticmethod
    async def check_ips_and_domains(
        ip_data_list: List[IPData], 
        domain_data_list: List[DomainData],
        hash_data_list: List[HashData] = None
    ) -> Tuple[List[Dict[str, Any]], List[Dict], List[Dict[str, Any]], List[Dict], List[Dict[str, Any]], List[Dict], Dict[str, Any]]:
        """
        Processes ALL IOCs (IPs, domains, and hashes) using the Lookup Service.
        Returns: (cached_ips, not_found_ips, cached_domains, not_found_domains, cached_hashes, not_found_hashes, stats)
        """
        if hash_data_list is None:
            hash_data_list = []
            
        if not ip_data_list and not domain_data_list and not hash_data_list:
            return [], [], [], [], [], [], {
                "redis_hits": 0, 
                "postgresql_hits": 0, 
                "external_api_calls": 0
            }
        
        ips = [item.ip_address for item in ip_data_list]
        domains = [item.domain_name for item in domain_data_list]
        hashes = [{"hash_value": item.hash_value, "hash_type": item.hash_type} for item in hash_data_list]
        
        logger.info(f"Checking {len(ips)} IPs, {len(domains)} domains, and {len(hashes)} hashes via Lookup Service.")
        
        try:
            lookup_client = await get_lookup_client()
            response = await lookup_client.lookup_ips_and_domains(ips=ips, domains=domains, hashes=hashes)
            
            results = response.get("results", {})
            stats = response.get("stats", {})
            
            ip_results = results.get("ips", [])
            domain_results = results.get("domains", [])
            hash_results = results.get("hashes", [])
            
            final_cached_ips = []
            final_not_found_ips = []
            processed_ips_set = set()
            
            ip_log_id_map = {item.ip_address: item.log_id for item in ip_data_list}
            domain_log_id_map = {item.domain_name: item.log_id for item in domain_data_list}
            
            for ip_result in ip_results:
                if ip_result and ip_result.get('ip_address'):
                    ip_address = ip_result.get('ip_address')
                    ip_result['event_key'] = ip_log_id_map.get(ip_address, f"lookup_{ip_address}")
                    
                    fields_to_remove = ['raw_data', 'from_redis', 'from_db', 'from_db_recache', 'from_api']
                    for field in fields_to_remove:
                        if field in ip_result:
                            del ip_result[field]
                    
                    if 'source_name' in ip_result:
                        ip_result['source_api'] = ip_result['source_name']
                        del ip_result['source_name']
                    
                    final_cached_ips.append(ip_result)
                    processed_ips_set.add(ip_address)
            
            for item in ip_data_list:
                if item.ip_address not in processed_ips_set:
                    final_not_found_ips.append({
                        "ip_address": item.ip_address,
                        "log_id": item.log_id
                    })
            
            final_cached_domains = []
            final_not_found_domains = []
            processed_domains_set = set()
            
            for domain_result in domain_results:
                if domain_result and domain_result.get('domain_name'):
                    domain_name = domain_result.get('domain_name')
                    domain_result['event_key'] = domain_log_id_map.get(domain_name, f"lookup_{domain_name}")

                    fields_to_remove = ['raw_data', 'from_redis', 'from_db', 'from_db_recache', 'from_api']
                    for field in fields_to_remove:
                        if field in domain_result:
                            del domain_result[field]
                    
                    if 'source_name' in domain_result:
                        domain_result['source_api'] = domain_result['source_name']
                        del domain_result['source_name']
                    
                    final_cached_domains.append(domain_result)
                    processed_domains_set.add(domain_name)
            
            for item in domain_data_list:
                if item.domain_name not in processed_domains_set:
                    final_not_found_domains.append({
                        "domain_name": item.domain_name,
                        "log_id": item.log_id
                    })
            
            final_cached_hashes = []
            final_not_found_hashes = []
            processed_hashes_set = set()
            
            hash_log_id_map = {item.hash_value: item.log_id for item in hash_data_list}
            
            for hash_result in hash_results:
                if hash_result and hash_result.get('hash_value'):
                    hash_value = hash_result.get('hash_value')
                    hash_result['event_key'] = hash_log_id_map.get(hash_value, f"lookup_{hash_value}")
                    
                    fields_to_remove = ['raw_data', 'from_redis', 'from_db', 'from_db_recache', 'from_api']
                    for field in fields_to_remove:
                        if field in hash_result:
                            del hash_result[field]
                    
                    if 'source_name' in hash_result:
                        hash_result['source_api'] = hash_result['source_name']
                        del hash_result['source_name']
                    
                    final_cached_hashes.append(hash_result)
                    processed_hashes_set.add(hash_value)
            
            for item in hash_data_list:
                if item.hash_value not in processed_hashes_set:
                    final_not_found_hashes.append({
                        "hash_value": item.hash_value,
                        "hash_type": item.hash_type,
                        "log_id": item.log_id
                    })

            final_stats = {
                "redis_hits": stats.get("cache_hits", 0),
                "postgresql_hits": stats.get("db_hits", 0),
                "external_api_calls": stats.get("external_api_calls", 0)
            }
            
            logger.info(f"Final response: Cached IPs: {len(final_cached_ips)}, Not found IPs: {len(final_not_found_ips)}, "
                       f"Cached domains: {len(final_cached_domains)}, Not found domains: {len(final_not_found_domains)}, "
                       f"Cached hashes: {len(final_cached_hashes)}, Not found hashes: {len(final_not_found_hashes)}, "
                       f"Cache hits: {final_stats['redis_hits']}, DB hits: {final_stats['postgresql_hits']}, API calls: {final_stats['external_api_calls']}")
            
            return final_cached_ips, final_not_found_ips, final_cached_domains, final_not_found_domains, final_cached_hashes, final_not_found_hashes, final_stats
                
        except Exception as e:
            logger.error(f"Error checking IOCs via Lookup Service: {e}", exc_info=True)
            raise