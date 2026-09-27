"""
Helper functions for extracting CPE (Common Platform Enumeration) strings from telemetry data.
"""

import logging
import re
import asyncio
from typing import List, Optional, Dict, Any

logger = logging.getLogger(__name__)


class CPEExtractor:
    """Extract CPE strings from telemetry data"""
    
    @staticmethod
    def parse_agent_string(agent_string: str) -> List[str]:
        """
        Parse agent string (e.g., "Java/11.0.18") and generate CPE strings.
        
        Args:
            agent_string: Agent string from telemetry (e.g., "Java/11.0.18", "Chrome/143.0.0.0")
            
        Returns:
            List of CPE strings
        """
        if not agent_string:
            return []
        
        cpe_list = []
        agent_string = agent_string.strip().strip("'\"")
        
        match = re.match(r'^([^/]+)/(.+)$', agent_string)
        if match:
            product = match.group(1).strip()
            version = match.group(2).strip()
            
            cpe = CPEExtractor._product_to_cpe(product, version)
            if cpe:
                cpe_list.append(cpe)
        
        return cpe_list
    
    @staticmethod
    def _product_to_cpe(product: str, version: str) -> Optional[str]:
        """
        Convert product/version to CPE string.
        
        This is a simplified mapping - in production, you'd want a more comprehensive mapping.
        """
        product_lower = product.lower()
        
        if product_lower in ['java', 'jdk', 'jre']:
            vendor = "oracle"
            if "openjdk" in product_lower or "openjdk" in version.lower():
                vendor = "eclipse"
            elif "ibm" in product_lower or "ibm" in version.lower():
                vendor = "ibm"
            
            return f"cpe:2.3:a:{vendor}:jdk:{version}:*:*:*:*:*:*:*"
        
        if product_lower == "log4j":
            return f"cpe:2.3:a:apache:log4j:{version}:*:*:*:*:*:*:*"
        
        if product_lower == "chrome":
            return f"cpe:2.3:a:google:chrome:{version}:*:*:*:*:*:*:*"
        
        if product_lower == "firefox":
            return f"cpe:2.3:a:mozilla:firefox:{version}:*:*:*:*:*:*:*"
        
        vendor = "unknown"
        product_normalized = product_lower.replace(" ", "_").replace("-", "_")
        
        return f"cpe:2.3:a:{vendor}:{product_normalized}:{version}:*:*:*:*:*:*:*"
    
    @staticmethod
    async def extract_cpes_from_log_ids_batch(log_ids: List[str]) -> Dict[str, List[str]]:
        """
        Extract CPE strings from multiple telemetry logs in a single query.
        More efficient for processing many log_ids at once.

        Args:
            log_ids: List of event keys / log IDs (64-char hex strings)

        Returns:
            Dictionary mapping log_id (hex string) -> list of CPE strings
        """
        if not log_ids:
            return {}

        try:
            from app.database.alerts_db import get_alerts_pool

            alerts_pool = await get_alerts_pool()
            async with alerts_pool.acquire() as conn:
                valid_log_ids: List[str] = []
                log_id_bytes_list: List[bytes] = []

                # Validate and convert each log_id from hex -> bytes
                for log_id in log_ids:
                    log_id_clean = log_id.strip().lower()

                    if not (
                        len(log_id_clean) == 64
                        and all(c in "0123456789abcdef" for c in log_id_clean)
                    ):
                        logger.debug(
                            f"Skipping invalid log_id format: {log_id} "
                            "(expected 64 hex chars)"
                        )
                        continue

                    try:
                        log_id_bytes = bytes.fromhex(log_id_clean)
                    except ValueError as e:
                        logger.debug(
                            f"Skipping invalid hex log_id '{log_id}': {e}"
                        )
                        continue

                    valid_log_ids.append(log_id_clean)
                    log_id_bytes_list.append(log_id_bytes)

                logger.debug(
                    f"Processed {len(valid_log_ids)} valid log_ids "
                    f"from {len(log_ids)} input log_ids"
                )

                if not log_id_bytes_list:
                    logger.warning("No valid log_ids found for CPE extraction")
                    return {}

                # Use bytea[] so Postgres can use idx_logs_event_key_timestamp
                try:
                    results = await asyncio.wait_for(
                        conn.fetch(
                            """
                            SELECT
                                encode(event_key, 'hex') AS event_key_hex,
                                CASE
                                    WHEN decoded_logs->'data' ? 'agent'
                                        THEN decoded_logs->'data'->>'agent'
                                    ELSE NULL
                                END AS agent_string,
                                CASE
                                    WHEN decoded_logs->'data' ? 'device_name'
                                        THEN decoded_logs->'data'->>'device_name'
                                    ELSE NULL
                                END AS device_name,
                                CASE
                                    WHEN decoded_logs->'data'->'request' ? 'method'
                                        THEN decoded_logs->'data'->'request'->>'method'
                                    ELSE NULL
                                END AS request_method
                            FROM logs
                            WHERE event_key = ANY($1::bytea[])
                              AND "timestamp" >= NOW() - INTERVAL '2 hours'
                            """,
                            log_id_bytes_list,
                        ),
                        timeout=30.0,
                    )
                    logger.info(
                        f"CPE extraction query returned {len(results)} rows "
                        f"for {len(valid_log_ids)} valid log_ids"
                    )
                except asyncio.TimeoutError:
                    logger.warning(
                        f"Batch CPE extraction query timed out for "
                        f"{len(log_id_bytes_list)} log_ids"
                    )
                    return {}

                # Initialise result dict with all valid log_ids
                cpe_results: Dict[str, List[str]] = {
                    log_id: [] for log_id in valid_log_ids
                }

                # Build CPE list per log_id (keyed by hex event_key from DB)
                for row in results:
                    log_id_hex = row["event_key_hex"]
                    cpe_list: List[str] = []

                    # Extract CPEs from agent field
                    if row.get("agent_string"):
                        agent_string = row["agent_string"].strip().strip("'\"")
                        if agent_string:
                            cpes = CPEExtractor.parse_agent_string(agent_string)
                            cpe_list.extend(cpes)
                            logger.debug(
                                f"Extracted {len(cpes)} CPEs from agent string "
                                f"for {log_id_hex}: {cpes}"
                            )

                    # Extract CPEs via asset inventory (device_name)
                    if row.get("device_name"):
                        device_name = row["device_name"].strip()
                        if device_name:
                            device_cpes = await CPEExtractor.get_cpes_for_agent_name(
                                device_name
                            )
                            cpe_list.extend(device_cpes)
                            if device_cpes:
                                logger.debug(
                                    f"Found {len(device_cpes)} CPEs from asset "
                                    f"inventory for device {device_name}"
                                )

                    cpe_results[log_id_hex] = cpe_list

                logger.info(
                    "Batch CPE extraction: processed %d valid log_ids, "
                    "CPEs found for %d log_ids",
                    len(valid_log_ids),
                    sum(1 for cpes in cpe_results.values() if cpes),
                )

                return cpe_results

        except Exception as e:
            logger.error(f"Error during batch CPE extraction: {e}", exc_info=True)
            return {}


    @staticmethod
    async def extract_cpes_from_log_id(log_id: str) -> List[str]:
        """
        Extract CPE strings from telemetry log by log_id.
        Queries the logs table to get agent information.
        
        Args:
            log_id: Event key / log ID
            
        Returns:
            List of CPE strings
        """
        try:
            from app.database.alerts_db import get_alerts_pool
            
            alerts_pool = await get_alerts_pool()
            async with alerts_pool.acquire() as conn:
                log_id_clean = log_id.strip().lower()
                
                if not all(c in '0123456789abcdef' for c in log_id_clean):
                    return []
                
                if len(log_id_clean) % 2 != 0:
                    return []
                
                try:
                    log_id_bytes = bytes.fromhex(log_id_clean)
                except ValueError as e:
                    logger.warning(f"Failed to convert log_id '{log_id}' to bytes: {e}")
                    return []
                
                result = await conn.fetchrow(
                    """
                    SELECT 
                        CASE 
                            WHEN decoded_logs->'data' ? 'agent' THEN decoded_logs->'data'->>'agent'
                            ELSE NULL 
                        END as agent_string,
                        CASE 
                            WHEN decoded_logs->'data' ? 'device_name' THEN decoded_logs->'data'->>'device_name'
                            ELSE NULL 
                        END as device_name,
                        CASE 
                            WHEN decoded_logs->'data'->'request' ? 'method' THEN decoded_logs->'data'->'request'->>'method'
                            ELSE NULL 
                        END as request_method,
                        decoded_logs->'data' as raw_data
                    FROM logs
                    WHERE event_key = $1
                    AND timestamp >= CURRENT_DATE - INTERVAL '1 day'
                    AND timestamp < CURRENT_DATE + INTERVAL '1 day'
                    ORDER BY timestamp DESC
                    LIMIT 1
                    """,
                    log_id_bytes
                )
                cpe_list = []
                
                if result:
                    logger.debug(f"Raw data for log_id {log_id}: {result.get('raw_data')}")
                
                if result and result.get('agent_string') is not None:
                    agent_string = result['agent_string'].strip().strip("'\"")
                    logger.debug(f"Found agent string for log_id {log_id}: {agent_string}")
                    if agent_string:
                        cpes = CPEExtractor.parse_agent_string(agent_string)
                        cpe_list.extend(cpes)
                        logger.debug(f"Extracted {len(cpes)} CPEs from agent string: {cpes}")
                else:
                    logger.debug(f"No agent string found for log_id {log_id}")

                if result and result.get('request_method') is not None:
                    request_method = result['request_method'].strip()
                    if 'http://' in request_method or 'https://' in request_method:
                        url_parts = request_method.split()
                        for part in url_parts:
                            if ':' in part and ('http' not in part):
                                continue
                
                if result and result.get('device_name') is not None:
                    device_name = result['device_name'].strip()
                    if device_name:
                        device_cpes = await CPEExtractor.get_cpes_for_agent_name(device_name)
                        cpe_list.extend(device_cpes)
                        logger.debug(f"Found {len(device_cpes)} CPEs from asset inventory for device {device_name}")
                
                return cpe_list
                
        except Exception as e:
            logger.warning(f"Error extracting CPEs from log_id {log_id}: {e}")
            return []
    
    @staticmethod
    async def get_cpes_for_agent_name(agent_name: str) -> List[str]:
        """
        Get CPE list for an agent_name from asset_inventory table.
        
        Args:
            agent_name: Agent name identifier
            
        Returns:
            List of CPE strings
        """
        try:
            from app.database.connection import db
            
            pool = await db.get_pool()
            async with pool.acquire() as conn:
                result = await conn.fetchrow(
                    """
                    SELECT cpe_list
                    FROM asset_inventory
                    WHERE agent_name = $1
                    LIMIT 1
                    """,
                    agent_name
                )
                
                if result and result.get('cpe_list'):
                    cpe_list = result['cpe_list']
                    if isinstance(cpe_list, list):
                        return cpe_list
                    elif isinstance(cpe_list, str):
                        import json
                        return json.loads(cpe_list)
                
                return []
                
        except Exception as e:
            logger.debug(f"Asset inventory query failed for {agent_name} (table may not exist): {e}")
            return []
