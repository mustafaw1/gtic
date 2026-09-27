import logging
import asyncio
from fastapi import APIRouter, HTTPException, status
from app.models.schemas import (
    CheckIOCsRequest,
    CheckIOCsResponse,
    HealthResponse,
    CPECollectorRequest,
    CPECollectorResponse,
    CVELookupRequest,
    CVELookupResponse,
    CVELookupStats,
    BehavioralPromotionRequest,
    BehavioralPromotionResponse,
)
from app.services.ip_checker import IOCCheckerService
from app.services.cve_checker import CVECheckerService
from app.services.correlation_engine import CorrelationEngine
from app.services.cpe_extractor import CPEExtractor
from app.services.behavioral_promoter import BehavioralPromoterService
import httpx
from app.database.connection import db
from app.config import get_settings

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post(
    "/api/v1/check-iocs",
    response_model=CheckIOCsResponse,
    status_code=status.HTTP_200_OK
)
async def check_iocs(request: CheckIOCsRequest):
    """
    Check multiple IOCs (IP addresses, domains, and/or hashes) against the threat database cache.
    Also performs CVE correlation based on CPE strings extracted from telemetry.
    
    Returns cached results, IOCs not found in cache, and CVE correlation data.
    Supports mixed batches with IPs, domains, and hashes.
    """
    settings = get_settings()
    
    total_iocs = len(request.ip_data) + len(request.domains_data) + len(request.hashes_data)
    if total_iocs > settings.max_iocs_per_request:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Too many IOCs. Maximum allowed: {settings.max_iocs_per_request}"
        )
    
    try:
        ioc_task = IOCCheckerService.check_ips_and_domains(
            request.ip_data, request.domains_data, request.hashes_data
        )
        
        cpe_list = []
        log_ids_for_cpe = []
        ioc_data_for_cpe = []
        all_log_ids = []
        log_id_to_ioc = {}
        
        for ip_item in request.ip_data:
            all_log_ids.append(ip_item.log_id)
            log_id_to_ioc[ip_item.log_id] = {"ioc_type": "ip", "ioc_value": ip_item.ip_address}
        for domain_item in request.domains_data:
            all_log_ids.append(domain_item.log_id)
            log_id_to_ioc[domain_item.log_id] = {"ioc_type": "domain", "ioc_value": domain_item.domain_name}
        for hash_item in request.hashes_data:
            all_log_ids.append(hash_item.log_id)
            log_id_to_ioc[hash_item.log_id] = {"ioc_type": "hash", "ioc_value": hash_item.hash_value}
        
        if all_log_ids:
            logger.info(f"CPE extraction starting with log_ids: {all_log_ids[:5]}{'...' if len(all_log_ids) > 5 else ''}")
            try:
                cpe_results_dict = await CPEExtractor.extract_cpes_from_log_ids_batch(all_log_ids)
                
                for log_id, cpes in cpe_results_dict.items():
                    if isinstance(cpes, list) and cpes:
                        logger.debug(f"Found {len(cpes)} CPEs for log_id {log_id}: {cpes}")
                        cpe_list.extend(cpes)
                        log_ids_for_cpe.extend([log_id] * len(cpes))
                        ioc_info = log_id_to_ioc.get(log_id, {})
                        ioc_data_for_cpe.extend([ioc_info] * len(cpes))
                    else:
                        logger.debug(f"No CPEs found for log_id {log_id}")
                        
            except Exception as e:
                logger.error(f"Batch CPE extraction failed, falling back to individual extraction: {e}")
                cpe_extraction_tasks = [CPEExtractor.extract_cpes_from_log_id(log_id) for log_id in all_log_ids]
                cpe_results = await asyncio.gather(*cpe_extraction_tasks, return_exceptions=True)
                
                for log_id, cpes in zip(all_log_ids, cpe_results):
                    if isinstance(cpes, Exception):
                        logger.warning(f"CPE extraction failed for log_id {log_id}: {cpes}")
                    elif isinstance(cpes, list) and cpes:
                        logger.debug(f"Found {len(cpes)} CPEs for log_id {log_id}: {cpes}")
                        cpe_list.extend(cpes)
                        log_ids_for_cpe.extend([log_id] * len(cpes))
                        ioc_info = log_id_to_ioc.get(log_id, {})
                        ioc_data_for_cpe.extend([ioc_info] * len(cpes))
                    else:
                        logger.debug(f"No CPEs found for log_id {log_id}")
        
        logger.info(f"Total CPEs for CVE lookup: {len(cpe_list)} (extracted from log_ids)")

        cve_task = None
        if cpe_list:
            logger.info(f"Starting CVE lookup for {len(cpe_list)} CPEs")
            cve_task = CVECheckerService.check_cves_by_cpe(cpe_list, log_ids_for_cpe, ioc_data_for_cpe)
        else:
            logger.warning("No CPEs found, skipping CVE lookup")
        
        cached_ips, not_found_ips, cached_domains, not_found_domains, cached_hashes, not_found_hashes, stats = await ioc_task

        ip_tier_map = {
            item.ip_address: item
            for item in request.ip_data
            if item.rule_tier is not None and item.rule_tier >= 2
        }
        if ip_tier_map:
            promotion_targets = [
                entry for entry in not_found_ips
                if entry.get("ip_address") in ip_tier_map
            ]
            for entry in promotion_targets:
                ip_item = ip_tier_map[entry["ip_address"]]
                try:
                    await BehavioralPromoterService.promote_ip(
                        ip_address=ip_item.ip_address,
                        rule_tier=ip_item.rule_tier,
                        log_id=ip_item.log_id,
                        threat_categories=ip_item.threat_categories,
                        agent_id=ip_item.agent_id,
                    )
                    logger.info(
                        f"Auto-promoted {ip_item.ip_address} to GTIC-Behavioral "
                        f"(rule_tier={ip_item.rule_tier})"
                    )
                except Exception as promo_err:
                    logger.error(
                        f"Auto-promotion failed for {ip_item.ip_address}: {promo_err}"
                    )

        matched_cves = []
        not_found_cpes = []
        cve_stats = {"redis_hits": 0, "postgresql_hits": 0, "external_api_calls": 0}
        
        if cve_task:
            try:
                matched_cves, not_found_cpes, cve_stats = await cve_task
            except Exception as e:
                logger.warning(f"CVE check failed (continuing without CVE data): {e}")
        
        all_ioc_results = cached_ips + cached_domains + cached_hashes
        correlation_metadata = CorrelationEngine.correlate_ioc_and_cve(all_ioc_results, matched_cves)
        
        response = CheckIOCsResponse(
            total_requested=request.total_ips + request.total_domains + request.total_hashes,
            cache_hits=len(cached_ips) + len(cached_domains) + len(cached_hashes),
            cache_misses=len(not_found_ips) + len(not_found_domains) + len(not_found_hashes),
            redis_hits=stats.get("redis_hits", 0) + cve_stats.get("redis_hits", 0),
            postgresql_hits=stats.get("postgresql_hits", 0) + cve_stats.get("postgresql_hits", 0),
            external_api_calls=stats.get("external_api_calls", 0) + cve_stats.get("external_api_calls", 0),
            cached_ips=cached_ips,
            not_found_ips=not_found_ips,
            cached_domains=cached_domains,
            not_found_domains=not_found_domains,
            cached_hashes=cached_hashes,
            not_found_hashes=not_found_hashes,
            cve_correlation={
                'matched_cves': matched_cves,
                'not_found_cpes': not_found_cpes,
                'stats': cve_stats
            },
            correlation_metadata=correlation_metadata
        )
        
        response_dict = response.model_dump()
        
        return response_dict
        
    except Exception as e:
        logger.error(f"Error processing IOC check request: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error while processing request"
        )


@router.post(
    "/api/v1/cpe-lookup",
    response_model=CPECollectorResponse,
    status_code=status.HTTP_200_OK,
)
async def cpe_lookup(request: CPECollectorRequest):
    """
    Bulk CVE lookup for assets sent by cpe_collector.

    Accepts a list of CPE strings with asset metadata. Returns matched
    CVEs, each with the specific matched CPE.

    AND/OR config evaluation is performed per-device: each item's CVEs are
    evaluated against only that device's CPE set (the item's own CPE plus the
    OS CPE of its device where known), preventing cross-device confirmation.
    """
    try:
        logger.info(f"CPE lookup: {len(request.items)} items")

        device_os_cpe: dict[str, str] = {}
        for item in request.items:
            if item.type == "os" and item.meta.device_id:
                device_os_cpe[item.meta.device_id] = item.cpe_string

        def _item_context(item) -> list[str]:
            """Return the CPE evaluation context for one item (item CPE + device OS CPE)."""
            if item.type == "os":
                return [item.cpe_string]
            os_cpes = [
                device_os_cpe[dev.device_id]
                for dev in (item.meta.affected_devices or [])
                if dev.device_id in device_os_cpe
            ]
            return list(dict.fromkeys([item.cpe_string] + os_cpes))

        context_to_items: dict[tuple, list] = {}
        for item in request.items:
            ctx_key = tuple(sorted(_item_context(item)))
            context_to_items.setdefault(ctx_key, []).append(item)

        _lookup_semaphore = asyncio.Semaphore(8)

        async def _lookup_context(ctx_key: tuple, items: list) -> tuple[list, dict]:
            """Run one lookup for a unique context and return (items, cpe→cves map)."""
            async with _lookup_semaphore:
                ctx_list = list(ctx_key)
                matched, *_ = await CVECheckerService.check_cves_by_cpe(
                    cpe_list=ctx_list,
                    log_ids=ctx_list,
                )
            cpe_to_cves: dict[str, list] = {}
            for cve in matched:
                cpe_str = cve.get("log_id")
                if cpe_str:
                    cve_out = {k: v for k, v in cve.items() if k not in ("log_id", "criteria")}
                    cve_out["cpe"] = cve.get("criteria")
                    cpe_to_cves.setdefault(cpe_str, []).append(cve_out)
            return items, cpe_to_cves

        lookup_results = await asyncio.gather(*[
            _lookup_context(ctx_key, items)
            for ctx_key, items in context_to_items.items()
        ])

        item_cve_map: dict[int, list] = {}
        for items, cpe_to_cves in lookup_results:
            for item in items:
                item_cve_map[id(item)] = cpe_to_cves.get(item.cpe_string, [])

        results = []
        total_cves = 0
        for item in request.items:
            cves = item_cve_map.get(id(item), [])

            if item.type == "os":
                result = {
                    "type": "os",
                    "device_id": item.meta.device_id,
                    "asset_name": item.meta.asset_name,
                    "mac_level": item.meta.mac_level,
                    "env_vector": item.meta.env_vector,
                    "cpe_confidence": item.meta.cpe_confidence,
                    "cpe_string": item.cpe_string,
                    "cves": cves,
                }
            else:
                affected_devices = [
                    d.model_dump() for d in (item.meta.affected_devices or [])
                ]
                result = {
                    "type": "software",
                    "catalog_id": item.meta.catalog_id,
                    "software_name": item.meta.software_name,
                    "software_version": item.meta.software_version,
                    "vendor": item.meta.vendor,
                    "cpe_confidence": item.meta.cpe_confidence,
                    "cpe_string": item.cpe_string,
                    "affected_devices": affected_devices,
                    "cves": cves,
                }

            results.append(result)
            total_cves += len(cves)

        logger.info(f"CPE lookup response: {total_cves} total CVEs across {len(results)} items")
        return CPECollectorResponse(
            total_cves_found=total_cves,
            results=results,
        )

    except Exception as e:
        logger.error(f"Error processing CPE lookup request: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error while processing CPE lookup",
        )


@router.post(
    "/api/v1/cve-lookup",
    response_model=CVELookupResponse,
    status_code=status.HTTP_200_OK,
)
async def cve_lookup(request: CVELookupRequest):
    """
    Bulk CVE lookup by CVE identifier (e.g. CVE-2021-44228).
    Proxies to the internal lookup service.
    """
    settings = get_settings()
    cve_id_list = request.cve_ids

    if len(cve_id_list) > settings.max_iocs_per_request:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Too many CVE IDs. Maximum allowed: {settings.max_iocs_per_request}",
        )

    try:
        logger.info(f"CVE lookup: {len(cve_id_list)} CVE IDs")

        matched_cves, not_found_cve_ids, cve_stats = await CVECheckerService.check_cves_by_id(
            cve_id_list=cve_id_list,
        )
        return CVELookupResponse(
            total_requested=len(cve_id_list),
            total_matched=len(matched_cves),
            matched_cves=matched_cves,
            not_found_cve_ids=not_found_cve_ids,
            stats=CVELookupStats(**cve_stats),
        )
    except Exception as e:
        logger.error(f"Error processing CVE lookup request: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error while processing CVE lookup",
        )


@router.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK
)
async def health_check():
    """
    Health check endpoint
    
    Returns service status and database connectivity
    """
    db_status = "healthy" if await db.health_check() else "unhealthy"
    
    if db_status == "unhealthy":
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database connection unhealthy"
        )
    
    return HealthResponse(
        status="healthy",
        database=db_status
    )


@router.post(
    "/api/v1/promote-behavioral-ioc",
    response_model=BehavioralPromotionResponse,
    status_code=status.HTTP_200_OK,
)
async def promote_behavioral_ioc(request: BehavioralPromotionRequest):
    """
    Promote a behaviorally-detected IP to malicious status in the GTIC.

    When the behavioral detection engine flags an IP with HIGH (rule_tier=2) or
    CRITICAL (rule_tier=3) severity and no external threat intelligence source
    confirms it, this endpoint persists an internally-derived threat record in
    the GTIC under the 'GTIC-Behavioral' source.

    The record is written only when the derived threat_score exceeds any score
    already present for that IP — existing entries are never downgraded.

    rule_tier mapping:
      - 0 (Low) / 1 (Medium): not promoted, returns promoted=false
      - 2 (High):     threat_score=7, threat_level=2, TTL=7 days
      - 3 (Critical): threat_score=9, threat_level=3, TTL=30 days
    """
    try:
        result = await BehavioralPromoterService.promote_ip(
            ip_address=request.ip_address,
            rule_tier=request.rule_tier,
            log_id=request.log_id,
            threat_categories=request.threat_categories,
            agent_id=request.agent_id,
        )

        return BehavioralPromotionResponse(
            ip_address=request.ip_address,
            promoted=result["promoted"],
            threat_score=result.get("threat_score", 0),
            threat_level=result.get("threat_level", 0),
            threat_categories=result.get("threat_categories", ""),
            source_api=result.get("source_api", ""),
            message=result["message"],
        )

    except Exception as e:
        logger.error(f"Error promoting behavioral IOC {request.ip_address}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error while promoting behavioral IOC",
        )


@router.post("/admin/nvd/cpe-sync")
async def trigger_cpe_dict_sync_endpoint(mode: str = "incremental"):
    """
    Manually trigger NVD CPE dictionary sync.

    Args:
        mode: "incremental" (default) — fetch only entries modified since last sync
              "full" — fetch entire CPE dictionary (~1M entries, takes hours)
    """
    if mode not in ("incremental", "full"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Mode must be 'incremental' or 'full'",
        )
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"http://localhost:8002/trigger/nvd-cpe?mode={mode}",
                timeout=3600.0,
            )
            response.raise_for_status()
            result = response.json()
        return {"status": "success", "message": f"CPE dictionary sync completed (mode: {mode})", "result": result}
    except httpx.HTTPError as e:
        logger.error(f"Error calling ingestion service for CPE dict sync: {e}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to connect to ingestion service: {str(e)}",
        )


@router.post("/admin/otx/sync")
async def trigger_otx_sync_endpoint():
    """
    Manually trigger OTX domain collection and storage
    Returns statistics about the sync operation
    """
    try:
        logger.info("Manual OTX sync triggered via API")
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post("http://localhost:8002/admin/manual-sync", timeout=300.0)
                response.raise_for_status()
                result = response.json()
            except httpx.HTTPError as e:
                logger.error(f"Error calling ingestion service: {e}")
                return {
                    "status": "error",
                    "message": f"Failed to connect to ingestion service: {str(e)}"
                }

        if result["status"] == "error":
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=result["message"]
            )

        logger.info("Manual OTX sync completed successfully")
        return {
            "status": "success",
            "message": "OTX domain sync completed",
            "result": result
        }
        
    except Exception as e:
        logger.error(f"Manual OTX sync failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"OTX sync failed: {str(e)}"
        )


@router.post("/admin/nvd/sync")
async def trigger_nvd_sync_endpoint(mode: str = "incremental"):
    """
    Manually trigger NVD CVE ingestion
    
    Args:
        mode: "incremental" (default) - fetch only modified CVEs since last sync
              "full" - fetch all CVEs (for initial ingestion)
    
    Returns statistics about the sync operation
    """
    if mode not in ["incremental", "full"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Mode must be 'incremental' or 'full'"
        )
    
    try:
        logger.info(f"Manual NVD CVE sync triggered via API (mode: {mode})")
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    f"http://localhost:8002/trigger/nvd?mode={mode}",
                    timeout=3600.0  # Longer timeout for full ingestion
                )
                response.raise_for_status()
                result = response.json()
            except httpx.HTTPError as e:
                logger.error(f"Error calling ingestion service: {e}")
                return {
                    "status": "error",
                    "message": f"Failed to connect to ingestion service: {str(e)}"
                }
        
        if result.get("status") == "error":
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=result.get("message", "Unknown error")
            )
        
        logger.info(f"Manual NVD CVE sync completed successfully (mode: {mode})")
        return {
            "status": "success",
            "message": f"NVD CVE sync completed (mode: {mode})",
            "result": result
        }
        
    except Exception as e:
        logger.error(f"Manual NVD sync failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"NVD sync failed: {str(e)}"
        )
