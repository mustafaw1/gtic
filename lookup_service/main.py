#!/usr/bin/env python3
"""
Global Threat Intelligence Cache - Lookup Service
Independent service for IP and domain threat intelligence lookups
"""

import asyncio
import logging
import signal
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
import os

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .config import get_settings
from .logging_config import setup_logging
from .database.connection import db
from .factory import get_ip_lookup_service, get_domain_lookup_service, close_ip_lookup_service
from .cve_processor import CVEProcessor
from .implementations.redis_cache import RedisCache
from .implementations.cve_postgres_repo import CVEPostgreSQLRepository
from .implementations.nvd_client import NVDProvider

parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

try:
    from version import get_version_info, __version__
except ImportError:
    def get_version_info():
        return {
            "version": "1.2.0", 
            "version_info": (1, 2, 0),
            "sprint": "Sprint 27",
            "release_date": "2026-01-09",
            "title": "Global Threat Intelligence Cache (GTIC)",
            "description": "Multi-service threat intelligence platform with IOC correlation and CVE tracking"
        }
    __version__ = "1.2.0"

logger = logging.getLogger(__name__)


# Request/Response Models
class HashInput(BaseModel):
    hash_value: str
    hash_type: str = "sha256"

class LookupRequest(BaseModel):
    ips: List[str] = []
    domains: List[str] = []
    hashes: List[Dict[str, str]] = []

class LookupResponse(BaseModel):
    results: Dict[str, Any]
    stats: Dict[str, int]


class PromoteRequest(BaseModel):
    """Direct injection of a behaviorally-derived threat record into the GTIC."""
    ip_address: str
    threat_score: int
    threat_level: int
    threat_categories: str
    source_name: str
    country_code: Optional[str] = None
    total_reports: int = 1
    first_seen: Optional[str] = None
    last_fetched: Optional[str] = None
    expires_at: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = None


class PromoteResponse(BaseModel):
    stored: bool
    message: str
    ip_address: str
    threat_score: int
    previous_threat_score: Optional[int] = None


class CVELookupByCPERequest(BaseModel):
    cpe_entries: List[Dict[str, str]]  # List of dicts with 'cpe_string' and optional 'log_id'


class CVELookupByIDRequest(BaseModel):
    cve_entries: List[Dict[str, str]]  # List of dicts with 'cve_id' and optional 'log_id'


class CVELookupResponse(BaseModel):
    results: Dict[str, Any]
    stats: Dict[str, int]


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events"""
    settings = get_settings()
    
    setup_logging(log_level=settings.log_level, log_dir=settings.log_directory)
    logger.info(f"Starting Lookup Service (Log Level: {settings.log_level})")
    
    try:
        await db.connect()
        logger.info("Lookup service started successfully")
        yield
    except Exception as e:
        logger.error(f"Failed to start lookup service: {e}")
        raise
    finally:
        try:
            await close_ip_lookup_service()
            await db.disconnect()
            logger.info("Lookup service shutdown complete")
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")


version_info = get_version_info()
app = FastAPI(
    title="Global Threat Intelligence Cache - Lookup Service",
    description="Independent service for IP, domain, and file hash threat intelligence lookups",
    version=__version__,
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/lookup", response_model=LookupResponse)
async def perform_lookup(request: LookupRequest):
    """
    Perform threat intelligence lookup for IPs and/or domains
    
    Returns threat intelligence data from cache or external sources
    """
    try:
        results = {}
        stats = {"cache_hits": 0, "external_api_calls": 0, "db_hits": 0}
        
        settings = get_settings()
        
        service_config = {
            'redis_host': getattr(settings, 'REDIS_HOST', 'localhost'),
            'redis_port': getattr(settings, 'REDIS_PORT', 6379),
            'abuseipdb_api_key': getattr(settings, 'ABUSEIPDB_API_KEY', ''),
            'virustotal_api_key': getattr(settings, 'VIRUSTOTAL_API_KEY', ''),
            'abuseipdb_rate_limit': getattr(settings, 'ABUSEIPDB_RATE_LIMIT', 0.001),
            'virustotal_rate_limit': getattr(settings, 'VIRUSTOTAL_RATE_LIMIT', 0.001)
        }
        
        from .database.connection import get_db_pool
        db_pool = await get_db_pool()
        
        tasks = []
        
        if request.ips:
            async def process_ips():
                ip_processor = await get_ip_lookup_service(
                    db_pool=db_pool,
                    config=service_config,
                    max_workers=getattr(settings, 'MAX_WORKERS', 20),
                    abuseipdb_limit=getattr(settings, 'ABUSEIPDB_LIMIT', 50000),
                    mock_mode=getattr(settings, 'MOCK_API_MODE', False)
                )
                ip_entries = [{"ip_address": ip, "log_id": f"lookup_{i}"} for i, ip in enumerate(request.ips)]
                
                ip_processing_result = await ip_processor.process_ips(ip_entries)
                
                return {
                    "ips": [ip.to_dict() for ip in ip_processing_result.cached_ips] if ip_processing_result.cached_ips else [],
                    "cache_hits": ip_processing_result.redis_hits if hasattr(ip_processing_result, 'redis_hits') else 0,
                    "db_hits": ip_processing_result.postgresql_hits if hasattr(ip_processing_result, 'postgresql_hits') else 0,
                    "external_api_calls": ip_processing_result.external_api_calls if hasattr(ip_processing_result, 'external_api_calls') else 0
                }
            
            tasks.append(asyncio.create_task(process_ips()))
        
        if request.domains:
            async def process_domains():
                domain_processor = await get_domain_lookup_service(
                    db_pool=db_pool,
                    config=service_config,
                    max_workers=getattr(settings, 'MAX_WORKERS', 20),
                    mock_mode=getattr(settings, 'MOCK_API_MODE', False)
                )
                domain_entries = [{"domain_name": domain, "log_id": f"lookup_{i}"} for i, domain in enumerate(request.domains)]
                
                domain_processing_result = await domain_processor.process_domains(domain_entries)
                
                return {
                    "domains": [domain.to_dict() for domain in domain_processing_result.cached_domains] if domain_processing_result.cached_domains else [],
                    "cache_hits": domain_processing_result.redis_hits if hasattr(domain_processing_result, 'redis_hits') else 0,
                    "db_hits": domain_processing_result.postgresql_hits if hasattr(domain_processing_result, 'postgresql_hits') else 0,
                    "external_api_calls": domain_processing_result.external_api_calls if hasattr(domain_processing_result, 'external_api_calls') else 0
                }
            
            tasks.append(asyncio.create_task(process_domains()))
        
        if request.hashes:
            async def process_hashes():
                from .factory import get_hash_lookup_service
                
                hash_processor = await get_hash_lookup_service(
                    db_pool=db_pool,
                    config=service_config,
                    max_workers=getattr(settings, 'MAX_WORKERS', 20),
                    mock_mode=getattr(settings, 'MOCK_API_MODE', False)
                )
                hash_entries = [
                    {
                        "hash_value": h.get('hash_value'),
                        "hash_type": h.get('hash_type', 'sha256'),
                        "log_id": f"lookup_{i}"
                    }
                    for i, h in enumerate(request.hashes)
                ]
                
                hash_processing_result = await hash_processor.process_hashes(hash_entries)
                
                return {
                    "hashes": [h.to_dict() for h in hash_processing_result.cached_hashes] if hash_processing_result.cached_hashes else [],
                    "cache_hits": hash_processing_result.redis_hits if hasattr(hash_processing_result, 'redis_hits') else 0,
                    "db_hits": hash_processing_result.postgresql_hits if hasattr(hash_processing_result, 'postgresql_hits') else 0,
                    "external_api_calls": hash_processing_result.external_api_calls if hasattr(hash_processing_result, 'external_api_calls') else 0
                }
            
            tasks.append(asyncio.create_task(process_hashes()))
        
        if tasks:
            task_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in task_results:
                if isinstance(result, Exception):
                    logger.error(f"Lookup task failed: {result}", exc_info=result)
                elif isinstance(result, dict):
                    if "ips" in result:
                        results["ips"] = result["ips"]
                    if "domains" in result:
                        results["domains"] = result["domains"]
                    if "hashes" in result:
                        results["hashes"] = result["hashes"]
                    stats["cache_hits"] += result.get("cache_hits", 0)
                    stats["db_hits"] += result.get("db_hits", 0)
                    stats["external_api_calls"] += result.get("external_api_calls", 0)
        
        return LookupResponse(results=results, stats=stats)
        
    except Exception as e:
        logger.error(f"Lookup request failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during lookup"
        )


@app.post("/promote", response_model=PromoteResponse)
async def promote_behavioral_ioc(request: PromoteRequest):
    """
    Directly store a behaviorally-derived threat record in the GTIC.

    The record is written only when its threat_score exceeds the score already
    cached for that IP. This guarantees that an internally-derived classification
    never downgrades an existing external-source entry.

    Both the PostgreSQL cache table and the Redis hot-cache are updated on a
    successful write.
    """
    try:
        from .database.connection import get_db_pool
        from .implementations.postgres_repo import PostgreSQLRepository
        from .implementations.redis_cache import RedisCache

        db_pool = await get_db_pool()
        db_repo = PostgreSQLRepository(db_pool=db_pool)
        existing = await db_repo.find_by_ip(request.ip_address)
        existing_score: int = existing.get("threat_score", 0) if existing else 0

        if existing_score >= request.threat_score:
            return PromoteResponse(
                stored=False,
                message=(
                    f"Existing GTIC entry has an equal or higher threat_score "
                    f"({existing_score}). Behavioral promotion skipped to avoid "
                    "downgrading an external-source classification."
                ),
                ip_address=request.ip_address,
                threat_score=existing_score,
                previous_threat_score=existing_score,
            )

        now = datetime.now(timezone.utc)

        def _parse_dt(value: Optional[str], fallback: datetime) -> datetime:
            if not value:
                return fallback
            dt = datetime.fromisoformat(value)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

        first_seen_dt = _parse_dt(request.first_seen, now)
        last_fetched_dt = _parse_dt(request.last_fetched, now)
        expires_at_dt = _parse_dt(request.expires_at, now + timedelta(days=7))

        db_dict = {
            "ip_address": request.ip_address,
            "threat_score": request.threat_score,
            "threat_level": request.threat_level,
            "threat_categories": request.threat_categories,
            "source_name": request.source_name,
            "country_code": request.country_code,
            "total_reports": request.total_reports,
            "first_seen": first_seen_dt,
            "last_fetched": last_fetched_dt,
            "expires_at": expires_at_dt,
            "raw_data": request.raw_data,
        }

        saved = await db_repo.save(db_dict)
        if saved:
            try:
                settings = get_settings()
                redis_cache = RedisCache(
                    host=getattr(settings, "REDIS_HOST", "localhost"),
                    port=getattr(settings, "REDIS_PORT", 6379),
                )
                await redis_cache.connect()

                cache_dict = {
                    **db_dict,
                    "first_seen": first_seen_dt.isoformat(),
                    "last_fetched": last_fetched_dt.isoformat(),
                    "expires_at": expires_at_dt.isoformat(),
                    "log_id": "",
                }
                ttl = max(1, int((expires_at_dt - now).total_seconds()))
                await redis_cache.set(request.ip_address, cache_dict, ttl)
                await redis_cache.close()
                logger.info(
                    f"Promoted {request.ip_address} to GTIC-Behavioral "
                    f"(score {existing_score} → {request.threat_score})"
                )
            except Exception as redis_err:
                logger.warning(
                    f"Redis update failed for promoted IP {request.ip_address}: {redis_err}"
                )

        return PromoteResponse(
            stored=saved,
            message=(
                f"IP promoted to malicious status in GTIC (source: {request.source_name})"
                if saved
                else "Failed to persist threat record in GTIC"
            ),
            ip_address=request.ip_address,
            threat_score=request.threat_score,
            previous_threat_score=existing_score if existing else None,
        )

    except Exception as e:
        logger.error(f"/promote endpoint failed for {request.ip_address}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error during IP promotion: {str(e)}",
        )


@app.post("/lookup/cve/by-cpe", response_model=CVELookupResponse)
async def lookup_cves_by_cpe(request: CVELookupByCPERequest):
    """
    Perform CVE lookup for CPE strings
    
    Returns CVE data matching the provided CPE strings
    """
    try:
        settings = get_settings()
        
        from .database.connection import get_db_pool
        db_pool = await get_db_pool()
        
        # Create CVE processor
        redis_cache = RedisCache(
            prefix="cve:",
            host=getattr(settings, 'REDIS_HOST', 'localhost'),
            port=getattr(settings, 'REDIS_PORT', 6379)
        )
        await redis_cache.connect()
        
        cve_repo = CVEPostgreSQLRepository(db_pool=db_pool)

        cve_processor = CVEProcessor(
            cache=redis_cache,
            database=cve_repo,
            provider=None,
            max_workers=getattr(settings, 'MAX_WORKERS', 10)
        )
        await cve_processor.start()

        processing_result = await cve_processor.process_cpes(request.cpe_entries)
        
        matched_cves = [cve.to_dict() for cve in processing_result.matched_cves]
        
        results = {
            "matched_cves": matched_cves,
            "not_found_cpes": processing_result.not_found_cpes
        }
        
        stats = {
            "redis_hits": processing_result.redis_hits,
            "postgresql_hits": processing_result.postgresql_hits,
            "external_api_calls": processing_result.external_api_calls
        }
        
        return CVELookupResponse(results=results, stats=stats)
        
    except Exception as e:
        logger.error(f"CVE lookup by CPE failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error during CVE lookup: {str(e)}"
        )


@app.post("/lookup/cve/by-id", response_model=CVELookupResponse)
async def lookup_cves_by_id(request: CVELookupByIDRequest):
    """
    Perform CVE lookup for CVE IDs
    
    Returns CVE data for the provided CVE IDs
    """
    try:
        settings = get_settings()
        
        from .database.connection import get_db_pool
        db_pool = await get_db_pool()
        
        redis_cache = RedisCache(
            prefix="cve:",
            host=getattr(settings, 'REDIS_HOST', 'localhost'),
            port=getattr(settings, 'REDIS_PORT', 6379)
        )
        await redis_cache.connect()
        
        cve_repo = CVEPostgreSQLRepository(db_pool=db_pool)
        
        nvd_api_key = getattr(settings, 'NVD_API_KEY', None)
        nvd_rate_limit = getattr(settings, 'NVD_RATE_LIMIT', 0.67) if nvd_api_key else 6.0
        nvd_provider = NVDProvider(
            api_key=nvd_api_key,
            mock_mode=getattr(settings, 'MOCK_API_MODE', False),
            rate_limit=nvd_rate_limit
        )
        await nvd_provider.connect()

        cve_processor = CVEProcessor(
            cache=redis_cache,
            database=cve_repo,
            provider=nvd_provider,
            max_workers=getattr(settings, 'MAX_WORKERS', 10)
        )
        await cve_processor.start()

        processing_result = await cve_processor.process_cve_ids(request.cve_entries)
        
        matched_cves = [cve.to_dict() for cve in processing_result.matched_cves]
        
        results = {
            "matched_cves": matched_cves,
            "not_found_cve_ids": processing_result.not_found_cpes
        }
        
        stats = {
            "redis_hits": processing_result.redis_hits,
            "postgresql_hits": processing_result.postgresql_hits,
            "external_api_calls": processing_result.external_api_calls
        }
        
        return CVELookupResponse(results=results, stats=stats)
        
    except Exception as e:
        logger.error(f"CVE lookup by ID failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error during CVE lookup: {str(e)}"
        )


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    db_status = "healthy" if await db.health_check() else "unhealthy"
    
    if db_status == "unhealthy":
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database connection unhealthy"
        )
    
    version_info = get_version_info()
    return {
        "status": "healthy",
        "service": "lookup_service",
        "version": version_info["version"],
        "sprint": version_info["sprint"],
        "database": db_status
    }

@app.get("/version")
async def get_version():
    """Get version information"""
    return get_version_info()

def handle_shutdown(signum, frame):
    """Handle shutdown signals"""
    logger.info(f"Received signal {signum}, shutting down...")
    sys.exit(0)


if __name__ == "__main__":
    import uvicorn
    
    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)
    
    settings = get_settings()
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8001,
        reload=settings.debug_mode,
        log_level=settings.log_level.lower()
    )