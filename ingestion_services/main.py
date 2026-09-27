"""
Ingestion Services Main Entry Point
Handles OTX and Malware Bazaar ingestion services
"""

import asyncio
import logging
import signal
import sys
from contextlib import asynccontextmanager
import os

from fastapi import FastAPI, HTTPException
# JSONResponse imported but handled by FastAPI automatically

from config import get_ingestion_settings
from logging_config import setup_logging
from database.connection import IngestionDatabase
from services.scheduler import IngestionScheduler

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

ingestion_scheduler: IngestionScheduler = None
ingestion_database: IngestionDatabase = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events"""
    global ingestion_scheduler, ingestion_database
    
    settings = get_ingestion_settings()
    setup_logging(log_level=settings.log_level, log_dir=settings.log_directory)
    
    logger.info(f"Starting {settings.service_name}")
    logger.info(f"Logging configured - writing to {settings.log_directory}/ directory")
    
    ingestion_database = IngestionDatabase(settings)
    if not await ingestion_database.connect():
        logger.error("Failed to connect to database, exiting")
        sys.exit(1)
    
    # Start unified scheduler (handles both OTX and Malware Bazaar)
    ingestion_scheduler = IngestionScheduler(settings, ingestion_database)
    await ingestion_scheduler.start()
    
    logger.info("Ingestion Services startup complete")
    
    yield
    
    logger.info("Shutting down Ingestion Services")
    
    if ingestion_scheduler:
        await ingestion_scheduler.stop()
    
    if ingestion_database:
        await ingestion_database.disconnect()
    
    logger.info("Ingestion Services shutdown complete")


version_info = get_version_info()
app = FastAPI(
    title="GTIC Ingestion Services",
    description="Background service for ingesting threat intelligence data (OTX, Malware Bazaar, NVD CVE)",
    version=__version__,
    lifespan=lifespan
)


@app.get("/")
async def root():
    """Root endpoint"""
    version_info = get_version_info()
    return {
        "service": "GTIC Ingestion Services",
        "version": version_info["version"],
        "sprint": version_info["sprint"],
        "release_date": version_info["release_date"],
        "status": "running",
        "services": ["OTX", "Malware Bazaar", "NVD CVE"]
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        db_stats = await ingestion_database.get_stats() if ingestion_database else {}
        return {
            "status": "healthy",
            "database": "connected" if ingestion_database else "disconnected",
            "scheduler": "running" if ingestion_scheduler and not ingestion_scheduler.stop_event.is_set() else "stopped",
            "stats": db_stats
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Health check failed: {str(e)}")


@app.post("/trigger/otx")
async def manual_trigger_otx():
    """Manually trigger OTX ingestion"""
    if not ingestion_scheduler:
        raise HTTPException(status_code=503, detail="Scheduler not initialized")
    
    try:
        logger.info("Manual OTX ingestion triggered via API")
        stats = await ingestion_scheduler.trigger_manual_otx_run()
        return {
            "status": "success",
            "message": "OTX ingestion completed",
            "stats": stats.model_dump()
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Manual OTX trigger failed: {e}")
        raise HTTPException(status_code=500, detail=f"Manual trigger failed: {str(e)}")


@app.post("/trigger/malwarebazaar")
async def manual_trigger_malwarebazaar():
    """Manually trigger Malware Bazaar ingestion"""
    if not ingestion_scheduler:
        raise HTTPException(status_code=503, detail="Scheduler not initialized")
    
    try:
        logger.info("Manual Malware Bazaar ingestion triggered via API")
        stats = await ingestion_scheduler.trigger_manual_malwarebazaar_run()
        return {
            "status": "success",
            "message": "Malware Bazaar ingestion completed",
            "stats": stats.model_dump()
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Manual Malware Bazaar trigger failed: {e}")
        raise HTTPException(status_code=500, detail=f"Manual trigger failed: {str(e)}")


@app.post("/trigger/nvd")
async def manual_trigger_nvd(mode: str = "incremental"):
    """
    Manually trigger NVD CVE ingestion
    
    Args:
        mode: "incremental" (default) - fetch only modified CVEs since last sync
              "full" - fetch all CVEs (for initial ingestion)
    """
    if not ingestion_scheduler:
        raise HTTPException(status_code=503, detail="Scheduler not initialized")
    
    if mode not in ["incremental", "full"]:
        raise HTTPException(status_code=400, detail="Mode must be 'incremental' or 'full'")
    
    try:
        logger.info(f"Manual NVD CVE ingestion triggered via API (mode: {mode})")
        stats = await ingestion_scheduler.trigger_manual_nvd_run(mode=mode)
        return {
            "status": "success",
            "message": f"NVD CVE ingestion completed (mode: {mode})",
            "stats": stats.model_dump()
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Manual NVD trigger failed: {e}")
        raise HTTPException(status_code=500, detail=f"Manual trigger failed: {str(e)}")


@app.post("/trigger/nvd-cpe")
async def manual_trigger_cpe_dict(mode: str = "incremental"):
    """
    Manually trigger NVD CPE dictionary sync.

    Args:
        mode: "incremental" (default) - fetch only entries modified since last sync
              "full" - fetch entire CPE dictionary (slow, ~1M entries)
    """
    if not ingestion_scheduler:
        raise HTTPException(status_code=503, detail="Scheduler not initialized")

    if mode not in ("incremental", "full"):
        raise HTTPException(status_code=400, detail="Mode must be 'incremental' or 'full'")

    try:
        logger.info(f"Manual CPE dictionary sync triggered (mode: {mode})")
        stats = await ingestion_scheduler.trigger_manual_cpe_dict_run(mode=mode)
        return {
            "status": "success",
            "message": f"CPE dictionary sync completed (mode: {mode})",
            "stats": stats.model_dump(),
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"CPE dictionary sync trigger failed: {e}")
        raise HTTPException(status_code=500, detail=f"Sync failed: {str(e)}")


@app.get("/stats")
async def get_stats():
    """Get current statistics"""
    try:
        import tracemalloc
        import psutil
        import os
        
        db_stats = await ingestion_database.get_stats() if ingestion_database else {}
        
        process = psutil.Process(os.getpid())
        memory_info = process.memory_info()
        
        tracemalloc_stats = {}
        if tracemalloc.is_tracing():
            snapshot = tracemalloc.take_snapshot()
            top_stats = snapshot.statistics('lineno')[:5]
            tracemalloc_stats = {
                "total_size_mb": sum(stat.size for stat in top_stats) / (1024 * 1024),
                "top_allocations": [f"{stat.traceback.format()[-1]} - {stat.size / 1024:.1f}KB" for stat in top_stats[:3]]
            }
        
        return {
            "database": db_stats,
            "scheduler_status": "running" if ingestion_scheduler and not ingestion_scheduler.stop_event.is_set() else "stopped",
            "memory": {
                "rss_mb": memory_info.rss / (1024 * 1024),
                "vms_mb": memory_info.vms / (1024 * 1024),
                "tracemalloc": tracemalloc_stats
            }
        }
    except Exception as e:
        logger.error(f"Stats retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=f"Stats retrieval failed: {str(e)}")

@app.get("/version")
async def get_version():
    """Get version information"""
    return get_version_info()

async def main():
    """Main function for running the service"""
    settings = get_ingestion_settings()
    
    def signal_handler(sig, _):
        logger.info(f"Received signal {sig}, shutting down...")
        asyncio.create_task(shutdown())
    
    async def shutdown():
        pass
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    import uvicorn
    
    logger.info(f"Starting Ingestion Services on port {settings.service_port}")
    
    config = uvicorn.Config(
        app,
        host="0.0.0.0",
        port=settings.service_port,
        log_level=settings.log_level.lower(),
        access_log=True
    )
    server = uvicorn.Server(config)
    await server.serve()


if __name__ == "__main__":
    asyncio.run(main())