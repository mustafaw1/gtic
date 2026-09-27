"""
OTX Ingestion Service Main Entry Point
"""

import asyncio
import logging
import signal
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
# JSONResponse imported but handled by FastAPI automatically

from config import get_otx_settings
from logging_config import setup_logging
from database.connection import OTXDatabase
from services.scheduler import OTXScheduler

logger = logging.getLogger(__name__)

otx_scheduler: OTXScheduler = None
otx_database: OTXDatabase = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events"""
    global otx_scheduler, otx_database
    
    settings = get_otx_settings()
    setup_logging(log_level=settings.log_level, log_dir=settings.log_directory)
    
    logger.info(f"Starting {settings.service_name}")
    logger.info(f"Logging configured - writing to {settings.log_directory}/ directory")
    
    otx_database = OTXDatabase(settings)
    if not await otx_database.connect():
        logger.error("Failed to connect to database, exiting")
        sys.exit(1)
    
    otx_scheduler = OTXScheduler(settings, otx_database)
    await otx_scheduler.start()
    
    logger.info("OTX Ingestion Service startup complete")
    
    yield
    
    logger.info("Shutting down OTX Ingestion Service")
    
    if otx_scheduler:
        await otx_scheduler.stop()
    
    if otx_database:
        await otx_database.disconnect()
    
    logger.info("OTX Ingestion Service shutdown complete")


app = FastAPI(
    title="OTX Ingestion Service",
    description="Background service for ingesting OTX threat intelligence data",
    version="1.0.0",
    lifespan=lifespan
)


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "OTX Ingestion Service",
        "version": "1.0.0",
        "status": "running"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        db_stats = await otx_database.get_stats() if otx_database else {}
        return {
            "status": "healthy",
            "database": "connected" if otx_database else "disconnected",
            "scheduler": "running" if otx_scheduler and not otx_scheduler.stop_event.is_set() else "stopped",
            "stats": db_stats
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Health check failed: {str(e)}")


@app.post("/trigger")
async def manual_trigger():
    """Manually trigger OTX ingestion"""
    if not otx_scheduler:
        raise HTTPException(status_code=503, detail="Scheduler not initialized")
    
    try:
        logger.info("Manual OTX ingestion triggered via API")
        stats = await otx_scheduler.trigger_manual_run()
        return {
            "status": "success",
            "message": "OTX ingestion completed",
            "stats": stats.model_dump()
        }
    except Exception as e:
        logger.error(f"Manual trigger failed: {e}")
        raise HTTPException(status_code=500, detail=f"Manual trigger failed: {str(e)}")


@app.get("/stats")
async def get_stats():
    """Get current statistics"""
    try:
        import tracemalloc
        import psutil
        import os
        
        db_stats = await otx_database.get_stats() if otx_database else {}
        
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
            "scheduler_status": "running" if otx_scheduler and not otx_scheduler.stop_event.is_set() else "stopped",
            "memory": {
                "rss_mb": memory_info.rss / (1024 * 1024),
                "vms_mb": memory_info.vms / (1024 * 1024),
                "tracemalloc": tracemalloc_stats
            }
        }
    except Exception as e:
        logger.error(f"Stats retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=f"Stats retrieval failed: {str(e)}")


async def main():
    """Main function for running the service"""
    settings = get_otx_settings()
    
    def signal_handler(sig, _):
        logger.info(f"Received signal {sig}, shutting down...")
        asyncio.create_task(shutdown())
    
    async def shutdown():
        pass
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    import uvicorn
    
    logger.info(f"Starting OTX Ingestion Service on port {settings.service_port}")
    
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