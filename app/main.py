import logging
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.api.endpoints import router
from app.database.connection import db
from app.database.alerts_db import alerts_db
from app.config import get_settings
from app.logging_config import setup_logging

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

background_tasks = set()
shutdown_in_progress = False


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events"""
    settings = get_settings()
    
    setup_logging(log_level=settings.log_level, log_dir=settings.log_directory)
    logger.info(f"Starting IOC Threat API (Log Level: {settings.log_level})")
    logger.info(f"Logging configured - writing to console and {settings.log_directory}/ directory")
    
    await db.connect()
    await alerts_db.connect()

    logger.info("Application startup complete")

    yield

    global shutdown_in_progress
    shutdown_in_progress = True
    logger.info("Shutting down application")

    if background_tasks:
        logger.info(f"Waiting for {len(background_tasks)} background tasks to complete...")
        await asyncio.gather(*background_tasks, return_exceptions=True)
        logger.info("All background tasks completed")

    try:
        from app.services.lookup_client import close_lookup_client
        logger.info("Closing IOC lookup service client...")
        await close_lookup_client()
        logger.info("IOC Lookup service client closed successfully")
    except Exception as e:
        logger.error(f"Error closing IP lookup service: {e}")

    await db.disconnect()
    await alerts_db.disconnect()
    logger.info("Application shutdown complete")


# Create FastAPI app
version_info = get_version_info()
app = FastAPI(
    title=version_info["title"],
    description=version_info["description"],
    version=__version__,
    lifespan=lifespan
)

@app.middleware("http")
async def shutdown_middleware(request: Request, call_next):
    """Middleware to reject new requests during shutdown"""
    if shutdown_in_progress:
        logger.warning(f"Rejecting request to {request.url.path} - server is shutting down")
        return JSONResponse(
            status_code=503,
            content={
                "error": "Service Unavailable", 
                "message": "Server is shutting down, please retry later"
            }
        )
    return await call_next(request)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(router)


@app.get("/")
async def root():
    """Root endpoint"""
    version_info = get_version_info()
    return {
        "service": version_info["title"],
        "version": version_info["version"],
        "sprint": version_info["sprint"],
        "release_date": version_info["release_date"],
        "status": "running"
    }

@app.get("/version")
async def get_version():
    """Get version information"""
    return get_version_info()
