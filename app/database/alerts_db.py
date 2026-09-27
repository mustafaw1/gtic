import asyncpg
import logging
from typing import Optional
from app.config import get_settings

logger = logging.getLogger(__name__)


class AlertsDatabase:
    def __init__(self):
        self.pool: Optional[asyncpg.Pool] = None
    
    async def connect(self):
        try:
            settings = get_settings()
            self.pool = await asyncpg.create_pool(
                host="192.168.1.234",
                port=5432,
                database="alerts",
                user="alerts_admin",
                password=settings.ALERTS_DB_PASSWORD,
                min_size=1,
                max_size=3,
                command_timeout=settings.command_timeout,
            )
            logger.info("Alerts database connection pool created")
        except Exception as e:
            logger.error(f"Failed to create alerts database pool: {e}")
            raise
    
    async def disconnect(self):
        if self.pool:
            await self.pool.close()
            logger.info("Alerts database connection pool closed")


alerts_db = AlertsDatabase()


async def get_alerts_pool() -> asyncpg.Pool:
    if not alerts_db.pool:
        raise RuntimeError("Alerts database pool not initialized")
    return alerts_db.pool


