from pydantic_settings import BaseSettings
from functools import lru_cache
from typing import Optional 
import os

class Settings(BaseSettings):
    """Application settings loaded from environment variables"""

    database_url: str
    
    DB_NAME: str = "intelligence"
    DB_USER: str = "intelligence_app"
    DB_PASSWORD: str = "overpower"
    DB_HOST: str = "127.0.0.1"
    DB_PORT: int = 5432
    
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    
    ALERTS_DB_PASSWORD: str

    log_level: str = "INFO"
    log_directory: str = "logs"
    max_iocs_per_request: int = 20000
    query_timeout: int = 180
    command_timeout: int = 180

    lookup_service_url: str = "http://localhost:8001"
    
    # Database pool settings
    db_pool_min_size: int = 3
    db_pool_max_size: int = 15
    batch_processing_chunk_size: int = 2000

    ABUSEIPDB_API_KEY: str
    VIRUSTOTAL_API_KEY: str
    OTX_API_KEY: Optional[str] = None
    MALWAREBAZAAR_API_KEY: Optional[str] = None
    NVD_API_KEY: Optional[str] = None

    MOCK_API_MODE: bool = False
    NVD_RATE_LIMIT: float = 0.67
    
    MAX_WORKERS: int = 25
    ABUSEIPDB_RATE_LIMIT: float = 0.001
    VIRUSTOTAL_RATE_LIMIT: float = 0.001
    ABUSEIPDB_LIMIT: int = 50000
    CACHE_TTL_BUFFER: int = 300
    
    redis_max_connections: int = 25
    redis_connection_pool_timeout: int = 30
    redis_socket_keepalive: bool = True

    class Config:
        env_file = ".env.test" if os.getenv("ENVIRONMENT") == "test" else ".env"
        case_sensitive = False 
        extra = "ignore" 


@lru_cache()
def get_settings() -> Settings:
    """Cached settings instance, loaded from environment."""
    return Settings()

settings = get_settings()
