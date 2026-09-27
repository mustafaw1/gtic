from pydantic_settings import BaseSettings
from functools import lru_cache
from typing import Optional

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
    
    log_level: str = "INFO"
    log_directory: str = "logs"
    max_iocs_per_request: int = 100000
    query_timeout: int = 180
    command_timeout: int = 180
    
    db_pool_min_size: int = 3
    db_pool_max_size: int = 25

    ABUSEIPDB_API_KEY: str
    VIRUSTOTAL_API_KEY: str
    OTX_API_KEY: Optional[str] = None
    MALWAREBAZAAR_API_KEY: Optional[str] = None
 
    NVD_API_KEY: Optional[str] = "bffbaa88-f4e4-4cb8-a8cb-f55424362c35"

    MOCK_API_MODE: bool = False
    NVD_RATE_LIMIT: float = 0.67
    
    MAX_WORKERS: int = 25
    ABUSEIPDB_RATE_LIMIT: float = 0.001
    VIRUSTOTAL_RATE_LIMIT: float = 0.25
    ABUSEIPDB_LIMIT: int = 50000
    CACHE_TTL_BUFFER: int = 300
    batch_processing_chunk_size: int = 2000

    class Config:
        env_file = ".env"
        case_sensitive = False
        extra = "ignore"


@lru_cache()
def get_settings() -> Settings:
    """Cached settings instance, loaded from environment."""
    return Settings()

settings = get_settings()
