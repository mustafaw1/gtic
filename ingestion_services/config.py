from pydantic_settings import BaseSettings
from functools import lru_cache
from pydantic import Field
import os

class IngestionServiceSettings(BaseSettings):
    """Ingestion Services configuration settings (OTX, Malware Bazaar, etc.)"""

    OTX_API_KEY: str
    otx_base_url: str = "https://otx.alienvault.com/api/v1"
    otx_pulse_delay: float = 3.0
    
    MALWAREBazaar_API_KEY: str
    malwarebazaar_base_url: str = "https://mb-api.abuse.ch/api/v1"
    malwarebazaar_query_limit: int = 1000
    
    NVD_API_KEY: str
    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_rate_limit: float = 0.67  # ~50 requests per 30 seconds with API key
    
    DB_HOST: str = "127.0.0.1"
    DB_PORT: int = 5432
    DB_NAME: str = "intelligence"
    DB_USER: str = "intelligence_app"
    DB_PASSWORD: str = "overpower"
    
    batch_size: int = 200
    max_memory_mb: int = 100
    
    schedule_interval_hours: int = 1
    
    log_level: str = "INFO"
    log_directory: str = "logs"
    
    service_name: str = "ingestion-services"
    service_port: int = 8002
    
    db_pool_min_size: int = Field(default=1, env=None)
    db_pool_max_size: int = Field(default=5, env=None)
    http_connection_limit: int = Field(default=20, env=None)
    http_per_host_limit: int = Field(default=5, env=None)

    model_config = {
        "env_file": "../.env.test" if os.getenv('ENV') == 'test' else "../.env",
        "case_sensitive": False,
        "extra": "ignore"
    }


@lru_cache()
def get_ingestion_settings() -> IngestionServiceSettings:
    """Get ingestion services settings instance"""
    return IngestionServiceSettings()