"""
Service factory for creating and configuring IP lookup services.
This factory handles dependency injection and configuration of all modular components.
"""

import asyncio
import logging
from typing import List, Optional, Dict, Any
import os

from .interfaces.cache import CacheInterface
from .interfaces.database import DatabaseRepositoryInterface
from .interfaces.providers import ThreatProviderInterface
from .implementations.redis_cache import RedisCache
from .implementations.postgres_repo import PostgreSQLRepository
from .implementations.domain_postgres_repo import DomainPostgreSQLRepository
from .implementations.abuseipdb import AbuseIPDBProvider
from .implementations.virustotal import VirusTotalProvider
from .implementations.virustotal_domain import VirusTotalDomainProvider
from .processor import IPProcessor
from .domain_processor import DomainProcessor

logger = logging.getLogger(__name__)


class IPLookupServiceFactory:
    """
    Factory for creating and configuring IP lookup services.
    Handles dependency injection and service configuration.
    """
    
    def __init__(self, db_pool=None, config: Optional[Dict[str, Any]] = None):
        self.db_pool = db_pool
        self.config = config or {}
        self._cache: Optional[CacheInterface] = None
        self._database: Optional[DatabaseRepositoryInterface] = None
        self._domain_database: Optional[DatabaseRepositoryInterface] = None
        self._providers: List[ThreatProviderInterface] = []
        self._domain_providers: List[ThreatProviderInterface] = []
        self._hash_providers: List[ThreatProviderInterface] = []
        self._processor: Optional[IPProcessor] = None
        self._domain_processor: Optional[DomainProcessor] = None
        self._hash_processor: Optional['HashProcessor'] = None
    
    async def create_processor(
        self,
        max_workers: int = 20,
        abuseipdb_limit: int = 50000,
        mock_mode: bool = False
    ) -> IPProcessor:
        """
        Create a fully configured IP processor.
        
        Args:
            max_workers: Maximum concurrent workers
            abuseipdb_limit: Number of requests to send to AbuseIPDB before switching to VirusTotal
            mock_mode: Whether to use mock providers for testing
            
        Returns:
            Configured IPProcessor instance
        """
        if self._processor:
            return self._processor
        
        cache = await self._create_cache()
        database = await self._create_database()
        providers = await self._create_providers(mock_mode)
        
        if not providers:
            logger.warning("No threat intelligence providers configured")

        self._processor = IPProcessor(
            cache=cache,
            database=database,
            providers=providers,
            max_workers=max_workers,
            abuseipdb_limit=abuseipdb_limit
        )
        
        for provider in providers:
            if hasattr(provider, 'set_rate_limit_callback'):
                provider.set_rate_limit_callback(self._processor.set_batch_rate_limited)
        
        logger.info(f"Created IP processor with {len(providers)} providers")
        return self._processor
    
    async def create_domain_processor(
        self,
        max_workers: int = 20,
        mock_mode: bool = False
    ) -> DomainProcessor:
        """
        Create a fully configured domain processor.
        
        Args:
            max_workers: Maximum concurrent workers
            mock_mode: Whether to use mock providers for testing
            
        Returns:
            Configured DomainProcessor instance
        """
        if self._domain_processor:
            return self._domain_processor
        
        cache = await self._create_cache()
        domain_database = await self._create_domain_database()
        domain_providers = await self._create_domain_providers(mock_mode)
        
        if not domain_providers:
            logger.warning("No domain threat intelligence providers configured")

        self._domain_processor = DomainProcessor(
            cache=cache,
            database=domain_database,
            providers=domain_providers,
            max_workers=max_workers
        )
        
        for provider in domain_providers:
            if hasattr(provider, 'set_rate_limit_callback'):
                provider.set_rate_limit_callback(self._domain_processor.set_batch_rate_limited)
        
        logger.info(f"Created domain processor with {len(domain_providers)} providers")
        return self._domain_processor
    
    async def create_hash_processor(
        self,
        max_workers: int = 20,
        mock_mode: bool = False
    ) -> 'HashProcessor':
        """
        Create a fully configured hash processor.
        
        Args:
            max_workers: Maximum concurrent workers
            mock_mode: Whether to use mock providers for testing
            
        Returns:
            Configured HashProcessor instance
        """
        if self._hash_processor:
            return self._hash_processor
        
        from .hash_processor import HashProcessor
        
        cache = await self._create_cache()
        database = await self._create_database()
        hash_providers = await self._create_hash_providers(mock_mode)
        
        if not hash_providers:
            logger.warning("No hash threat intelligence providers configured")

        self._hash_processor = HashProcessor(
            cache=cache,
            database=database,
            providers=hash_providers,
            max_workers=max_workers
        )
        
        for provider in hash_providers:
            if hasattr(provider, 'set_rate_limit_callback'):
                provider.set_rate_limit_callback(self._hash_processor.set_batch_rate_limited)
        
        await self._hash_processor.start()
        logger.info(f"Created hash processor with {len(hash_providers)} providers")
        return self._hash_processor
    
    async def _create_cache(self) -> CacheInterface:
        """Create and configure Redis cache"""
        if self._cache:
            return self._cache
        
        redis_host = self.config.get('redis_host', os.getenv('REDIS_HOST', 'localhost'))
        redis_port = self.config.get('redis_port', int(os.getenv('REDIS_PORT', '6379')))
        redis_password = self.config.get('redis_password', os.getenv('REDIS_PASSWORD'))
        
        connection_kwargs = {}
        if redis_password:
            connection_kwargs['password'] = redis_password
        
        self._cache = RedisCache(
            host=redis_host,
            port=redis_port,
            **connection_kwargs
        )
        
        await self._cache.connect()
        logger.info(f"Connected to Redis cache at {redis_host}:{redis_port}")
        return self._cache
    
    async def _create_database(self) -> DatabaseRepositoryInterface:
        """Create and configure database repository"""
        if self._database:
            return self._database
        
        if not self.db_pool:
            raise RuntimeError("Database pool is required for PostgreSQL repository")
        
        self._database = PostgreSQLRepository(db_pool=self.db_pool)
        logger.info("Created PostgreSQL repository")
        return self._database
    
    async def _create_domain_database(self) -> DatabaseRepositoryInterface:
        """Create and configure domain database repository"""
        if self._domain_database:
            return self._domain_database
        
        if not self.db_pool:
            raise RuntimeError("Database pool is required for domain PostgreSQL repository")
        
        self._domain_database = DomainPostgreSQLRepository(db_pool=self.db_pool)
        logger.info("Created domain PostgreSQL repository")
        return self._domain_database
    
    async def _create_providers(self, mock_mode: bool = False) -> List[ThreatProviderInterface]:
        """Create and configure threat intelligence providers"""
        if self._providers:
            return self._providers
        
        providers = []

        abuseipdb_key = self.config.get('abuseipdb_api_key', os.getenv('ABUSEIPDB_API_KEY'))
        if abuseipdb_key or mock_mode:
            abuseipdb_provider = AbuseIPDBProvider(
                api_key=abuseipdb_key or 'mock-key',
                mock_mode=mock_mode,
                rate_limit=self.config.get('abuseipdb_rate_limit', 0.001)
            )
            await abuseipdb_provider.connect()
            providers.append(abuseipdb_provider)
            logger.info(f"Created AbuseIPDB provider (mock_mode: {mock_mode})")
        else:
            logger.warning("AbuseIPDB API key not found, skipping AbuseIPDB provider")

        virustotal_key = self.config.get('virustotal_api_key', os.getenv('VIRUSTOTAL_API_KEY'))
        if virustotal_key or mock_mode:
            virustotal_provider = VirusTotalProvider(
                api_key=virustotal_key or 'mock-key',
                mock_mode=mock_mode,
                rate_limit=self.config.get('virustotal_rate_limit', 0.001)
            )
            await virustotal_provider.connect()
            providers.append(virustotal_provider)
            logger.info(f"Created VirusTotal provider (mock_mode: {mock_mode})")
        else:
            logger.warning("VirusTotal API key not found, skipping VirusTotal provider")
        
        self._providers = providers
        return providers
    
    async def _create_domain_providers(self, mock_mode: bool = False) -> List[ThreatProviderInterface]:
        """Create and configure domain threat intelligence providers"""
        if self._domain_providers:
            return self._domain_providers
        
        providers = []

        # COMMENTED OUT: VirusTotal domain lookup (no premium API keys available)
        # Only using Redis cache and database lookup for domains
        # virustotal_key = self.config.get('virustotal_api_key', os.getenv('VIRUSTOTAL_API_KEY'))
        # if virustotal_key or mock_mode:
        #     virustotal_domain_provider = VirusTotalDomainProvider(
        #         api_key=virustotal_key or 'mock-key',
        #         mock_mode=mock_mode,
        #         rate_limit=self.config.get('virustotal_rate_limit', 0.001)
        #     )
        #     await virustotal_domain_provider.connect()
        #     providers.append(virustotal_domain_provider)
        # else:
        #     logger.warning("VirusTotal API key not found, skipping VirusTotal domain provider")
        
        self._domain_providers = providers
        return providers
    
    async def _create_hash_providers(self, mock_mode: bool = False) -> List[ThreatProviderInterface]:
        """Create and configure hash threat intelligence providers"""
        if self._hash_providers:
            return self._hash_providers
        
        providers = []

        # virustotal_key = self.config.get('virustotal_api_key', os.getenv('VIRUSTOTAL_API_KEY'))
        # if virustotal_key or mock_mode:
        #     virustotal_hash_provider = VirusTotalProvider(
        #         api_key=virustotal_key or 'mock-key',
        #         mock_mode=mock_mode,
        #         rate_limit=self.config.get('virustotal_rate_limit', 0.25)
        #     )
        #     await virustotal_hash_provider.connect()
        #     providers.append(virustotal_hash_provider)
        #     logger.info(f"Created VirusTotal hash provider (mock_mode: {mock_mode})")
        # else:
        #     logger.warning("VirusTotal API key not found, skipping VirusTotal hash provider")
        
        self._hash_providers = providers
        return providers
    
    async def health_check(self) -> Dict[str, bool]:
        """Check health of all components"""
        health_status = {}
        
        if self._processor:
            ip_health = await self._processor.health_check()
            health_status.update({f"ip_{k}": v for k, v in ip_health.items()})
        else:
            health_status["ip_processor"] = False
            
        if self._domain_processor:
            domain_health = await self._domain_processor.health_check()
            health_status.update({f"domain_{k}": v for k, v in domain_health.items()})
        else:
            health_status["domain_processor"] = False
            
        if self._hash_processor:
            hash_health = await self._hash_processor.health_check()
            health_status.update({f"hash_{k}": v for k, v in hash_health.items()})
        else:
            health_status["hash_processor"] = False
        
        return health_status
    
    async def close(self) -> None:
        """Close all connections and cleanup resources"""
        logger.info("Closing IP lookup service factory")
        
        if self._processor:
            await self._processor.close()
            self._processor = None
            
        if self._domain_processor:
            await self._domain_processor.close()
            self._domain_processor = None
            
        if self._hash_processor:
            await self._hash_processor.close()
            self._hash_processor = None
        
        if self._cache:
            await self._cache.close()
            self._cache = None
        
        if self._database:
            await self._database.close()
            self._database = None
            
        if self._domain_database:
            await self._domain_database.close()
            self._domain_database = None

        for provider in self._providers:
            try:
                await provider.close()
            except Exception as e:
                logger.error(f"Error closing IP provider {provider.get_provider_name()}: {e}")
        
        for provider in self._domain_providers:
            try:
                await provider.close()
            except Exception as e:
                logger.error(f"Error closing domain provider {provider.get_provider_name()}: {e}")
        
        for provider in self._hash_providers:
            try:
                await provider.close()
            except Exception as e:
                logger.error(f"Error closing hash provider {provider.get_provider_name()}: {e}")
        
        self._providers.clear()
        self._domain_providers.clear()
        self._hash_providers.clear()
        logger.info("IP lookup service factory closed")


_factory_instance: Optional[IPLookupServiceFactory] = None


async def get_ip_lookup_service(
    db_pool=None,
    config: Optional[Dict[str, Any]] = None,
    max_workers: int = 20,
    abuseipdb_limit: int = 50000,
    mock_mode: bool = False
) -> IPProcessor:
    """
    Get or create the IP lookup service.
    
    This function provides a singleton-like interface for getting the IP processor.
    """
    global _factory_instance
    
    if not _factory_instance:
        _factory_instance = IPLookupServiceFactory(db_pool=db_pool, config=config)
    
    return await _factory_instance.create_processor(
        max_workers=max_workers,
        abuseipdb_limit=abuseipdb_limit,
        mock_mode=mock_mode
    )


async def get_domain_lookup_service(
    db_pool=None,
    config: Optional[Dict[str, Any]] = None,
    max_workers: int = 20,
    mock_mode: bool = False
) -> DomainProcessor:
    """
    Get or create the domain lookup service.
    
    This function provides a singleton-like interface for getting the domain processor.
    """
    global _factory_instance
    
    if not _factory_instance:
        _factory_instance = IPLookupServiceFactory(db_pool=db_pool, config=config)
    
    return await _factory_instance.create_domain_processor(
        max_workers=max_workers,
        mock_mode=mock_mode
    )


async def get_hash_lookup_service(
    db_pool=None,
    config: Optional[Dict[str, Any]] = None,
    max_workers: int = 20,
    mock_mode: bool = False
) -> 'HashProcessor':
    """
    Get or create the hash lookup service.
    
    This function provides a singleton-like interface for getting the hash processor.
    """
    global _factory_instance
    
    if not _factory_instance:
        _factory_instance = IPLookupServiceFactory(db_pool=db_pool, config=config)
    
    return await _factory_instance.create_hash_processor(
        max_workers=max_workers,
        mock_mode=mock_mode
    )


async def close_ip_lookup_service() -> None:
    """Close the IP lookup service and cleanup resources"""
    global _factory_instance
    
    if _factory_instance:
        await _factory_instance.close()
        _factory_instance = None