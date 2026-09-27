"""Service interfaces for dependency injection and testing."""

from .cache import CacheInterface
from .database import DatabaseRepositoryInterface
from .providers import ThreatProviderInterface

__all__ = [
    "CacheInterface",
    "DatabaseRepositoryInterface", 
    "ThreatProviderInterface"
]