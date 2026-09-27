"""
Resource usage metrics and monitoring for IP lookup services.

This module provides comprehensive metrics collection, monitoring, and reporting
for all resources used in the threat intelligence processing system.
"""

import time
import psutil
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field

from .resource_manager import get_resource_manager

logger = logging.getLogger(__name__)


@dataclass
class SystemMetrics:
    """System-level resource usage metrics."""
    cpu_percent: float
    memory_usage_mb: float
    memory_percent: float
    available_memory_mb: float
    disk_usage_percent: float
    network_connections: int
    open_files: int
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ServiceMetrics:
    """Service-specific metrics for IP lookup components."""
    cache_hits: int = 0
    cache_misses: int = 0
    db_queries: int = 0
    api_calls: int = 0
    errors: int = 0
    processed_ips: int = 0
    processing_time_ms: float = 0.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    @property
    def cache_hit_rate(self) -> float:
        """Calculate cache hit rate as percentage."""
        total = self.cache_hits + self.cache_misses
        return (self.cache_hits / total * 100) if total > 0 else 0.0
    
    @property
    def error_rate(self) -> float:
        """Calculate error rate as percentage."""
        total = self.processed_ips
        return (self.errors / total * 100) if total > 0 else 0.0


@dataclass
class ResourceUtilization:
    """Resource utilization statistics."""
    database_connections_active: int = 0
    database_connections_peak: int = 0
    redis_operations_active: int = 0
    redis_operations_peak: int = 0
    ip_locks_active: int = 0
    ip_locks_peak: int = 0
    memory_pools_active: int = 0
    memory_pools_size_mb: float = 0.0
    total_resources: int = 0
    leaked_resources: int = 0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class MetricsCollector:
    """
    Centralized metrics collection and reporting system.
    
    Collects metrics from all components and provides reporting capabilities.
    """
    
    def __init__(self):
        self.resource_manager = get_resource_manager()
        self.process = psutil.Process()
        self.start_time = time.time()
        
        # Metrics history
        self._system_metrics_history: List[SystemMetrics] = []
        self._service_metrics_history: List[ServiceMetrics] = []
        self._resource_utilization_history: List[ResourceUtilization] = []
        
        # Keep last 100 metric points (adjustable)
        self._max_history_size = 100
        
    def collect_system_metrics(self) -> SystemMetrics:
        """Collect current system-level metrics."""
        try:
            cpu_percent = self.process.cpu_percent()
            memory_info = self.process.memory_info()
            memory_percent = self.process.memory_percent()
            
            system_memory = psutil.virtual_memory()
            available_memory_mb = system_memory.available / 1024 / 1024
            
            disk_usage = psutil.disk_usage('/')
            disk_usage_percent = (disk_usage.used / disk_usage.total) * 100
            
            connections = len(self.process.net_connections())
            open_files = self.process.num_fds() if hasattr(self.process, 'num_fds') else 0
            
            metrics = SystemMetrics(
                cpu_percent=cpu_percent,
                memory_usage_mb=memory_info.rss / 1024 / 1024,
                memory_percent=memory_percent,
                available_memory_mb=available_memory_mb,
                disk_usage_percent=disk_usage_percent,
                network_connections=connections,
                open_files=open_files
            )
            
            # Store in history
            self._system_metrics_history.append(metrics)
            if len(self._system_metrics_history) > self._max_history_size:
                self._system_metrics_history.pop(0)
                
            return metrics
            
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
            return SystemMetrics(0, 0, 0, 0, 0, 0, 0)
    
    def collect_service_metrics(self, processor_stats: Dict[str, Any] = None) -> ServiceMetrics:
        """Collect service-specific metrics."""
        try:
            stats = processor_stats or {}
            
            metrics = ServiceMetrics(
                cache_hits=stats.get('cache_hits', 0),
                cache_misses=stats.get('cache_misses', 0),
                db_queries=stats.get('db_hits', 0),
                api_calls=stats.get('external_api_calls', 0),
                errors=stats.get('error_count', 0),
                processed_ips=stats.get('processed_count', 0),
                processing_time_ms=stats.get('processing_time_ms', 0.0)
            )
            
            # Store in history
            self._service_metrics_history.append(metrics)
            if len(self._service_metrics_history) > self._max_history_size:
                self._service_metrics_history.pop(0)
                
            return metrics
            
        except Exception as e:
            logger.error(f"Error collecting service metrics: {e}")
            return ServiceMetrics()
    
    def collect_resource_utilization(self) -> ResourceUtilization:
        """Collect resource utilization metrics."""
        try:
            resource_metrics = self.resource_manager.get_metrics()
            resource_details = self.resource_manager.get_resource_details()
            
            db_connections = 0
            redis_ops = 0
            ip_locks = 0
            memory_pools = 0
            memory_size = 0.0
            
            for resource in resource_details:
                res_type = resource['type']
                if res_type == 'database_connection':
                    db_connections += 1
                elif res_type == 'redis_connection':
                    redis_ops += 1
                elif res_type == 'ip_lock':
                    ip_locks += 1
                elif res_type == 'memory_cache':
                    memory_pools += 1
                    metadata = resource.get('metadata', {})
                    if 'size_mb' in metadata:
                        memory_size += metadata['size_mb']
            
            # Get peak values from resource metrics
            total_leaks = sum(
                rm.get('leak_count', 0) 
                for rm in resource_metrics.get('resource_metrics', {}).values()
            )
            
            metrics = ResourceUtilization(
                database_connections_active=db_connections,
                redis_operations_active=redis_ops,
                ip_locks_active=ip_locks,
                memory_pools_active=memory_pools,
                memory_pools_size_mb=memory_size,
                total_resources=resource_metrics.get('total_tracked_resources', 0),
                leaked_resources=total_leaks
            )
            
            # Store in history
            self._resource_utilization_history.append(metrics)
            if len(self._resource_utilization_history) > self._max_history_size:
                self._resource_utilization_history.pop(0)
                
            return metrics
            
        except Exception as e:
            logger.error(f"Error collecting resource utilization: {e}")
            return ResourceUtilization()
    
    def get_comprehensive_metrics(self, processor_stats: Dict[str, Any] = None) -> Dict[str, Any]:
        """Get all metrics in a comprehensive report."""
        system_metrics = self.collect_system_metrics()
        service_metrics = self.collect_service_metrics(processor_stats)
        resource_metrics = self.collect_resource_utilization()
        
        # Calculate uptime
        uptime_seconds = time.time() - self.start_time
        uptime_str = str(timedelta(seconds=int(uptime_seconds)))
        
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "uptime_seconds": uptime_seconds,
            "uptime": uptime_str,
            "system_metrics": {
                "cpu_percent": system_metrics.cpu_percent,
                "memory_usage_mb": system_metrics.memory_usage_mb,
                "memory_percent": system_metrics.memory_percent,
                "available_memory_mb": system_metrics.available_memory_mb,
                "disk_usage_percent": system_metrics.disk_usage_percent,
                "network_connections": system_metrics.network_connections,
                "open_files": system_metrics.open_files
            },
            "service_metrics": {
                "cache_hit_rate": service_metrics.cache_hit_rate,
                "error_rate": service_metrics.error_rate,
                "cache_hits": service_metrics.cache_hits,
                "cache_misses": service_metrics.cache_misses,
                "db_queries": service_metrics.db_queries,
                "api_calls": service_metrics.api_calls,
                "errors": service_metrics.errors,
                "processed_ips": service_metrics.processed_ips,
                "processing_time_ms": service_metrics.processing_time_ms
            },
            "resource_utilization": {
                "database_connections_active": resource_metrics.database_connections_active,
                "redis_operations_active": resource_metrics.redis_operations_active,
                "ip_locks_active": resource_metrics.ip_locks_active,
                "memory_pools_active": resource_metrics.memory_pools_active,
                "memory_pools_size_mb": resource_metrics.memory_pools_size_mb,
                "total_resources": resource_metrics.total_resources,
                "leaked_resources": resource_metrics.leaked_resources
            }
        }
    
    def get_performance_trends(self, minutes: int = 30) -> Dict[str, Any]:
        """Get performance trends over the specified time window."""
        cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        
        # Filter metrics within time window
        recent_system = [m for m in self._system_metrics_history if m.timestamp > cutoff_time]
        recent_service = [m for m in self._service_metrics_history if m.timestamp > cutoff_time]
        recent_resource = [m for m in self._resource_utilization_history if m.timestamp > cutoff_time]
        
        if not recent_system:
            return {"error": "No metrics available for the specified time window"}
        
        # Calculate trends
        system_trend = {
            "avg_cpu_percent": sum(m.cpu_percent for m in recent_system) / len(recent_system),
            "avg_memory_mb": sum(m.memory_usage_mb for m in recent_system) / len(recent_system),
            "max_memory_mb": max(m.memory_usage_mb for m in recent_system),
            "avg_connections": sum(m.network_connections for m in recent_system) / len(recent_system),
        }
        
        if recent_service:
            service_trend = {
                "avg_cache_hit_rate": sum(m.cache_hit_rate for m in recent_service) / len(recent_service),
                "avg_error_rate": sum(m.error_rate for m in recent_service) / len(recent_service),
                "total_processed": sum(m.processed_ips for m in recent_service),
                "total_errors": sum(m.errors for m in recent_service),
            }
        else:
            service_trend = {}
        
        if recent_resource:
            resource_trend = {
                "avg_total_resources": sum(m.total_resources for m in recent_resource) / len(recent_resource),
                "max_db_connections": max(m.database_connections_active for m in recent_resource),
                "max_ip_locks": max(m.ip_locks_active for m in recent_resource),
                "total_leaks": sum(m.leaked_resources for m in recent_resource),
            }
        else:
            resource_trend = {}
        
        return {
            "time_window_minutes": minutes,
            "sample_count": len(recent_system),
            "system_trends": system_trend,
            "service_trends": service_trend,
            "resource_trends": resource_trend
        }
    
    def get_health_score(self) -> Dict[str, Any]:
        """Calculate overall system health score."""
        try:
            system = self.collect_system_metrics()
            service = self.collect_service_metrics()
            resource = self.collect_resource_utilization()
            
            # Health scoring (0-100)
            health_factors = []
            
            # Memory health (100 = good, 0 = critical)
            memory_score = max(0, 100 - system.memory_percent)
            health_factors.append(("memory", memory_score))
            
            # CPU health
            cpu_score = max(0, 100 - system.cpu_percent)
            health_factors.append(("cpu", cpu_score))
            
            # Error rate health
            error_score = max(0, 100 - service.error_rate)
            health_factors.append(("errors", error_score))
            
            # Resource leak health
            leak_score = 100 if resource.leaked_resources == 0 else max(0, 100 - resource.leaked_resources * 5)
            health_factors.append(("leaks", leak_score))
            
            # Overall health score (weighted average)
            overall_score = sum(score for _, score in health_factors) / len(health_factors)
            
            # Health status
            if overall_score >= 80:
                status = "HEALTHY"
            elif overall_score >= 60:
                status = "WARNING"
            elif overall_score >= 40:
                status = "CRITICAL"
            else:
                status = "FAILING"
            
            return {
                "overall_score": round(overall_score, 2),
                "status": status,
                "factors": dict(health_factors),
                "recommendations": self._get_health_recommendations(health_factors)
            }
            
        except Exception as e:
            logger.error(f"Error calculating health score: {e}")
            return {"overall_score": 0, "status": "ERROR", "error": str(e)}
    
    def _get_health_recommendations(self, health_factors: List[tuple]) -> List[str]:
        """Generate health recommendations based on scores."""
        recommendations = []
        
        for factor, score in health_factors:
            if score < 50:
                if factor == "memory":
                    recommendations.append("High memory usage detected. Consider reducing batch sizes or adding memory.")
                elif factor == "cpu":
                    recommendations.append("High CPU usage detected. Consider reducing concurrency or optimizing queries.")
                elif factor == "errors":
                    recommendations.append("High error rate detected. Check logs and external service connectivity.")
                elif factor == "leaks":
                    recommendations.append("Resource leaks detected. Review resource cleanup and connection management.")
        
        if not recommendations:
            recommendations.append("System is operating within normal parameters.")
        
        return recommendations


# Global metrics collector instance
metrics_collector = MetricsCollector()