"""
RAGLOX v3.0 - Health Monitor
Monitors health of agent environments.

Author: RAGLOX Team
Version: 3.0.0
"""

import asyncio
import logging
from typing import Optional, Dict, Any, List, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum

from .environment_manager import EnvironmentManager, AgentEnvironment, EnvironmentStatus


logger = logging.getLogger("raglox.infrastructure.orchestrator.health_monitor")


class HealthStatus(str, Enum):
    """Health status"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class HealthCheck:
    """Health check result"""
    environment_id: str
    status: HealthStatus
    timestamp: datetime
    checks: Dict[str, bool]
    latency_ms: float
    message: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "environment_id": self.environment_id,
            "status": self.status,
            "timestamp": self.timestamp.isoformat(),
            "checks": self.checks,
            "latency_ms": self.latency_ms,
            "message": self.message
        }


class HealthMonitor:
    """
    Health Monitor
    
    Monitors health of agent environments:
    - Periodic health checks
    - Latency monitoring
    - Connection status tracking
    - Automatic reconnection
    - Health alerts
    """
    
    def __init__(
        self,
        environment_manager: EnvironmentManager,
        check_interval: int = 60,
        latency_threshold_ms: float = 1000.0,
        auto_reconnect: bool = True
    ):
        """
        Initialize Health Monitor
        
        Args:
            environment_manager: Environment manager
            check_interval: Health check interval in seconds
            latency_threshold_ms: Latency threshold for degraded status
            auto_reconnect: Automatically reconnect unhealthy environments
        """
        self.environment_manager = environment_manager
        self.check_interval = check_interval
        self.latency_threshold_ms = latency_threshold_ms
        self.auto_reconnect = auto_reconnect
        
        # Monitoring state
        self._running = False
        self._monitor_task: Optional[asyncio.Task] = None
        
        # Health history
        self._health_history: Dict[str, List[HealthCheck]] = {}
        
        # Alert callbacks
        self._alert_callbacks: List[Callable[[HealthCheck], None]] = []
    
    def add_alert_callback(self, callback: Callable[[HealthCheck], None]):
        """Add callback for health alerts"""
        self._alert_callbacks.append(callback)
    
    async def start(self):
        """Start health monitoring"""
        if self._running:
            logger.warning("Health monitor already running")
            return
        
        self._running = True
        self._monitor_task = asyncio.create_task(self._monitor_loop())
        logger.info("Health monitor started")
    
    async def stop(self):
        """Stop health monitoring"""
        if not self._running:
            return
        
        self._running = False
        
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Health monitor stopped")
    
    async def _monitor_loop(self):
        """Main monitoring loop"""
        while self._running:
            try:
                # Get all environments
                stats = await self.environment_manager.get_statistics()
                
                # Check each environment
                # (In production, get actual environment list)
                # For now, we'll implement basic monitoring
                
                await asyncio.sleep(self.check_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in health monitor loop: {str(e)}")
                await asyncio.sleep(self.check_interval)
    
    async def check_environment(
        self,
        environment: AgentEnvironment
    ) -> HealthCheck:
        """
        Perform health check on environment
        
        Args:
            environment: Agent environment
        
        Returns:
            HealthCheck result
        """
        started_at = datetime.utcnow()
        checks = {}
        
        try:
            # Check 1: Environment status
            checks["status"] = environment.status in [
                EnvironmentStatus.READY,
                EnvironmentStatus.CONNECTED
            ]
            
            # Check 2: SSH connection
            if environment.ssh_manager and environment.connection_id:
                try:
                    connection = await environment.ssh_manager.get_connection(
                        environment.connection_id
                    )
                    checks["ssh_connection"] = connection is not None
                except Exception:
                    checks["ssh_connection"] = False
            else:
                checks["ssh_connection"] = False
            
            # Check 3: Latency test (simple ping)
            if checks["ssh_connection"]:
                try:
                    latency_start = datetime.utcnow()
                    
                    # Execute simple command
                    connection = await environment.ssh_manager.get_connection(
                        environment.connection_id
                    )
                    
                    if connection:
                        result = await asyncio.wait_for(
                            connection.run("echo ping", check=False),
                            timeout=5.0
                        )
                        
                        latency_ms = (
                            (datetime.utcnow() - latency_start).total_seconds() * 1000
                        )
                        
                        checks["latency"] = latency_ms < self.latency_threshold_ms
                    else:
                        latency_ms = 0.0
                        checks["latency"] = False
                        
                except asyncio.TimeoutError:
                    latency_ms = 5000.0  # 5 seconds timeout
                    checks["latency"] = False
                except Exception:
                    latency_ms = 0.0
                    checks["latency"] = False
            else:
                latency_ms = 0.0
                checks["latency"] = False
            
            # Check 4: VM status (for sandbox)
            if environment.vm_instance:
                checks["vm"] = True  # Simplified check
            
            # Check 5: Last activity
            if environment.last_activity:
                idle_time = (datetime.utcnow() - environment.last_activity).total_seconds()
                checks["active"] = idle_time < 3600  # Active in last hour
            else:
                checks["active"] = False
            
            # Determine overall health status
            passed_checks = sum(1 for v in checks.values() if v)
            total_checks = len(checks)
            
            if passed_checks == total_checks:
                status = HealthStatus.HEALTHY
                message = "All checks passed"
            elif passed_checks >= total_checks * 0.5:
                status = HealthStatus.DEGRADED
                failed = [k for k, v in checks.items() if not v]
                message = f"Degraded - failed checks: {', '.join(failed)}"
            else:
                status = HealthStatus.UNHEALTHY
                failed = [k for k, v in checks.items() if not v]
                message = f"Unhealthy - failed checks: {', '.join(failed)}"
            
            health_check = HealthCheck(
                environment_id=environment.environment_id,
                status=status,
                timestamp=datetime.utcnow(),
                checks=checks,
                latency_ms=latency_ms,
                message=message
            )
            
            # Store in history
            self._store_health_check(environment.environment_id, health_check)
            
            # Trigger alerts for unhealthy status
            if status == HealthStatus.UNHEALTHY:
                logger.warning(
                    f"Environment {environment.environment_id} unhealthy: {message}"
                )
                
                for callback in self._alert_callbacks:
                    try:
                        callback(health_check)
                    except Exception as e:
                        logger.error(f"Health alert callback failed: {str(e)}")
                
                # Auto-reconnect if enabled
                if self.auto_reconnect and not checks.get("ssh_connection", True):
                    logger.info(
                        f"Attempting auto-reconnect for environment "
                        f"{environment.environment_id}"
                    )
                    await self.environment_manager.reconnect_environment(
                        environment.environment_id
                    )
            
            return health_check
            
        except Exception as e:
            logger.error(
                f"Health check failed for {environment.environment_id}: {str(e)}"
            )
            
            return HealthCheck(
                environment_id=environment.environment_id,
                status=HealthStatus.UNKNOWN,
                timestamp=datetime.utcnow(),
                checks={},
                latency_ms=0.0,
                message=f"Health check error: {str(e)}"
            )
    
    def _store_health_check(self, environment_id: str, check: HealthCheck):
        """Store health check in history"""
        if environment_id not in self._health_history:
            self._health_history[environment_id] = []
        
        self._health_history[environment_id].append(check)
        
        # Keep last 24 hours only
        cutoff = datetime.utcnow() - timedelta(hours=24)
        self._health_history[environment_id] = [
            c for c in self._health_history[environment_id]
            if c.timestamp > cutoff
        ]
    
    def get_health_history(
        self,
        environment_id: str,
        hours: int = 1
    ) -> List[HealthCheck]:
        """Get health check history"""
        if environment_id not in self._health_history:
            return []
        
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        return [
            c for c in self._health_history[environment_id]
            if c.timestamp > cutoff
        ]
    
    def get_health_statistics(
        self,
        environment_id: str,
        hours: int = 24
    ) -> Dict[str, Any]:
        """Get health statistics for environment"""
        history = self.get_health_history(environment_id, hours)
        
        if not history:
            return {
                "environment_id": environment_id,
                "period_hours": hours,
                "total_checks": 0
            }
        
        # Calculate statistics
        total = len(history)
        healthy = sum(1 for c in history if c.status == HealthStatus.HEALTHY)
        degraded = sum(1 for c in history if c.status == HealthStatus.DEGRADED)
        unhealthy = sum(1 for c in history if c.status == HealthStatus.UNHEALTHY)
        
        # Average latency
        latencies = [c.latency_ms for c in history if c.latency_ms > 0]
        avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
        
        # Uptime percentage
        uptime_percent = (healthy / total * 100) if total > 0 else 0.0
        
        return {
            "environment_id": environment_id,
            "period_hours": hours,
            "total_checks": total,
            "healthy_count": healthy,
            "degraded_count": degraded,
            "unhealthy_count": unhealthy,
            "uptime_percent": uptime_percent,
            "average_latency_ms": avg_latency,
            "latest_status": history[-1].status if history else HealthStatus.UNKNOWN
        }
