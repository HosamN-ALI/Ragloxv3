"""
RAGLOX v3.0 - Resource Monitor
Monitors VM resource usage and alerts on thresholds.

Author: RAGLOX Team
Version: 3.0.0
"""

import asyncio
import logging
from typing import Optional, Dict, Any, List, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum

from .oneprovider_client import OneProviderClient


logger = logging.getLogger("raglox.infrastructure.cloud_provider.resource_monitor")


class ResourceType(str, Enum):
    """Resource type"""
    BANDWIDTH = "bandwidth"
    DISK = "disk"
    CPU = "cpu"
    MEMORY = "memory"


class AlertLevel(str, Enum):
    """Alert severity level"""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class ResourceAlert:
    """Resource usage alert"""
    vm_id: str
    resource_type: ResourceType
    level: AlertLevel
    current_value: float
    threshold_value: float
    message: str
    timestamp: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "vm_id": self.vm_id,
            "resource_type": self.resource_type,
            "level": self.level,
            "current_value": self.current_value,
            "threshold_value": self.threshold_value,
            "message": self.message,
            "timestamp": self.timestamp.isoformat()
        }


@dataclass
class ResourceUsage:
    """VM resource usage snapshot"""
    vm_id: str
    timestamp: datetime
    bandwidth_used_gb: float
    bandwidth_limit_gb: Optional[float]
    bandwidth_percent: float
    disk_used_gb: float
    disk_total_gb: float
    disk_percent: float
    cpu_percent: float
    memory_used_mb: float
    memory_total_mb: float
    memory_percent: float


class ResourceMonitor:
    """
    Resource Monitor for VM usage tracking
    
    Features:
    - Continuous resource monitoring
    - Threshold-based alerts
    - Historical usage tracking
    - Alert callbacks
    """
    
    def __init__(
        self,
        client: OneProviderClient,
        poll_interval: int = 60,
        bandwidth_warning_threshold: float = 0.8,  # 80%
        bandwidth_critical_threshold: float = 0.95,  # 95%
        disk_warning_threshold: float = 0.8,
        disk_critical_threshold: float = 0.9
    ):
        """
        Initialize Resource Monitor
        
        Args:
            client: OneProvider client
            poll_interval: Polling interval in seconds
            bandwidth_warning_threshold: Bandwidth warning threshold (0.0-1.0)
            bandwidth_critical_threshold: Bandwidth critical threshold (0.0-1.0)
            disk_warning_threshold: Disk warning threshold (0.0-1.0)
            disk_critical_threshold: Disk critical threshold (0.0-1.0)
        """
        self.client = client
        self.poll_interval = poll_interval
        
        # Thresholds
        self.bandwidth_warning = bandwidth_warning_threshold
        self.bandwidth_critical = bandwidth_critical_threshold
        self.disk_warning = disk_warning_threshold
        self.disk_critical = disk_critical_threshold
        
        # Monitoring state
        self._running = False
        self._monitor_task: Optional[asyncio.Task] = None
        self._monitored_vms: set = set()
        
        # Usage history
        self._usage_history: Dict[str, List[ResourceUsage]] = {}
        self._alerts: List[ResourceAlert] = []
        
        # Alert callbacks
        self._alert_callbacks: List[Callable[[ResourceAlert], None]] = []
    
    def add_alert_callback(self, callback: Callable[[ResourceAlert], None]):
        """Add callback for alerts"""
        self._alert_callbacks.append(callback)
    
    async def start(self):
        """Start resource monitoring"""
        if self._running:
            logger.warning("Resource monitor already running")
            return
        
        self._running = True
        self._monitor_task = asyncio.create_task(self._monitor_loop())
        logger.info("Resource monitor started")
    
    async def stop(self):
        """Stop resource monitoring"""
        if not self._running:
            return
        
        self._running = False
        
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Resource monitor stopped")
    
    def monitor_vm(self, vm_id: str):
        """Add VM to monitoring"""
        self._monitored_vms.add(vm_id)
        logger.info(f"Added VM {vm_id} to monitoring")
    
    def unmonitor_vm(self, vm_id: str):
        """Remove VM from monitoring"""
        self._monitored_vms.discard(vm_id)
        logger.info(f"Removed VM {vm_id} from monitoring")
    
    async def _monitor_loop(self):
        """Main monitoring loop"""
        while self._running:
            try:
                for vm_id in list(self._monitored_vms):
                    await self._check_vm_resources(vm_id)
                
                await asyncio.sleep(self.poll_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in monitor loop: {str(e)}")
                await asyncio.sleep(self.poll_interval)
    
    async def _check_vm_resources(self, vm_id: str):
        """Check resources for a VM"""
        try:
            # Get VM info
            vm_info = await self.client.get_vm_info(vm_id)
            
            # Get bandwidth usage
            bandwidth_data = await self.client.get_bandwidth_usage(vm_id)
            bandwidth_used = bandwidth_data.get("total_used_gb", 0.0)
            bandwidth_limit = bandwidth_data.get("limit_gb")
            
            # Calculate percentages
            bandwidth_percent = 0.0
            if bandwidth_limit and bandwidth_limit > 0:
                bandwidth_percent = bandwidth_used / bandwidth_limit
            
            # Disk usage (from VM info)
            disk_used = vm_info.get("disk_used_gb", 0.0)
            disk_total = vm_info.get("disk_gb", 0.0)
            disk_percent = disk_used / disk_total if disk_total > 0 else 0.0
            
            # CPU and Memory (if available)
            cpu_percent = vm_info.get("cpu_percent", 0.0)
            memory_used = vm_info.get("memory_used_mb", 0.0)
            memory_total = vm_info.get("memory_mb", 0.0)
            memory_percent = memory_used / memory_total if memory_total > 0 else 0.0
            
            # Create usage snapshot
            usage = ResourceUsage(
                vm_id=vm_id,
                timestamp=datetime.utcnow(),
                bandwidth_used_gb=bandwidth_used,
                bandwidth_limit_gb=bandwidth_limit,
                bandwidth_percent=bandwidth_percent,
                disk_used_gb=disk_used,
                disk_total_gb=disk_total,
                disk_percent=disk_percent,
                cpu_percent=cpu_percent,
                memory_used_mb=memory_used,
                memory_total_mb=memory_total,
                memory_percent=memory_percent
            )
            
            # Store in history
            if vm_id not in self._usage_history:
                self._usage_history[vm_id] = []
            
            self._usage_history[vm_id].append(usage)
            
            # Keep last 24 hours only
            cutoff = datetime.utcnow() - timedelta(hours=24)
            self._usage_history[vm_id] = [
                u for u in self._usage_history[vm_id]
                if u.timestamp > cutoff
            ]
            
            # Check thresholds
            await self._check_thresholds(usage)
            
        except Exception as e:
            logger.error(f"Failed to check resources for VM {vm_id}: {str(e)}")
    
    async def _check_thresholds(self, usage: ResourceUsage):
        """Check if usage exceeds thresholds"""
        alerts = []
        
        # Bandwidth check
        if usage.bandwidth_limit_gb:
            if usage.bandwidth_percent >= self.bandwidth_critical:
                alerts.append(ResourceAlert(
                    vm_id=usage.vm_id,
                    resource_type=ResourceType.BANDWIDTH,
                    level=AlertLevel.CRITICAL,
                    current_value=usage.bandwidth_used_gb,
                    threshold_value=usage.bandwidth_limit_gb,
                    message=f"Bandwidth usage critical: {usage.bandwidth_percent * 100:.1f}%",
                    timestamp=usage.timestamp
                ))
            elif usage.bandwidth_percent >= self.bandwidth_warning:
                alerts.append(ResourceAlert(
                    vm_id=usage.vm_id,
                    resource_type=ResourceType.BANDWIDTH,
                    level=AlertLevel.WARNING,
                    current_value=usage.bandwidth_used_gb,
                    threshold_value=usage.bandwidth_limit_gb,
                    message=f"Bandwidth usage high: {usage.bandwidth_percent * 100:.1f}%",
                    timestamp=usage.timestamp
                ))
        
        # Disk check
        if usage.disk_percent >= self.disk_critical:
            alerts.append(ResourceAlert(
                vm_id=usage.vm_id,
                resource_type=ResourceType.DISK,
                level=AlertLevel.CRITICAL,
                current_value=usage.disk_used_gb,
                threshold_value=usage.disk_total_gb,
                message=f"Disk usage critical: {usage.disk_percent * 100:.1f}%",
                timestamp=usage.timestamp
            ))
        elif usage.disk_percent >= self.disk_warning:
            alerts.append(ResourceAlert(
                vm_id=usage.vm_id,
                resource_type=ResourceType.DISK,
                level=AlertLevel.WARNING,
                current_value=usage.disk_used_gb,
                threshold_value=usage.disk_total_gb,
                message=f"Disk usage high: {usage.disk_percent * 100:.1f}%",
                timestamp=usage.timestamp
            ))
        
        # Trigger alerts
        for alert in alerts:
            self._alerts.append(alert)
            logger.warning(f"Resource alert: {alert.message} for VM {alert.vm_id}")
            
            # Call callbacks
            for callback in self._alert_callbacks:
                try:
                    callback(alert)
                except Exception as e:
                    logger.error(f"Alert callback failed: {str(e)}")
    
    def get_usage_history(
        self,
        vm_id: str,
        hours: int = 1
    ) -> List[ResourceUsage]:
        """Get usage history for VM"""
        if vm_id not in self._usage_history:
            return []
        
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        return [
            u for u in self._usage_history[vm_id]
            if u.timestamp > cutoff
        ]
    
    def get_recent_alerts(
        self,
        vm_id: Optional[str] = None,
        hours: int = 24
    ) -> List[ResourceAlert]:
        """Get recent alerts"""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        alerts = [a for a in self._alerts if a.timestamp > cutoff]
        
        if vm_id:
            alerts = [a for a in alerts if a.vm_id == vm_id]
        
        return alerts
