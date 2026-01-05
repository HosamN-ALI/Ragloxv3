"""
RAGLOX v3.0 - Advanced Logging and Monitoring System
====================================================

Comprehensive logging, monitoring, and alerting for all RAGLOX operations.
Provides real-time insights, performance metrics, and security event tracking.

Author: RAGLOX Team
Date: 2026-01-05
Version: 3.0.0
"""

import asyncio
import logging
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict, deque
import hashlib


class LogLevel(Enum):
    """Log severity levels"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class EventType(Enum):
    """Types of monitored events"""
    OPERATION_START = "operation_start"
    OPERATION_COMPLETE = "operation_complete"
    OPERATION_FAILURE = "operation_failure"
    TARGET_DISCOVERED = "target_discovered"
    VULNERABILITY_FOUND = "vulnerability_found"
    EXPLOIT_ATTEMPT = "exploit_attempt"
    EXPLOIT_SUCCESS = "exploit_success"
    CREDENTIAL_OBTAINED = "credential_obtained"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE_ESTABLISHED = "persistence_established"
    DEFENSE_DETECTED = "defense_detected"
    EVASION_ACTIVATED = "evasion_activated"
    DATA_EXFILTRATED = "data_exfiltrated"
    ERROR_OCCURRED = "error_occurred"
    RECOVERY_ATTEMPT = "recovery_attempt"
    PERFORMANCE_ALERT = "performance_alert"
    SECURITY_ALERT = "security_alert"


class AlertSeverity(Enum):
    """Alert severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class LogEntry:
    """Structured log entry"""
    timestamp: str
    level: LogLevel
    event_type: EventType
    component: str
    message: str
    operation_id: Optional[str] = None
    target_id: Optional[str] = None
    mission_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    duration_ms: Optional[int] = None
    error: Optional[str] = None
    stack_trace: Optional[str] = None


@dataclass
class PerformanceMetric:
    """Performance measurement"""
    metric_name: str
    value: float
    unit: str
    timestamp: str
    component: str
    operation_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Alert:
    """System alert"""
    alert_id: str
    severity: AlertSeverity
    event_type: EventType
    title: str
    description: str
    timestamp: str
    component: str
    action_required: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    acknowledged: bool = False
    resolved: bool = False


@dataclass
class MonitoringStats:
    """Real-time monitoring statistics"""
    total_operations: int = 0
    successful_operations: int = 0
    failed_operations: int = 0
    total_targets: int = 0
    compromised_targets: int = 0
    vulnerabilities_found: int = 0
    credentials_obtained: int = 0
    lateral_moves: int = 0
    detections_encountered: int = 0
    evasions_activated: int = 0
    data_exfiltrated_mb: float = 0.0
    average_operation_duration_ms: float = 0.0
    total_errors: int = 0
    recovery_attempts: int = 0
    successful_recoveries: int = 0
    active_missions: int = 0
    uptime_seconds: float = 0.0


class LoggingMonitoringSystem:
    """
    Advanced logging and monitoring system for RAGLOX
    
    Features:
    - Structured logging with multiple output formats
    - Real-time performance monitoring
    - Security event tracking
    - Alert management
    - Metrics collection and aggregation
    - Health check monitoring
    """
    
    def __init__(
        self,
        log_file: Optional[str] = None,
        enable_console: bool = True,
        enable_file: bool = True,
        enable_json: bool = True,
        log_level: LogLevel = LogLevel.INFO,
        max_log_size_mb: int = 100,
        alert_callback: Optional[Callable] = None
    ):
        """
        Initialize logging and monitoring system
        
        Args:
            log_file: Path to log file (default: logs/raglox.log)
            enable_console: Enable console output
            enable_file: Enable file output
            enable_json: Enable JSON-formatted logs
            log_level: Minimum log level to capture
            max_log_size_mb: Maximum log file size before rotation
            alert_callback: Callback function for alerts
        """
        self.log_file = log_file or '/root/RAGLOX_V3/webapp/logs/raglox.log'
        self.enable_console = enable_console
        self.enable_file = enable_file
        self.enable_json = enable_json
        self.log_level = log_level
        self.max_log_size_mb = max_log_size_mb
        self.alert_callback = alert_callback
        
        # Initialize loggers
        self._setup_loggers()
        
        # Storage
        self.logs: deque = deque(maxlen=10000)  # Keep last 10k logs in memory
        self.metrics: deque = deque(maxlen=5000)  # Keep last 5k metrics
        self.alerts: List[Alert] = []
        
        # Statistics
        self.stats = MonitoringStats()
        self.start_time = time.time()
        
        # Performance tracking
        self.operation_timings: Dict[str, List[float]] = defaultdict(list)
        self.component_errors: Dict[str, int] = defaultdict(int)
        
        # Health check
        self.last_health_check = time.time()
        self.health_status: Dict[str, Any] = {}
        
        self.logger.info("Logging and Monitoring System initialized")
    
    def _setup_loggers(self):
        """Set up Python logging infrastructure"""
        # Create logger
        self.logger = logging.getLogger('raglox')
        self.logger.setLevel(getattr(logging, self.log_level.value))
        
        # Remove existing handlers
        self.logger.handlers = []
        
        # Console handler
        if self.enable_console:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(getattr(logging, self.log_level.value))
            console_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            console_handler.setFormatter(console_formatter)
            self.logger.addHandler(console_handler)
        
        # File handler
        if self.enable_file:
            try:
                import os
                os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
                
                file_handler = logging.FileHandler(self.log_file)
                file_handler.setLevel(getattr(logging, self.log_level.value))
                file_formatter = logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
                file_handler.setFormatter(file_formatter)
                self.logger.addHandler(file_handler)
            except Exception as e:
                print(f"Warning: Could not set up file logging: {e}")
    
    def log(
        self,
        level: LogLevel,
        event_type: EventType,
        component: str,
        message: str,
        operation_id: Optional[str] = None,
        target_id: Optional[str] = None,
        mission_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        duration_ms: Optional[int] = None,
        error: Optional[str] = None,
        stack_trace: Optional[str] = None
    ) -> LogEntry:
        """
        Create a structured log entry
        
        Args:
            level: Log severity level
            event_type: Type of event
            component: Component generating the log
            message: Log message
            operation_id: Associated operation ID
            target_id: Associated target ID
            mission_id: Associated mission ID
            metadata: Additional metadata
            duration_ms: Operation duration
            error: Error message if applicable
            stack_trace: Stack trace if applicable
        
        Returns:
            Created log entry
        """
        entry = LogEntry(
            timestamp=datetime.now().isoformat(),
            level=level,
            event_type=event_type,
            component=component,
            message=message,
            operation_id=operation_id,
            target_id=target_id,
            mission_id=mission_id,
            metadata=metadata or {},
            duration_ms=duration_ms,
            error=error,
            stack_trace=stack_trace
        )
        
        # Store in memory
        self.logs.append(entry)
        
        # Log to Python logger
        log_method = getattr(self.logger, level.value.lower())
        log_msg = self._format_log_message(entry)
        log_method(log_msg)
        
        # Write JSON log if enabled
        if self.enable_json:
            self._write_json_log(entry)
        
        # Update statistics based on event type
        self._update_stats_from_log(entry)
        
        return entry
    
    def _format_log_message(self, entry: LogEntry) -> str:
        """Format log entry as string"""
        parts = [f"[{entry.event_type.value}]", entry.message]
        
        if entry.operation_id:
            parts.append(f"op={entry.operation_id}")
        if entry.target_id:
            parts.append(f"target={entry.target_id}")
        if entry.duration_ms:
            parts.append(f"duration={entry.duration_ms}ms")
        if entry.error:
            parts.append(f"error={entry.error}")
        
        return " | ".join(parts)
    
    def _write_json_log(self, entry: LogEntry):
        """Write log entry as JSON"""
        try:
            json_file = self.log_file.replace('.log', '.json')
            with open(json_file, 'a') as f:
                json_entry = asdict(entry)
                # Convert enums to strings
                json_entry['level'] = entry.level.value
                json_entry['event_type'] = entry.event_type.value
                f.write(json.dumps(json_entry) + '\n')
        except Exception as e:
            self.logger.warning(f"Failed to write JSON log: {e}")
    
    def _update_stats_from_log(self, entry: LogEntry):
        """Update statistics based on log entry"""
        if entry.event_type == EventType.OPERATION_START:
            self.stats.total_operations += 1
        elif entry.event_type == EventType.OPERATION_COMPLETE:
            self.stats.successful_operations += 1
        elif entry.event_type == EventType.OPERATION_FAILURE:
            self.stats.failed_operations += 1
            self.stats.total_errors += 1
        elif entry.event_type == EventType.TARGET_DISCOVERED:
            self.stats.total_targets += 1
        elif entry.event_type == EventType.VULNERABILITY_FOUND:
            self.stats.vulnerabilities_found += 1
        elif entry.event_type == EventType.EXPLOIT_SUCCESS:
            self.stats.compromised_targets += 1
        elif entry.event_type == EventType.CREDENTIAL_OBTAINED:
            self.stats.credentials_obtained += 1
        elif entry.event_type == EventType.LATERAL_MOVEMENT:
            self.stats.lateral_moves += 1
        elif entry.event_type == EventType.DEFENSE_DETECTED:
            self.stats.detections_encountered += 1
        elif entry.event_type == EventType.EVASION_ACTIVATED:
            self.stats.evasions_activated += 1
        elif entry.event_type == EventType.ERROR_OCCURRED:
            self.stats.total_errors += 1
            self.component_errors[entry.component] += 1
        elif entry.event_type == EventType.RECOVERY_ATTEMPT:
            self.stats.recovery_attempts += 1
        elif entry.event_type == EventType.DATA_EXFILTRATED:
            if 'size_mb' in entry.metadata:
                self.stats.data_exfiltrated_mb += entry.metadata['size_mb']
        
        # Track operation duration
        if entry.duration_ms and entry.component:
            self.operation_timings[entry.component].append(entry.duration_ms)
            # Calculate average
            all_durations = []
            for timings in self.operation_timings.values():
                all_durations.extend(timings)
            if all_durations:
                self.stats.average_operation_duration_ms = sum(all_durations) / len(all_durations)
    
    def record_metric(
        self,
        metric_name: str,
        value: float,
        unit: str,
        component: str,
        operation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> PerformanceMetric:
        """
        Record a performance metric
        
        Args:
            metric_name: Name of the metric
            value: Metric value
            unit: Unit of measurement
            component: Component generating the metric
            operation_id: Associated operation ID
            metadata: Additional metadata
        
        Returns:
            Created metric entry
        """
        metric = PerformanceMetric(
            metric_name=metric_name,
            value=value,
            unit=unit,
            timestamp=datetime.now().isoformat(),
            component=component,
            operation_id=operation_id,
            metadata=metadata or {}
        )
        
        self.metrics.append(metric)
        
        # Check for performance alerts
        self._check_performance_thresholds(metric)
        
        return metric
    
    def _check_performance_thresholds(self, metric: PerformanceMetric):
        """Check if metric exceeds performance thresholds"""
        thresholds = {
            'operation_duration_ms': 60000,  # 1 minute
            'memory_usage_mb': 1000,  # 1 GB
            'cpu_usage_percent': 90,
            'error_rate_percent': 10
        }
        
        if metric.metric_name in thresholds:
            if metric.value > thresholds[metric.metric_name]:
                self.create_alert(
                    severity=AlertSeverity.HIGH,
                    event_type=EventType.PERFORMANCE_ALERT,
                    title=f"Performance Threshold Exceeded: {metric.metric_name}",
                    description=f"{metric.metric_name} = {metric.value} {metric.unit} (threshold: {thresholds[metric.metric_name]} {metric.unit})",
                    component=metric.component,
                    action_required=True,
                    metadata={'metric': asdict(metric)}
                )
    
    def create_alert(
        self,
        severity: AlertSeverity,
        event_type: EventType,
        title: str,
        description: str,
        component: str,
        action_required: bool = False,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Alert:
        """
        Create a system alert
        
        Args:
            severity: Alert severity
            event_type: Type of event
            title: Alert title
            description: Alert description
            component: Component generating the alert
            action_required: Whether action is required
            metadata: Additional metadata
        
        Returns:
            Created alert
        """
        alert_id = hashlib.md5(
            f"{datetime.now().isoformat()}{title}{component}".encode()
        ).hexdigest()[:16]
        
        alert = Alert(
            alert_id=alert_id,
            severity=severity,
            event_type=event_type,
            title=title,
            description=description,
            timestamp=datetime.now().isoformat(),
            component=component,
            action_required=action_required,
            metadata=metadata or {}
        )
        
        self.alerts.append(alert)
        
        # Log alert
        self.log(
            level=LogLevel.WARNING if severity in [AlertSeverity.LOW, AlertSeverity.MEDIUM] else LogLevel.ERROR,
            event_type=EventType.SECURITY_ALERT,
            component=component,
            message=f"Alert: {title}",
            metadata={'alert': asdict(alert)}
        )
        
        # Call alert callback if provided
        if self.alert_callback:
            try:
                self.alert_callback(alert)
            except Exception as e:
                self.logger.error(f"Alert callback failed: {e}")
        
        return alert
    
    def acknowledge_alert(self, alert_id: str):
        """Mark alert as acknowledged"""
        for alert in self.alerts:
            if alert.alert_id == alert_id:
                alert.acknowledged = True
                self.log(
                    level=LogLevel.INFO,
                    event_type=EventType.SECURITY_ALERT,
                    component="monitoring",
                    message=f"Alert acknowledged: {alert.title}",
                    metadata={'alert_id': alert_id}
                )
                break
    
    def resolve_alert(self, alert_id: str):
        """Mark alert as resolved"""
        for alert in self.alerts:
            if alert.alert_id == alert_id:
                alert.resolved = True
                alert.acknowledged = True
                self.log(
                    level=LogLevel.INFO,
                    event_type=EventType.SECURITY_ALERT,
                    component="monitoring",
                    message=f"Alert resolved: {alert.title}",
                    metadata={'alert_id': alert_id}
                )
                break
    
    def get_stats(self) -> MonitoringStats:
        """Get current monitoring statistics"""
        self.stats.uptime_seconds = time.time() - self.start_time
        return self.stats
    
    def get_recent_logs(
        self,
        count: int = 100,
        level: Optional[LogLevel] = None,
        event_type: Optional[EventType] = None,
        component: Optional[str] = None
    ) -> List[LogEntry]:
        """
        Get recent log entries with optional filters
        
        Args:
            count: Number of logs to retrieve
            level: Filter by log level
            event_type: Filter by event type
            component: Filter by component
        
        Returns:
            List of log entries
        """
        logs = list(self.logs)
        
        # Apply filters
        if level:
            logs = [log for log in logs if log.level == level]
        if event_type:
            logs = [log for log in logs if log.event_type == event_type]
        if component:
            logs = [log for log in logs if log.component == component]
        
        # Return most recent
        return logs[-count:]
    
    def get_active_alerts(self, severity: Optional[AlertSeverity] = None) -> List[Alert]:
        """Get active (unresolved) alerts"""
        alerts = [alert for alert in self.alerts if not alert.resolved]
        
        if severity:
            alerts = [alert for alert in alerts if alert.severity == severity]
        
        return sorted(alerts, key=lambda a: a.timestamp, reverse=True)
    
    def get_component_health(self, component: str) -> Dict[str, Any]:
        """Get health status for a specific component"""
        recent_logs = self.get_recent_logs(count=100, component=component)
        
        error_logs = [log for log in recent_logs if log.level in [LogLevel.ERROR, LogLevel.CRITICAL]]
        error_rate = len(error_logs) / len(recent_logs) if recent_logs else 0.0
        
        avg_duration = 0.0
        if component in self.operation_timings and self.operation_timings[component]:
            avg_duration = sum(self.operation_timings[component]) / len(self.operation_timings[component])
        
        return {
            'component': component,
            'status': 'healthy' if error_rate < 0.1 else 'degraded' if error_rate < 0.3 else 'unhealthy',
            'error_rate': error_rate,
            'total_errors': self.component_errors[component],
            'average_operation_ms': avg_duration,
            'recent_logs': len(recent_logs),
            'last_activity': recent_logs[-1].timestamp if recent_logs else None
        }
    
    def perform_health_check(self) -> Dict[str, Any]:
        """Perform comprehensive system health check"""
        self.last_health_check = time.time()
        
        # Get all components
        components = set(log.component for log in self.logs)
        component_health = {
            comp: self.get_component_health(comp)
            for comp in components
        }
        
        # Overall health
        unhealthy_components = [
            comp for comp, health in component_health.items()
            if health['status'] == 'unhealthy'
        ]
        
        overall_status = 'healthy'
        if unhealthy_components:
            overall_status = 'unhealthy'
        elif any(h['status'] == 'degraded' for h in component_health.values()):
            overall_status = 'degraded'
        
        self.health_status = {
            'timestamp': datetime.now().isoformat(),
            'overall_status': overall_status,
            'uptime_seconds': time.time() - self.start_time,
            'components': component_health,
            'active_alerts': len(self.get_active_alerts()),
            'critical_alerts': len(self.get_active_alerts(AlertSeverity.CRITICAL)),
            'statistics': asdict(self.get_stats())
        }
        
        return self.health_status
    
    def export_logs(
        self,
        output_file: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        format: str = 'json'
    ):
        """
        Export logs to file
        
        Args:
            output_file: Path to output file
            start_time: Start timestamp (ISO format)
            end_time: End timestamp (ISO format)
            format: Output format ('json' or 'csv')
        """
        logs = list(self.logs)
        
        # Filter by time range
        if start_time:
            logs = [log for log in logs if log.timestamp >= start_time]
        if end_time:
            logs = [log for log in logs if log.timestamp <= end_time]
        
        if format == 'json':
            with open(output_file, 'w') as f:
                json.dump([asdict(log) for log in logs], f, indent=2, default=str)
        elif format == 'csv':
            import csv
            with open(output_file, 'w', newline='') as f:
                if logs:
                    writer = csv.DictWriter(f, fieldnames=asdict(logs[0]).keys())
                    writer.writeheader()
                    for log in logs:
                        writer.writerow(asdict(log))
        
        self.logger.info(f"Exported {len(logs)} logs to {output_file}")


# Global instance
_monitoring_system: Optional[LoggingMonitoringSystem] = None


def get_monitoring_system() -> LoggingMonitoringSystem:
    """Get or create global monitoring system instance"""
    global _monitoring_system
    if _monitoring_system is None:
        _monitoring_system = LoggingMonitoringSystem()
    return _monitoring_system


def setup_monitoring(
    log_file: Optional[str] = None,
    enable_console: bool = True,
    enable_file: bool = True,
    enable_json: bool = True,
    log_level: LogLevel = LogLevel.INFO,
    alert_callback: Optional[Callable] = None
) -> LoggingMonitoringSystem:
    """
    Set up global monitoring system
    
    Args:
        log_file: Path to log file
        enable_console: Enable console output
        enable_file: Enable file output
        enable_json: Enable JSON logs
        log_level: Minimum log level
        alert_callback: Alert callback function
    
    Returns:
        Configured monitoring system
    """
    global _monitoring_system
    _monitoring_system = LoggingMonitoringSystem(
        log_file=log_file,
        enable_console=enable_console,
        enable_file=enable_file,
        enable_json=enable_json,
        log_level=log_level,
        alert_callback=alert_callback
    )
    return _monitoring_system
