# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Executor Models
# Data models for the Execution Layer
# ═══════════════════════════════════════════════════════════════

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, SecretStr, ConfigDict


# ═══════════════════════════════════════════════════════════════
# Enums
# ═══════════════════════════════════════════════════════════════

class ExecutorType(str, Enum):
    """Types of command executors."""
    LOCAL = "local"          # Local shell execution
    SSH = "ssh"              # SSH for Linux/Unix
    WINRM = "winrm"          # WinRM for Windows
    WMI = "wmi"              # WMI for Windows (legacy)
    AGENT = "agent"          # RAGLOX Agent (future)


class ExecutionStatus(str, Enum):
    """Execution result status."""
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CONNECTION_ERROR = "connection_error"
    AUTH_ERROR = "auth_error"
    PERMISSION_DENIED = "permission_denied"
    NOT_FOUND = "not_found"
    PARTIAL = "partial"
    CANCELLED = "cancelled"


class ShellType(str, Enum):
    """Types of shells."""
    BASH = "bash"
    SH = "sh"
    ZSH = "zsh"
    POWERSHELL = "powershell"
    CMD = "cmd"
    PYTHON = "python"


class Platform(str, Enum):
    """Target platforms."""
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    UNKNOWN = "unknown"


# ═══════════════════════════════════════════════════════════════
# Connection Configuration Models
# ═══════════════════════════════════════════════════════════════

class BaseConnectionConfig(BaseModel):
    """Base configuration for all connection types."""
    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
    )
    
    host: str = Field(..., description="Target hostname or IP")
    port: Optional[int] = None
    timeout: int = Field(default=30, ge=1, le=3600, description="Connection timeout in seconds")
    retry_count: int = Field(default=3, ge=0, le=10, description="Number of retry attempts")
    retry_delay: float = Field(default=1.0, ge=0.1, le=60, description="Delay between retries in seconds")


class SSHConfig(BaseConnectionConfig):
    """SSH connection configuration."""
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(..., description="SSH username")
    password: Optional[SecretStr] = Field(default=None, description="SSH password")
    private_key: Optional[str] = Field(default=None, description="Path to private key file")
    private_key_passphrase: Optional[SecretStr] = Field(default=None, description="Private key passphrase")
    
    # SSH-specific options
    known_hosts_file: Optional[str] = Field(default=None, description="Path to known_hosts file")
    host_key_checking: bool = Field(default=False, description="Enable strict host key checking")
    compression: bool = Field(default=True, description="Enable compression")
    
    # Execution options
    shell: ShellType = Field(default=ShellType.BASH, description="Remote shell type")
    sudo: bool = Field(default=False, description="Execute commands with sudo")
    sudo_password: Optional[SecretStr] = Field(default=None, description="Sudo password if different")
    
    # Connection pooling
    keepalive_interval: int = Field(default=30, description="SSH keepalive interval")
    max_sessions: int = Field(default=10, description="Maximum concurrent sessions")


class WinRMConfig(BaseConnectionConfig):
    """WinRM connection configuration."""
    port: int = Field(default=5985, ge=1, le=65535)  # 5985 for HTTP, 5986 for HTTPS
    username: str = Field(..., description="Windows username")
    password: Optional[SecretStr] = Field(default=None, description="Windows password")
    domain: Optional[str] = Field(default=None, description="Windows domain")
    
    # WinRM-specific options
    transport: str = Field(default="ntlm", description="Authentication transport: ntlm, kerberos, basic")
    ssl: bool = Field(default=False, description="Use HTTPS (port 5986)")
    ssl_verify: bool = Field(default=False, description="Verify SSL certificate")
    
    # Execution options
    shell: ShellType = Field(default=ShellType.POWERSHELL, description="Remote shell type")
    codepage: int = Field(default=65001, description="Windows codepage (65001 = UTF-8)")
    
    # Connection pooling
    max_sessions: int = Field(default=5, description="Maximum concurrent sessions")
    
    @property
    def endpoint(self) -> str:
        """Get WinRM endpoint URL."""
        protocol = "https" if self.ssl else "http"
        return f"{protocol}://{self.host}:{self.port}/wsman"


class LocalConfig(BaseConnectionConfig):
    """Local execution configuration."""
    host: str = Field(default="localhost", description="Always localhost")
    shell: ShellType = Field(default=ShellType.BASH, description="Local shell type")
    working_directory: Optional[str] = Field(default=None, description="Working directory for commands")
    environment: Dict[str, str] = Field(default_factory=dict, description="Environment variables")
    
    # Elevation
    sudo: bool = Field(default=False, description="Execute commands with sudo")
    sudo_password: Optional[SecretStr] = Field(default=None, description="Sudo password")


# Type alias for any connection config
ConnectionConfig = Union[SSHConfig, WinRMConfig, LocalConfig]


# ═══════════════════════════════════════════════════════════════
# Execution Request/Response Models
# ═══════════════════════════════════════════════════════════════

class ExecutionRequest(BaseModel):
    """Request to execute a command."""
    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
    )
    
    id: UUID = Field(default_factory=uuid4, description="Unique request ID")
    
    # Command details
    command: str = Field(..., min_length=1, description="Command to execute")
    shell: Optional[ShellType] = Field(default=None, description="Override shell type")
    working_directory: Optional[str] = Field(default=None, description="Working directory")
    environment: Dict[str, str] = Field(default_factory=dict, description="Environment variables")
    
    # Execution options
    timeout: int = Field(default=300, ge=1, le=3600, description="Command timeout in seconds")
    capture_output: bool = Field(default=True, description="Capture stdout/stderr")
    combine_stderr: bool = Field(default=False, description="Combine stderr into stdout")
    
    # Elevation
    elevated: bool = Field(default=False, description="Require elevated privileges")
    
    # Context (for logging and tracking)
    task_id: Optional[UUID] = Field(default=None, description="Associated task ID")
    mission_id: Optional[UUID] = Field(default=None, description="Associated mission ID")
    rx_module_id: Optional[str] = Field(default=None, description="RX Module being executed")
    
    # Cleanup
    cleanup_command: Optional[str] = Field(default=None, description="Cleanup command to run after")


class ExecutionResult(BaseModel):
    """Result of command execution."""
    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
    )
    
    # Request tracking
    request_id: UUID = Field(..., description="Original request ID")
    
    # Status
    status: ExecutionStatus = Field(..., description="Execution status")
    exit_code: Optional[int] = Field(default=None, description="Process exit code")
    
    # Output
    stdout: str = Field(default="", description="Standard output")
    stderr: str = Field(default="", description="Standard error")
    output: str = Field(default="", description="Combined output (if combine_stderr=True)")
    
    # Timing
    started_at: datetime = Field(default_factory=datetime.utcnow, description="Execution start time")
    completed_at: Optional[datetime] = Field(default=None, description="Execution end time")
    duration_ms: int = Field(default=0, description="Execution duration in milliseconds")
    
    # Error details (if failed)
    error_type: Optional[str] = Field(default=None, description="Error type classification")
    error_message: Optional[str] = Field(default=None, description="Human-readable error message")
    error_details: Dict[str, Any] = Field(default_factory=dict, description="Additional error context")
    
    # Context
    executor_type: ExecutorType = Field(..., description="Executor type used")
    host: str = Field(..., description="Target host")
    
    # Cleanup result
    cleanup_executed: bool = Field(default=False, description="Whether cleanup was executed")
    cleanup_success: Optional[bool] = Field(default=None, description="Cleanup result")
    cleanup_output: Optional[str] = Field(default=None, description="Cleanup output")
    
    @property
    def success(self) -> bool:
        """Check if execution was successful."""
        return self.status == ExecutionStatus.SUCCESS and (self.exit_code == 0 or self.exit_code is None)
    
    @property
    def duration_seconds(self) -> float:
        """Get duration in seconds."""
        return self.duration_ms / 1000.0
    
    def to_execution_log(self) -> Dict[str, Any]:
        """Convert to ExecutionLog format for Task model."""
        return {
            "timestamp": self.completed_at or self.started_at,
            "level": "info" if self.success else "error",
            "message": f"Command executed with status {self.status.value}",
            "data": {
                "exit_code": self.exit_code,
                "duration_ms": self.duration_ms,
                "stdout_length": len(self.stdout),
                "stderr_length": len(self.stderr),
                "executor_type": self.executor_type.value,
                "host": self.host,
            }
        }


# ═══════════════════════════════════════════════════════════════
# RX Module Execution Models
# ═══════════════════════════════════════════════════════════════

class RXModuleRequest(BaseModel):
    """Request to execute an RX Module."""
    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
    )
    
    id: UUID = Field(default_factory=uuid4, description="Unique request ID")
    
    # Module identification
    rx_module_id: str = Field(..., description="RX Module ID (e.g., rx-t1003-001)")
    technique_id: Optional[str] = Field(default=None, description="MITRE technique ID")
    
    # Target
    target_host: str = Field(..., description="Target hostname or IP")
    target_platform: Platform = Field(..., description="Target platform")
    
    # Variables
    variables: Dict[str, str] = Field(default_factory=dict, description="Variable substitutions")
    
    # Connection
    connection_config: Optional[ConnectionConfig] = Field(default=None, description="Connection configuration")
    
    # Execution options
    check_prerequisites: bool = Field(default=True, description="Check prerequisites before execution")
    run_cleanup: bool = Field(default=False, description="Run cleanup command after execution")
    timeout: int = Field(default=300, ge=1, le=3600, description="Execution timeout")
    
    # Context
    task_id: Optional[UUID] = Field(default=None, description="Associated task ID")
    mission_id: Optional[UUID] = Field(default=None, description="Associated mission ID")
    session_id: Optional[UUID] = Field(default=None, description="Session to use (if available)")


class RXModuleResult(BaseModel):
    """Result of RX Module execution."""
    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
    )
    
    # Request tracking
    request_id: UUID = Field(..., description="Original request ID")
    rx_module_id: str = Field(..., description="RX Module ID")
    
    # Overall status
    success: bool = Field(..., description="Overall success")
    status: ExecutionStatus = Field(..., description="Detailed status")
    
    # Phase results
    prerequisite_results: List[ExecutionResult] = Field(default_factory=list, description="Prerequisite check results")
    prerequisites_passed: bool = Field(default=True, description="All prerequisites passed")
    
    main_result: Optional[ExecutionResult] = Field(default=None, description="Main command result")
    cleanup_result: Optional[ExecutionResult] = Field(default=None, description="Cleanup command result")
    
    # Timing
    total_duration_ms: int = Field(default=0, description="Total duration including all phases")
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = Field(default=None)
    
    # Parsed output (if applicable)
    parsed_data: Dict[str, Any] = Field(default_factory=dict, description="Parsed output data")
    
    # Error context (for Reflexion)
    error_context: Optional[Dict[str, Any]] = Field(default=None, description="Error context for analysis")
    
    def to_error_context(self) -> Dict[str, Any]:
        """Convert to ErrorContext format for Task model."""
        if self.success:
            return {}
        
        error_type = "unknown"
        error_message = "Unknown error"
        
        if self.main_result:
            if self.main_result.status == ExecutionStatus.TIMEOUT:
                error_type = "timeout"
                error_message = "Command execution timed out"
            elif self.main_result.status == ExecutionStatus.CONNECTION_ERROR:
                error_type = "network"
                error_message = self.main_result.error_message or "Connection failed"
            elif self.main_result.status == ExecutionStatus.AUTH_ERROR:
                error_type = "authentication"
                error_message = self.main_result.error_message or "Authentication failed"
            elif self.main_result.status == ExecutionStatus.PERMISSION_DENIED:
                error_type = "defense"
                error_message = self.main_result.error_message or "Permission denied (possible AV/EDR)"
            else:
                error_type = "technical"
                error_message = self.main_result.error_message or self.main_result.stderr[:500]
        
        return {
            "error_type": error_type,
            "error_message": error_message,
            "module_used": self.rx_module_id,
            "command_executed": self.main_result.stdout[:200] if self.main_result else None,
            "retry_recommended": error_type in ["timeout", "network"],
        }


# ═══════════════════════════════════════════════════════════════
# Connection Pool Models
# ═══════════════════════════════════════════════════════════════

class ConnectionInfo(BaseModel):
    """Information about an active connection."""
    id: UUID = Field(default_factory=uuid4)
    executor_type: ExecutorType
    host: str
    port: Optional[int] = Field(default=0, description="Connection port (0 for local)")
    username: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_used_at: datetime = Field(default_factory=datetime.utcnow)
    is_active: bool = True
    session_count: int = 0
