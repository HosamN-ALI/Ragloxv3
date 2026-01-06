# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Enhanced Validators (SEC-03)
# Pydantic models with comprehensive validation
# ═══════════════════════════════════════════════════════════════

"""
SEC-03: Enhanced Input Validation with Pydantic

This module provides:
- Enhanced Pydantic models with built-in validation
- Custom field validators
- Reusable validation patterns
- Type-safe API request/response models

Usage:
```python
from src.core.validators_enhanced import (
    MissionCreateRequest,
    TargetCreateRequest,
    validate_mission_scope,
)

# Use in FastAPI routes
@router.post("/missions")
async def create_mission(request: MissionCreateRequest):
    ...
```
"""

from typing import Any, Dict, List, Optional, Set, Union, Annotated
from uuid import UUID
from datetime import datetime, timedelta
from enum import Enum
import re
import ipaddress

from pydantic import (
    BaseModel,
    Field,
    field_validator,
    model_validator,
    ConfigDict,
    ValidationError,
    BeforeValidator,
    AfterValidator,
)
from pydantic.functional_validators import PlainValidator


# ═══════════════════════════════════════════════════════════════
# Validation Patterns
# ═══════════════════════════════════════════════════════════════

# Safe name pattern (alphanumeric, underscores, hyphens, spaces)
SAFE_NAME_PATTERN = re.compile(r'^[A-Za-z0-9_\-\s]+$')

# CVE pattern
CVE_PATTERN = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)

# Hostname pattern (RFC 1123)
HOSTNAME_PATTERN = re.compile(
    r'^(?=.{1,253}$)'
    r'(?!-)[A-Za-z0-9-]{1,63}(?<!-)'
    r'(\.[A-Za-z0-9-]{1,63})*$'
)

# Domain pattern
DOMAIN_PATTERN = re.compile(
    r'^(?=.{1,253}$)'
    r'(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*'
    r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$'
)

# Dangerous characters
DANGEROUS_CHARS = re.compile(r'[<>&\'"\x00-\x1f\x7f-\x9f]')

# Command injection pattern
CMD_INJECTION_PATTERN = re.compile(r'[;|&`$(){}[\]\\]')

# Path traversal pattern
PATH_TRAVERSAL_PATTERN = re.compile(r'\.\.[/\\]')


# ═══════════════════════════════════════════════════════════════
# Custom Validators
# ═══════════════════════════════════════════════════════════════

def validate_safe_string(value: str) -> str:
    """Validate and sanitize a string for safety."""
    if not value:
        return value
    
    # Strip whitespace
    value = value.strip()
    
    # Remove null bytes
    value = value.replace('\x00', '')
    
    # Check for dangerous patterns
    if CMD_INJECTION_PATTERN.search(value):
        raise ValueError("String contains potentially dangerous characters")
    
    if PATH_TRAVERSAL_PATTERN.search(value):
        raise ValueError("String contains path traversal patterns")
    
    return value


def validate_ip_address(value: str) -> str:
    """Validate an IP address (IPv4 or IPv6)."""
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        raise ValueError(f"Invalid IP address: {value}")


def validate_cidr(value: str) -> str:
    """Validate a CIDR notation."""
    try:
        network = ipaddress.ip_network(value.strip(), strict=False)
        return str(network)
    except ValueError:
        raise ValueError(f"Invalid CIDR notation: {value}")


def validate_hostname(value: str) -> str:
    """Validate a hostname (RFC 1123)."""
    if not value or len(value) > 253:
        raise ValueError(f"Invalid hostname length: {value}")
    
    # Remove trailing dot
    if value.endswith('.'):
        value = value[:-1]
    
    if not HOSTNAME_PATTERN.match(value):
        raise ValueError(f"Invalid hostname format: {value}")
    
    return value.lower()


def validate_port(value: int) -> int:
    """Validate a port number."""
    if not isinstance(value, int):
        raise ValueError(f"Port must be an integer: {value}")
    
    if value < 1 or value > 65535:
        raise ValueError(f"Port must be between 1 and 65535: {value}")
    
    return value


def validate_cve(value: str) -> str:
    """Validate a CVE identifier."""
    value = value.strip().upper()
    
    if not CVE_PATTERN.match(value):
        raise ValueError(f"Invalid CVE format: {value}")
    
    return value


def validate_cvss(value: float) -> float:
    """Validate a CVSS score."""
    if value < 0.0 or value > 10.0:
        raise ValueError(f"CVSS score must be between 0.0 and 10.0: {value}")
    
    return round(value, 1)


def validate_scope_entry(value: str) -> str:
    """Validate a single scope entry (IP, CIDR, or hostname)."""
    value = value.strip()
    
    if not value:
        raise ValueError("Scope entry cannot be empty")
    
    # Try as IP
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    
    # Try as CIDR
    try:
        ipaddress.ip_network(value, strict=False)
        return value
    except ValueError:
        pass
    
    # Try as hostname/domain
    if HOSTNAME_PATTERN.match(value) or DOMAIN_PATTERN.match(value):
        return value.lower()
    
    raise ValueError(f"Invalid scope entry: {value}")


# ═══════════════════════════════════════════════════════════════
# Annotated Types
# ═══════════════════════════════════════════════════════════════

# Safe string type (sanitized, no injection)
SafeString = Annotated[str, AfterValidator(validate_safe_string)]

# IP address type
IPAddress = Annotated[str, AfterValidator(validate_ip_address)]

# CIDR type
CIDR = Annotated[str, AfterValidator(validate_cidr)]

# Hostname type
Hostname = Annotated[str, AfterValidator(validate_hostname)]

# Port type
Port = Annotated[int, AfterValidator(validate_port)]

# CVE type
CVE = Annotated[str, AfterValidator(validate_cve)]

# CVSS score type
CVSSScore = Annotated[float, AfterValidator(validate_cvss)]

# Scope entry type
ScopeEntry = Annotated[str, AfterValidator(validate_scope_entry)]


# ═══════════════════════════════════════════════════════════════
# Enums
# ═══════════════════════════════════════════════════════════════

class MissionStatus(str, Enum):
    """Mission status enum."""
    CREATED = "created"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"


class Priority(str, Enum):
    """Priority level enum."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Severity(str, Enum):
    """Severity level enum."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RiskLevel(str, Enum):
    """Risk level enum."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


class ActionType(str, Enum):
    """Action type enum."""
    SCAN = "scan"
    EXPLOIT = "exploit"
    LATERAL = "lateral"
    EXFIL = "exfil"
    PERSIST = "persist"
    CLEANUP = "cleanup"


class TargetStatus(str, Enum):
    """Target status enum."""
    DISCOVERED = "discovered"
    SCANNING = "scanning"
    SCANNED = "scanned"
    EXPLOITING = "exploiting"
    COMPROMISED = "compromised"
    UNREACHABLE = "unreachable"


class SessionType(str, Enum):
    """Session type enum."""
    SHELL = "shell"
    METERPRETER = "meterpreter"
    SSH = "ssh"
    WMI = "wmi"
    WINRM = "winrm"
    BEACON = "beacon"


# ═══════════════════════════════════════════════════════════════
# Base Models
# ═══════════════════════════════════════════════════════════════

class RAGLOXBaseModel(BaseModel):
    """Base model with common configuration."""
    
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_default=True,
        extra='forbid',
        json_schema_extra={
            "example": {}
        }
    )


# ═══════════════════════════════════════════════════════════════
# Mission Models (SEC-03 Enhanced)
# ═══════════════════════════════════════════════════════════════

class MissionCreateRequest(RAGLOXBaseModel):
    """
    Request model for creating a new mission.
    
    SEC-03 Validation:
    - Name: Safe characters only, 3-100 chars
    - Scope: Valid IPs, CIDRs, or hostnames
    - Goals: At least one goal required
    - Constraints: Optional configuration
    """
    
    name: SafeString = Field(
        ...,
        min_length=3,
        max_length=100,
        description="Mission name (alphanumeric, spaces, hyphens, underscores)",
        json_schema_extra={"example": "Enterprise Network Assessment"}
    )
    
    description: Optional[SafeString] = Field(
        None,
        max_length=1000,
        description="Optional mission description",
        json_schema_extra={"example": "Full security assessment of corporate network"}
    )
    
    scope: List[ScopeEntry] = Field(
        ...,
        min_length=1,
        max_length=1000,
        description="List of target ranges (IPs, CIDRs, hostnames)",
        json_schema_extra={"example": ["192.168.1.0/24", "10.0.0.1", "target.example.com"]}
    )
    
    goals: List[SafeString] = Field(
        ...,
        min_length=1,
        max_length=20,
        description="List of mission objectives",
        json_schema_extra={"example": ["domain_admin", "data_exfil", "persistence"]}
    )
    
    constraints: Optional[Dict[str, Any]] = Field(
        None,
        description="Optional mission constraints",
        json_schema_extra={"example": {"stealth": True, "avoid_detection": True}}
    )
    
    priority: Priority = Field(
        Priority.MEDIUM,
        description="Mission priority level",
    )
    
    timeout_hours: Optional[int] = Field(
        None,
        ge=1,
        le=720,  # Max 30 days
        description="Mission timeout in hours",
    )
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Validate mission name."""
        if not SAFE_NAME_PATTERN.match(v):
            raise ValueError(
                "Name can only contain letters, numbers, spaces, hyphens, and underscores"
            )
        return v
    
    @field_validator('scope')
    @classmethod
    def validate_scope(cls, v: List[str]) -> List[str]:
        """Validate scope entries."""
        validated = []
        for entry in v:
            validated.append(validate_scope_entry(entry))
        return list(set(validated))  # Remove duplicates
    
    @field_validator('goals')
    @classmethod
    def validate_goals(cls, v: List[str]) -> List[str]:
        """Validate goal entries."""
        valid_goals = {
            "domain_admin", "local_admin", "data_exfil", "persistence",
            "lateral_movement", "credential_harvest", "network_map",
            "vuln_assessment", "full_compromise", "custom"
        }
        
        for goal in v:
            goal_lower = goal.lower()
            if goal_lower not in valid_goals and not goal_lower.startswith("custom:"):
                raise ValueError(f"Invalid goal: {goal}. Valid goals: {valid_goals}")
        
        return list(set(v))  # Remove duplicates
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "Corporate Network Assessment",
                "description": "Full red team engagement for corporate network",
                "scope": ["192.168.1.0/24", "10.0.0.0/8"],
                "goals": ["domain_admin", "data_exfil"],
                "constraints": {"stealth": True},
                "priority": "high",
                "timeout_hours": 48
            }
        }
    )


class MissionUpdateRequest(RAGLOXBaseModel):
    """Request model for updating a mission."""
    
    name: Optional[SafeString] = Field(None, min_length=3, max_length=100)
    description: Optional[SafeString] = Field(None, max_length=1000)
    scope: Optional[List[ScopeEntry]] = Field(None, min_length=1, max_length=1000)
    goals: Optional[List[SafeString]] = Field(None, min_length=1, max_length=20)
    constraints: Optional[Dict[str, Any]] = None
    priority: Optional[Priority] = None
    timeout_hours: Optional[int] = Field(None, ge=1, le=720)


# ═══════════════════════════════════════════════════════════════
# Target Models (SEC-03 Enhanced)
# ═══════════════════════════════════════════════════════════════

class TargetCreateRequest(RAGLOXBaseModel):
    """Request model for adding a target."""
    
    ip: IPAddress = Field(
        ...,
        description="Target IP address",
        json_schema_extra={"example": "192.168.1.100"}
    )
    
    hostname: Optional[Hostname] = Field(
        None,
        description="Target hostname",
        json_schema_extra={"example": "dc01.corp.local"}
    )
    
    os: Optional[SafeString] = Field(
        None,
        max_length=100,
        description="Operating system",
        json_schema_extra={"example": "Windows Server 2019"}
    )
    
    priority: Priority = Field(
        Priority.MEDIUM,
        description="Target priority",
    )
    
    ports: Optional[Dict[int, SafeString]] = Field(
        None,
        description="Open ports and services",
        json_schema_extra={"example": {22: "ssh", 80: "http", 443: "https"}}
    )
    
    @field_validator('ports')
    @classmethod
    def validate_ports(cls, v: Optional[Dict[int, str]]) -> Optional[Dict[int, str]]:
        """Validate port numbers."""
        if v is None:
            return v
        
        validated = {}
        for port, service in v.items():
            if not isinstance(port, int):
                raise ValueError(f"Port must be an integer: {port}")
            if port < 1 or port > 65535:
                raise ValueError(f"Port must be between 1 and 65535: {port}")
            validated[port] = service
        
        return validated


class TargetScanRequest(RAGLOXBaseModel):
    """Request model for scanning a target."""
    
    target_id: str = Field(..., description="Target ID")
    
    scan_type: str = Field(
        "full",
        description="Type of scan to perform",
        pattern="^(quick|full|vuln|custom)$",
    )
    
    ports: Optional[str] = Field(
        None,
        description="Port specification (e.g., '80,443,8080' or '1-1024')",
        pattern=r"^[\d,\-\s]+$",
    )
    
    intensity: int = Field(
        3,
        ge=1,
        le=5,
        description="Scan intensity (1-5)",
    )


# ═══════════════════════════════════════════════════════════════
# Vulnerability Models (SEC-03 Enhanced)
# ═══════════════════════════════════════════════════════════════

class VulnerabilityCreateRequest(RAGLOXBaseModel):
    """Request model for reporting a vulnerability."""
    
    target_id: str = Field(..., description="Target ID")
    
    type: SafeString = Field(
        ...,
        min_length=3,
        max_length=100,
        description="Vulnerability type",
        json_schema_extra={"example": "SMB_EternalBlue"}
    )
    
    name: Optional[SafeString] = Field(
        None,
        max_length=200,
        description="Vulnerability name",
        json_schema_extra={"example": "MS17-010 EternalBlue SMB Remote Code Execution"}
    )
    
    cve: Optional[CVE] = Field(
        None,
        description="CVE identifier",
        json_schema_extra={"example": "CVE-2017-0144"}
    )
    
    severity: Severity = Field(
        Severity.MEDIUM,
        description="Vulnerability severity",
    )
    
    cvss: Optional[CVSSScore] = Field(
        None,
        description="CVSS score (0.0-10.0)",
    )
    
    description: Optional[SafeString] = Field(
        None,
        max_length=2000,
        description="Vulnerability description",
    )
    
    exploit_available: bool = Field(
        False,
        description="Whether an exploit is available",
    )
    
    affected_component: Optional[SafeString] = Field(
        None,
        max_length=200,
        description="Affected component/service",
        json_schema_extra={"example": "Microsoft SMBv1"}
    )


# ═══════════════════════════════════════════════════════════════
# Exploitation Models (SEC-03 Enhanced)
# ═══════════════════════════════════════════════════════════════

class ExploitExecuteRequest(RAGLOXBaseModel):
    """Request model for executing an exploit."""
    
    target_id: str = Field(..., description="Target ID")
    
    vuln_id: Optional[str] = Field(None, description="Vulnerability ID to exploit")
    
    exploit_module: SafeString = Field(
        ...,
        min_length=3,
        max_length=200,
        description="Exploit module to use",
        json_schema_extra={"example": "exploit/windows/smb/ms17_010_eternalblue"}
    )
    
    payload: Optional[SafeString] = Field(
        None,
        max_length=200,
        description="Payload to use",
        json_schema_extra={"example": "windows/x64/meterpreter/reverse_tcp"}
    )
    
    options: Optional[Dict[str, Any]] = Field(
        None,
        description="Exploit options",
        json_schema_extra={"example": {"LHOST": "192.168.1.10", "LPORT": 4444}}
    )
    
    @field_validator('options')
    @classmethod
    def validate_options(cls, v: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Validate exploit options."""
        if v is None:
            return v
        
        # Validate LHOST if present
        if 'LHOST' in v:
            try:
                ipaddress.ip_address(v['LHOST'])
            except ValueError:
                raise ValueError(f"Invalid LHOST IP address: {v['LHOST']}")
        
        # Validate LPORT if present
        if 'LPORT' in v:
            port = v['LPORT']
            if not isinstance(port, int) or port < 1 or port > 65535:
                raise ValueError(f"Invalid LPORT: {port}")
        
        return v


class C2CommandRequest(RAGLOXBaseModel):
    """Request model for C2 commands."""
    
    session_id: str = Field(..., description="Session ID")
    
    command: SafeString = Field(
        ...,
        min_length=1,
        max_length=10000,
        description="Command to execute",
    )
    
    timeout: int = Field(
        300,
        ge=1,
        le=3600,
        description="Command timeout in seconds",
    )
    
    @field_validator('command')
    @classmethod
    def validate_command(cls, v: str) -> str:
        """Validate command for dangerous patterns."""
        # Note: In a red team tool, we allow shell commands
        # but still sanitize for injection in the API layer
        dangerous_api_patterns = [
            r'\{\{.*\}\}',  # Template injection
            r'\$\{.*\}',  # Variable injection
        ]
        
        for pattern in dangerous_api_patterns:
            if re.search(pattern, v):
                raise ValueError("Command contains potentially dangerous patterns")
        
        return v


# ═══════════════════════════════════════════════════════════════
# HITL Models (SEC-03 Enhanced)
# ═══════════════════════════════════════════════════════════════

class ApprovalRequest(RAGLOXBaseModel):
    """Request model for approving an action."""
    
    user_comment: Optional[SafeString] = Field(
        None,
        max_length=500,
        description="Optional approval comment",
    )


class RejectionRequest(RAGLOXBaseModel):
    """Request model for rejecting an action."""
    
    rejection_reason: Optional[SafeString] = Field(
        None,
        max_length=500,
        description="Reason for rejection",
    )
    
    user_comment: Optional[SafeString] = Field(
        None,
        max_length=500,
        description="Additional comment",
    )


class ChatMessageRequest(RAGLOXBaseModel):
    """Request model for chat messages."""
    
    content: SafeString = Field(
        ...,
        min_length=1,
        max_length=4096,
        description="Message content",
    )
    
    related_task_id: Optional[str] = Field(
        None,
        description="Related task ID",
    )
    
    related_action_id: Optional[str] = Field(
        None,
        description="Related approval action ID",
    )


# ═══════════════════════════════════════════════════════════════
# Infrastructure Models (SEC-03 Enhanced)
# ═══════════════════════════════════════════════════════════════

class SSHConnectionRequest(RAGLOXBaseModel):
    """Request model for SSH connection."""
    
    host: IPAddress = Field(..., description="SSH host IP")
    
    port: Port = Field(22, description="SSH port")
    
    username: SafeString = Field(
        ...,
        min_length=1,
        max_length=64,
        description="SSH username",
    )
    
    password: Optional[str] = Field(
        None,
        max_length=256,
        description="SSH password (sensitive)",
    )
    
    key_filename: Optional[SafeString] = Field(
        None,
        max_length=256,
        description="Path to SSH private key",
    )
    
    passphrase: Optional[str] = Field(
        None,
        max_length=256,
        description="Key passphrase (sensitive)",
    )
    
    @model_validator(mode='after')
    def validate_auth(self):
        """Validate that either password or key is provided."""
        if not self.password and not self.key_filename:
            raise ValueError("Either password or key_filename must be provided")
        return self


class CommandExecuteRequest(RAGLOXBaseModel):
    """Request model for command execution."""
    
    command: SafeString = Field(
        ...,
        min_length=1,
        max_length=10000,
        description="Command to execute",
    )
    
    timeout: int = Field(
        300,
        ge=1,
        le=3600,
        description="Command timeout in seconds",
    )
    
    cwd: Optional[SafeString] = Field(
        None,
        max_length=256,
        description="Working directory",
    )
    
    env: Optional[Dict[str, SafeString]] = Field(
        None,
        description="Environment variables",
    )


# ═══════════════════════════════════════════════════════════════
# Knowledge Query Models (SEC-03 Enhanced)
# ═══════════════════════════════════════════════════════════════

class KnowledgeSearchRequest(RAGLOXBaseModel):
    """Request model for knowledge search."""
    
    query: SafeString = Field(
        ...,
        min_length=1,
        max_length=200,
        description="Search query",
    )
    
    platform: Optional[SafeString] = Field(
        None,
        pattern="^(windows|linux|macos|network|cloud)$",
        description="Target platform",
    )
    
    tactic: Optional[SafeString] = Field(
        None,
        pattern="^TA\d{4}$",
        description="MITRE ATT&CK tactic ID",
    )
    
    limit: int = Field(
        20,
        ge=1,
        le=100,
        description="Maximum results",
    )


class TechniqueQueryRequest(RAGLOXBaseModel):
    """Request model for technique queries."""
    
    technique_id: SafeString = Field(
        ...,
        pattern="^T\d{4}(\.\d{3})?$",
        description="MITRE ATT&CK technique ID",
        json_schema_extra={"example": "T1003.001"}
    )
    
    platform: Optional[SafeString] = Field(
        None,
        pattern="^(windows|linux|macos)$",
        description="Target platform",
    )


# ═══════════════════════════════════════════════════════════════
# Utility Functions
# ═══════════════════════════════════════════════════════════════

def validate_request_data(data: Dict[str, Any], model_class: type) -> BaseModel:
    """
    Validate request data against a Pydantic model.
    
    Args:
        data: Request data dictionary
        model_class: Pydantic model class
        
    Returns:
        Validated model instance
        
    Raises:
        ValidationError: If validation fails
    """
    return model_class(**data)


def get_validation_errors(exc: ValidationError) -> List[Dict[str, Any]]:
    """
    Extract validation errors from a Pydantic ValidationError.
    
    Args:
        exc: ValidationError exception
        
    Returns:
        List of error dictionaries
    """
    errors = []
    for error in exc.errors():
        errors.append({
            'field': '.'.join(str(loc) for loc in error['loc']),
            'message': error['msg'],
            'type': error['type'],
        })
    return errors
