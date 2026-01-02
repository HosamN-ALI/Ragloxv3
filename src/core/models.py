# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Data Models
# Pydantic models for Blackboard entities
# ═══════════════════════════════════════════════════════════════

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, ConfigDict


# ═══════════════════════════════════════════════════════════════
# Enums
# ═══════════════════════════════════════════════════════════════

class MissionStatus(str, Enum):
    """Mission lifecycle states."""
    CREATED = "created"
    STARTING = "starting"
    RUNNING = "running"
    PAUSED = "paused"
    WAITING_FOR_APPROVAL = "waiting_for_approval"  # HITL: Waiting for user approval
    COMPLETING = "completing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    ARCHIVED = "archived"


class TargetStatus(str, Enum):
    """Target discovery and exploitation states."""
    DISCOVERED = "discovered"
    SCANNING = "scanning"
    SCANNED = "scanned"
    EXPLOITING = "exploiting"
    EXPLOITED = "exploited"
    OWNED = "owned"
    FAILED = "failed"


class Priority(str, Enum):
    """Priority levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Severity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CredentialType(str, Enum):
    """Types of credentials."""
    PASSWORD = "password"
    HASH = "hash"
    KEY = "key"
    TOKEN = "token"
    CERTIFICATE = "certificate"


class PrivilegeLevel(str, Enum):
    """Privilege levels for credentials/sessions."""
    USER = "user"
    ADMIN = "admin"
    SYSTEM = "system"
    ROOT = "root"
    DOMAIN_ADMIN = "domain_admin"
    UNKNOWN = "unknown"


class SessionStatus(str, Enum):
    """Session lifecycle states."""
    ACTIVE = "active"
    IDLE = "idle"
    DEAD = "dead"


class SessionType(str, Enum):
    """Types of sessions."""
    SHELL = "shell"
    METERPRETER = "meterpreter"
    SSH = "ssh"
    RDP = "rdp"
    WMI = "wmi"
    WINRM = "winrm"
    SMB = "smb"


class TaskStatus(str, Enum):
    """Task execution states."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TaskType(str, Enum):
    """Types of tasks."""
    NETWORK_SCAN = "network_scan"
    PORT_SCAN = "port_scan"
    SERVICE_ENUM = "service_enum"
    VULN_SCAN = "vuln_scan"
    EXPLOIT = "exploit"
    PRIVESC = "privesc"
    LATERAL = "lateral"
    CRED_HARVEST = "cred_harvest"
    PERSISTENCE = "persistence"
    EVASION = "evasion"
    CLEANUP = "cleanup"


class SpecialistType(str, Enum):
    """Types of specialists."""
    RECON = "recon"
    VULN = "vuln"
    ATTACK = "attack"
    CRED = "cred"
    PERSISTENCE = "persistence"
    EVASION = "evasion"
    CLEANUP = "cleanup"
    ANALYSIS = "analysis"


class GoalStatus(str, Enum):
    """Goal achievement states."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    ACHIEVED = "achieved"
    FAILED = "failed"


class PathStatus(str, Enum):
    """Attack path states."""
    DISCOVERED = "discovered"
    TESTED = "tested"
    WORKING = "working"
    FAILED = "failed"


# ═══════════════════════════════════════════════════════════════
# Base Models
# ═══════════════════════════════════════════════════════════════

class BaseEntity(BaseModel):
    """Base model for all entities."""
    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        use_enum_values=True,
    )
    
    id: UUID = Field(default_factory=uuid4, description="Unique identifier")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


# ═══════════════════════════════════════════════════════════════
# Mission Models
# ═══════════════════════════════════════════════════════════════

class Goal(BaseModel):
    """Mission goal."""
    name: str
    status: GoalStatus = GoalStatus.PENDING
    achieved_at: Optional[datetime] = None
    achieved_via: Optional[str] = None  # Reference to achieving event


class MissionCreate(BaseModel):
    """Model for creating a new mission."""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    scope: List[str] = Field(..., min_length=1)  # CIDRs, domains, IPs
    goals: List[str] = Field(..., min_length=1)  # Goal names
    constraints: Dict[str, Any] = Field(default_factory=dict)


class Mission(BaseEntity):
    """Mission entity."""
    name: str
    description: Optional[str] = None
    status: MissionStatus = MissionStatus.CREATED
    scope: List[str] = Field(default_factory=list)
    goals: Dict[str, GoalStatus] = Field(default_factory=dict)
    constraints: Dict[str, Any] = Field(default_factory=dict)
    
    # Lifecycle timestamps
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    # Statistics
    targets_discovered: int = 0
    vulns_found: int = 0
    creds_harvested: int = 0
    sessions_established: int = 0
    goals_achieved: int = 0
    
    # Ownership
    created_by: Optional[UUID] = None


class MissionStats(BaseModel):
    """Mission statistics."""
    targets_discovered: int = 0
    vulns_found: int = 0
    creds_harvested: int = 0
    sessions_established: int = 0
    goals_achieved: int = 0
    goals_total: int = 0
    
    # Breakdown
    critical_vulns: int = 0
    high_vulns: int = 0
    active_sessions: int = 0


# ═══════════════════════════════════════════════════════════════
# Target Models
# ═══════════════════════════════════════════════════════════════

class Port(BaseModel):
    """Port information."""
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None


class Service(BaseModel):
    """Service information."""
    port: int
    protocol: str = "tcp"
    name: str
    product: Optional[str] = None
    version: Optional[str] = None
    extra_info: Optional[str] = None


class Target(BaseEntity):
    """Target entity - a discovered host."""
    mission_id: UUID
    ip: str
    hostname: Optional[str] = None
    os: Optional[str] = None
    os_version: Optional[str] = None
    status: TargetStatus = TargetStatus.DISCOVERED
    priority: Priority = Priority.MEDIUM
    risk_score: Optional[float] = None
    
    # Discovery
    discovered_by: Optional[str] = None
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Detailed info
    ports: Dict[int, str] = Field(default_factory=dict)  # port -> service|product
    services: List[Service] = Field(default_factory=list)


# ═══════════════════════════════════════════════════════════════
# Vulnerability Models
# ═══════════════════════════════════════════════════════════════

class Vulnerability(BaseEntity):
    """Vulnerability entity."""
    mission_id: UUID
    target_id: UUID
    
    # Identification
    type: str  # CVE-XXXX-XXXXX or custom identifier
    name: Optional[str] = None
    description: Optional[str] = None
    
    # Severity
    severity: Severity = Severity.MEDIUM
    cvss: Optional[float] = None
    
    # Discovery
    discovered_by: Optional[str] = None
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Status
    status: str = "discovered"  # discovered, verified, exploited, failed
    
    # Exploitation
    exploit_available: bool = False
    rx_modules: List[str] = Field(default_factory=list)  # RX module IDs


# ═══════════════════════════════════════════════════════════════
# Credential Models
# ═══════════════════════════════════════════════════════════════

class Credential(BaseEntity):
    """Credential entity."""
    mission_id: UUID
    target_id: UUID
    
    # Credential info
    type: CredentialType = CredentialType.PASSWORD
    username: Optional[str] = None
    domain: Optional[str] = None
    value_encrypted: Optional[bytes] = None  # Encrypted credential value
    
    # Discovery
    source: Optional[str] = None  # How it was obtained (mimikatz, brute_force, etc.)
    discovered_by: Optional[str] = None
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Verification
    verified: bool = False
    privilege_level: PrivilegeLevel = PrivilegeLevel.UNKNOWN


# ═══════════════════════════════════════════════════════════════
# Session Models
# ═══════════════════════════════════════════════════════════════

class Session(BaseEntity):
    """Session entity - an active connection to a target."""
    mission_id: UUID
    target_id: UUID
    
    # Session info
    type: SessionType = SessionType.SHELL
    user: Optional[str] = None
    privilege: PrivilegeLevel = PrivilegeLevel.USER
    
    # Lifecycle
    established_at: datetime = Field(default_factory=datetime.utcnow)
    last_activity: datetime = Field(default_factory=datetime.utcnow)
    closed_at: Optional[datetime] = None
    status: SessionStatus = SessionStatus.ACTIVE
    
    # How it was obtained
    via_vuln_id: Optional[UUID] = None
    via_cred_id: Optional[UUID] = None


# ═══════════════════════════════════════════════════════════════
# Task Models
# ═══════════════════════════════════════════════════════════════

class ExecutionLog(BaseModel):
    """Log entry for task execution - for Reflexion Logic."""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    level: str = "info"  # debug, info, warning, error
    message: str
    data: Dict[str, Any] = Field(default_factory=dict)


class ErrorContext(BaseModel):
    """
    Detailed error context for failed tasks - enables Reflexion Logic.
    
    This structure captures the full context of a failure so that:
    1. AnalysisSpecialist can understand what went wrong
    2. LLM can reason about alternative approaches
    3. System can learn from failures
    """
    error_type: str  # connection_refused, av_detected, auth_failed, timeout, etc.
    error_code: Optional[str] = None
    error_message: str
    
    # Contextual information
    target_ip: Optional[str] = None
    target_port: Optional[int] = None
    target_service: Optional[str] = None
    
    # What was attempted
    technique_id: Optional[str] = None  # MITRE ATT&CK technique
    module_used: Optional[str] = None   # RX module ID
    command_executed: Optional[str] = None
    
    # Environment context
    detected_defenses: List[str] = Field(default_factory=list)  # AV, EDR, firewall
    network_conditions: Optional[str] = None  # filtered, blocked, slow
    
    # Suggestions for retry
    retry_recommended: bool = False
    alternative_techniques: List[str] = Field(default_factory=list)
    alternative_modules: List[str] = Field(default_factory=list)
    
    # Stack trace for debugging
    stack_trace: Optional[str] = None


class Task(BaseEntity):
    """Task entity - a unit of work for specialists."""
    mission_id: UUID
    
    # Task info
    type: TaskType
    specialist: SpecialistType
    priority: int = Field(default=5, ge=1, le=10)
    
    # References
    target_id: Optional[UUID] = None
    vuln_id: Optional[UUID] = None
    cred_id: Optional[UUID] = None
    session_id: Optional[UUID] = None
    rx_module: Optional[str] = None
    
    # Execution
    status: TaskStatus = TaskStatus.PENDING
    assigned_to: Optional[str] = None  # Worker ID
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    # Result
    result: Optional[str] = None  # success, failure, partial
    result_data: Dict[str, Any] = Field(default_factory=dict)
    error_message: Optional[str] = None
    
    # ═══════════════════════════════════════════════════════════
    # Reflexion Logic Fields - For LLM Analysis
    # ═══════════════════════════════════════════════════════════
    
    # Detailed error context for failures
    error_context: Optional[ErrorContext] = None
    
    # Execution logs for analysis
    execution_logs: List[ExecutionLog] = Field(default_factory=list)
    
    # Retry tracking
    retry_count: int = 0
    max_retries: int = 3
    parent_task_id: Optional[UUID] = None  # If this is a retry of another task
    
    # Analysis flags
    needs_analysis: bool = False  # Flag for AnalysisSpecialist to review
    analysis_result: Optional[str] = None  # Decision from analysis


# ═══════════════════════════════════════════════════════════════
# Attack Path Models
# ═══════════════════════════════════════════════════════════════

class AttackPath(BaseEntity):
    """Attack path entity - a discovered lateral movement path."""
    mission_id: UUID
    from_target_id: UUID
    to_target_id: UUID
    
    # Path info
    method: str  # pass_the_hash, rdp, ssh, smb, wmi, etc.
    requires_cred_id: Optional[UUID] = None
    
    # Status
    status: PathStatus = PathStatus.DISCOVERED
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    tested_at: Optional[datetime] = None


# ═══════════════════════════════════════════════════════════════
# Event Models (for Pub/Sub)
# ═══════════════════════════════════════════════════════════════

class BlackboardEvent(BaseModel):
    """Base event for Pub/Sub."""
    event: str
    mission_id: UUID
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    data: Dict[str, Any] = Field(default_factory=dict)


class NewTargetEvent(BlackboardEvent):
    """Event when a new target is discovered."""
    event: str = "new_target"
    target_id: UUID
    ip: str
    priority: Priority = Priority.MEDIUM
    needs_deep_scan: bool = True


class NewVulnEvent(BlackboardEvent):
    """Event when a new vulnerability is discovered."""
    event: str = "new_vuln"
    vuln_id: UUID
    target_id: UUID
    severity: Severity
    exploit_available: bool = False


class NewCredEvent(BlackboardEvent):
    """Event when a new credential is discovered."""
    event: str = "new_cred"
    cred_id: UUID
    target_id: UUID
    type: CredentialType
    privilege_level: PrivilegeLevel


class NewSessionEvent(BlackboardEvent):
    """Event when a new session is established."""
    event: str = "new_session"
    session_id: UUID
    target_id: UUID
    privilege: PrivilegeLevel
    needs_privesc: bool = False


class NewTaskEvent(BlackboardEvent):
    """Event when a new task is created."""
    event: str = "new_task"
    task_id: UUID
    type: TaskType
    specialist: SpecialistType
    priority: int = 5


class GoalAchievedEvent(BlackboardEvent):
    """Event when a goal is achieved."""
    event: str = "goal_achieved"
    goal: str
    via_cred_id: Optional[UUID] = None
    via_session_id: Optional[UUID] = None


class TaskFailedEvent(BlackboardEvent):
    """
    Event when a task fails - triggers AnalysisSpecialist.
    
    This event contains the full context of the failure to enable:
    1. AnalysisSpecialist to determine next steps
    2. LLM to reason about alternative approaches
    3. MissionController to decide on retries
    """
    event: str = "task_failed"
    task_id: UUID
    task_type: TaskType
    target_id: Optional[UUID] = None
    
    # Failure details
    error_type: str  # connection_refused, av_detected, auth_failed, timeout
    error_message: str
    
    # Context for analysis
    technique_id: Optional[str] = None
    module_used: Optional[str] = None
    detected_defenses: List[str] = Field(default_factory=list)
    
    # Retry info
    retry_count: int = 0
    max_retries: int = 3
    retry_recommended: bool = False
    
    # Suggestions
    alternative_techniques: List[str] = Field(default_factory=list)
    alternative_modules: List[str] = Field(default_factory=list)


class TaskAnalysisRequestEvent(BlackboardEvent):
    """Event requesting AnalysisSpecialist to review a failed task."""
    event: str = "analysis_request"
    task_id: UUID
    task_type: TaskType
    error_context: Dict[str, Any] = Field(default_factory=dict)
    execution_logs: List[Dict[str, Any]] = Field(default_factory=list)
    priority: int = 8  # High priority for analysis


class TaskAnalysisResultEvent(BlackboardEvent):
    """Event with AnalysisSpecialist's decision on a failed task."""
    event: str = "analysis_result"
    original_task_id: UUID
    
    # Analysis decision
    decision: str  # retry, skip, escalate, modify_approach
    reasoning: str
    
    # If retry
    new_task_id: Optional[UUID] = None
    modified_parameters: Dict[str, Any] = Field(default_factory=dict)
    
    # If escalate
    escalation_reason: Optional[str] = None


class ControlEvent(BaseModel):
    """Control command event."""
    command: str  # pause, resume, stop
    mission_id: Optional[UUID] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# ═══════════════════════════════════════════════════════════════
# HITL (Human-in-the-Loop) Models
# ═══════════════════════════════════════════════════════════════

class RiskLevel(str, Enum):
    """Risk level for operations requiring approval."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ApprovalStatus(str, Enum):
    """Approval request status."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class ActionType(str, Enum):
    """Types of actions that may require approval."""
    EXPLOIT = "exploit"           # Exploitation attempt
    WRITE_OPERATION = "write"     # File/system writes
    LATERAL_MOVEMENT = "lateral"  # Moving to other targets
    PRIVILEGE_ESCALATION = "privesc"  # Privilege escalation
    DATA_EXFILTRATION = "exfil"   # Data extraction
    PERSISTENCE = "persistence"   # Installing persistence
    DESTRUCTIVE = "destructive"   # Potentially destructive action


class ApprovalAction(BaseEntity):
    """
    Action awaiting approval from user.
    
    When AnalysisSpecialist determines an action is HIGH_RISK or involves
    sensitive operations, it creates an ApprovalAction and waits for
    user consent before proceeding.
    """
    mission_id: UUID
    task_id: Optional[UUID] = None
    
    # Action details
    action_type: ActionType
    action_description: str
    target_ip: Optional[str] = None
    target_hostname: Optional[str] = None
    
    # Risk assessment
    risk_level: RiskLevel = RiskLevel.MEDIUM
    risk_reasons: List[str] = Field(default_factory=list)
    potential_impact: Optional[str] = None
    
    # What will be executed
    module_to_execute: Optional[str] = None
    command_preview: Optional[str] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)
    
    # Status
    status: ApprovalStatus = ApprovalStatus.PENDING
    requested_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    
    # Response
    responded_at: Optional[datetime] = None
    responded_by: Optional[str] = None
    rejection_reason: Optional[str] = None
    user_comment: Optional[str] = None


class ApprovalRequestEvent(BlackboardEvent):
    """
    Event when system requests user approval for a high-risk action.
    
    This event is broadcast via WebSocket to the frontend, which should
    display an approval dialog to the user.
    """
    event: str = "approval_request"
    action_id: UUID
    action_type: ActionType
    action_description: str
    
    # Target info
    target_ip: Optional[str] = None
    target_hostname: Optional[str] = None
    
    # Risk info
    risk_level: RiskLevel
    risk_reasons: List[str] = Field(default_factory=list)
    potential_impact: Optional[str] = None
    
    # Preview
    command_preview: Optional[str] = None
    
    # Timing
    expires_at: Optional[datetime] = None


class ApprovalResponseEvent(BlackboardEvent):
    """
    Event when user responds to an approval request.
    """
    event: str = "approval_response"
    action_id: UUID
    approved: bool
    rejection_reason: Optional[str] = None
    user_comment: Optional[str] = None


class ChatMessage(BaseModel):
    """
    Chat message for human-system interaction.
    
    Allows users to send instructions or ask questions about the mission.
    """
    id: UUID = Field(default_factory=uuid4)
    mission_id: UUID
    
    # Message content
    role: str = "user"  # user, system, assistant
    content: str
    
    # Context
    related_task_id: Optional[UUID] = None
    related_action_id: Optional[UUID] = None
    
    # Timestamp
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    # Optional metadata
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ChatEvent(BlackboardEvent):
    """Event for chat messages."""
    event: str = "chat_message"
    message_id: UUID
    role: str
    content: str
    related_task_id: Optional[UUID] = None
    related_action_id: Optional[UUID] = None
