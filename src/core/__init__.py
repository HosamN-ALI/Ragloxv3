# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Core Module
# Blackboard Architecture Components + Hybrid Intelligence Layer
# ═══════════════════════════════════════════════════════════════

from .blackboard import Blackboard
from .config import Settings, get_settings
from .models import (
    Mission,
    MissionStatus,
    Target,
    TargetStatus,
    Vulnerability,
    Severity,
    Credential,
    CredentialType,
    Session,
    SessionStatus,
    Task,
    TaskStatus,
    TaskType,
    AttackPath,
    Goal,
    GoalStatus,
)
from .exceptions import (
    RAGLOXException,
    MissionNotFoundError,
    TargetNotFoundError,
    TaskNotFoundError,
    ValidationException,
    InvalidIPAddressError,
)
from .logging import (
    get_logger,
    configure_logging,
    logging_context,
    audit_logger,
    performance_logger,
)
from .validators import (
    validate_ip_address,
    validate_uuid,
    validate_scope,
    sanitize_string,
)
from .knowledge import (
    EmbeddedKnowledge,
    get_knowledge,
    init_knowledge,
    RXModule,
    Technique,
    Tactic,
    KnowledgeStats,
)
from .scanners import (
    NucleiScanner,
    NucleiScanResult,
    NucleiVulnerability,
)

# ═══════════════════════════════════════════════════════════════
# Hybrid Intelligence Layer Components (NEW)
# ═══════════════════════════════════════════════════════════════

from .operational_memory import (
    OperationalMemory,
    DecisionRecord,
    DecisionOutcome,
    OperationalContext,
)
from .intelligence_coordinator import (
    IntelligenceCoordinator,
    AttackPath as IntelligentAttackPath,
    AttackPathType,
    StrategicAnalysis,
)
from .strategic_scorer import (
    StrategicScorer,
    VulnerabilityScore,
    PrioritizedTarget,
    RiskLevel,
    ExploitDifficulty,
    ImpactScope,
)
from .stealth_profiles import (
    StealthManager,
    StealthLevel,
    StealthParameters,
    DetectionRisk,
    DefenseType,
    DefenseProfile,
    OperationFootprint,
    STEALTH_PROFILES,
    EVASION_TECHNIQUES,
)

__all__ = [
    # Blackboard
    "Blackboard",
    # Config
    "Settings",
    "get_settings",
    # Models
    "Mission",
    "MissionStatus",
    "Target",
    "TargetStatus",
    "Vulnerability",
    "Severity",
    "Credential",
    "CredentialType",
    "Session",
    "SessionStatus",
    "Task",
    "TaskStatus",
    "TaskType",
    "AttackPath",
    "Goal",
    "GoalStatus",
    # Exceptions
    "RAGLOXException",
    "MissionNotFoundError",
    "TargetNotFoundError",
    "TaskNotFoundError",
    "ValidationException",
    "InvalidIPAddressError",
    # Logging
    "get_logger",
    "configure_logging",
    "logging_context",
    "audit_logger",
    "performance_logger",
    # Validators
    "validate_ip_address",
    "validate_uuid",
    "validate_scope",
    "sanitize_string",
    # Knowledge
    "EmbeddedKnowledge",
    "get_knowledge",
    "init_knowledge",
    "RXModule",
    "Technique",
    "Tactic",
    "KnowledgeStats",
    # Scanners
    "NucleiScanner",
    "NucleiScanResult",
    "NucleiVulnerability",
    # ═══════════════════════════════════════════════════════════
    # Hybrid Intelligence Layer (NEW)
    # ═══════════════════════════════════════════════════════════
    # Operational Memory
    "OperationalMemory",
    "DecisionRecord",
    "DecisionOutcome",
    "OperationalContext",
    # Intelligence Coordinator
    "IntelligenceCoordinator",
    "IntelligentAttackPath",
    "AttackPathType",
    "StrategicAnalysis",
    # Strategic Scorer
    "StrategicScorer",
    "VulnerabilityScore",
    "PrioritizedTarget",
    "RiskLevel",
    "ExploitDifficulty",
    "ImpactScope",
    # Stealth Manager
    "StealthManager",
    "StealthLevel",
    "StealthParameters",
    "DetectionRisk",
    "DefenseType",
    "DefenseProfile",
    "OperationFootprint",
    "STEALTH_PROFILES",
    "EVASION_TECHNIQUES",
]
