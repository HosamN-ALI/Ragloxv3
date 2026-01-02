# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - LLM Response Models
# Pydantic models for structured LLM output validation
# ═══════════════════════════════════════════════════════════════

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


# ═══════════════════════════════════════════════════════════════
# Enums for Decision Making
# ═══════════════════════════════════════════════════════════════

class DecisionType(str, Enum):
    """Decision types for failure analysis."""
    
    RETRY = "retry"                    # Retry the same task
    MODIFY_APPROACH = "modify_approach"  # Try different parameters/module
    SKIP = "skip"                      # Skip this task
    ESCALATE = "escalate"              # Escalate for human review
    PIVOT = "pivot"                    # Change attack vector entirely


class ConfidenceLevel(str, Enum):
    """Confidence level for analysis."""
    
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FailureCategory(str, Enum):
    """Categories of failure."""
    
    NETWORK = "network"
    DEFENSE = "defense"
    AUTHENTICATION = "authentication"
    VULNERABILITY = "vulnerability"
    TECHNICAL = "technical"
    UNKNOWN = "unknown"


class DefenseType(str, Enum):
    """Types of detected defenses."""
    
    ANTIVIRUS = "antivirus"
    EDR = "edr"
    FIREWALL = "firewall"
    IDS_IPS = "ids_ips"
    SANDBOX = "sandbox"
    WAF = "waf"
    DLP = "dlp"
    AMSI = "amsi"
    APPLOCKER = "applocker"
    CREDENTIAL_GUARD = "credential_guard"
    OTHER = "other"


# ═══════════════════════════════════════════════════════════════
# Request Models
# ═══════════════════════════════════════════════════════════════

class TaskContext(BaseModel):
    """Context about the failed task."""
    
    task_id: str = Field(..., description="ID of the failed task")
    task_type: str = Field(..., description="Type of task (EXPLOIT, RECON, etc.)")
    target_ip: Optional[str] = Field(None, description="Target IP address")
    target_hostname: Optional[str] = Field(None, description="Target hostname")
    target_os: Optional[str] = Field(None, description="Target operating system")
    target_platform: Optional[str] = Field(None, description="Platform (windows/linux/macos)")


class ExecutionContext(BaseModel):
    """Context about the execution attempt."""
    
    module_used: Optional[str] = Field(None, description="RX Module that was used")
    technique_id: Optional[str] = Field(None, description="MITRE ATT&CK technique ID")
    command_executed: Optional[str] = Field(None, description="Command that was executed")
    exit_code: Optional[int] = Field(None, description="Exit code if available")
    duration_ms: Optional[int] = Field(None, description="Execution duration in milliseconds")


class ErrorDetails(BaseModel):
    """Details about the error."""
    
    error_type: str = Field(..., description="Type of error")
    error_message: str = Field(..., description="Error message")
    stderr: Optional[str] = Field(None, description="Standard error output")
    stdout: Optional[str] = Field(None, description="Standard output (may contain error info)")
    detected_defenses: List[str] = Field(default_factory=list, description="Detected defenses")


class AvailableModule(BaseModel):
    """Information about an available alternative module."""
    
    rx_module_id: str = Field(..., description="RX Module ID")
    name: str = Field(..., description="Module name")
    description: Optional[str] = Field(None, description="Module description")
    technique_id: Optional[str] = Field(None, description="MITRE technique ID")
    supports_evasion: bool = Field(False, description="Whether module supports evasion")
    success_rate: Optional[float] = Field(None, description="Historical success rate")


class AnalysisRequest(BaseModel):
    """Request for failure analysis."""
    
    task: TaskContext = Field(..., description="Context about the failed task")
    execution: ExecutionContext = Field(..., description="Execution details")
    error: ErrorDetails = Field(..., description="Error details")
    
    retry_count: int = Field(0, description="Number of previous retry attempts")
    max_retries: int = Field(3, description="Maximum allowed retries")
    
    available_modules: List[AvailableModule] = Field(
        default_factory=list,
        description="Available alternative modules"
    )
    
    mission_goals: List[str] = Field(
        default_factory=list,
        description="Mission goals for context"
    )
    
    previous_analysis: Optional[str] = Field(
        None,
        description="Previous analysis result if retrying"
    )


# ═══════════════════════════════════════════════════════════════
# Response Models (Structured Output)
# ═══════════════════════════════════════════════════════════════

class RootCauseAnalysis(BaseModel):
    """Analysis of the root cause of failure."""
    
    category: FailureCategory = Field(..., description="Failure category")
    root_cause: str = Field(..., description="Identified root cause")
    contributing_factors: List[str] = Field(
        default_factory=list,
        description="Contributing factors to the failure"
    )
    detected_defenses: List[DefenseType] = Field(
        default_factory=list,
        description="Detected defense mechanisms"
    )
    confidence: ConfidenceLevel = Field(
        ConfidenceLevel.MEDIUM,
        description="Confidence in the analysis"
    )


class AlternativeModule(BaseModel):
    """Recommended alternative module."""
    
    rx_module_id: str = Field(..., description="RX Module ID")
    reason: str = Field(..., description="Why this module is recommended")
    expected_success_rate: float = Field(
        0.5,
        description="Expected success rate (0-1)",
        ge=0.0,
        le=1.0
    )
    required_parameters: Dict[str, Any] = Field(
        default_factory=dict,
        description="Required parameter changes"
    )
    evasion_techniques: List[str] = Field(
        default_factory=list,
        description="Evasion techniques to use"
    )


class RecommendedAction(BaseModel):
    """Recommended action to take."""
    
    decision: DecisionType = Field(..., description="Decision type")
    reasoning: str = Field(..., description="Reasoning for this decision")
    
    # For RETRY
    delay_seconds: int = Field(0, description="Delay before retry in seconds")
    
    # For MODIFY_APPROACH
    alternative_module: Optional[AlternativeModule] = Field(
        None,
        description="Alternative module to use"
    )
    modified_parameters: Dict[str, Any] = Field(
        default_factory=dict,
        description="Modified parameters for retry"
    )
    
    # For PIVOT
    new_attack_vector: Optional[str] = Field(
        None,
        description="New attack vector to try"
    )
    new_technique_id: Optional[str] = Field(
        None,
        description="New MITRE technique to try"
    )
    
    # For ESCALATE
    escalation_reason: Optional[str] = Field(
        None,
        description="Reason for escalation"
    )
    human_guidance_needed: List[str] = Field(
        default_factory=list,
        description="Specific guidance needed from human"
    )


class FailureAnalysis(BaseModel):
    """Complete failure analysis result."""
    
    analysis: RootCauseAnalysis = Field(..., description="Root cause analysis")
    recommended_action: RecommendedAction = Field(..., description="Recommended action")
    
    additional_recommendations: List[str] = Field(
        default_factory=list,
        description="Additional recommendations"
    )
    
    lessons_learned: List[str] = Field(
        default_factory=list,
        description="Lessons learned for future attempts"
    )
    
    should_update_knowledge: bool = Field(
        False,
        description="Whether knowledge base should be updated"
    )
    knowledge_update: Optional[str] = Field(
        None,
        description="Suggested knowledge base update"
    )


class AnalysisResponse(BaseModel):
    """Complete response from LLM analysis."""
    
    success: bool = Field(..., description="Whether analysis was successful")
    analysis: Optional[FailureAnalysis] = Field(None, description="Analysis result")
    error: Optional[str] = Field(None, description="Error message if failed")
    
    # Metadata
    model_used: str = Field("unknown", description="Model that performed analysis")
    tokens_used: int = Field(0, description="Tokens used for this analysis")
    latency_ms: float = Field(0.0, description="Analysis latency in milliseconds")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    @field_validator("analysis", mode="before")
    @classmethod
    def validate_analysis(cls, v, info):
        """Ensure analysis is provided if success is True."""
        # Get success value from data
        data = info.data
        if data.get("success") and v is None:
            raise ValueError("Analysis must be provided when success is True")
        return v


# ═══════════════════════════════════════════════════════════════
# Module Selection Models
# ═══════════════════════════════════════════════════════════════

class ModuleRanking(BaseModel):
    """Ranking of a module for selection."""
    
    rx_module_id: str = Field(..., description="RX Module ID")
    rank: int = Field(..., description="Rank (1 is best)", ge=1)
    score: float = Field(..., description="Score (0-100)", ge=0, le=100)
    reasoning: str = Field(..., description="Reasoning for this ranking")
    pros: List[str] = Field(default_factory=list, description="Advantages")
    cons: List[str] = Field(default_factory=list, description="Disadvantages")


class ModuleSelectionResponse(BaseModel):
    """Response for module selection request."""
    
    selected_module: str = Field(..., description="Selected module ID")
    rankings: List[ModuleRanking] = Field(..., description="All module rankings")
    selection_reasoning: str = Field(..., description="Overall selection reasoning")
    
    confidence: ConfidenceLevel = Field(
        ConfidenceLevel.MEDIUM,
        description="Confidence in selection"
    )
    
    # Parameters for selected module
    recommended_parameters: Dict[str, Any] = Field(
        default_factory=dict,
        description="Recommended parameters"
    )
    
    warnings: List[str] = Field(
        default_factory=list,
        description="Warnings about the selection"
    )
