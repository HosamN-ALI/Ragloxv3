# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Intelligence-Driven Decision Engine
# Advanced decision-making framework for exploitation operations
# Integrates: Strategic Scorer, Operational Memory, Defense Intelligence
# ═══════════════════════════════════════════════════════════════

"""
Intelligence-Driven Decision Engine

This module provides an advanced decision-making framework that integrates
all intelligence layers (Strategic Scorer, Operational Memory, Defense Intelligence)
to make informed, risk-aware decisions about exploitation operations.

Key Features:
- Multi-factor risk assessment
- Historical pattern analysis
- Defense-aware decision gates
- Adaptive strategy selection
- HITL integration for high-risk operations
- Fallback and alternative selection

Author: RAGLOX Team
Version: 3.0.0
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from ..core.strategic_scorer import StrategicScorer, VulnerabilityScore, RiskLevel
    from ..core.operational_memory import OperationalMemory, DecisionOutcome
    from ..intelligence.defense_intelligence import DefenseIntelligence
    from ..core.blackboard import Blackboard


class DecisionType(Enum):
    """Types of decisions the engine can make"""
    EXECUTE = "execute"              # Proceed with operation
    SKIP = "skip"                    # Skip this target/vuln
    DEFER = "defer"                  # Defer to later time
    REQUEST_APPROVAL = "request_approval"  # Request human approval
    USE_ALTERNATIVE = "use_alternative"    # Try alternative approach
    ABORT_MISSION = "abort_mission"  # Abort entire mission


class DecisionReason(Enum):
    """Reasons for decision"""
    # Execute reasons
    HIGH_SUCCESS_PROBABILITY = "high_success_probability"
    LOW_DETECTION_RISK = "low_detection_risk"
    STRATEGIC_VALUE = "strategic_value"
    HISTORICAL_SUCCESS = "historical_success"
    
    # Skip reasons
    LOW_SUCCESS_PROBABILITY = "low_success_probability"
    HIGH_DETECTION_RISK = "high_detection_risk"
    HISTORICAL_FAILURE = "historical_failure"
    DEFENSE_DETECTED = "defense_detected"
    
    # Defer reasons
    INSUFFICIENT_DATA = "insufficient_data"
    RESOURCE_CONSTRAINTS = "resource_constraints"
    TIMING_SUBOPTIMAL = "timing_suboptimal"
    
    # Approval reasons
    CRITICAL_RISK_LEVEL = "critical_risk_level"
    HIGH_VALUE_TARGET = "high_value_target"
    POTENTIAL_IMPACT = "potential_impact"
    
    # Alternative reasons
    BETTER_PATH_AVAILABLE = "better_path_available"
    CREDENTIAL_AVAILABLE = "credential_available"
    EVASION_REQUIRED = "evasion_required"


@dataclass
class DecisionContext:
    """
    Context information for decision-making
    
    Aggregates all relevant information from different sources
    for making an informed decision about an operation.
    """
    # Operation details
    operation_type: str  # "exploit", "privesc", "lateral", etc.
    target_id: str
    vuln_id: Optional[str] = None
    technique_id: Optional[str] = None
    
    # Target information
    target_os: Optional[str] = None
    target_ip: Optional[str] = None
    target_services: List[str] = field(default_factory=list)
    target_criticality: str = "medium"  # low, medium, high, critical
    
    # Mission constraints
    mission_id: str = ""
    mission_goals: List[str] = field(default_factory=list)
    stealth_level: str = "normal"  # low, normal, high, extreme
    time_constraints: Optional[int] = None  # seconds
    
    # Intelligence scores (populated by engine)
    strategic_score: Optional['VulnerabilityScore'] = None
    historical_success_rate: float = 0.0
    detected_defenses: List[Dict] = field(default_factory=list)
    similar_operations: List[Dict] = field(default_factory=list)
    
    # Resource availability
    available_credentials: List[str] = field(default_factory=list)
    available_sessions: List[str] = field(default_factory=list)
    alternative_techniques: List[str] = field(default_factory=list)


@dataclass
class Decision:
    """
    A decision made by the Intelligence Engine
    
    Contains the decision type, confidence level, reasoning,
    and any additional data needed to execute the decision.
    """
    decision_type: DecisionType
    confidence: float  # 0.0 - 1.0
    primary_reason: DecisionReason
    reasoning: List[str]  # Detailed explanation
    
    # Additional decision data
    recommended_action: Optional[Dict[str, Any]] = None
    alternative_options: List[Dict[str, Any]] = field(default_factory=list)
    risk_factors: Dict[str, float] = field(default_factory=dict)
    mitigation_strategies: List[str] = field(default_factory=list)
    
    # Timing
    decided_at: datetime = field(default_factory=datetime.utcnow)
    defer_until: Optional[datetime] = None
    
    # HITL
    requires_approval: bool = False
    approval_timeout: int = 300  # seconds
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert decision to dictionary"""
        return {
            "decision_type": self.decision_type.value,
            "confidence": self.confidence,
            "primary_reason": self.primary_reason.value,
            "reasoning": self.reasoning,
            "recommended_action": self.recommended_action,
            "alternative_options": self.alternative_options,
            "risk_factors": self.risk_factors,
            "mitigation_strategies": self.mitigation_strategies,
            "decided_at": self.decided_at.isoformat(),
            "defer_until": self.defer_until.isoformat() if self.defer_until else None,
            "requires_approval": self.requires_approval,
            "approval_timeout": self.approval_timeout
        }


class IntelligenceDecisionEngine:
    """
    Advanced decision engine that integrates all intelligence layers
    
    This engine serves as the central decision-making component for
    exploitation operations. It consults multiple intelligence sources
    and applies a sophisticated decision framework to determine the
    best course of action for each operation.
    
    Architecture:
    ┌─────────────────────────────────────────────────────────┐
    │          Intelligence Decision Engine                   │
    ├─────────────────────────────────────────────────────────┤
    │                                                         │
    │  ┌──────────────┐  ┌─────────────────┐  ┌───────────┐ │
    │  │   Strategic  │  │  Operational    │  │  Defense  │ │
    │  │    Scorer    │─▶│    Memory       │─▶│   Intel   │ │
    │  └──────────────┘  └─────────────────┘  └───────────┘ │
    │         │                    │                  │       │
    │         └────────────┬───────┴──────────────────┘       │
    │                      ▼                                   │
    │             ┌─────────────────┐                         │
    │             │ Decision Matrix │                         │
    │             │   & Risk Model  │                         │
    │             └─────────────────┘                         │
    │                      │                                   │
    │         ┌────────────┼────────────┐                     │
    │         ▼            ▼            ▼                     │
    │   [EXECUTE]     [SKIP/DEFER]   [APPROVE]              │
    └─────────────────────────────────────────────────────────┘
    
    Decision Flow:
    1. Gather context from all intelligence sources
    2. Calculate multi-factor risk score
    3. Apply decision gates and thresholds
    4. Select optimal strategy
    5. Generate decision with reasoning
    6. Include fallback options
    """
    
    def __init__(
        self,
        strategic_scorer: 'StrategicScorer',
        operational_memory: 'OperationalMemory',
        defense_intelligence: Optional['DefenseIntelligence'] = None,
        blackboard: Optional['Blackboard'] = None,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize Intelligence Decision Engine
        
        Args:
            strategic_scorer: Strategic Scorer for vulnerability assessment
            operational_memory: Operational Memory for historical patterns
            defense_intelligence: Defense Intelligence for defense detection
            blackboard: Blackboard for mission context
            logger: Logger instance
        """
        self.strategic_scorer = strategic_scorer
        self.operational_memory = operational_memory
        self.defense_intelligence = defense_intelligence
        self.blackboard = blackboard
        self.logger = logger or logging.getLogger(__name__)
        
        # Decision thresholds (configurable)
        self.thresholds = {
            "min_success_probability": 0.3,      # Skip if below
            "max_detection_risk": 0.7,           # Skip if above
            "critical_risk_approval": 0.8,       # Request approval if above
            "high_value_target_approval": 0.9,   # Request approval for HVT
            "min_confidence_execute": 0.6,       # Min confidence to execute
            "historical_failure_weight": 0.8,    # Weight for past failures
        }
        
        # Statistics
        self.stats = {
            "decisions_made": 0,
            "execute_decisions": 0,
            "skip_decisions": 0,
            "approval_requests": 0,
            "alternative_selections": 0,
            "intelligence_queries": 0
        }
    
    async def make_decision(
        self,
        context: DecisionContext
    ) -> Decision:
        """
        Make an intelligence-driven decision about an operation
        
        This is the main entry point for decision-making. It gathers
        intelligence from all sources, applies the decision framework,
        and returns a comprehensive decision with reasoning.
        
        Args:
            context: Decision context with operation details
            
        Returns:
            Decision object with recommended action and reasoning
        """
        self.stats["decisions_made"] += 1
        self.logger.info(
            f"[DECISION ENGINE] Making decision for {context.operation_type} "
            f"on target {context.target_id}"
        )
        
        try:
            # Phase 1: Gather Intelligence
            await self._enrich_context(context)
            
            # Phase 2: Calculate Risk Score
            risk_assessment = await self._assess_risk(context)
            
            # Phase 3: Apply Decision Gates
            decision = await self._apply_decision_gates(context, risk_assessment)
            
            # Phase 4: Select Strategy
            if decision.decision_type == DecisionType.EXECUTE:
                await self._select_optimal_strategy(context, decision)
            
            # Phase 5: Add Fallback Options
            await self._add_fallback_options(context, decision)
            
            # Update statistics
            self._update_stats(decision)
            
            self.logger.info(
                f"[DECISION ENGINE] Decision: {decision.decision_type.value} "
                f"(confidence: {decision.confidence:.2%}, "
                f"reason: {decision.primary_reason.value})"
            )
            
            return decision
            
        except Exception as e:
            self.logger.error(f"[DECISION ENGINE] Decision-making failed: {e}", exc_info=True)
            # Return safe default: SKIP with low confidence
            return Decision(
                decision_type=DecisionType.SKIP,
                confidence=0.0,
                primary_reason=DecisionReason.INSUFFICIENT_DATA,
                reasoning=[f"Decision engine error: {str(e)}"]
            )
    
    async def _enrich_context(self, context: DecisionContext) -> None:
        """
        Enrich decision context with intelligence from all sources
        
        Queries:
        1. Strategic Scorer - for vulnerability assessment
        2. Operational Memory - for historical patterns
        3. Defense Intelligence - for defense detection
        4. Blackboard - for mission state and resources
        
        Args:
            context: Decision context to enrich (modified in-place)
        """
        self.stats["intelligence_queries"] += 1
        
        # 1. Strategic Scoring
        if context.vuln_id and self.strategic_scorer:
            try:
                # Create minimal vuln dict for scoring
                vuln_dict = {
                    "vuln_id": context.vuln_id,
                    "type": context.technique_id or "unknown",
                    "target_id": context.target_id,
                    "target_os": context.target_os,
                    "severity": context.target_criticality
                }
                
                mission_context = {
                    "mission_id": context.mission_id,
                    "goals": context.mission_goals,
                    "stealth_level": context.stealth_level
                }
                
                context.strategic_score = await self.strategic_scorer.score_vulnerability(
                    vuln_dict,
                    mission_context
                )
                
                self.logger.debug(
                    f"[INTELLIGENCE] Strategic score: "
                    f"success={context.strategic_score.success_probability:.2%}, "
                    f"detection={context.strategic_score.detection_probability:.2%}, "
                    f"risk={context.strategic_score.risk_level.value if hasattr(context.strategic_score, 'risk_level') else 'unknown'}"
                )
                
            except Exception as e:
                self.logger.warning(f"[INTELLIGENCE] Strategic scoring failed: {e}")
        
        # 2. Operational Memory - Query similar past operations
        if self.operational_memory:
            try:
                context.similar_operations = await self.operational_memory.query_similar_operations(
                    operation_type=context.operation_type,
                    target_os=context.target_os,
                    technique_id=context.technique_id,
                    limit=5
                )
                
                if context.similar_operations:
                    # Calculate success rate from history
                    successes = sum(
                        1 for op in context.similar_operations
                        if op.get("outcome") == "SUCCESS"
                    )
                    context.historical_success_rate = successes / len(context.similar_operations)
                    
                    self.logger.debug(
                        f"[INTELLIGENCE] Historical success rate: "
                        f"{context.historical_success_rate:.2%} "
                        f"({successes}/{len(context.similar_operations)} operations)"
                    )
                
            except Exception as e:
                self.logger.warning(f"[INTELLIGENCE] Operational memory query failed: {e}")
        
        # 3. Defense Intelligence - Check for detected defenses
        if self.defense_intelligence and context.target_id:
            try:
                # Query blackboard for recent operation results on this target
                # (This would need actual operation logs)
                operation_result = {"success": True}  # Placeholder
                execution_logs = []  # Placeholder
                
                context.detected_defenses = await self.defense_intelligence.detect_defenses(
                    target_id=context.target_id,
                    operation_result=operation_result,
                    execution_logs=execution_logs
                )
                
                if context.detected_defenses:
                    self.logger.warning(
                        f"[INTELLIGENCE] Detected {len(context.detected_defenses)} defenses: "
                        f"{[d.defense_type for d in context.detected_defenses]}"
                    )
                
            except Exception as e:
                self.logger.warning(f"[INTELLIGENCE] Defense detection failed: {e}")
        
        # 4. Blackboard - Get available resources
        if self.blackboard and context.mission_id:
            try:
                # Get available credentials for target
                creds = await self.blackboard.get_target_credentials(
                    context.mission_id,
                    context.target_id
                )
                context.available_credentials = [c.get("cred_id") for c in (creds or [])]
                
                # Get active sessions on target
                sessions = await self.blackboard.get_target_sessions(
                    context.mission_id,
                    context.target_id
                )
                context.available_sessions = [s.get("session_id") for s in (sessions or [])]
                
                self.logger.debug(
                    f"[INTELLIGENCE] Resources: "
                    f"{len(context.available_credentials)} creds, "
                    f"{len(context.available_sessions)} sessions"
                )
                
            except Exception as e:
                self.logger.warning(f"[INTELLIGENCE] Resource query failed: {e}")
    
    async def _assess_risk(self, context: DecisionContext) -> Dict[str, float]:
        """
        Calculate multi-factor risk assessment
        
        Combines:
        - Success probability (from strategic scorer)
        - Detection risk (from strategic scorer + defenses)
        - Historical patterns (from operational memory)
        - Defense presence (from defense intelligence)
        - Target criticality
        
        Args:
            context: Enriched decision context
            
        Returns:
            Risk assessment dictionary with individual factor scores
        """
        risk_assessment = {
            "success_probability": 0.5,  # Default medium
            "detection_risk": 0.5,       # Default medium
            "defense_risk": 0.0,         # No defenses by default
            "historical_risk": 0.5,      # Unknown history
            "overall_risk": 0.5          # Calculated below
        }
        
        # Factor 1: Success Probability (from Strategic Scorer)
        if context.strategic_score:
            risk_assessment["success_probability"] = context.strategic_score.success_probability
            risk_assessment["detection_risk"] = context.strategic_score.detection_probability
        
        # Factor 2: Historical Patterns (from Operational Memory)
        if context.similar_operations:
            # Higher historical failure rate = higher risk
            risk_assessment["historical_risk"] = 1.0 - context.historical_success_rate
        
        # Factor 3: Defense Presence (from Defense Intelligence)
        if context.detected_defenses:
            # Each detected defense increases risk
            defense_risk = min(len(context.detected_defenses) * 0.2, 1.0)
            risk_assessment["defense_risk"] = defense_risk
        
        # Calculate overall risk (weighted average)
        weights = {
            "success_probability": -0.3,  # Higher success = lower risk (negative weight)
            "detection_risk": 0.3,
            "defense_risk": 0.2,
            "historical_risk": 0.2
        }
        
        overall_risk = 0.5  # Baseline
        for factor, weight in weights.items():
            overall_risk += risk_assessment[factor] * weight
        
        risk_assessment["overall_risk"] = max(0.0, min(1.0, overall_risk))
        
        self.logger.debug(
            f"[RISK ASSESSMENT] Overall: {risk_assessment['overall_risk']:.2%}, "
            f"Success: {risk_assessment['success_probability']:.2%}, "
            f"Detection: {risk_assessment['detection_risk']:.2%}, "
            f"Defenses: {risk_assessment['defense_risk']:.2%}, "
            f"Historical: {risk_assessment['historical_risk']:.2%}"
        )
        
        return risk_assessment
    
    async def _apply_decision_gates(
        self,
        context: DecisionContext,
        risk_assessment: Dict[str, float]
    ) -> Decision:
        """
        Apply decision gates based on risk assessment and thresholds
        
        Decision Gates (in order):
        1. Critical Risk Gate - Request approval for high-risk ops
        2. Historical Failure Gate - Skip if historically failed
        3. Defense Detection Gate - Skip/defer if defenses detected
        4. Success Probability Gate - Skip if too low
        5. Detection Risk Gate - Request approval if too high
        6. Alternative Available Gate - Use alternative if better
        7. Execute Gate - Proceed with execution
        
        Args:
            context: Decision context
            risk_assessment: Risk assessment from _assess_risk
            
        Returns:
            Decision object
        """
        reasoning = []
        
        # Gate 1: Critical Risk - Request Approval
        if risk_assessment["overall_risk"] >= self.thresholds["critical_risk_approval"]:
            reasoning.append(
                f"Overall risk {risk_assessment['overall_risk']:.2%} exceeds "
                f"critical threshold {self.thresholds['critical_risk_approval']:.2%}"
            )
            return Decision(
                decision_type=DecisionType.REQUEST_APPROVAL,
                confidence=0.9,
                primary_reason=DecisionReason.CRITICAL_RISK_LEVEL,
                reasoning=reasoning,
                requires_approval=True,
                risk_factors=risk_assessment
            )
        
        # Gate 2: Historical Failure - Skip if consistently failed
        if context.similar_operations:
            failures = [
                op for op in context.similar_operations
                if op.get("outcome") == "FAILURE"
            ]
            if len(failures) >= 3:  # 3+ consecutive failures
                reasoning.append(
                    f"Historical analysis shows {len(failures)} previous failures "
                    f"for similar operations"
                )
                return Decision(
                    decision_type=DecisionType.SKIP,
                    confidence=0.8,
                    primary_reason=DecisionReason.HISTORICAL_FAILURE,
                    reasoning=reasoning,
                    risk_factors=risk_assessment
                )
        
        # Gate 3: Defense Detection - Evaluate evasion need
        if context.detected_defenses:
            high_confidence_defenses = [
                d for d in context.detected_defenses
                if getattr(d, 'confidence', 0.0) >= 0.7
            ]
            if len(high_confidence_defenses) >= 2:
                reasoning.append(
                    f"Detected {len(high_confidence_defenses)} high-confidence defenses: "
                    f"{[getattr(d, 'defense_type', 'unknown') for d in high_confidence_defenses]}"
                )
                # Don't skip automatically - suggest alternative with evasion
                return Decision(
                    decision_type=DecisionType.USE_ALTERNATIVE,
                    confidence=0.7,
                    primary_reason=DecisionReason.EVASION_REQUIRED,
                    reasoning=reasoning,
                    risk_factors=risk_assessment,
                    mitigation_strategies=["use_evasion_techniques", "obfuscate_payload", "rate_limiting"]
                )
        
        # Gate 4: Success Probability - Skip if too low
        if risk_assessment["success_probability"] < self.thresholds["min_success_probability"]:
            reasoning.append(
                f"Success probability {risk_assessment['success_probability']:.2%} "
                f"below minimum threshold {self.thresholds['min_success_probability']:.2%}"
            )
            
            # Check if alternative available
            if context.available_credentials:
                reasoning.append(f"But {len(context.available_credentials)} credentials available for alternative approach")
                return Decision(
                    decision_type=DecisionType.USE_ALTERNATIVE,
                    confidence=0.6,
                    primary_reason=DecisionReason.CREDENTIAL_AVAILABLE,
                    reasoning=reasoning,
                    risk_factors=risk_assessment
                )
            
            return Decision(
                decision_type=DecisionType.SKIP,
                confidence=0.75,
                primary_reason=DecisionReason.LOW_SUCCESS_PROBABILITY,
                reasoning=reasoning,
                risk_factors=risk_assessment
            )
        
        # Gate 5: Detection Risk - Request approval if high
        if risk_assessment["detection_risk"] > self.thresholds["max_detection_risk"]:
            reasoning.append(
                f"Detection risk {risk_assessment['detection_risk']:.2%} "
                f"exceeds maximum threshold {self.thresholds['max_detection_risk']:.2%}"
            )
            
            # If stealth is critical, skip instead
            if context.stealth_level in ("high", "extreme"):
                reasoning.append(f"Stealth level '{context.stealth_level}' requires skipping high-detection operations")
                return Decision(
                    decision_type=DecisionType.SKIP,
                    confidence=0.85,
                    primary_reason=DecisionReason.HIGH_DETECTION_RISK,
                    reasoning=reasoning,
                    risk_factors=risk_assessment
                )
            
            # Otherwise request approval
            return Decision(
                decision_type=DecisionType.REQUEST_APPROVAL,
                confidence=0.8,
                primary_reason=DecisionReason.HIGH_DETECTION_RISK,
                reasoning=reasoning,
                requires_approval=True,
                risk_factors=risk_assessment
            )
        
        # Gate 6: All checks passed - Execute
        reasoning.append(
            f"Risk assessment favorable: "
            f"success={risk_assessment['success_probability']:.2%}, "
            f"detection={risk_assessment['detection_risk']:.2%}, "
            f"overall_risk={risk_assessment['overall_risk']:.2%}"
        )
        
        if risk_assessment["success_probability"] >= 0.7:
            reasoning.append("High success probability - recommended for execution")
            primary_reason = DecisionReason.HIGH_SUCCESS_PROBABILITY
        elif context.historical_success_rate >= 0.7:
            reasoning.append("Strong historical success pattern")
            primary_reason = DecisionReason.HISTORICAL_SUCCESS
        elif risk_assessment["detection_risk"] <= 0.3:
            reasoning.append("Low detection risk environment")
            primary_reason = DecisionReason.LOW_DETECTION_RISK
        else:
            primary_reason = DecisionReason.HIGH_SUCCESS_PROBABILITY
        
        return Decision(
            decision_type=DecisionType.EXECUTE,
            confidence=risk_assessment["success_probability"],
            primary_reason=primary_reason,
            reasoning=reasoning,
            risk_factors=risk_assessment
        )
    
    async def _select_optimal_strategy(
        self,
        context: DecisionContext,
        decision: Decision
    ) -> None:
        """
        Select optimal execution strategy based on context
        
        Strategies:
        - Credential-based (if credentials available)
        - Exploit-based (standard exploitation)
        - Evasion-enhanced (if defenses detected)
        - Stealthy (if high stealth required)
        
        Args:
            context: Decision context
            decision: Decision object to populate with recommended action
        """
        strategy = {}
        
        # Strategy 1: Credential-based (preferred if available)
        if context.available_credentials:
            strategy["method"] = "credential_based"
            strategy["credential_id"] = context.available_credentials[0]
            decision.reasoning.append(
                f"Using credential-based approach ({len(context.available_credentials)} creds available)"
            )
        
        # Strategy 2: Evasion-enhanced (if defenses detected)
        elif context.detected_defenses:
            strategy["method"] = "evasion_enhanced"
            strategy["evasion_techniques"] = ["obfuscation", "encoding", "rate_limiting"]
            decision.reasoning.append(
                f"Using evasion-enhanced approach ({len(context.detected_defenses)} defenses detected)"
            )
        
        # Strategy 3: Stealthy (if high stealth required)
        elif context.stealth_level in ("high", "extreme"):
            strategy["method"] = "stealthy"
            strategy["scan_rate"] = "slow"
            strategy["randomize_timing"] = True
            decision.reasoning.append(
                f"Using stealthy approach (stealth level: {context.stealth_level})"
            )
        
        # Strategy 4: Standard exploit
        else:
            strategy["method"] = "standard_exploit"
            decision.reasoning.append("Using standard exploitation approach")
        
        decision.recommended_action = strategy
    
    async def _add_fallback_options(
        self,
        context: DecisionContext,
        decision: Decision
    ) -> None:
        """
        Add fallback options to decision
        
        Provides alternative approaches if primary decision fails.
        
        Args:
            context: Decision context
            decision: Decision object to populate with alternatives
        """
        alternatives = []
        
        # Alternative 1: Try credential-based if exploit recommended
        if (decision.decision_type == DecisionType.EXECUTE and
            decision.recommended_action and
            decision.recommended_action.get("method") != "credential_based" and
            context.available_credentials):
            alternatives.append({
                "method": "credential_based",
                "credential_id": context.available_credentials[0],
                "reason": "Fallback to credential-based approach"
            })
        
        # Alternative 2: Try different technique
        if context.alternative_techniques:
            alternatives.append({
                "method": "alternative_technique",
                "technique_id": context.alternative_techniques[0],
                "reason": "Try alternative exploitation technique"
            })
        
        # Alternative 3: Defer and gather more intelligence
        if len(context.similar_operations) < 3:
            alternatives.append({
                "method": "defer_and_gather",
                "reason": "Insufficient historical data - gather more intelligence"
            })
        
        decision.alternative_options = alternatives
    
    def _update_stats(self, decision: Decision) -> None:
        """Update decision statistics"""
        if decision.decision_type == DecisionType.EXECUTE:
            self.stats["execute_decisions"] += 1
        elif decision.decision_type == DecisionType.SKIP:
            self.stats["skip_decisions"] += 1
        elif decision.decision_type == DecisionType.REQUEST_APPROVAL:
            self.stats["approval_requests"] += 1
        elif decision.decision_type == DecisionType.USE_ALTERNATIVE:
            self.stats["alternative_selections"] += 1
    
    def get_stats(self) -> Dict[str, int]:
        """Get decision engine statistics"""
        return self.stats.copy()
