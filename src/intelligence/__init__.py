"""
═══════════════════════════════════════════════════════════════════════════════
RAGLOX v3.0 - Intelligence Layer
═══════════════════════════════════════════════════════════════════════════════

Advanced AI-powered intelligence system for autonomous red team operations.

Modules:
- AdaptiveLearningLayer: Learn from successes and failures
- DefenseIntelligence: Detect defenses and suggest evasions
- (Future) StrategicAttackPlanner: Plan optimal attack sequences

Author: RAGLOX Team
Version: 3.0.0
"""

from .adaptive_learning import (
    AdaptiveLearningLayer,
    OperationRecord,
    SuccessPattern,
    FailurePattern,
    LearningStats,
    OutcomeType,
)

from .defense_intelligence import (
    DefenseIntelligence,
    DefenseType,
    DetectedDefense,
    EvasionTechnique,
    EvasionPlan,
    EvasionPriority,
)

from .strategic_attack_planner import (
    StrategicAttackPlanner,
    AttackCampaign,
    CampaignStage,
    AttackStage,
    OptimizationGoal,
)

__version__ = "3.0.0"
__author__ = "RAGLOX Team"

__all__ = [
    # Adaptive Learning
    "AdaptiveLearningLayer",
    "OperationRecord",
    "SuccessPattern",
    "FailurePattern",
    "LearningStats",
    "OutcomeType",
    
    # Defense Intelligence
    "DefenseIntelligence",
    "DefenseType",
    "DetectedDefense",
    "EvasionTechnique",
    "EvasionPlan",
    "EvasionPriority",
    
    # Strategic Attack Planner
    "StrategicAttackPlanner",
    "AttackCampaign",
    "CampaignStage",
    "AttackStage",
    "OptimizationGoal",
]
