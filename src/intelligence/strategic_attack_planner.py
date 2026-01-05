"""
═══════════════════════════════════════════════════════════════════════════════
RAGLOX v3.0 - Strategic Attack Planner
═══════════════════════════════════════════════════════════════════════════════

High-level attack campaign planner that orchestrates complex multi-stage operations
using intelligence from all subsystems.

Features:
- Multi-stage attack campaign planning
- MITRE ATT&CK kill chain orchestration
- Resource allocation and timing
- Risk assessment and fallback planning
- Goal-driven path optimization
- Stealth vs speed optimization

Author: RAGLOX Team
Version: 3.0.0
"""

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import uuid4

logger = logging.getLogger("raglox.intelligence.strategic_planner")


# ═══════════════════════════════════════════════════════════════════════════════
# Data Models
# ═══════════════════════════════════════════════════════════════════════════════

class AttackStage(Enum):
    """MITRE ATT&CK-aligned attack stages."""
    RECONNAISSANCE = "reconnaissance"       # T1595, T1046, T1592
    RESOURCE_DEVELOPMENT = "resource_dev"  # T1583, T1585, T1587
    INITIAL_ACCESS = "initial_access"      # T1190, T1133, T1078
    EXECUTION = "execution"                # T1059, T1203, T1204
    PERSISTENCE = "persistence"            # T1053, T1136, T1547
    PRIVILEGE_ESCALATION = "privesc"       # T1068, T1078, T1055
    DEFENSE_EVASION = "defense_evasion"    # T1027, T1070, T1112
    CREDENTIAL_ACCESS = "credential"       # T1003, T1110, T1555
    DISCOVERY = "discovery"                # T1087, T1046, T1083
    LATERAL_MOVEMENT = "lateral"           # T1021, T1550, T1563
    COLLECTION = "collection"              # T1005, T1039, T1113
    COMMAND_AND_CONTROL = "c2"             # T1071, T1090, T1095
    EXFILTRATION = "exfiltration"         # T1041, T1048, T1567
    IMPACT = "impact"                      # T1486, T1490, T1498


class OptimizationGoal(Enum):
    """Campaign optimization goals."""
    SPEED = "speed"           # Fastest path to goal
    STEALTH = "stealth"       # Minimize detection risk
    RELIABILITY = "reliability"  # Highest success probability
    BALANCED = "balanced"     # Balance all factors


@dataclass
class CampaignStage:
    """A single stage in an attack campaign."""
    stage_id: str
    stage_type: AttackStage
    name: str
    description: str
    techniques: List[str]  # MITRE technique IDs
    
    # Dependencies
    depends_on: List[str] = field(default_factory=list)  # stage_ids
    
    # Targets
    target_ids: List[str] = field(default_factory=list)
    
    # Execution
    execution_order: List[Dict[str, Any]] = field(default_factory=list)
    parallel_tasks: List[List[str]] = field(default_factory=list)
    
    # Estimates
    estimated_duration_minutes: int = 15
    success_probability: float = 0.7
    detection_risk: float = 0.3
    
    # Resources
    required_credentials: List[str] = field(default_factory=list)
    required_tools: List[str] = field(default_factory=list)
    
    # Fallback
    fallback_stages: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "stage_id": self.stage_id,
            "stage_type": self.stage_type.value,
            "name": self.name,
            "description": self.description,
            "techniques": self.techniques,
            "depends_on": self.depends_on,
            "target_ids": self.target_ids,
            "execution_order": self.execution_order,
            "parallel_tasks": self.parallel_tasks,
            "estimated_duration_minutes": self.estimated_duration_minutes,
            "success_probability": self.success_probability,
            "detection_risk": self.detection_risk,
            "required_credentials": self.required_credentials,
            "required_tools": self.required_tools,
            "fallback_stages": self.fallback_stages
        }


@dataclass
class AttackCampaign:
    """Complete attack campaign plan."""
    campaign_id: str
    mission_id: str
    name: str
    objectives: List[str]
    
    # Stages
    stages: List[CampaignStage] = field(default_factory=list)
    stage_graph: Dict[str, List[str]] = field(default_factory=dict)
    
    # Optimization
    optimization_goal: OptimizationGoal = OptimizationGoal.BALANCED
    
    # Estimates
    total_estimated_duration_minutes: int = 60
    overall_success_probability: float = 0.5
    overall_detection_risk: float = 0.4
    
    # Resources
    required_credentials: List[str] = field(default_factory=list)
    required_tools: Set[str] = field(default_factory=set)
    
    # Metadata
    created_at: float = field(default_factory=time.time)
    generated_by: str = "strategic_attack_planner"
    
    # Alternative plans
    alternative_campaigns: List['AttackCampaign'] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "campaign_id": self.campaign_id,
            "mission_id": self.mission_id,
            "name": self.name,
            "objectives": self.objectives,
            "stages": [s.to_dict() for s in self.stages],
            "stage_graph": self.stage_graph,
            "optimization_goal": self.optimization_goal.value,
            "total_estimated_duration_minutes": self.total_estimated_duration_minutes,
            "overall_success_probability": self.overall_success_probability,
            "overall_detection_risk": self.overall_detection_risk,
            "required_credentials": self.required_credentials,
            "required_tools": list(self.required_tools),
            "created_at": self.created_at,
            "generated_by": self.generated_by,
            "alternative_count": len(self.alternative_campaigns)
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Strategic Attack Planner
# ═══════════════════════════════════════════════════════════════════════════════

class StrategicAttackPlanner:
    """
    High-level strategic attack campaign planner.
    
    Integrates all intelligence subsystems to create comprehensive multi-stage
    attack campaigns optimized for specific goals.
    
    Core Capabilities:
    1. **Campaign Planning**: Multi-stage attack campaigns
    2. **Kill Chain Orchestration**: MITRE ATT&CK aligned sequences
    3. **Resource Allocation**: Tools, credentials, timing
    4. **Risk Assessment**: Success probability and detection risk
    5. **Optimization**: Speed vs stealth vs reliability
    6. **Fallback Planning**: Alternative paths on failure
    
    Usage:
        planner = StrategicAttackPlanner(
            intelligence_coordinator=coordinator,
            strategic_scorer=scorer,
            operational_memory=memory,
            adaptive_learning=learning,
            defense_intelligence=defense_intel
        )
        
        campaign = await planner.plan_campaign(
            mission_id="mission_123",
            mission_goals=["domain_admin"],
            targets=[...],
            constraints={"stealth_level": "high", "max_duration_hours": 4}
        )
    """
    
    # Goal-to-stage mapping
    GOAL_STAGE_MAP = {
        "initial_access": [AttackStage.RECONNAISSANCE, AttackStage.INITIAL_ACCESS],
        "domain_admin": [
            AttackStage.RECONNAISSANCE,
            AttackStage.INITIAL_ACCESS,
            AttackStage.EXECUTION,
            AttackStage.PRIVILEGE_ESCALATION,
            AttackStage.CREDENTIAL_ACCESS,
            AttackStage.LATERAL_MOVEMENT
        ],
        "data_exfiltration": [
            AttackStage.RECONNAISSANCE,
            AttackStage.INITIAL_ACCESS,
            AttackStage.DISCOVERY,
            AttackStage.COLLECTION,
            AttackStage.EXFILTRATION
        ],
        "persistence": [
            AttackStage.RECONNAISSANCE,
            AttackStage.INITIAL_ACCESS,
            AttackStage.EXECUTION,
            AttackStage.PERSISTENCE,
            AttackStage.COMMAND_AND_CONTROL
        ],
        "credential_harvest": [
            AttackStage.RECONNAISSANCE,
            AttackStage.INITIAL_ACCESS,
            AttackStage.CREDENTIAL_ACCESS
        ]
    }
    
    def __init__(
        self,
        intelligence_coordinator=None,
        strategic_scorer=None,
        operational_memory=None,
        adaptive_learning=None,
        defense_intelligence=None
    ):
        """
        Initialize strategic attack planner.
        
        Args:
            intelligence_coordinator: IntelligenceCoordinator for path generation
            strategic_scorer: StrategicScorer for vulnerability scoring
            operational_memory: OperationalMemory for historical data
            adaptive_learning: AdaptiveLearningLayer for learning insights
            defense_intelligence: DefenseIntelligence for evasion planning
        """
        self.intelligence_coordinator = intelligence_coordinator
        self.strategic_scorer = strategic_scorer
        self.operational_memory = operational_memory
        self.adaptive_learning = adaptive_learning
        self.defense_intelligence = defense_intelligence
        
        # Campaign cache
        self.campaign_cache: Dict[str, AttackCampaign] = {}
        
        # Statistics
        self.stats = {
            "campaigns_generated": 0,
            "stages_planned": 0,
            "optimizations_performed": 0
        }
        
        logger.info("StrategicAttackPlanner initialized")
    
    # ═══════════════════════════════════════════════════════════════════════════
    # Main Campaign Planning
    # ═══════════════════════════════════════════════════════════════════════════
    
    async def plan_campaign(
        self,
        mission_id: str,
        mission_goals: List[str],
        targets: List[Dict[str, Any]],
        discovered_data: Optional[Dict[str, Any]] = None,
        constraints: Optional[Dict[str, Any]] = None
    ) -> AttackCampaign:
        """
        Plan a comprehensive attack campaign.
        
        Args:
            mission_id: Mission identifier
            mission_goals: List of mission objectives (e.g., ["domain_admin"])
            targets: List of discovered targets
            discovered_data: Services, vulnerabilities, credentials
            constraints: Stealth level, max duration, etc.
            
        Returns:
            Complete AttackCampaign with stages and execution plan
        """
        logger.info(f"Planning campaign for mission {mission_id} with goals: {mission_goals}")
        
        constraints = constraints or {}
        discovered_data = discovered_data or {}
        
        # Generate campaign ID
        campaign_id = f"campaign_{mission_id}_{int(time.time())}"
        
        # 1. Determine required stages based on goals
        required_stages = self._determine_required_stages(mission_goals)
        
        # 2. Build stage graph (dependencies)
        stage_graph = self._build_stage_graph(required_stages)
        
        # 3. Create campaign stages with details
        stages = await self._create_campaign_stages(
            mission_id=mission_id,
            required_stages=required_stages,
            targets=targets,
            discovered_data=discovered_data,
            constraints=constraints
        )
        
        # 4. Calculate campaign estimates
        total_duration, success_prob, detection_risk = self._calculate_campaign_metrics(stages)
        
        # 5. Extract required resources
        required_creds, required_tools = self._extract_required_resources(stages)
        
        # Create campaign
        campaign = AttackCampaign(
            campaign_id=campaign_id,
            mission_id=mission_id,
            name=self._generate_campaign_name(mission_goals),
            objectives=mission_goals,
            stages=stages,
            stage_graph=stage_graph,
            optimization_goal=self._determine_optimization_goal(constraints),
            total_estimated_duration_minutes=total_duration,
            overall_success_probability=success_prob,
            overall_detection_risk=detection_risk,
            required_credentials=required_creds,
            required_tools=required_tools
        )
        
        # 6. Generate alternative campaigns
        if constraints.get("generate_alternatives", False):
            campaign.alternative_campaigns = await self._generate_alternatives(
                campaign, targets, discovered_data, constraints
            )
        
        # Cache and track
        self.campaign_cache[campaign_id] = campaign
        self.stats["campaigns_generated"] += 1
        self.stats["stages_planned"] += len(stages)
        
        logger.info(
            f"Campaign generated: {len(stages)} stages, "
            f"{total_duration}min duration, "
            f"{success_prob:.1%} success probability"
        )
        
        return campaign
    
    def _determine_required_stages(self, mission_goals: List[str]) -> List[AttackStage]:
        """Determine required attack stages based on mission goals."""
        stages_set = set()
        
        for goal in mission_goals:
            goal_lower = goal.lower()
            
            # Map to stages
            for goal_key, stages in self.GOAL_STAGE_MAP.items():
                if goal_key in goal_lower:
                    stages_set.update(stages)
        
        # Always include reconnaissance
        stages_set.add(AttackStage.RECONNAISSANCE)
        
        # Convert to ordered list
        all_stages = list(AttackStage)
        ordered_stages = [s for s in all_stages if s in stages_set]
        
        return ordered_stages
    
    def _build_stage_graph(self, stages: List[AttackStage]) -> Dict[str, List[str]]:
        """Build dependency graph between stages."""
        graph = {}
        
        # Define dependencies
        dependencies = {
            AttackStage.RECONNAISSANCE: [],
            AttackStage.RESOURCE_DEVELOPMENT: [AttackStage.RECONNAISSANCE],
            AttackStage.INITIAL_ACCESS: [AttackStage.RECONNAISSANCE],
            AttackStage.EXECUTION: [AttackStage.INITIAL_ACCESS],
            AttackStage.PERSISTENCE: [AttackStage.EXECUTION],
            AttackStage.PRIVILEGE_ESCALATION: [AttackStage.EXECUTION],
            AttackStage.DEFENSE_EVASION: [AttackStage.EXECUTION],
            AttackStage.CREDENTIAL_ACCESS: [AttackStage.EXECUTION],
            AttackStage.DISCOVERY: [AttackStage.EXECUTION],
            AttackStage.LATERAL_MOVEMENT: [AttackStage.PRIVILEGE_ESCALATION, AttackStage.CREDENTIAL_ACCESS],
            AttackStage.COLLECTION: [AttackStage.DISCOVERY],
            AttackStage.COMMAND_AND_CONTROL: [AttackStage.PERSISTENCE],
            AttackStage.EXFILTRATION: [AttackStage.COLLECTION],
            AttackStage.IMPACT: [AttackStage.PRIVILEGE_ESCALATION]
        }
        
        for stage in stages:
            deps = dependencies.get(stage, [])
            # Filter to only include dependencies that are in our stages
            graph[stage.value] = [d.value for d in deps if d in stages]
        
        return graph
    
    async def _create_campaign_stages(
        self,
        mission_id: str,
        required_stages: List[AttackStage],
        targets: List[Dict[str, Any]],
        discovered_data: Dict[str, Any],
        constraints: Dict[str, Any]
    ) -> List[CampaignStage]:
        """Create detailed campaign stages."""
        stages = []
        
        services = discovered_data.get("services", {})
        vulnerabilities = discovered_data.get("vulnerabilities", {})
        credentials = discovered_data.get("credentials", [])
        
        for stage_type in required_stages:
            stage = await self._create_stage(
                mission_id=mission_id,
                stage_type=stage_type,
                targets=targets,
                services=services,
                vulnerabilities=vulnerabilities,
                credentials=credentials,
                constraints=constraints
            )
            
            if stage:
                stages.append(stage)
        
        return stages
    
    async def _create_stage(
        self,
        mission_id: str,
        stage_type: AttackStage,
        targets: List[Dict],
        services: Dict,
        vulnerabilities: Dict,
        credentials: List,
        constraints: Dict
    ) -> Optional[CampaignStage]:
        """Create a single campaign stage."""
        
        stage_id = f"stage_{stage_type.value}_{int(time.time())}"
        
        # Stage-specific creation
        if stage_type == AttackStage.RECONNAISSANCE:
            return self._create_recon_stage(stage_id, targets, constraints)
        
        elif stage_type == AttackStage.INITIAL_ACCESS:
            return await self._create_initial_access_stage(
                stage_id, targets, services, vulnerabilities, credentials
            )
        
        elif stage_type == AttackStage.EXECUTION:
            return self._create_execution_stage(stage_id, targets)
        
        elif stage_type == AttackStage.PRIVILEGE_ESCALATION:
            return self._create_privesc_stage(stage_id, targets, vulnerabilities)
        
        elif stage_type == AttackStage.CREDENTIAL_ACCESS:
            return self._create_credential_stage(stage_id, targets)
        
        elif stage_type == AttackStage.LATERAL_MOVEMENT:
            return self._create_lateral_stage(stage_id, targets, credentials)
        
        elif stage_type == AttackStage.PERSISTENCE:
            return self._create_persistence_stage(stage_id, targets)
        
        elif stage_type == AttackStage.COLLECTION:
            return self._create_collection_stage(stage_id, targets)
        
        elif stage_type == AttackStage.EXFILTRATION:
            return self._create_exfiltration_stage(stage_id, targets)
        
        else:
            # Generic stage
            return CampaignStage(
                stage_id=stage_id,
                stage_type=stage_type,
                name=stage_type.value.replace("_", " ").title(),
                description=f"Execute {stage_type.value} operations",
                techniques=[],
                target_ids=[t.get("id", "") for t in targets[:3]]
            )
    
    def _create_recon_stage(
        self,
        stage_id: str,
        targets: List[Dict],
        constraints: Dict
    ) -> CampaignStage:
        """Create reconnaissance stage."""
        return CampaignStage(
            stage_id=stage_id,
            stage_type=AttackStage.RECONNAISSANCE,
            name="Network Reconnaissance",
            description="Discover targets, services, and potential vulnerabilities",
            techniques=["T1046", "T1595.002", "T1592.002"],  # Port scan, vuln scan
            target_ids=[t.get("id", "") for t in targets],
            execution_order=[
                {"task_type": "NETWORK_SCAN", "priority": 10},
                {"task_type": "PORT_SCAN", "priority": 9},
                {"task_type": "SERVICE_ENUM", "priority": 8},
                {"task_type": "VULN_SCAN", "priority": 7}
            ],
            estimated_duration_minutes=10,
            success_probability=0.9,
            detection_risk=0.2,
            required_tools=["nmap", "nuclei"]
        )
    
    async def _create_initial_access_stage(
        self,
        stage_id: str,
        targets: List[Dict],
        services: Dict,
        vulnerabilities: Dict,
        credentials: List
    ) -> CampaignStage:
        """Create initial access stage using intelligence coordinator."""
        
        # Use IntelligenceCoordinator if available
        if self.intelligence_coordinator and targets and vulnerabilities:
            # Get attack paths from coordinator
            target = targets[0]
            target_vulns = vulnerabilities.get(target.get("id", ""), [])
            
            if target_vulns:
                paths = await self.intelligence_coordinator.generate_attack_paths(
                    target_id=target.get("id", ""),
                    services=services.get(target.get("id", ""), []),
                    vulnerabilities=target_vulns,
                    credentials=credentials
                )
                
                if paths:
                    best_path = paths[0]
                    
                    return CampaignStage(
                        stage_id=stage_id,
                        stage_type=AttackStage.INITIAL_ACCESS,
                        name="Initial Access",
                        description=best_path.reasoning,
                        techniques=["T1190", "T1078"],  # Exploit, Valid Accounts
                        target_ids=[target.get("id", "")],
                        execution_order=[
                            {"task_type": "EXPLOIT", "priority": 10, "path_id": str(best_path.id)}
                        ],
                        estimated_duration_minutes=best_path.time_estimate_minutes,
                        success_probability=best_path.success_probability,
                        detection_risk=1.0 - best_path.stealth_score,
                        required_credentials=best_path.required_credentials,
                        required_tools=["metasploit", "hydra"]
                    )
        
        # Fallback to generic initial access
        return CampaignStage(
            stage_id=stage_id,
            stage_type=AttackStage.INITIAL_ACCESS,
            name="Initial Access",
            description="Gain initial foothold on target systems",
            techniques=["T1190", "T1078", "T1133"],
            target_ids=[t.get("id", "") for t in targets[:3]],
            execution_order=[
                {"task_type": "EXPLOIT", "priority": 10}
            ],
            estimated_duration_minutes=15,
            success_probability=0.6,
            detection_risk=0.4,
            required_tools=["metasploit"]
        )
    
    def _create_execution_stage(self, stage_id: str, targets: List[Dict]) -> CampaignStage:
        """Create execution stage."""
        return CampaignStage(
            stage_id=stage_id,
            stage_type=AttackStage.EXECUTION,
            name="Command Execution",
            description="Execute commands on compromised systems",
            techniques=["T1059.001", "T1059.003", "T1203"],
            target_ids=[t.get("id", "") for t in targets[:3]],
            execution_order=[
                {"task_type": "EXECUTE", "priority": 9}
            ],
            estimated_duration_minutes=5,
            success_probability=0.8,
            detection_risk=0.3,
            depends_on=[AttackStage.INITIAL_ACCESS.value]
        )
    
    def _create_privesc_stage(
        self,
        stage_id: str,
        targets: List[Dict],
        vulnerabilities: Dict
    ) -> CampaignStage:
        """Create privilege escalation stage."""
        return CampaignStage(
            stage_id=stage_id,
            stage_type=AttackStage.PRIVILEGE_ESCALATION,
            name="Privilege Escalation",
            description="Escalate privileges to admin/SYSTEM",
            techniques=["T1068", "T1078", "T1548"],
            target_ids=[t.get("id", "") for t in targets[:3]],
            execution_order=[
                {"task_type": "PRIVESC", "priority": 8}
            ],
            estimated_duration_minutes=10,
            success_probability=0.65,
            detection_risk=0.45,
            depends_on=[AttackStage.EXECUTION.value]
        )
    
    def _create_credential_stage(self, stage_id: str, targets: List[Dict]) -> CampaignStage:
        """Create credential harvesting stage."""
        return CampaignStage(
            stage_id=stage_id,
            stage_type=AttackStage.CREDENTIAL_ACCESS,
            name="Credential Harvesting",
            description="Extract credentials from memory and files",
            techniques=["T1003", "T1555", "T1552"],
            target_ids=[t.get("id", "") for t in targets[:3]],
            execution_order=[
                {"task_type": "CRED_HARVEST", "priority": 8}
            ],
            estimated_duration_minutes=8,
            success_probability=0.75,
            detection_risk=0.5,
            depends_on=[AttackStage.EXECUTION.value],
            required_tools=["mimikatz", "lazagne"]
        )
    
    def _create_lateral_stage(
        self,
        stage_id: str,
        targets: List[Dict],
        credentials: List
    ) -> CampaignStage:
        """Create lateral movement stage."""
        return CampaignStage(
            stage_id=stage_id,
            stage_type=AttackStage.LATERAL_MOVEMENT,
            name="Lateral Movement",
            description="Move laterally to other systems using credentials",
            techniques=["T1021.001", "T1021.002", "T1550"],
            target_ids=[t.get("id", "") for t in targets[:5]],
            execution_order=[
                {"task_type": "LATERAL", "priority": 7}
            ],
            estimated_duration_minutes=12,
            success_probability=0.7,
            detection_risk=0.4,
            depends_on=[AttackStage.CREDENTIAL_ACCESS.value],
            required_credentials=[c.get("id", "") for c in credentials[:3]]
        )
    
    def _create_persistence_stage(self, stage_id: str, targets: List[Dict]) -> CampaignStage:
        """Create persistence stage."""
        return CampaignStage(
            stage_id=stage_id,
            stage_type=AttackStage.PERSISTENCE,
            name="Establish Persistence",
            description="Install persistence mechanisms",
            techniques=["T1053", "T1547", "T1543"],
            target_ids=[t.get("id", "") for t in targets[:3]],
            execution_order=[
                {"task_type": "PERSIST", "priority": 6}
            ],
            estimated_duration_minutes=8,
            success_probability=0.7,
            detection_risk=0.5,
            depends_on=[AttackStage.EXECUTION.value]
        )
    
    def _create_collection_stage(self, stage_id: str, targets: List[Dict]) -> CampaignStage:
        """Create collection stage."""
        return CampaignStage(
            stage_id=stage_id,
            stage_type=AttackStage.COLLECTION,
            name="Data Collection",
            description="Collect data from target systems",
            techniques=["T1005", "T1039", "T1119"],
            target_ids=[t.get("id", "") for t in targets[:3]],
            execution_order=[
                {"task_type": "COLLECT", "priority": 6}
            ],
            estimated_duration_minutes=10,
            success_probability=0.8,
            detection_risk=0.35,
            depends_on=[AttackStage.DISCOVERY.value]
        )
    
    def _create_exfiltration_stage(self, stage_id: str, targets: List[Dict]) -> CampaignStage:
        """Create exfiltration stage."""
        return CampaignStage(
            stage_id=stage_id,
            stage_type=AttackStage.EXFILTRATION,
            name="Data Exfiltration",
            description="Exfiltrate collected data",
            techniques=["T1041", "T1048", "T1567"],
            target_ids=[t.get("id", "") for t in targets[:3]],
            execution_order=[
                {"task_type": "EXFIL", "priority": 5}
            ],
            estimated_duration_minutes=15,
            success_probability=0.75,
            detection_risk=0.6,
            depends_on=[AttackStage.COLLECTION.value]
        )
    
    # ═══════════════════════════════════════════════════════════════════════════
    # Optimization Methods
    # ═══════════════════════════════════════════════════════════════════════════
    
    async def optimize_for_stealth(self, campaign: AttackCampaign) -> AttackCampaign:
        """
        Optimize campaign for maximum stealth.
        
        Changes:
        - Increase delays between stages
        - Use quieter techniques
        - Add defense evasion stages
        - Reduce parallel operations
        """
        self.stats["optimizations_performed"] += 1
        
        optimized = AttackCampaign(**asdict(campaign))
        optimized.optimization_goal = OptimizationGoal.STEALTH
        
        for stage in optimized.stages:
            # Increase duration (slower = stealthier)
            stage.estimated_duration_minutes = int(stage.estimated_duration_minutes * 1.5)
            
            # Reduce detection risk
            stage.detection_risk *= 0.7
            
            # Reduce parallel tasks
            stage.parallel_tasks = []
        
        # Recalculate metrics
        optimized.total_estimated_duration_minutes = sum(
            s.estimated_duration_minutes for s in optimized.stages
        )
        optimized.overall_detection_risk = max(s.detection_risk for s in optimized.stages) * 0.8
        
        logger.info(f"Optimized campaign for stealth: detection risk reduced to {optimized.overall_detection_risk:.1%}")
        
        return optimized
    
    async def optimize_for_speed(self, campaign: AttackCampaign) -> AttackCampaign:
        """
        Optimize campaign for maximum speed.
        
        Changes:
        - Enable parallel operations
        - Use faster techniques
        - Skip optional stages
        - Reduce delays
        """
        self.stats["optimizations_performed"] += 1
        
        optimized = AttackCampaign(**asdict(campaign))
        optimized.optimization_goal = OptimizationGoal.SPEED
        
        for stage in optimized.stages:
            # Decrease duration
            stage.estimated_duration_minutes = max(5, int(stage.estimated_duration_minutes * 0.7))
            
            # Enable parallelization where possible
            if len(stage.execution_order) > 1:
                stage.parallel_tasks = [[task["task_type"] for task in stage.execution_order]]
        
        # Recalculate metrics
        optimized.total_estimated_duration_minutes = int(
            sum(s.estimated_duration_minutes for s in optimized.stages) * 0.6
        )
        
        logger.info(f"Optimized campaign for speed: duration reduced to {optimized.total_estimated_duration_minutes}min")
        
        return optimized
    
    # ═══════════════════════════════════════════════════════════════════════════
    # Helper Methods
    # ═══════════════════════════════════════════════════════════════════════════
    
    def _calculate_campaign_metrics(
        self,
        stages: List[CampaignStage]
    ) -> Tuple[int, float, float]:
        """Calculate total duration, success probability, detection risk."""
        total_duration = sum(s.estimated_duration_minutes for s in stages)
        
        # Overall success = product of individual stage probabilities
        overall_success = 1.0
        for stage in stages:
            overall_success *= stage.success_probability
        
        # Overall detection risk = max of individual risks
        overall_detection = max((s.detection_risk for s in stages), default=0.5)
        
        return total_duration, overall_success, overall_detection
    
    def _extract_required_resources(
        self,
        stages: List[CampaignStage]
    ) -> Tuple[List[str], Set[str]]:
        """Extract required credentials and tools."""
        all_creds = []
        all_tools = set()
        
        for stage in stages:
            all_creds.extend(stage.required_credentials)
            all_tools.update(stage.required_tools)
        
        return list(set(all_creds)), all_tools
    
    def _generate_campaign_name(self, mission_goals: List[str]) -> str:
        """Generate descriptive campaign name."""
        if "domain_admin" in mission_goals:
            return "Domain Dominance Campaign"
        elif "data_exfiltration" in mission_goals:
            return "Data Exfiltration Campaign"
        elif "persistence" in mission_goals:
            return "Persistent Access Campaign"
        else:
            return f"Multi-Objective Campaign ({len(mission_goals)} goals)"
    
    def _determine_optimization_goal(self, constraints: Dict) -> OptimizationGoal:
        """Determine optimization goal from constraints."""
        stealth_level = constraints.get("stealth_level", "normal").lower()
        
        if stealth_level in ("high", "maximum"):
            return OptimizationGoal.STEALTH
        elif constraints.get("speed_priority"):
            return OptimizationGoal.SPEED
        elif constraints.get("reliability_priority"):
            return OptimizationGoal.RELIABILITY
        else:
            return OptimizationGoal.BALANCED
    
    async def _generate_alternatives(
        self,
        primary_campaign: AttackCampaign,
        targets: List[Dict],
        discovered_data: Dict,
        constraints: Dict
    ) -> List[AttackCampaign]:
        """Generate alternative campaign plans."""
        alternatives = []
        
        # Alternative 1: Stealth-optimized
        stealth_campaign = await self.optimize_for_stealth(primary_campaign)
        alternatives.append(stealth_campaign)
        
        # Alternative 2: Speed-optimized
        speed_campaign = await self.optimize_for_speed(primary_campaign)
        alternatives.append(speed_campaign)
        
        return alternatives
    
    # ═══════════════════════════════════════════════════════════════════════════
    # Statistics
    # ═══════════════════════════════════════════════════════════════════════════
    
    def get_stats(self) -> Dict[str, Any]:
        """Get planner statistics."""
        return {
            **self.stats,
            "cached_campaigns": len(self.campaign_cache)
        }
    
    def get_campaign(self, campaign_id: str) -> Optional[AttackCampaign]:
        """Retrieve a cached campaign."""
        return self.campaign_cache.get(campaign_id)
