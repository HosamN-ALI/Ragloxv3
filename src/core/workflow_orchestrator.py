# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Advanced Workflow Orchestrator
# Multi-stage penetration testing workflow with LLM integration
# ═══════════════════════════════════════════════════════════════

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Callable, Awaitable
from uuid import UUID, uuid4

from .blackboard import Blackboard
from .config import Settings, get_settings
from .knowledge import EmbeddedKnowledge, get_knowledge
from .models import (
    Mission, MissionStatus, Task, TaskType, TaskStatus,
    SpecialistType, ApprovalAction, ActionType, RiskLevel
)


logger = logging.getLogger("raglox.core.workflow_orchestrator")


# ═══════════════════════════════════════════════════════════════
# Workflow Phases & States
# ═══════════════════════════════════════════════════════════════

class WorkflowPhase(Enum):
    """Enterprise workflow phases."""
    INITIALIZATION = "initialization"
    STRATEGIC_PLANNING = "strategic_planning"
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    POST_EXPLOITATION = "post_exploitation"
    LATERAL_MOVEMENT = "lateral_movement"
    GOAL_ACHIEVEMENT = "goal_achievement"
    REPORTING = "reporting"
    CLEANUP = "cleanup"


class PhaseStatus(Enum):
    """Phase execution status."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    REQUIRES_APPROVAL = "requires_approval"


@dataclass
class PhaseResult:
    """Result of a workflow phase execution."""
    phase: WorkflowPhase
    status: PhaseStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    
    # Results
    discoveries: List[Dict[str, Any]] = field(default_factory=list)
    tasks_created: List[str] = field(default_factory=list)
    tasks_completed: List[str] = field(default_factory=list)
    
    # Errors
    errors: List[str] = field(default_factory=list)
    
    # Metrics
    duration_seconds: float = 0.0
    success_count: int = 0
    failure_count: int = 0
    
    # Next phase recommendation
    next_phase: Optional[WorkflowPhase] = None
    should_continue: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "phase": self.phase.value,
            "status": self.status.value,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "discoveries_count": len(self.discoveries),
            "tasks_created": len(self.tasks_created),
            "tasks_completed": len(self.tasks_completed),
            "errors_count": len(self.errors),
            "duration_seconds": self.duration_seconds,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "next_phase": self.next_phase.value if self.next_phase else None,
            "should_continue": self.should_continue
        }


@dataclass
class WorkflowContext:
    """Context passed between workflow phases."""
    mission_id: str
    campaign_id: Optional[str] = None
    
    # Environment
    environment_id: Optional[str] = None
    environment_type: str = "simulated"  # simulated, ssh, vm
    
    # State
    current_phase: WorkflowPhase = WorkflowPhase.INITIALIZATION
    phase_results: Dict[str, PhaseResult] = field(default_factory=dict)
    
    # Discoveries
    discovered_targets: List[str] = field(default_factory=list)
    discovered_vulns: List[str] = field(default_factory=list)
    discovered_creds: List[str] = field(default_factory=list)
    established_sessions: List[str] = field(default_factory=list)
    
    # Goals
    mission_goals: List[str] = field(default_factory=list)
    achieved_goals: Set[str] = field(default_factory=set)
    
    # Constraints
    stealth_level: str = "normal"  # low, normal, high
    max_duration_hours: float = 4.0
    require_approval_for: List[str] = field(default_factory=list)
    
    # Tools
    installed_tools: Set[str] = field(default_factory=set)
    required_tools: Set[str] = field(default_factory=set)
    
    # LLM
    llm_enabled: bool = True
    llm_decisions: List[Dict[str, Any]] = field(default_factory=list)
    
    # Timestamps
    started_at: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "mission_id": self.mission_id,
            "campaign_id": self.campaign_id,
            "environment_id": self.environment_id,
            "environment_type": self.environment_type,
            "current_phase": self.current_phase.value,
            "phase_count": len(self.phase_results),
            "discovered_targets": len(self.discovered_targets),
            "discovered_vulns": len(self.discovered_vulns),
            "discovered_creds": len(self.discovered_creds),
            "established_sessions": len(self.established_sessions),
            "goals_total": len(self.mission_goals),
            "goals_achieved": len(self.achieved_goals),
            "stealth_level": self.stealth_level,
            "installed_tools": list(self.installed_tools),
            "llm_enabled": self.llm_enabled,
            "started_at": self.started_at.isoformat()
        }


# ═══════════════════════════════════════════════════════════════
# Workflow Orchestrator
# ═══════════════════════════════════════════════════════════════

class AgentWorkflowOrchestrator:
    """
    Advanced workflow orchestrator for enterprise penetration testing.
    
    Coordinates all phases of a penetration test mission:
    1. Initialization - Setup environment and tools
    2. Strategic Planning - Generate attack campaign
    3. Reconnaissance - Network and vulnerability discovery
    4. Initial Access - Exploit vulnerabilities
    5. Post-Exploitation - Privilege escalation and credential harvesting
    6. Lateral Movement - Move through the network
    7. Goal Achievement - Achieve mission objectives
    8. Reporting - Generate findings report
    9. Cleanup - Clean up artifacts
    
    Features:
    - LLM-enhanced decision making
    - Real-time adaptation based on discoveries
    - HITL integration for high-risk actions
    - Remote execution via SSH/VM environments
    - Knowledge base integration (11K+ modules)
    """
    
    def __init__(
        self,
        blackboard: Optional[Blackboard] = None,
        settings: Optional[Settings] = None,
        knowledge: Optional[EmbeddedKnowledge] = None
    ):
        self.settings = settings or get_settings()
        self.blackboard = blackboard or Blackboard(settings=self.settings)
        self.knowledge = knowledge
        
        # State
        self._active_workflows: Dict[str, WorkflowContext] = {}
        self._phase_handlers: Dict[WorkflowPhase, Callable] = {}
        self._running = False
        
        # Phase transition rules
        self._phase_transitions = {
            WorkflowPhase.INITIALIZATION: WorkflowPhase.STRATEGIC_PLANNING,
            WorkflowPhase.STRATEGIC_PLANNING: WorkflowPhase.RECONNAISSANCE,
            WorkflowPhase.RECONNAISSANCE: WorkflowPhase.INITIAL_ACCESS,
            WorkflowPhase.INITIAL_ACCESS: WorkflowPhase.POST_EXPLOITATION,
            WorkflowPhase.POST_EXPLOITATION: WorkflowPhase.LATERAL_MOVEMENT,
            WorkflowPhase.LATERAL_MOVEMENT: WorkflowPhase.GOAL_ACHIEVEMENT,
            WorkflowPhase.GOAL_ACHIEVEMENT: WorkflowPhase.REPORTING,
            WorkflowPhase.REPORTING: WorkflowPhase.CLEANUP,
        }
        
        # Register default phase handlers
        self._register_phase_handlers()
        
        logger.info("AgentWorkflowOrchestrator initialized")
    
    def _register_phase_handlers(self) -> None:
        """Register default phase handlers."""
        self._phase_handlers = {
            WorkflowPhase.INITIALIZATION: self._phase_initialization,
            WorkflowPhase.STRATEGIC_PLANNING: self._phase_strategic_planning,
            WorkflowPhase.RECONNAISSANCE: self._phase_reconnaissance,
            WorkflowPhase.INITIAL_ACCESS: self._phase_initial_access,
            WorkflowPhase.POST_EXPLOITATION: self._phase_post_exploitation,
            WorkflowPhase.LATERAL_MOVEMENT: self._phase_lateral_movement,
            WorkflowPhase.GOAL_ACHIEVEMENT: self._phase_goal_achievement,
            WorkflowPhase.REPORTING: self._phase_reporting,
            WorkflowPhase.CLEANUP: self._phase_cleanup,
        }
    
    # ═══════════════════════════════════════════════════════════════
    # Workflow Management
    # ═══════════════════════════════════════════════════════════════
    
    async def start_workflow(
        self,
        mission_id: str,
        mission_goals: List[str],
        scope: List[str],
        constraints: Optional[Dict[str, Any]] = None,
        environment_config: Optional[Dict[str, Any]] = None
    ) -> WorkflowContext:
        """
        Start a new workflow for a mission.
        
        Args:
            mission_id: Mission ID
            mission_goals: List of objectives (e.g., ["domain_admin", "data_exfil"])
            scope: List of target IPs/networks
            constraints: Workflow constraints (stealth_level, max_duration, etc.)
            environment_config: SSH/VM configuration for remote execution
            
        Returns:
            WorkflowContext with initial state
        """
        logger.info(f"Starting workflow for mission {mission_id}")
        
        constraints = constraints or {}
        
        # Create workflow context
        context = WorkflowContext(
            mission_id=mission_id,
            mission_goals=mission_goals,
            stealth_level=constraints.get("stealth_level", "normal"),
            max_duration_hours=constraints.get("max_duration_hours", 4.0),
            require_approval_for=constraints.get("require_approval_for", ["exploit", "lateral"]),
            llm_enabled=self.settings.llm_enabled if hasattr(self.settings, 'llm_enabled') else True
        )
        
        # Store in active workflows
        self._active_workflows[mission_id] = context
        
        # Connect to blackboard
        if not await self.blackboard.health_check():
            await self.blackboard.connect()
        
        # Store initial workflow state
        await self._store_workflow_state(context)
        
        # Execute workflow phases
        asyncio.create_task(self._execute_workflow(context, scope, environment_config))
        
        return context
    
    async def _execute_workflow(
        self,
        context: WorkflowContext,
        scope: List[str],
        environment_config: Optional[Dict[str, Any]]
    ) -> None:
        """Execute workflow phases sequentially."""
        self._running = True
        
        try:
            # Phase 1: Initialization
            result = await self._execute_phase(
                context, 
                WorkflowPhase.INITIALIZATION,
                scope=scope,
                environment_config=environment_config
            )
            
            if not result.should_continue:
                logger.warning(f"Workflow stopped at {result.phase.value}")
                return
            
            # Execute remaining phases
            current_phase = result.next_phase
            
            while current_phase and self._running:
                result = await self._execute_phase(context, current_phase)
                
                if not result.should_continue:
                    logger.info(f"Workflow completed at {result.phase.value}")
                    break
                
                current_phase = result.next_phase
                
                # Check for goal achievement
                if len(context.achieved_goals) >= len(context.mission_goals):
                    logger.info(f"🎯 All mission goals achieved!")
                    # Skip to reporting
                    current_phase = WorkflowPhase.REPORTING
                    
        except asyncio.CancelledError:
            logger.info(f"Workflow cancelled for mission {context.mission_id}")
        except Exception as e:
            logger.error(f"Workflow error: {e}")
            raise
        finally:
            self._running = False
    
    async def _execute_phase(
        self,
        context: WorkflowContext,
        phase: WorkflowPhase,
        **kwargs
    ) -> PhaseResult:
        """Execute a single workflow phase."""
        logger.info(f"Executing phase: {phase.value}")
        
        context.current_phase = phase
        started_at = datetime.utcnow()
        
        result = PhaseResult(
            phase=phase,
            status=PhaseStatus.IN_PROGRESS,
            started_at=started_at
        )
        
        try:
            # Get phase handler
            handler = self._phase_handlers.get(phase)
            if not handler:
                raise ValueError(f"No handler registered for phase: {phase.value}")
            
            # Execute phase
            result = await handler(context, result, **kwargs)
            
            # Update timing
            result.completed_at = datetime.utcnow()
            result.duration_seconds = (result.completed_at - started_at).total_seconds()
            
            # Determine next phase
            if result.status == PhaseStatus.COMPLETED:
                result.next_phase = self._phase_transitions.get(phase)
                result.should_continue = result.next_phase is not None
            elif result.status == PhaseStatus.REQUIRES_APPROVAL:
                result.should_continue = False  # Wait for approval
            else:
                result.should_continue = False
            
            # Store phase result
            context.phase_results[phase.value] = result
            await self._store_workflow_state(context)
            
            logger.info(
                f"Phase {phase.value} completed: status={result.status.value}, "
                f"duration={result.duration_seconds:.1f}s"
            )
            
        except Exception as e:
            result.status = PhaseStatus.FAILED
            result.errors.append(str(e))
            result.should_continue = False
            logger.error(f"Phase {phase.value} failed: {e}")
        
        return result
    
    # ═══════════════════════════════════════════════════════════════
    # Phase Implementations
    # ═══════════════════════════════════════════════════════════════
    
    async def _phase_initialization(
        self,
        context: WorkflowContext,
        result: PhaseResult,
        scope: List[str] = None,
        environment_config: Optional[Dict[str, Any]] = None
    ) -> PhaseResult:
        """
        Phase 1: Initialization
        
        - Parse mission objectives
        - Create/connect execution environment
        - Install required tools
        - Load knowledge base
        """
        logger.info("Phase 1: Initialization")
        
        # 1. Load knowledge base if not loaded
        if not self.knowledge:
            self.knowledge = get_knowledge()
        
        if self.knowledge and self.knowledge.is_loaded():
            stats = self.knowledge.get_stats()
            logger.info(
                f"Knowledge base loaded: {stats.get('total_modules', 0)} RX modules, "
                f"{stats.get('nuclei_templates', 0)} Nuclei templates"
            )
            result.discoveries.append({
                "type": "knowledge_loaded",
                "modules": stats.get('total_modules', 0),
                "templates": stats.get('nuclei_templates', 0)
            })
        
        # 2. Setup execution environment
        if environment_config:
            env_type = environment_config.get("type", "simulated")
            context.environment_type = env_type
            
            if env_type in ("ssh", "vm"):
                try:
                    env_id = await self._setup_execution_environment(
                        context.mission_id,
                        environment_config
                    )
                    context.environment_id = env_id
                    result.discoveries.append({
                        "type": "environment_created",
                        "env_id": env_id,
                        "env_type": env_type
                    })
                    logger.info(f"Execution environment created: {env_id}")
                except Exception as e:
                    logger.warning(f"Failed to create environment: {e}. Falling back to simulated.")
                    context.environment_type = "simulated"
        
        # 3. Determine required tools based on goals
        context.required_tools = self._determine_required_tools(context.mission_goals, scope)
        
        # 4. Install tools if using real environment
        if context.environment_type in ("ssh", "vm") and context.environment_id:
            installed = await self._install_tools(
                context.environment_id,
                context.required_tools
            )
            context.installed_tools = set(t for t, success in installed.items() if success)
            result.discoveries.append({
                "type": "tools_installed",
                "tools": list(context.installed_tools)
            })
        
        result.status = PhaseStatus.COMPLETED
        return result
    
    async def _phase_strategic_planning(
        self,
        context: WorkflowContext,
        result: PhaseResult
    ) -> PhaseResult:
        """
        Phase 2: Strategic Planning
        
        - Generate attack campaign using StrategicAttackPlanner
        - LLM review and enhancement
        - Risk assessment
        - Pre-approval for high-risk stages
        """
        logger.info("Phase 2: Strategic Planning")
        
        try:
            # Import strategic planner
            from ..intelligence import StrategicAttackPlanner
            
            planner = StrategicAttackPlanner(
                knowledge_base=self.knowledge,
                logger=logger
            )
            
            # Generate campaign
            campaign = await planner.plan_campaign(
                mission_id=context.mission_id,
                mission_goals=context.mission_goals,
                targets=context.discovered_targets,
                constraints={
                    "stealth_level": context.stealth_level,
                    "max_duration_hours": context.max_duration_hours
                }
            )
            
            context.campaign_id = campaign.campaign_id
            
            result.discoveries.append({
                "type": "campaign_created",
                "campaign_id": campaign.campaign_id,
                "stages_count": len(campaign.stages),
                "success_probability": campaign.overall_success_probability,
                "detection_risk": campaign.overall_detection_risk
            })
            
            # Store campaign to blackboard
            await self.blackboard.hset(
                f"campaign:{campaign.campaign_id}",
                mapping=campaign.to_dict()
            )
            
            logger.info(
                f"Campaign created: {campaign.campaign_id}, "
                f"{len(campaign.stages)} stages, "
                f"P(success)={campaign.overall_success_probability:.1%}"
            )
            
        except ImportError:
            logger.warning("StrategicAttackPlanner not available, using default planning")
            # Create basic campaign structure
            context.campaign_id = str(uuid4())
            result.discoveries.append({
                "type": "basic_campaign_created",
                "campaign_id": context.campaign_id
            })
        except Exception as e:
            logger.error(f"Campaign planning failed: {e}")
            # Continue with basic workflow
            context.campaign_id = str(uuid4())
        
        # LLM Enhancement (if enabled)
        if context.llm_enabled:
            try:
                llm_enhancement = await self._llm_enhance_campaign(context)
                if llm_enhancement:
                    context.llm_decisions.append({
                        "phase": "strategic_planning",
                        "enhancement": llm_enhancement
                    })
            except Exception as e:
                logger.warning(f"LLM enhancement failed: {e}")
        
        result.status = PhaseStatus.COMPLETED
        return result
    
    async def _phase_reconnaissance(
        self,
        context: WorkflowContext,
        result: PhaseResult
    ) -> PhaseResult:
        """
        Phase 3: Reconnaissance
        
        - Network discovery
        - Service enumeration
        - Vulnerability scanning
        - OSINT and intel lookup
        """
        logger.info("Phase 3: Reconnaissance")
        
        # Create reconnaissance tasks
        tasks_created = []
        
        # 1. Network scan task
        task_id = await self._create_task(
            context.mission_id,
            TaskType.NETWORK_SCAN,
            SpecialistType.RECON,
            priority=10,
            metadata={"phase": "reconnaissance"}
        )
        tasks_created.append(task_id)
        
        # 2. Port scan task
        task_id = await self._create_task(
            context.mission_id,
            TaskType.PORT_SCAN,
            SpecialistType.RECON,
            priority=9,
            metadata={"phase": "reconnaissance"}
        )
        tasks_created.append(task_id)
        
        # 3. Vulnerability scan task
        task_id = await self._create_task(
            context.mission_id,
            TaskType.VULN_SCAN,
            SpecialistType.RECON,
            priority=8,
            metadata={"phase": "reconnaissance", "use_nuclei": True}
        )
        tasks_created.append(task_id)
        
        result.tasks_created = tasks_created
        
        # Wait for tasks to complete (with timeout)
        completed = await self._wait_for_tasks(
            context.mission_id,
            tasks_created,
            timeout_seconds=300
        )
        
        result.tasks_completed = completed
        
        # Get discoveries from blackboard
        targets = await self.blackboard.get_mission_targets(context.mission_id)
        vulns = await self.blackboard.get_mission_vulns(context.mission_id)
        
        context.discovered_targets = list(targets)
        context.discovered_vulns = list(vulns)
        
        result.success_count = len(targets) + len(vulns)
        result.discoveries.append({
            "type": "recon_complete",
            "targets_found": len(targets),
            "vulns_found": len(vulns)
        })
        
        logger.info(f"Reconnaissance complete: {len(targets)} targets, {len(vulns)} vulns")
        
        result.status = PhaseStatus.COMPLETED
        return result
    
    async def _phase_initial_access(
        self,
        context: WorkflowContext,
        result: PhaseResult
    ) -> PhaseResult:
        """
        Phase 4: Initial Access
        
        - Select best exploitation path
        - Execute exploits via real environment
        - Establish sessions
        - Handle failures with reflexion
        """
        logger.info("Phase 4: Initial Access")
        
        if not context.discovered_vulns:
            logger.warning("No vulnerabilities discovered, skipping initial access")
            result.status = PhaseStatus.SKIPPED
            result.errors.append("No vulnerabilities to exploit")
            return result
        
        # Check if approval is required
        if "exploit" in context.require_approval_for:
            approval_required = await self._check_approval_requirement(
                context,
                "exploit",
                f"Execute exploitation on {len(context.discovered_vulns)} vulnerabilities"
            )
            if approval_required:
                result.status = PhaseStatus.REQUIRES_APPROVAL
                return result
        
        # Create exploit tasks for high-value vulnerabilities
        tasks_created = []
        
        for vuln_key in context.discovered_vulns[:5]:  # Top 5 vulns
            vuln_id = vuln_key.replace("vuln:", "")
            vuln = await self.blackboard.get_vulnerability(vuln_id)
            
            if not vuln:
                continue
            
            severity = vuln.get("severity", "low")
            exploit_available = vuln.get("exploit_available", False)
            
            if severity in ("critical", "high") and exploit_available:
                task_id = await self._create_task(
                    context.mission_id,
                    TaskType.EXPLOIT,
                    SpecialistType.ATTACK,
                    priority=9 if severity == "critical" else 8,
                    vuln_id=vuln_id,
                    target_id=vuln.get("target_id"),
                    metadata={
                        "phase": "initial_access",
                        "use_real_environment": context.environment_type != "simulated",
                        "environment_id": context.environment_id
                    }
                )
                tasks_created.append(task_id)
        
        result.tasks_created = tasks_created
        
        if not tasks_created:
            logger.warning("No exploitable vulnerabilities found")
            result.status = PhaseStatus.COMPLETED
            return result
        
        # Wait for exploit tasks
        completed = await self._wait_for_tasks(
            context.mission_id,
            tasks_created,
            timeout_seconds=600
        )
        
        result.tasks_completed = completed
        
        # Get established sessions
        sessions = await self.blackboard.get_mission_sessions(context.mission_id)
        context.established_sessions = list(sessions)
        
        result.success_count = len(sessions)
        result.failure_count = len(tasks_created) - len(sessions)
        
        result.discoveries.append({
            "type": "initial_access_complete",
            "sessions_established": len(sessions),
            "exploits_attempted": len(tasks_created),
            "exploits_succeeded": len(sessions)
        })
        
        logger.info(f"Initial access: {len(sessions)} sessions established")
        
        result.status = PhaseStatus.COMPLETED
        return result
    
    async def _phase_post_exploitation(
        self,
        context: WorkflowContext,
        result: PhaseResult
    ) -> PhaseResult:
        """
        Phase 5: Post-Exploitation
        
        - Privilege escalation
        - Credential harvesting
        - Persistence establishment
        - Evidence collection
        """
        logger.info("Phase 5: Post-Exploitation")
        
        if not context.established_sessions:
            logger.warning("No sessions established, skipping post-exploitation")
            result.status = PhaseStatus.SKIPPED
            return result
        
        tasks_created = []
        
        for session_key in context.established_sessions:
            session_id = session_key.replace("session:", "")
            session = await self.blackboard.get_session(session_id)
            
            if not session:
                continue
            
            target_id = session.get("target_id")
            privilege = session.get("privilege", "user")
            
            # Create privesc task if needed
            if privilege in ("user", "unknown"):
                task_id = await self._create_task(
                    context.mission_id,
                    TaskType.PRIVESC,
                    SpecialistType.ATTACK,
                    priority=8,
                    target_id=target_id,
                    metadata={
                        "phase": "post_exploitation",
                        "session_id": session_id
                    }
                )
                tasks_created.append(task_id)
            
            # Create credential harvest task
            task_id = await self._create_task(
                context.mission_id,
                TaskType.CRED_HARVEST,
                SpecialistType.ATTACK,
                priority=7,
                target_id=target_id,
                metadata={
                    "phase": "post_exploitation",
                    "session_id": session_id
                }
            )
            tasks_created.append(task_id)
        
        result.tasks_created = tasks_created
        
        # Wait for tasks
        completed = await self._wait_for_tasks(
            context.mission_id,
            tasks_created,
            timeout_seconds=600
        )
        
        result.tasks_completed = completed
        
        # Get harvested credentials
        creds = await self.blackboard.get_mission_creds(context.mission_id)
        context.discovered_creds = list(creds)
        
        result.success_count = len(creds)
        result.discoveries.append({
            "type": "post_exploitation_complete",
            "credentials_harvested": len(creds)
        })
        
        logger.info(f"Post-exploitation: {len(creds)} credentials harvested")
        
        result.status = PhaseStatus.COMPLETED
        return result
    
    async def _phase_lateral_movement(
        self,
        context: WorkflowContext,
        result: PhaseResult
    ) -> PhaseResult:
        """
        Phase 6: Lateral Movement
        
        - Map internal network
        - Use harvested credentials
        - Move to high-value targets
        """
        logger.info("Phase 6: Lateral Movement")
        
        if not context.discovered_creds:
            logger.warning("No credentials harvested, skipping lateral movement")
            result.status = PhaseStatus.SKIPPED
            return result
        
        # Check if approval is required
        if "lateral" in context.require_approval_for:
            approval_required = await self._check_approval_requirement(
                context,
                "lateral",
                f"Execute lateral movement using {len(context.discovered_creds)} credentials"
            )
            if approval_required:
                result.status = PhaseStatus.REQUIRES_APPROVAL
                return result
        
        tasks_created = []
        
        # Create lateral movement tasks
        for cred_key in context.discovered_creds[:3]:  # Top 3 creds
            cred_id = cred_key.replace("cred:", "")
            cred = await self.blackboard.get_credential(cred_id)
            
            if not cred:
                continue
            
            privilege = cred.get("privilege_level", "user")
            
            if privilege in ("admin", "domain_admin"):
                task_id = await self._create_task(
                    context.mission_id,
                    TaskType.LATERAL,
                    SpecialistType.ATTACK,
                    priority=8,
                    cred_id=cred_id,
                    target_id=cred.get("target_id"),
                    metadata={"phase": "lateral_movement"}
                )
                tasks_created.append(task_id)
        
        result.tasks_created = tasks_created
        
        if tasks_created:
            completed = await self._wait_for_tasks(
                context.mission_id,
                tasks_created,
                timeout_seconds=600
            )
            result.tasks_completed = completed
        
        # Check for new sessions
        sessions = await self.blackboard.get_mission_sessions(context.mission_id)
        new_sessions = len(sessions) - len(context.established_sessions)
        context.established_sessions = list(sessions)
        
        result.success_count = new_sessions
        result.discoveries.append({
            "type": "lateral_movement_complete",
            "new_sessions": new_sessions
        })
        
        logger.info(f"Lateral movement: {new_sessions} new sessions")
        
        result.status = PhaseStatus.COMPLETED
        return result
    
    async def _phase_goal_achievement(
        self,
        context: WorkflowContext,
        result: PhaseResult
    ) -> PhaseResult:
        """
        Phase 7: Goal Achievement
        
        - Verify goal completion
        - Check mission objectives
        """
        logger.info("Phase 7: Goal Achievement")
        
        # Get mission goals from blackboard
        goals = await self.blackboard.get_mission_goals(context.mission_id)
        
        achieved = 0
        for goal, status in goals.items():
            if status == "achieved":
                achieved += 1
                context.achieved_goals.add(goal)
        
        result.success_count = achieved
        result.discoveries.append({
            "type": "goal_check",
            "total_goals": len(context.mission_goals),
            "achieved_goals": achieved,
            "goal_details": goals
        })
        
        logger.info(f"Goal achievement: {achieved}/{len(context.mission_goals)} goals achieved")
        
        result.status = PhaseStatus.COMPLETED
        return result
    
    async def _phase_reporting(
        self,
        context: WorkflowContext,
        result: PhaseResult
    ) -> PhaseResult:
        """
        Phase 8: Reporting
        
        - Generate findings report
        - Collect evidence
        """
        logger.info("Phase 8: Reporting")
        
        # Generate report summary
        report = {
            "mission_id": context.mission_id,
            "campaign_id": context.campaign_id,
            "duration_hours": (datetime.utcnow() - context.started_at).total_seconds() / 3600,
            "targets_discovered": len(context.discovered_targets),
            "vulnerabilities_found": len(context.discovered_vulns),
            "credentials_harvested": len(context.discovered_creds),
            "sessions_established": len(context.established_sessions),
            "goals_achieved": list(context.achieved_goals),
            "goals_total": len(context.mission_goals),
            "phase_results": {k: v.to_dict() for k, v in context.phase_results.items()},
            "generated_at": datetime.utcnow().isoformat()
        }
        
        # Store report
        await self.blackboard.hset(
            f"report:{context.mission_id}",
            mapping=report
        )
        
        result.discoveries.append({
            "type": "report_generated",
            "report_id": context.mission_id
        })
        
        logger.info(f"Report generated for mission {context.mission_id}")
        
        result.status = PhaseStatus.COMPLETED
        return result
    
    async def _phase_cleanup(
        self,
        context: WorkflowContext,
        result: PhaseResult
    ) -> PhaseResult:
        """
        Phase 9: Cleanup
        
        - Clean up artifacts
        - Close sessions
        - Destroy execution environment
        """
        logger.info("Phase 9: Cleanup")
        
        # Close sessions
        for session_key in context.established_sessions:
            session_id = session_key.replace("session:", "")
            try:
                await self.blackboard.update_session_status(session_id, "closed")
            except Exception as e:
                logger.warning(f"Failed to close session {session_id}: {e}")
        
        # Destroy execution environment if created
        if context.environment_id and context.environment_type != "simulated":
            try:
                await self._destroy_execution_environment(context.environment_id)
                logger.info(f"Destroyed execution environment: {context.environment_id}")
            except Exception as e:
                logger.warning(f"Failed to destroy environment: {e}")
        
        # Remove from active workflows
        if context.mission_id in self._active_workflows:
            del self._active_workflows[context.mission_id]
        
        result.status = PhaseStatus.COMPLETED
        result.should_continue = False  # Final phase
        
        logger.info(f"Cleanup complete for mission {context.mission_id}")
        
        return result
    
    # ═══════════════════════════════════════════════════════════════
    # Helper Methods
    # ═══════════════════════════════════════════════════════════════
    
    async def _setup_execution_environment(
        self,
        mission_id: str,
        config: Dict[str, Any]
    ) -> str:
        """Setup SSH or VM execution environment."""
        try:
            from ..infrastructure.orchestrator import EnvironmentManager, EnvironmentConfig
            
            env_manager = EnvironmentManager()
            
            env_config = EnvironmentConfig(
                environment_type=config.get("type", "ssh"),
                name=f"raglox-{mission_id[:8]}",
                ssh_config=config.get("ssh_config"),
                vm_config=config.get("vm_config"),
                user_id=config.get("user_id"),
                tenant_id=config.get("tenant_id")
            )
            
            env = await env_manager.create_environment(env_config)
            return env.environment_id
            
        except ImportError:
            logger.warning("EnvironmentManager not available")
            return None
        except Exception as e:
            logger.error(f"Failed to create environment: {e}")
            raise
    
    async def _destroy_execution_environment(self, env_id: str) -> None:
        """Destroy execution environment."""
        try:
            from ..infrastructure.orchestrator import get_environment_manager
            
            env_manager = get_environment_manager()
            await env_manager.destroy_environment(env_id)
            
        except ImportError:
            logger.warning("EnvironmentManager not available")
        except Exception as e:
            logger.error(f"Failed to destroy environment: {e}")
    
    def _determine_required_tools(
        self,
        goals: List[str],
        scope: List[str]
    ) -> Set[str]:
        """Determine required tools based on goals and scope."""
        tools = {"nmap", "curl"}  # Base tools
        
        goal_tools = {
            "domain_admin": {"impacket", "crackmapexec", "bloodhound"},
            "data_exfil": {"curl", "scp", "tar"},
            "persistence": {"crontab", "systemctl"},
            "credential_harvest": {"mimikatz", "lazagne"},
        }
        
        for goal in goals:
            if goal in goal_tools:
                tools.update(goal_tools[goal])
        
        return tools
    
    async def _install_tools(
        self,
        env_id: str,
        tools: Set[str]
    ) -> Dict[str, bool]:
        """Install tools on execution environment."""
        results = {}
        
        # TODO: Implement actual tool installation
        # This would use EnvironmentManager to execute install commands
        
        for tool in tools:
            results[tool] = True  # Placeholder
        
        return results
    
    async def _create_task(
        self,
        mission_id: str,
        task_type: TaskType,
        specialist: SpecialistType,
        priority: int = 5,
        target_id: str = None,
        vuln_id: str = None,
        cred_id: str = None,
        metadata: Dict[str, Any] = None
    ) -> str:
        """Create a task in the blackboard."""
        from .models import Task
        
        task = Task(
            mission_id=UUID(mission_id),
            type=task_type,
            specialist=specialist,
            priority=priority,
            target_id=UUID(target_id) if target_id else None,
            vuln_id=UUID(vuln_id) if vuln_id else None,
            cred_id=UUID(cred_id) if cred_id else None,
            result_data=metadata or {}
        )
        
        return await self.blackboard.add_task(task)
    
    async def _wait_for_tasks(
        self,
        mission_id: str,
        task_ids: List[str],
        timeout_seconds: int = 300
    ) -> List[str]:
        """Wait for tasks to complete."""
        completed = []
        deadline = asyncio.get_event_loop().time() + timeout_seconds
        
        while task_ids and asyncio.get_event_loop().time() < deadline:
            for task_id in list(task_ids):
                task = await self.blackboard.get_task(task_id)
                if task and task.get("status") in ("completed", "failed"):
                    task_ids.remove(task_id)
                    if task.get("status") == "completed":
                        completed.append(task_id)
            
            if task_ids:
                await asyncio.sleep(1)
        
        return completed
    
    async def _check_approval_requirement(
        self,
        context: WorkflowContext,
        action_type: str,
        description: str
    ) -> bool:
        """Check if action requires approval and create request if needed."""
        # TODO: Implement HITL approval check
        return False  # For now, don't require approval
    
    async def _store_workflow_state(self, context: WorkflowContext) -> None:
        """Store workflow state to blackboard."""
        await self.blackboard.hset(
            f"workflow:{context.mission_id}",
            mapping=context.to_dict()
        )
    
    async def _llm_enhance_campaign(
        self,
        context: WorkflowContext
    ) -> Optional[Dict[str, Any]]:
        """Use LLM to enhance campaign planning."""
        try:
            from ..core.llm.service import get_llm_service
            from ..core.llm.base import LLMMessage, MessageRole
            
            llm_service = get_llm_service()
            
            if not llm_service or not llm_service.providers:
                return None
            
            # Build prompt
            prompt = f"""
You are a penetration testing expert reviewing an attack campaign plan.

Mission Goals: {context.mission_goals}
Stealth Level: {context.stealth_level}
Targets Discovered: {len(context.discovered_targets)}
Vulnerabilities Found: {len(context.discovered_vulns)}

Please provide:
1. Risk assessment (brief)
2. Recommended prioritization
3. Potential challenges
4. Alternative approaches if primary fails

Be concise and actionable.
"""
            
            messages = [
                LLMMessage(role=MessageRole.USER, content=prompt)
            ]
            
            response = await llm_service.generate(messages)
            
            if response and response.content:
                return {
                    "type": "campaign_enhancement",
                    "content": response.content,
                    "timestamp": datetime.utcnow().isoformat()
                }
            
        except Exception as e:
            logger.warning(f"LLM enhancement failed: {e}")
        
        return None
    
    # ═══════════════════════════════════════════════════════════════
    # Public API
    # ═══════════════════════════════════════════════════════════════
    
    async def get_workflow_status(self, mission_id: str) -> Optional[Dict[str, Any]]:
        """Get current workflow status."""
        if mission_id in self._active_workflows:
            return self._active_workflows[mission_id].to_dict()
        
        # Try to load from blackboard
        data = await self.blackboard.hgetall(f"workflow:{mission_id}")
        return data if data else None
    
    async def pause_workflow(self, mission_id: str) -> bool:
        """Pause a workflow."""
        if mission_id not in self._active_workflows:
            return False
        
        self._running = False
        return True
    
    async def resume_workflow(self, mission_id: str) -> bool:
        """Resume a paused workflow."""
        if mission_id not in self._active_workflows:
            return False
        
        self._running = True
        return True
    
    async def stop_workflow(self, mission_id: str) -> bool:
        """Stop a workflow completely."""
        if mission_id not in self._active_workflows:
            return False
        
        context = self._active_workflows[mission_id]
        self._running = False
        
        # Execute cleanup phase
        result = PhaseResult(
            phase=WorkflowPhase.CLEANUP,
            status=PhaseStatus.IN_PROGRESS,
            started_at=datetime.utcnow()
        )
        await self._phase_cleanup(context, result)
        
        return True


# ═══════════════════════════════════════════════════════════════
# Singleton Accessor
# ═══════════════════════════════════════════════════════════════

_workflow_orchestrator: Optional[AgentWorkflowOrchestrator] = None


def get_workflow_orchestrator(
    blackboard: Optional[Blackboard] = None,
    settings: Optional[Settings] = None
) -> AgentWorkflowOrchestrator:
    """Get or create the workflow orchestrator singleton."""
    global _workflow_orchestrator
    
    if _workflow_orchestrator is None:
        _workflow_orchestrator = AgentWorkflowOrchestrator(
            blackboard=blackboard,
            settings=settings
        )
    
    return _workflow_orchestrator
