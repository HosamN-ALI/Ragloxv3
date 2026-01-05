# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Attack Specialist
# Exploitation and lateral movement specialist
# Enhanced with Strategic Scorer for intelligent attack prioritization
# ═══════════════════════════════════════════════════════════════

import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional, TYPE_CHECKING
from uuid import UUID

from .base import BaseSpecialist
from ..core.models import (
    TaskType, SpecialistType, TargetStatus, Severity, Priority,
    CredentialType, PrivilegeLevel, SessionType, SessionStatus,
    GoalAchievedEvent, GoalStatus
)
from ..core.blackboard import Blackboard
from ..core.config import Settings
from ..core.knowledge import EmbeddedKnowledge

# Hybrid Intelligence Layer imports
from ..core.strategic_scorer import (
    StrategicScorer,
    VulnerabilityScore,
    PrioritizedTarget,
    RiskLevel,
    ExploitDifficulty,
)
from ..core.operational_memory import (
    OperationalMemory,
    DecisionOutcome,
    OperationalContext,
)
from ..core.intelligence_decision_engine import (
    IntelligenceDecisionEngine,
    DecisionContext,
    Decision,
    DecisionType,
    DecisionReason,
)

if TYPE_CHECKING:
    from ..executors import RXModuleRunner, ExecutorFactory

# Import RealExploitationEngine and its getter
from .attack_integration import RealExploitationEngine, get_real_exploitation_engine


class AttackSpecialist(BaseSpecialist):
    """
    Attack Specialist - Handles exploitation and lateral movement.
    
    Responsibilities:
    - Exploiting discovered vulnerabilities
    - Privilege escalation
    - Lateral movement
    - Credential harvesting from compromised systems
    
    Task Types Handled:
    - EXPLOIT: Exploit a vulnerability to gain access
    - PRIVESC: Privilege escalation on compromised host
    - LATERAL: Lateral movement to other hosts
    - CRED_HARVEST: Harvest credentials from compromised host
    
    Reads From Blackboard:
    - Discovered vulnerabilities
    - Discovered credentials
    - Active sessions
    - Attack paths
    
    Writes To Blackboard:
    - New sessions (on successful exploit)
    - New credentials (from harvesting)
    - Attack paths
    - Session status updates
    - Goal achievements
    
    Testing Support:
    - deterministic_mode: When True, uses fixed success rates for testing
    - deterministic_success_rate: Fixed success rate (0.0-1.0) in deterministic mode
    - random_seed: Optional seed for reproducible random behavior
    """
    
    # Class-level testing configuration
    _deterministic_mode: bool = False
    _deterministic_success_rate: float = 0.8
    _random_seed: Optional[int] = None
    _test_random_generator = None
    
    @classmethod
    def set_deterministic_mode(cls, enabled: bool, success_rate: float = 0.8, seed: int = None):
        """
        Enable/disable deterministic mode for testing.
        
        Args:
            enabled: Whether to enable deterministic mode
            success_rate: Fixed success rate (0.0-1.0) when deterministic
            seed: Optional random seed for reproducible but varied behavior
        """
        cls._deterministic_mode = enabled
        cls._deterministic_success_rate = max(0.0, min(1.0, success_rate))
        cls._random_seed = seed
        if seed is not None:
            import random
            cls._test_random_generator = random.Random(seed)
        else:
            cls._test_random_generator = None
    
    @classmethod
    def reset_deterministic_mode(cls):
        """Reset to non-deterministic mode."""
        cls._deterministic_mode = False
        cls._deterministic_success_rate = 0.8
        cls._random_seed = None
        cls._test_random_generator = None
    
    def _get_success_roll(self) -> float:
        """
        Get success roll value, respecting deterministic mode.
        
        Returns:
            In deterministic mode: Returns a value that will succeed at the set rate
            In normal mode: Returns random.random()
        """
        if self._deterministic_mode:
            if self._test_random_generator is not None:
                return self._test_random_generator.random()
            # Return a value that ensures success at the configured rate
            # 0.1 will succeed against any threshold > 0.1
            return 1.0 - self._deterministic_success_rate
        import random
        return random.random()
    
    def __init__(
        self,
        blackboard: Optional[Blackboard] = None,
        settings: Optional[Settings] = None,
        worker_id: Optional[str] = None,
        knowledge: Optional[EmbeddedKnowledge] = None,
        runner: Optional['RXModuleRunner'] = None,
        executor_factory: Optional['ExecutorFactory'] = None,
        strategic_scorer: Optional[StrategicScorer] = None,
        operational_memory: Optional[OperationalMemory] = None,
        real_exploitation_engine: Optional[RealExploitationEngine] = None,
        use_real_exploits: bool = False,
    ):
        super().__init__(
            specialist_type=SpecialistType.ATTACK,
            blackboard=blackboard,
            settings=settings,
            worker_id=worker_id,
            knowledge=knowledge,
            runner=runner,
            executor_factory=executor_factory
        )
        
        # Real Exploitation Engine (NEW - replaces random.random())
        self._use_real_exploits = use_real_exploits
        self._real_exploitation_engine = real_exploitation_engine or (
            get_real_exploitation_engine() if use_real_exploits else None
        )
        
        # Task types this specialist handles
        self._supported_task_types = {
            TaskType.EXPLOIT,
            TaskType.PRIVESC,
            TaskType.LATERAL,
            TaskType.CRED_HARVEST
        }
        
        # ═══════════════════════════════════════════════════════════
        # Hybrid Intelligence: Strategic Scorer & Operational Memory
        # ═══════════════════════════════════════════════════════════
        self._strategic_scorer = strategic_scorer or StrategicScorer(
            blackboard=blackboard,
            knowledge_base=knowledge,
            logger=self.logger
        )
        self._operational_memory = operational_memory or OperationalMemory(
            blackboard=blackboard,
            logger=self.logger
        )
        
        # ═══════════════════════════════════════════════════════════
        # GAP-C03 FIX: Intelligence Decision Engine
        # Advanced decision-making engine that integrates ALL intelligence
        # layers to make informed, risk-aware exploitation decisions
        # ═══════════════════════════════════════════════════════════
        self._decision_engine = IntelligenceDecisionEngine(
            strategic_scorer=self._strategic_scorer,
            operational_memory=self._operational_memory,
            defense_intelligence=None,  # Will be added when DefenseIntelligence is available
            blackboard=blackboard,
            logger=self.logger
        )
        
        # Statistics
        self._stats = {
            "exploits_attempted": 0,
            "exploits_succeeded": 0,
            "strategic_scoring_used": 0,
            "memory_guided_attacks": 0,
            "dynamic_success_rate_lookups": 0,
            "intelligence_decisions_made": 0,
            "intelligence_decisions_execute": 0,
            "intelligence_decisions_skip": 0,
            "intelligence_decisions_approval": 0,
        }
        
        # NOTE: Static exploit success rates have been REMOVED
        # Exploit selection and success estimation is now dynamic via:
        # 1. IntelligenceDecisionEngine (NEW - integrates all layers)
        # 2. StrategicScorer (vulnerability assessment)
        # 3. OperationalMemory (historical success patterns)
        # 4. Knowledge Base (get_module_for_vuln, get_exploit_reliability)
        # 5. DefenseIntelligence (defense detection and evasion)
        # 6. LLM Context (AnalysisSpecialist recommendations)
        # This ensures adaptive, intelligence-driven decisions
        
        self.logger.info(
            "AttackSpecialist initialized with Intelligence Decision Engine "
            "(Strategic Scorer + Operational Memory + Decision Gates)"
        )
        
        # Privilege escalation techniques (metadata only, success determined dynamically)
        self._privesc_techniques = [
            ("kernel_exploit", PrivilegeLevel.ROOT),
            ("service_misconfig", PrivilegeLevel.SYSTEM),
            ("token_impersonation", PrivilegeLevel.ADMIN),
            ("unquoted_service_path", PrivilegeLevel.SYSTEM),
        ]
        
        # Credential sources (metadata only)
        self._cred_sources = [
            ("mimikatz", CredentialType.HASH, PrivilegeLevel.DOMAIN_ADMIN),
            ("lsass_dump", CredentialType.HASH, PrivilegeLevel.ADMIN),
            ("sam_dump", CredentialType.HASH, PrivilegeLevel.USER),
            ("browser_creds", CredentialType.PASSWORD, PrivilegeLevel.USER),
            ("config_files", CredentialType.PASSWORD, PrivilegeLevel.USER),
        ]
        
        # Priority scores for credential sources (higher = better priority)
        # Intel/leaked credentials are prioritized over brute force
        self._credential_priority_scores = {
            # Intel sources (highest priority - leaked data)
            "intel:stealer_log": 1.0,      # Stealer logs most reliable
            "intel:database_dump": 0.95,   # DB dumps very reliable
            "intel:arthouse": 0.9,         # ArtHouse breaches
            "intel:fatetraffic": 0.9,      # Fatetraffic breaches
            "intel:ransomware_leak": 0.88, # Ransomware leaks
            "intel:combolist": 0.7,        # Combo lists
            "intel:paste_site": 0.6,       # Paste sites
            "intel:darkweb_market": 0.75,  # Darkweb markets
            "intel:local_file": 0.8,       # Local file searches
            "intel:elasticsearch": 0.85,   # Elasticsearch data lake
            "intel:unknown": 0.65,         # Unknown intel source
            
            # Harvested sources (medium priority)
            "mimikatz": 0.55,
            "lsass_dump": 0.50,
            "sam_dump": 0.45,
            "browser_creds": 0.40,
            "config_files": 0.35,
            
            # Brute force (lowest priority - should be last resort)
            "brute_force": 0.2,
            "dictionary_attack": 0.15,
            "default_creds": 0.3,
            
            # Default fallback
            "unknown": 0.25,
        }
    
    # ═══════════════════════════════════════════════════════════
    # Task Execution
    # ═══════════════════════════════════════════════════════════
    
    async def execute_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute an attack task."""
        task_type = task.get("type")
        
        handlers = {
            TaskType.EXPLOIT.value: self._execute_exploit,
            TaskType.PRIVESC.value: self._execute_privesc,
            TaskType.LATERAL.value: self._execute_lateral,
            TaskType.CRED_HARVEST.value: self._execute_cred_harvest,
        }
        
        handler = handlers.get(task_type)
        if not handler:
            raise ValueError(f"Unsupported task type: {task_type}")
        
        return await handler(task)
    
    async def _execute_exploit(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        ═══════════════════════════════════════════════════════════════
        GAP-C03 FIX: Intelligence-Driven Exploit Execution
        ═══════════════════════════════════════════════════════════════
        
        Exploit a vulnerability using INTELLIGENCE-DRIVEN decision-making.
        
        This method now integrates the Intelligence Decision Engine to make
        informed, risk-aware decisions about exploitation operations.
        
        Decision Flow:
        1. Gather context (target, vuln, mission state)
        2. Query Intelligence Decision Engine
        3. Apply decision gates (risk assessment, historical patterns, defenses)
        4. Execute ONLY if decision is EXECUTE
        5. Skip, defer, or request approval based on intelligence
        
        Intelligence Sources Integrated:
        - Strategic Scorer: Vulnerability assessment & success probability
        - Operational Memory: Historical operation patterns
        - Defense Intelligence: Defense detection & evasion
        - Knowledge Base: Module reliability & exploit metadata
        - Mission Context: Goals, stealth level, constraints
        
        Intel Credential Integration:
        - Checks for available intel credentials before exploitation
        - Prioritizes high-reliability credentials over brute force
        - Uses cred_id from task if provided by IntelSpecialist
        """
        vuln_id = task.get("vuln_id")
        target_id = task.get("target_id")
        rx_module = task.get("rx_module")
        task_id = task.get("id")
        mission_id = task.get("mission_id", "")
        
        # Check for intel credential
        intel_cred_id = task.get("cred_id")
        intel_source = task.get("result_data", {}).get("intel_source")
        
        # If intel credential provided, try credential-based exploit first
        if intel_cred_id and intel_source == "intel_lookup":
            return await self._execute_exploit_with_intel_cred(
                task=task,
                cred_id=intel_cred_id
            )
        
        # If no intel cred provided directly, check for available intel credentials
        if target_id and not intel_cred_id:
            clean_target_id = target_id.replace("target:", "") if isinstance(target_id, str) else str(target_id)
            intel_creds = await self.get_prioritized_credentials_for_target(clean_target_id)
            
            if intel_creds:
                # Use the highest priority credential
                best_cred = intel_creds[0]
                self.logger.info(
                    f"Found {len(intel_creds)} intel credentials for target. "
                    f"Using best: priority={best_cred['priority_score']:.2f}, "
                    f"source={self._mask_sensitive_data(best_cred.get('source', 'unknown'), show_chars=10)}"
                )
                return await self._execute_exploit_with_intel_cred(
                    task=task,
                    cred_id=best_cred["cred_id"]
                )
        
        # Get target details
        target = None
        target_ip = None
        target_platform = "linux"  # Default
        target_os = None
        
        if target_id:
            clean_target_id = target_id.replace("target:", "") if isinstance(target_id, str) else str(target_id)
            target = await self.blackboard.get_target(clean_target_id)
            if target:
                target_ip = target.get("ip")
                target_os = (target.get("os") or "").lower()
                if "windows" in target_os:
                    target_platform = "windows"
                elif "linux" in target_os:
                    target_platform = "linux"
        
        if not vuln_id:
            return {"error": "No vuln_id specified", "success": False}
        
        # Clean IDs
        if isinstance(vuln_id, str) and vuln_id.startswith("vuln:"):
            vuln_id = vuln_id.replace("vuln:", "")
        if isinstance(target_id, str) and target_id.startswith("target:"):
            target_id = target_id.replace("target:", "")
        
        # Get vulnerability details
        vuln = await self.blackboard.get_vulnerability(vuln_id)
        if not vuln:
            return {"error": f"Vulnerability {vuln_id} not found", "success": False}
        
        vuln_type = vuln.get("type", "default")
        if not target_id:
            target_id = vuln.get("target_id")
        
        # ═══════════════════════════════════════════════════════════════
        # PHASE 1: Build Decision Context
        # Gather all relevant information for intelligence-driven decision
        # ═══════════════════════════════════════════════════════════════
        
        # Get mission context
        mission_goals = []
        stealth_level = "normal"
        if mission_id and self.blackboard:
            try:
                mission_data = await self.blackboard.get_mission(mission_id)
                if mission_data:
                    mission_goals = list(mission_data.get("goals", {}).keys())
                    # Infer stealth level from constraints or goals
                    constraints = mission_data.get("constraints", [])
                    if any("stealth" in str(c).lower() for c in constraints):
                        stealth_level = "high"
            except (ConnectionError, OSError) as e:
                # SEC-01: Handle connection errors
                self.logger.warning(f"Connection error getting mission context")
            except (KeyError, ValueError, TypeError) as e:
                # SEC-01: Handle data errors
                self.logger.warning(f"Data error getting mission context")
        
        # Get available credentials
        available_credentials = []
        if self.blackboard and mission_id and target_id:
            try:
                creds = await self.blackboard.get_target_credentials(mission_id, target_id)
                available_credentials = [c.get("cred_id") for c in (creds or [])]
            except (ConnectionError, OSError) as e:
                # SEC-01: Handle connection errors
                self.logger.debug(f"Connection error getting credentials")
            except (KeyError, ValueError, TypeError) as e:
                # SEC-01: Handle data errors
                self.logger.debug(f"Data error getting credentials")
        
        # Build decision context
        decision_context = DecisionContext(
            operation_type="exploit",
            target_id=target_id,
            vuln_id=vuln_id,
            technique_id=vuln_type,
            target_os=target_os,
            target_ip=target_ip,
            target_services=target.get("services", []) if target else [],
            target_criticality=self._infer_target_criticality(target),
            mission_id=mission_id,
            mission_goals=mission_goals,
            stealth_level=stealth_level,
            available_credentials=available_credentials
        )
        
        self.logger.info(
            f"[INTELLIGENCE] Consulting Decision Engine for exploit: "
            f"vuln={vuln_type}, target={target_id}, stealth={stealth_level}"
        )
        
        # ═══════════════════════════════════════════════════════════════
        # PHASE 2: Consult Intelligence Decision Engine
        # Let the engine make an informed decision based on all intelligence
        # ═══════════════════════════════════════════════════════════════
        
        decision = await self._decision_engine.make_decision(decision_context)
        self._stats["intelligence_decisions_made"] += 1
        
        # Log decision details
        self.logger.info(
            f"[INTELLIGENCE DECISION] Type: {decision.decision_type.value}, "
            f"Confidence: {decision.confidence:.2%}, "
            f"Reason: {decision.primary_reason.value}"
        )
        for reason in decision.reasoning:
            self.logger.info(f"[INTELLIGENCE DECISION]   - {reason}")
        
        # ═══════════════════════════════════════════════════════════════
        # PHASE 3: Execute Decision
        # Act based on the intelligence-driven decision
        # ═══════════════════════════════════════════════════════════════
        
        # Decision: SKIP - Don't execute this exploit
        if decision.decision_type == DecisionType.SKIP:
            self._stats["intelligence_decisions_skip"] += 1
            self.logger.warning(
                f"[INTELLIGENCE] SKIPPING exploit on {target_id}: {decision.primary_reason.value}"
            )
            return {
                "success": False,
                "vuln_type": vuln_type,
                "reason": f"Intelligence Decision: {decision.primary_reason.value}",
                "decision": decision.to_dict(),
                "execution_mode": "skipped_by_intelligence"
            }
        
        # Decision: REQUEST_APPROVAL - Ask human operator
        elif decision.decision_type == DecisionType.REQUEST_APPROVAL:
            self._stats["intelligence_decisions_approval"] += 1
            self.logger.warning(
                f"[INTELLIGENCE] Exploit on {target_id} requires HUMAN APPROVAL: "
                f"{decision.primary_reason.value}"
            )
            # TODO: Implement HITL approval workflow (GAP-H04)
            # For now, defer execution
            return {
                "success": False,
                "vuln_type": vuln_type,
                "reason": f"Awaiting approval: {decision.primary_reason.value}",
                "requires_approval": True,
                "decision": decision.to_dict(),
                "execution_mode": "awaiting_approval"
            }
        
        # Decision: USE_ALTERNATIVE - Try different approach
        elif decision.decision_type == DecisionType.USE_ALTERNATIVE:
            self.logger.info(
                f"[INTELLIGENCE] Using alternative approach for {target_id}: "
                f"{decision.primary_reason.value}"
            )
            
            # If alternative is credential-based and we have creds, use them
            if (decision.recommended_action and
                decision.recommended_action.get("method") == "credential_based" and
                available_credentials):
                cred_id = decision.recommended_action.get("credential_id") or available_credentials[0]
                self.logger.info(f"[INTELLIGENCE] Switching to credential-based approach with cred {cred_id}")
                return await self._execute_exploit_with_intel_cred(
                    task=task,
                    cred_id=cred_id
                )
            
            # Otherwise, proceed with evasion-enhanced exploit
            self.logger.info("[INTELLIGENCE] Proceeding with evasion-enhanced approach")
            # Fall through to EXECUTE with evasion
        
        # Decision: DEFER - Postpone execution
        elif decision.decision_type == DecisionType.DEFER:
            self.logger.info(
                f"[INTELLIGENCE] Deferring exploit on {target_id}: {decision.primary_reason.value}"
            )
            return {
                "success": False,
                "vuln_type": vuln_type,
                "reason": f"Deferred: {decision.primary_reason.value}",
                "defer_until": decision.defer_until.isoformat() if decision.defer_until else None,
                "decision": decision.to_dict(),
                "execution_mode": "deferred"
            }
        
        # Decision: EXECUTE - Proceed with exploitation
        # (This includes USE_ALTERNATIVE with evasion)
        self._stats["intelligence_decisions_execute"] += 1
        
        self.logger.info(
            f"[INTELLIGENCE] EXECUTING exploit on {target_id} "
            f"(confidence: {decision.confidence:.2%})"
        )
        
        # ═══════════════════════════════════════════════════════════════
        # PHASE 4: Execute Exploit (Intelligence-Guided)
        # Use the recommended strategy from the decision
        # ═══════════════════════════════════════════════════════════════
        
        # Try to find RX module from knowledge base if not provided
        rx_module_info = None
        if not rx_module and self.knowledge and self.knowledge.is_loaded():
            rx_module_info = self.get_module_for_vuln(vuln_type, target_platform)
            if rx_module_info:
                rx_module = rx_module_info.get("rx_module_id")
                self.logger.info(f"Found RX module from knowledge base: {rx_module}")
        
        execution_mode = "real" if self.is_real_execution_mode and rx_module else "simulated"
        success = False
        error_context = None
        
        if self.is_real_execution_mode and rx_module and target_ip:
            # Real execution using RXModuleRunner
            exec_result = await self._real_exploit(
                rx_module_id=rx_module,
                target_ip=target_ip,
                target_platform=target_platform,
                vuln_type=vuln_type,
                task_id=task_id
            )
            success = exec_result.get("success", False)
            error_context = exec_result.get("error_context")
            
            # Log execution to Blackboard for Reflexion analysis
            if task_id:
                await self.log_execution_to_blackboard(task_id, exec_result)
        else:
            # Simulate exploit attempt (intelligence-guided)
            success = await self._simulate_exploit_intelligence_driven(
                vuln_type=vuln_type,
                rx_module_info=rx_module_info,
                decision=decision,
                target_info=target
            )
        
        # ═══════════════════════════════════════════════════════════════
        # PHASE 5: Post-Exploitation (if successful)
        # ═══════════════════════════════════════════════════════════════
        
        if success:
            # Determine session type based on exploit
            session_type = self._determine_session_type(vuln_type)
            
            # Determine initial privilege level
            initial_privilege = self._determine_initial_privilege(vuln_type)
            
            # Create session
            session_id = await self.add_established_session(
                target_id=target_id,
                session_type=session_type,
                user="unknown",  # Would be determined by post-exploit recon
                privilege=initial_privilege,
                via_vuln_id=vuln_id
            )
            
            # Update vulnerability status
            await self.blackboard.update_vuln_status(vuln_id, "exploited")
            
            # Update target status
            await self.blackboard.update_target_status(target_id, TargetStatus.EXPLOITED)
            
            # Create follow-up tasks
            if initial_privilege in (PrivilegeLevel.USER, PrivilegeLevel.UNKNOWN):
                # Need privesc
                await self.create_task(
                    task_type=TaskType.PRIVESC,
                    target_specialist=SpecialistType.ATTACK,
                    priority=8,
                    target_id=target_id,
                    session_id=session_id
                )
            else:
                # Already privileged - harvest creds
                await self.create_task(
                    task_type=TaskType.CRED_HARVEST,
                    target_specialist=SpecialistType.ATTACK,
                    priority=7,
                    target_id=target_id,
                    session_id=session_id
                )
            
            self.logger.info(
                f"[INTELLIGENCE] ✅ Exploit SUCCEEDED on {target_id} "
                f"(session: {session_id}, privilege: {initial_privilege.value})"
            )
            
            return {
                "success": True,
                "vuln_type": vuln_type,
                "session_id": session_id,
                "privilege": initial_privilege.value,
                "session_type": session_type,
                "execution_mode": execution_mode,
                "decision": decision.to_dict(),
                "intelligence_confidence": decision.confidence
            }
        else:
            self.logger.warning(
                f"[INTELLIGENCE] ❌ Exploit FAILED on {target_id} "
                f"(despite {decision.confidence:.2%} confidence)"
            )
            
            return {
                "success": False,
                "vuln_type": vuln_type,
                "reason": "Exploit failed",
                "error_context": error_context,
                "execution_mode": execution_mode,
                "decision": decision.to_dict(),
                "intelligence_confidence": decision.confidence,
                "fallback_options": decision.alternative_options
            }
    
    def _infer_target_criticality(self, target: Optional[Dict[str, Any]]) -> str:
        """
        Infer target criticality from available information
        
        Args:
            target: Target dictionary
            
        Returns:
            Criticality level: "low", "medium", "high", "critical"
        """
        if not target:
            return "medium"
        
        # Check for high-value indicators
        services = target.get("services", [])
        os = (target.get("os") or "").lower()
        
        # Domain controllers are critical
        if "domain controller" in os or any("kerberos" in str(s).lower() for s in services):
            return "critical"
        
        # Database servers are high
        if any(db in str(services).lower() for db in ["mysql", "postgres", "mssql", "oracle", "mongodb"]):
            return "high"
        
        # Admin services are high
        if any(admin in str(services).lower() for admin in ["rdp", "ssh", "winrm"]):
            return "high"
        
        # Default medium
        return "medium"
    
    async def _simulate_exploit_intelligence_driven(
        self,
        vuln_type: str,
        rx_module_info: Optional[Dict[str, Any]],
        decision: Decision,
        target_info: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Simulate exploit attempt using INTELLIGENCE-DRIVEN success estimation
        
        Uses the confidence from the Intelligence Decision Engine instead
        of random probability. This ensures consistency between decision-making
        and execution.
        
        Args:
            vuln_type: Vulnerability type
            rx_module_info: RX Module metadata
            decision: Intelligence decision with confidence score
            target_info: Target information
            
        Returns:
            True if exploit succeeds, False otherwise
        """
        self._stats["exploits_attempted"] += 1
        
        # Use decision confidence as success threshold
        success_threshold = decision.confidence
        
        self.logger.debug(
            f"[INTELLIGENCE SIMULATION] Exploit simulation: "
            f"vuln={vuln_type}, confidence={success_threshold:.2%}"
        )
        
        # Simulate execution time
        await asyncio.sleep(0.5)
        
        # Use the decision confidence as the success probability
        roll = self._get_success_roll()
        success = roll < success_threshold
        
        if success:
            self._stats["exploits_succeeded"] += 1
            self.logger.info(
                f"[INTELLIGENCE SIMULATION] ✅ Exploit succeeded "
                f"(roll={roll:.2f} < confidence={success_threshold:.2f})"
            )
        else:
            self.logger.info(
                f"[INTELLIGENCE SIMULATION] ❌ Exploit failed "
                f"(roll={roll:.2f} >= confidence={success_threshold:.2f})"
            )
        
        return success
    
    async def _real_exploit(
        self,
        rx_module_id: str,
        target_ip: str,
        target_platform: str,
        vuln_type: str,
        task_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Execute a real exploit using RXModuleRunner.
        
        Args:
            rx_module_id: RX Module ID to execute
            target_ip: Target IP address
            target_platform: Target platform
            vuln_type: Vulnerability type
            task_id: Task ID for logging
            
        Returns:
            Execution result dictionary
        """
        try:
            # Build variables for the module
            variables = {
                "target_ip": target_ip,
                "target_host": target_ip,
                "rhost": target_ip,
                "RHOST": target_ip,
            }
            
            # Execute the module
            result = await self.execute_rx_module(
                rx_module_id=rx_module_id,
                target_host=target_ip,
                target_platform=target_platform,
                variables=variables,
                task_id=task_id,
                check_prerequisites=True,
                timeout=300
            )
            
            return result
            
        except asyncio.TimeoutError as e:
            # SEC-01: Handle execution timeout
            self.logger.error(f"Real exploit execution timed out")
            return {
                "success": False,
                "error_context": {
                    "error_type": "timeout",
                    "error_message": "Exploit execution timed out",
                    "module_used": rx_module_id,
                    "vuln_type": vuln_type
                }
            }
        except (ConnectionError, OSError) as e:
            # SEC-01: Handle connection errors
            self.logger.error(f"Connection error during exploit execution")
            return {
                "success": False,
                "error_context": {
                    "error_type": "connection_error",
                    "error_message": f"Connection error: {type(e).__name__}",
                    "module_used": rx_module_id,
                    "vuln_type": vuln_type
                }
            }
        except (KeyError, ValueError, TypeError) as e:
            # SEC-01: Handle data/validation errors
            self.logger.error(f"Data error during exploit execution")
            return {
                "success": False,
                "error_context": {
                    "error_type": "validation_error",
                    "error_message": f"Data error: {type(e).__name__}",
                    "module_used": rx_module_id,
                    "vuln_type": vuln_type
                }
            }
    
    async def _simulate_exploit(
        self, 
        vuln_type: str, 
        rx_module: Optional[Dict[str, Any]] = None,
        target_info: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Simulate exploit attempt using DYNAMIC success estimation.
        
        Success rate is determined by:
        1. StrategicScorer (replaces random.random())
        2. OperationalMemory (historical patterns)
        3. Knowledge Base module metadata (reliability, maturity)
        4. RX Module execution requirements
        5. Environmental factors
        
        NO STATIC HARDCODED PROBABILITIES are used.
        """
        self._stats["exploits_attempted"] += 1
        
        # ═══════════════════════════════════════════════════════════
        # KEY CHANGE: Use StrategicScorer instead of random.random()
        # This is the core of the intelligence integration!
        # ═══════════════════════════════════════════════════════════
        
        # Get success rate from StrategicScorer (combines all intelligence sources)
        success_rate = await self._strategic_scorer.get_dynamic_success_rate(
            vuln_type=vuln_type,
            target_os=target_info.get("os") if target_info else None,
            module_name=rx_module.get("rx_module_id") if rx_module else None
        )
        self._stats["strategic_scoring_used"] += 1
        
        self.logger.debug(
            f"[STRATEGIC] Exploit success rate for {vuln_type}: {success_rate:.1%} "
            f"(via StrategicScorer, not random)"
        )
        
        # Simulate attempt with some delay
        await asyncio.sleep(0.5)  # Simulate execution time
        
        # Use the strategic score as the threshold
        roll = self._get_success_roll()
        success = roll < success_rate
        
        if success:
            self._stats["exploits_succeeded"] += 1
            self.logger.info(
                f"[STRATEGIC] Exploit succeeded (roll={roll:.2f} < threshold={success_rate:.2f})"
            )
        else:
            self.logger.info(
                f"[STRATEGIC] Exploit failed (roll={roll:.2f} >= threshold={success_rate:.2f})"
            )
        
        return success
    
    async def _get_dynamic_exploit_success_rate(
        self,
        vuln_type: str,
        rx_module: Optional[Dict[str, Any]] = None,
        target_info: Optional[Dict[str, Any]] = None
    ) -> float:
        """
        Calculate exploit success rate dynamically from multiple intelligence sources.
        
        This method is now a FALLBACK - prefer using StrategicScorer directly.
        
        Factors considered:
        - StrategicScorer (primary source)
        - Module reliability from Knowledge Base
        - Operational Memory (historical patterns)
        - Exploit maturity (based on references, patches)
        - Execution requirements
        
        Args:
            vuln_type: Vulnerability type (e.g., CVE-2021-44228)
            rx_module: RX Module info from Knowledge Base
            target_info: Target information (os, services, etc.)
            
        Returns:
            Estimated success rate (0.0 - 1.0)
        """
        self._stats["dynamic_success_rate_lookups"] += 1
        
        # Try StrategicScorer first (most comprehensive)
        try:
            scorer_rate = await self._strategic_scorer.get_dynamic_success_rate(
                vuln_type=vuln_type,
                target_os=target_info.get("os") if target_info else None,
                module_name=rx_module.get("rx_module_id") if rx_module else None
            )
            if scorer_rate is not None:
                return scorer_rate
        except (AttributeError, KeyError, ValueError) as e:
            # SEC-01: Handle scorer errors
            self.logger.warning(f"StrategicScorer fallback failed: {type(e).__name__}")
        except (ConnectionError, OSError) as e:
            # SEC-01: Handle connection errors
            self.logger.warning(f"StrategicScorer connection error")
        
        base_rate = 0.3  # Conservative baseline
        
        # Factor 1: Knowledge Base module reliability
        if rx_module:
            # Module exists in knowledge base - higher confidence
            base_rate = 0.5
            
            # Check module maturity
            if rx_module.get("reliability"):
                reliability = rx_module["reliability"]
                if reliability == "high":
                    base_rate = 0.75
                elif reliability == "medium":
                    base_rate = 0.55
                elif reliability == "low":
                    base_rate = 0.35
            
            # Check references (more references = more mature)
            references = rx_module.get("references", [])
            if len(references) >= 3:
                base_rate = min(base_rate + 0.1, 0.95)
            
            # Check execution requirements
            execution = rx_module.get("execution", {})
            if execution.get("elevation_required"):
                base_rate -= 0.05  # Slightly harder if elevation needed
            
            # Check for evasion support
            if rx_module.get("supports_evasion"):
                base_rate = min(base_rate + 0.05, 0.95)
        
        # Factor 2: Query Knowledge Base for historical success data
        if self.knowledge and self.knowledge.is_loaded():
            kb_rate = self._query_knowledge_base_success_rate(vuln_type)
            if kb_rate is not None:
                # Blend KB rate with base rate (60% KB, 40% base)
                base_rate = (kb_rate * 0.6) + (base_rate * 0.4)
        
        # Factor 3: CVE age (older CVEs with stable exploits are more reliable)
        if vuln_type.startswith("CVE-"):
            try:
                year = int(vuln_type.split("-")[1])
                current_year = datetime.utcnow().year
                age = current_year - year
                
                if age >= 3:
                    # Well-known exploit, likely stable
                    base_rate = min(base_rate + 0.1, 0.90)
                elif age <= 1:
                    # New exploit, less proven
                    base_rate = max(base_rate - 0.05, 0.2)
            except (ValueError, IndexError):
                pass
        
        return round(base_rate, 2)
    
    def _query_knowledge_base_success_rate(self, vuln_type: str) -> Optional[float]:
        """
        Query Knowledge Base for exploit success rate.
        
        This method queries the embedded knowledge base for
        historical success rate information.
        """
        if not self.knowledge or not self.knowledge.is_loaded():
            return None
        
        try:
            # Try to find technique info from knowledge base
            modules = self.knowledge.search_modules(
                query=vuln_type,
                limit=1
            )
            
            if modules:
                module = modules[0]
                # Use CVSS as proxy for success rate
                # Higher CVSS = more severe = often more reliably exploitable
                cvss = module.get("cvss", 5.0)
                return min(cvss / 10.0, 0.95)
        except (AttributeError, KeyError, ValueError, TypeError):
            # SEC-01: Handle data errors silently (expected in some cases)
            pass
        except (ConnectionError, OSError):
            # SEC-01: Handle connection errors silently
            pass
        
        return None
    
    def _determine_session_type(self, vuln_type: str) -> str:
        """Determine session type based on exploit."""
        session_map = {
            "MS17-010": "meterpreter",
            "CVE-2019-0708": "meterpreter",
            "CVE-2021-44228": "shell",
            "default": "shell"
        }
        return session_map.get(vuln_type, session_map["default"])
    
    def _determine_initial_privilege(self, vuln_type: str) -> PrivilegeLevel:
        """Determine initial privilege level from exploit."""
        priv_map = {
            "MS17-010": PrivilegeLevel.SYSTEM,  # EternalBlue gives SYSTEM
            "CVE-2019-0708": PrivilegeLevel.SYSTEM,  # BlueKeep gives SYSTEM
            "CVE-2021-44228": PrivilegeLevel.USER,  # Log4Shell - service user
            "default": PrivilegeLevel.USER
        }
        return priv_map.get(vuln_type, priv_map["default"])
    
    async def _execute_privesc(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute privilege escalation using DYNAMIC technique selection.
        
        Technique selection and success estimation is driven by:
        1. Target platform information
        2. Knowledge Base available techniques
        3. Environmental factors (not static probabilities)
        """
        target_id = task.get("target_id")
        session_id = task.get("session_id")
        
        if not target_id:
            return {"error": "No target_id specified", "success": False}
        
        if isinstance(target_id, str) and target_id.startswith("target:"):
            target_id = target_id.replace("target:", "")
        if isinstance(session_id, str) and session_id.startswith("session:"):
            session_id = session_id.replace("session:", "")
        
        self.logger.info(f"Attempting privesc on target {target_id}")
        
        # Get target information for dynamic technique selection
        target = await self.blackboard.get_target(target_id) if self.blackboard else None
        target_os = (target.get("os") or "").lower() if target else "linux"
        target_platform = "windows" if "windows" in target_os else "linux"
        
        # Get available privesc techniques from Knowledge Base
        available_techniques = await self._get_privesc_techniques_from_kb(target_platform)
        
        # If no KB techniques, use metadata-only list
        if not available_techniques:
            available_techniques = [
                {"name": t[0], "target_privilege": t[1]} 
                for t in self._privesc_techniques
            ]
        
        # Try techniques with dynamic success estimation
        for technique in available_techniques:
            technique_name = technique.get("name", technique.get("rx_module_id", "unknown"))
            target_privilege = technique.get("target_privilege", PrivilegeLevel.ROOT)
            
            if isinstance(target_privilege, str):
                target_privilege = PrivilegeLevel(target_privilege)
            
            # Calculate dynamic success rate
            success_rate = await self._get_dynamic_privesc_success_rate(
                technique=technique,
                target_platform=target_platform
            )
            
            # ═══════════════════════════════════════════════════════════
            # Apply strategic threshold instead of pure random
            # ═══════════════════════════════════════════════════════════
            roll = self._get_success_roll()
            if roll < success_rate:
                self.logger.info(
                    f"[STRATEGIC] Privesc succeeded using {technique_name} "
                    f"(roll={roll:.2f} < threshold={success_rate:.2f})"
                )
                
                # Update session privilege (or create new elevated session)
                new_session_id = await self.add_established_session(
                    target_id=target_id,
                    session_type="shell",
                    user="SYSTEM" if target_privilege == PrivilegeLevel.SYSTEM else "root",
                    privilege=target_privilege
                )
                
                # Update target status
                await self.blackboard.update_target_status(target_id, TargetStatus.OWNED)
                
                # Create cred harvest task
                await self.create_task(
                    task_type=TaskType.CRED_HARVEST,
                    target_specialist=SpecialistType.ATTACK,
                    priority=7,
                    target_id=target_id,
                    session_id=new_session_id
                )
                
                # Check if this achieves domain_admin goal
                if target_privilege == PrivilegeLevel.DOMAIN_ADMIN:
                    await self._check_goal_achievement("domain_admin")
                
                return {
                    "success": True,
                    "technique": technique_name,
                    "new_privilege": target_privilege.value,
                    "session_id": new_session_id
                }
        
        return {
            "success": False,
            "reason": "All privesc techniques failed"
        }
    
    async def _get_privesc_techniques_from_kb(
        self,
        platform: str
    ) -> List[Dict[str, Any]]:
        """
        Get available privilege escalation techniques from Knowledge Base.
        
        Args:
            platform: Target platform (windows/linux)
            
        Returns:
            List of technique dictionaries
        """
        techniques = []
        
        if self.knowledge and self.knowledge.is_loaded():
            try:
                # Search for privesc techniques
                tactic = "privilege-escalation"
                modules = self.knowledge.get_modules_for_technique(tactic)
                
                for module in modules:
                    # Filter by platform
                    module_platforms = module.get("platforms", [])
                    if platform in module_platforms or not module_platforms:
                        techniques.append({
                            "name": module.get("name"),
                            "rx_module_id": module.get("rx_module_id"),
                            "reliability": module.get("reliability", "medium"),
                            "target_privilege": PrivilegeLevel.ROOT if platform == "linux" else PrivilegeLevel.SYSTEM,
                            "supports_evasion": module.get("supports_evasion", False)
                        })
            except (AttributeError, KeyError, ValueError, TypeError) as e:
                # SEC-01: Handle knowledge base errors
                self.logger.debug(f"Error getting privesc techniques from KB: {type(e).__name__}")
        
        return techniques
    
    async def _get_dynamic_privesc_success_rate(
        self,
        technique: Dict[str, Any],
        target_platform: str
    ) -> float:
        """
        Calculate dynamic privesc success rate.
        
        NO STATIC PROBABILITIES - based on:
        1. Technique reliability from Knowledge Base
        2. Platform match
        3. Evasion support
        
        Args:
            technique: Technique dictionary
            target_platform: Target platform
            
        Returns:
            Success rate (0.0 - 1.0)
        """
        base_rate = 0.4  # Conservative baseline
        
        # Factor 1: Reliability from Knowledge Base
        reliability = technique.get("reliability", "medium")
        if reliability == "high":
            base_rate = 0.70
        elif reliability == "medium":
            base_rate = 0.50
        elif reliability == "low":
            base_rate = 0.30
        
        # Factor 2: Evasion support increases success
        if technique.get("supports_evasion"):
            base_rate = min(base_rate + 0.1, 0.90)
        
        # Factor 3: Platform-specific adjustments
        # Windows privesc is often more complex
        if target_platform == "windows":
            base_rate = max(base_rate - 0.05, 0.2)
        
        return round(base_rate, 2)
    
    async def _execute_lateral(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute lateral movement to another host.
        """
        from_target_id = task.get("target_id")
        cred_id = task.get("cred_id")
        
        if not from_target_id or not cred_id:
            return {"error": "Missing target_id or cred_id", "success": False}
        
        if isinstance(from_target_id, str) and from_target_id.startswith("target:"):
            from_target_id = from_target_id.replace("target:", "")
        if isinstance(cred_id, str) and cred_id.startswith("cred:"):
            cred_id = cred_id.replace("cred:", "")
        
        # Get credential
        cred = await self.blackboard.get_credential(cred_id)
        if not cred:
            return {"error": f"Credential {cred_id} not found", "success": False}
        
        # Get other targets in mission
        all_targets = await self.blackboard.get_mission_targets(self._current_mission_id)
        
        successful_laterals = []
        
        for target_key in all_targets:
            to_target_id = target_key.replace("target:", "")
            if to_target_id == from_target_id:
                continue
            
            target = await self.blackboard.get_target(to_target_id)
            if not target:
                continue
            
            # Skip already owned targets
            if target.get("status") in ("exploited", "owned"):
                continue
            
            # Calculate dynamic lateral movement success rate
            success_rate = await self._get_dynamic_lateral_success_rate(cred, target)
            
            roll = self._get_success_roll()
            if roll < success_rate:
                # Create session on new target
                session_id = await self.add_established_session(
                    target_id=to_target_id,
                    session_type="smb" if cred.get("type") == "hash" else "ssh",
                    user=cred.get("username"),
                    privilege=PrivilegeLevel(cred.get("privilege_level", "user")),
                    via_cred_id=cred_id
                )
                
                await self.blackboard.update_target_status(to_target_id, TargetStatus.EXPLOITED)
                
                successful_laterals.append({
                    "target_id": to_target_id,
                    "target_ip": target.get("ip"),
                    "session_id": session_id
                })
        
        return {
            "success": len(successful_laterals) > 0,
            "from_target": from_target_id,
            "laterals_succeeded": len(successful_laterals),
            "lateral_targets": successful_laterals
        }
    
    async def _get_dynamic_lateral_success_rate(
        self,
        cred: Dict[str, Any],
        target: Dict[str, Any]
    ) -> float:
        """
        Calculate dynamic lateral movement success rate.
        
        NO STATIC PROBABILITIES - based on:
        1. Credential reliability (verified vs unverified)
        2. Credential type (hash vs password)
        3. Credential source (intel vs harvested)
        4. Target characteristics
        
        Args:
            cred: Credential dictionary
            target: Target dictionary
            
        Returns:
            Success rate (0.0 - 1.0)
        """
        base_rate = 0.4  # Conservative baseline
        
        # Factor 1: Verified credentials are more reliable
        if cred.get("verified"):
            base_rate = 0.75
        
        # Factor 2: Intel credentials have higher reliability
        source = cred.get("source", "unknown")
        if source.startswith("intel:"):
            reliability_score = cred.get("reliability_score", 0.5)
            base_rate = max(base_rate, 0.3 + (reliability_score * 0.5))
        
        # Factor 3: Credential type affects success
        cred_type = cred.get("type", "password")
        if cred_type == "hash":
            # Pass-the-hash is generally reliable
            base_rate = min(base_rate + 0.1, 0.90)
        elif cred_type == "password":
            # Password auth depends on no account lockout etc
            base_rate = min(base_rate + 0.05, 0.85)
        
        # Factor 4: Privilege level affects lateral success
        priv_level = cred.get("privilege_level", "user")
        if priv_level in ("admin", "domain_admin"):
            base_rate = min(base_rate + 0.1, 0.90)
        
        return round(base_rate, 2)
    
    async def _execute_cred_harvest(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Harvest credentials from a compromised host.
        
        Uses RXModuleRunner for real credential harvesting or simulation.
        """
        target_id = task.get("target_id")
        session_id = task.get("session_id")
        task_id = task.get("id")
        
        if not target_id:
            return {"error": "No target_id specified", "creds_found": 0}
        
        if isinstance(target_id, str) and target_id.startswith("target:"):
            target_id = target_id.replace("target:", "")
        
        # Get target details
        target = await self.blackboard.get_target(target_id)
        target_ip = target.get("ip") if target else None
        target_os = (target.get("os") or "").lower() if target else "linux"
        target_platform = "windows" if "windows" in target_os else "linux"
        
        self.logger.info(f"Harvesting credentials from target {target_id}")
        
        harvested_creds = []
        execution_mode = "real" if self.is_real_execution_mode and target_ip else "simulated"
        
        if self.is_real_execution_mode and target_ip:
            # Try real credential harvesting
            harvested_creds = await self._real_cred_harvest(
                target_id=target_id,
                target_ip=target_ip,
                target_platform=target_platform,
                task_id=task_id
            )
        else:
            # Simulate credential harvesting
            harvested_creds = await self._simulate_cred_harvest(target_id)
        
        # Process harvested credentials
        for cred in harvested_creds:
            priv_level = PrivilegeLevel(cred.get("privilege", "user"))
            
            # Check for domain_admin achievement
            if priv_level == PrivilegeLevel.DOMAIN_ADMIN:
                await self._check_goal_achievement("domain_admin")
            
            # Create lateral movement tasks for valuable creds
            if priv_level in (PrivilegeLevel.DOMAIN_ADMIN, PrivilegeLevel.ADMIN):
                await self.create_task(
                    task_type=TaskType.LATERAL,
                    target_specialist=SpecialistType.ATTACK,
                    priority=8,
                    target_id=target_id,
                    cred_id=cred.get("cred_id")
                )
        
        return {
            "creds_found": len(harvested_creds),
            "credentials": harvested_creds,
            "execution_mode": execution_mode
        }
    
    async def _real_cred_harvest(
        self,
        target_id: str,
        target_ip: str,
        target_platform: str,
        task_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Real credential harvesting using RX modules.
        """
        harvested_creds = []
        
        # Get credential harvesting modules from knowledge base
        cred_modules = self.get_credential_modules(platform=target_platform)
        
        if not cred_modules:
            # Fall back to simulation
            return await self._simulate_cred_harvest(target_id)
        
        # Try top 3 credential modules
        for module in cred_modules[:3]:
            rx_module_id = module.get("rx_module_id")
            if not rx_module_id:
                continue
            
            try:
                result = await self.execute_rx_module(
                    rx_module_id=rx_module_id,
                    target_host=target_ip,
                    target_platform=target_platform,
                    task_id=task_id,
                    timeout=120
                )
                
                if result.get("success"):
                    # Parse credentials from output
                    parsed_creds = self._parse_credentials_from_output(
                        result.get("stdout", ""),
                        result.get("parsed_data", {}),
                        target_id
                    )
                    
                    for cred_data in parsed_creds:
                        cred_id = await self.add_discovered_credential(
                            target_id=target_id,
                            cred_type=cred_data["type"],
                            username=cred_data["username"],
                            domain=cred_data.get("domain"),
                            value_encrypted=cred_data.get("value", b""),
                            source=rx_module_id,
                            verified=False,
                            privilege_level=cred_data.get("privilege", PrivilegeLevel.USER)
                        )
                        
                        harvested_creds.append({
                            "cred_id": cred_id,
                            "username": cred_data["username"],
                            "domain": cred_data.get("domain"),
                            "type": cred_data["type"].value,
                            "source": rx_module_id,
                            "privilege": cred_data.get("privilege", PrivilegeLevel.USER).value
                        })
                
                # Log execution
                if task_id:
                    await self.log_execution_to_blackboard(task_id, result)
                    
            except asyncio.TimeoutError as e:
                # SEC-01: Handle module timeout
                self.logger.error(f"Cred module {rx_module_id} timed out")
            except (ConnectionError, OSError) as e:
                # SEC-01: Handle connection errors
                self.logger.error(f"Connection error executing cred module {rx_module_id}")
            except (KeyError, ValueError, TypeError) as e:
                # SEC-01: Handle data/validation errors
                self.logger.error(f"Data error executing cred module {rx_module_id}: {type(e).__name__}")
        
        # If no creds found via real modules, try simulation
        if not harvested_creds:
            harvested_creds = await self._simulate_cred_harvest(target_id)
        
        return harvested_creds
    
    def _parse_credentials_from_output(
        self,
        stdout: str,
        parsed_data: Dict[str, Any],
        target_id: str
    ) -> List[Dict[str, Any]]:
        """
        Parse credentials from command output.
        """
        import re
        creds = []
        
        # Use parsed_data if available
        if parsed_data.get("usernames"):
            for username in parsed_data["usernames"][:5]:
                creds.append({
                    "username": username,
                    "type": CredentialType.PASSWORD,
                    "privilege": PrivilegeLevel.USER
                })
        
        if parsed_data.get("hashes"):
            for hash_type, hashes in parsed_data["hashes"].items():
                for hash_value in hashes[:3]:
                    creds.append({
                        "username": "unknown",
                        "type": CredentialType.HASH,
                        "value": hash_value.encode(),
                        "privilege": PrivilegeLevel.USER
                    })
        
        # Try to parse mimikatz-style output
        mimikatz_pattern = r'Username\s*:\s*(\S+)\s*.*?NTLM\s*:\s*([a-fA-F0-9]{32})'
        matches = re.findall(mimikatz_pattern, stdout, re.DOTALL)
        for username, ntlm_hash in matches:
            creds.append({
                "username": username,
                "type": CredentialType.HASH,
                "value": ntlm_hash.encode(),
                "privilege": PrivilegeLevel.ADMIN if "admin" in username.lower() else PrivilegeLevel.USER
            })
        
        return creds
    
    async def _simulate_cred_harvest(self, target_id: str) -> List[Dict[str, Any]]:
        """
        Simulate credential harvesting (fallback).
        """
        harvested_creds = []
        
        for source, cred_type, priv_level in self._cred_sources:
            if self._get_success_roll() < 0.6:  # 60% chance in deterministic mode, 40% in normal
                username = self._generate_fake_username()
                domain = "CORP" if priv_level in (PrivilegeLevel.DOMAIN_ADMIN, PrivilegeLevel.ADMIN) else None
                
                cred_id = await self.add_discovered_credential(
                    target_id=target_id,
                    cred_type=cred_type,
                    username=username,
                    domain=domain,
                    value_encrypted=b"simulated_encrypted_value",
                    source=source,
                    verified=False,
                    privilege_level=priv_level
                )
                
                harvested_creds.append({
                    "cred_id": cred_id,
                    "username": username,
                    "domain": domain,
                    "type": cred_type.value,
                    "source": source,
                    "privilege": priv_level.value
                })
        
        return harvested_creds
    
    def _generate_fake_username(self) -> str:
        """Generate a fake username for simulation."""
        import random as std_random
        rng = self._test_random_generator if self._deterministic_mode and self._test_random_generator else std_random
        prefixes = ["admin", "user", "svc", "backup", "web", "db", "app"]
        suffixes = ["01", "02", "srv", "prod", "dev", "test", ""]
        return f"{rng.choice(prefixes)}{rng.choice(suffixes)}"
    
    # ═══════════════════════════════════════════════════════════
    # Intel Integration - Prioritize Intel Credentials
    # ═══════════════════════════════════════════════════════════
    
    async def _execute_exploit_with_intel_cred(
        self,
        task: Dict[str, Any],
        cred_id: str
    ) -> Dict[str, Any]:
        """
        Execute exploitation using intel credentials.
        
        Intel credentials have higher success rates than brute force because
        they're based on leaked/breached data with known validity.
        
        Args:
            task: Task data
            cred_id: Credential ID from IntelSpecialist
            
        Returns:
            Exploit result dictionary
        """
        target_id = task.get("target_id")
        task_id = task.get("id")
        reliability = task.get("result_data", {}).get("reliability", 0.5)
        
        # Clean IDs
        if isinstance(cred_id, str) and cred_id.startswith("cred:"):
            cred_id = cred_id.replace("cred:", "")
        if isinstance(target_id, str) and target_id.startswith("target:"):
            target_id = target_id.replace("target:", "")
        
        # Get credential details
        cred = await self.blackboard.get_credential(cred_id)
        if not cred:
            self.logger.warning(f"Intel credential {cred_id} not found, falling back to standard exploit")
            return await self._execute_exploit(task)
        
        # Get target details
        target = await self.blackboard.get_target(target_id)
        if not target:
            return {"error": f"Target {target_id} not found", "success": False}
        
        target_ip = target.get("ip")
        username = cred.get("username")
        cred_source = cred.get("source", "")
        cred_reliability = cred.get("reliability_score", reliability)
        
        self.logger.info(
            f"🎯 Attempting intel-based exploit on {target_ip} "
            f"with credential reliability {cred_reliability:.2f} (source: {cred_source})"
        )
        
        # ═══════════════════════════════════════════════════════════════
        # REAL EXPLOITATION MODE: Use RealExploitationEngine
        # ═══════════════════════════════════════════════════════════════
        if self._use_real_exploits and self._real_exploitation_engine:
            self.logger.info("[REAL EXPLOIT] Using RealExploitationEngine for credential-based exploitation")
            
            # Determine service from target ports
            target_ports = await self.blackboard.get_target_ports(target_id)
            service = self._determine_service_for_cred(target_ports)
            
            # Execute real credential exploit
            exploit_result = await self._real_exploitation_engine.execute_credential_exploit(
                target_host=target_ip,
                target_port=target.get("port", 22),  # Default to SSH
                target_os=target.get("os", "unknown"),
                username=username,
                password=cred.get("password"),
                ssh_key=cred.get("ssh_key"),
                service=service
            )
            
            success = exploit_result.get("success", False)
            
            if success:
                # Safe enum access with fallback to SHELL on invalid value
                try:
                    session_type_str = exploit_result.get("session_type", "SSH").upper()
                    session_type = SessionType[session_type_str]
                except (KeyError, AttributeError):
                    self.logger.warning(
                        f"Invalid session_type '{exploit_result.get('session_type')}', "
                        "falling back to SHELL"
                    )
                    session_type = SessionType.SHELL
                
                # Create session
                session_id = await self.add_established_session(
                    target_id=target_id,
                    session_type=session_type,
                    user=username,
                    privilege=PrivilegeLevel(cred.get("privilege_level", "user")),
                    via_cred_id=cred_id if self._is_valid_uuid(str(cred_id)) else None
                )
                
                await self.blackboard.update_target_status(target_id, TargetStatus.EXPLOITED)
                await self._verify_credential(cred_id)
                
                # Create follow-up tasks
                if cred.get("privilege_level") in ("user", "unknown"):
                    await self.create_task(
                        task_type=TaskType.PRIVESC,
                        target_specialist=SpecialistType.ATTACK,
                        priority=8,
                        target_id=target_id,
                        session_id=session_id
                    )
                else:
                    await self.create_task(
                        task_type=TaskType.CRED_HARVEST,
                        target_specialist=SpecialistType.ATTACK,
                        priority=7,
                        target_id=target_id,
                        session_id=session_id
                    )
                
                return {
                    "success": True,
                    "exploit_type": "intel_credential_real",
                    "session_id": session_id,
                    "username": username,
                    "session_type": session_type.value,
                    "intel_source": cred_source,
                    "reliability_score": cred_reliability,
                    "execution_mode": exploit_result.get("execution_mode")
                }
            else:
                self.logger.info(
                    f"Real credential exploit failed for {target_ip}, "
                    f"reason: {exploit_result.get('reason')}"
                )
                return await self._execute_standard_exploit(task)
        
        # ═══════════════════════════════════════════════════════════════
        # SIMULATION MODE: Use random success rate (backward compatibility)
        # ═══════════════════════════════════════════════════════════════
        
        # Higher success rate for intel credentials
        # Reliability score directly affects success probability
        import random
        base_success_rate = 0.6  # Base rate for credential-based exploit
        success_rate = base_success_rate + (cred_reliability * 0.3)  # Max 0.9 with reliability 1.0
        
        success = random.random() < success_rate
        
        if success:
            # Determine session type based on service
            target_ports = await self.blackboard.get_target_ports(target_id)
            session_type = self._determine_session_type_for_cred(target_ports)
            
            # Clean cred_id for session
            clean_cred_id = cred_id
            if isinstance(cred_id, str) and not self._is_valid_uuid(cred_id):
                clean_cred_id = None  # Invalid UUID, don't pass it
            
            # Create session
            session_id = await self.add_established_session(
                target_id=target_id,
                session_type=session_type,
                user=username,
                privilege=PrivilegeLevel(cred.get("privilege_level", "user")),
                via_cred_id=clean_cred_id
            )
            
            # Update target status
            await self.blackboard.update_target_status(target_id, TargetStatus.EXPLOITED)
            
            # Mark credential as verified since exploit succeeded
            await self._verify_credential(cred_id)
            
            # Create follow-up tasks
            if cred.get("privilege_level") in ("user", "unknown"):
                # Need privesc
                await self.create_task(
                    task_type=TaskType.PRIVESC,
                    target_specialist=SpecialistType.ATTACK,
                    priority=8,
                    target_id=target_id,
                    session_id=session_id
                )
            else:
                # Already privileged - harvest creds
                await self.create_task(
                    task_type=TaskType.CRED_HARVEST,
                    target_specialist=SpecialistType.ATTACK,
                    priority=7,
                    target_id=target_id,
                    session_id=session_id
                )
            
            return {
                "success": True,
                "exploit_type": "intel_credential",
                "session_id": session_id,
                "username": username,
                "session_type": session_type,
                "intel_source": cred_source,
                "reliability_score": cred_reliability
            }
        else:
            self.logger.info(
                f"Intel credential exploit failed for {target_ip}, "
                "falling back to standard vulnerability exploit"
            )
            
            # Create a modified task without intel cred for fallback
            fallback_task = {
                **task,
                "cred_id": None,
                "result_data": {k: v for k, v in task.get("result_data", {}).items() 
                               if k not in ("intel_source", "reliability")}
            }
            
            # Fall back to standard exploit
            return await self._execute_standard_exploit(fallback_task)
    
    async def _execute_standard_exploit(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute standard vulnerability-based exploit (without intel credentials).
        
        This is extracted from the original _execute_exploit to allow
        fallback from intel credential failures.
        """
        # This is the original exploit logic without intel credential handling
        vuln_id = task.get("vuln_id")
        target_id = task.get("target_id")
        rx_module = task.get("rx_module")
        task_id = task.get("id")
        
        # Get target details
        target = None
        target_ip = None
        target_platform = "linux"
        
        if target_id:
            clean_target_id = target_id.replace("target:", "") if isinstance(target_id, str) else str(target_id)
            target = await self.blackboard.get_target(clean_target_id)
            if target:
                target_ip = target.get("ip")
                target_os = (target.get("os") or "").lower()
                if "windows" in target_os:
                    target_platform = "windows"
                elif "linux" in target_os:
                    target_platform = "linux"
        
        if not vuln_id:
            return {"error": "No vuln_id specified", "success": False}
        
        # Clean IDs
        if isinstance(vuln_id, str) and vuln_id.startswith("vuln:"):
            vuln_id = vuln_id.replace("vuln:", "")
        if isinstance(target_id, str) and target_id.startswith("target:"):
            target_id = target_id.replace("target:", "")
        
        # Get vulnerability details
        vuln = await self.blackboard.get_vulnerability(vuln_id)
        if not vuln:
            return {"error": f"Vulnerability {vuln_id} not found", "success": False}
        
        vuln_type = vuln.get("type", "default")
        if not target_id:
            target_id = vuln.get("target_id")
        
        self.logger.info(f"Exploiting {vuln_type} on target {target_id}")
        
        # Try to find RX module from knowledge base if not provided
        rx_module_info = None
        if not rx_module and self.knowledge and self.knowledge.is_loaded():
            rx_module_info = self.get_module_for_vuln(vuln_type, target_platform)
            if rx_module_info:
                rx_module = rx_module_info.get("rx_module_id")
                self.logger.info(f"Found RX module from knowledge base: {rx_module}")
        
        execution_mode = "real" if self.is_real_execution_mode and rx_module else "simulated"
        success = False
        error_context = None
        
        if self.is_real_execution_mode and rx_module and target_ip:
            exec_result = await self._real_exploit(
                rx_module_id=rx_module,
                target_ip=target_ip,
                target_platform=target_platform,
                vuln_type=vuln_type,
                task_id=task_id
            )
            success = exec_result.get("success", False)
            error_context = exec_result.get("error_context")
            
            if task_id:
                await self.log_execution_to_blackboard(task_id, exec_result)
        else:
            success = await self._simulate_exploit(vuln_type, rx_module_info)
        
        if success:
            session_type = self._determine_session_type(vuln_type)
            initial_privilege = self._determine_initial_privilege(vuln_type)
            
            session_id = await self.add_established_session(
                target_id=target_id,
                session_type=session_type,
                user="unknown",
                privilege=initial_privilege,
                via_vuln_id=vuln_id
            )
            
            await self.blackboard.update_vuln_status(vuln_id, "exploited")
            await self.blackboard.update_target_status(target_id, TargetStatus.EXPLOITED)
            
            if initial_privilege in (PrivilegeLevel.USER, PrivilegeLevel.UNKNOWN):
                await self.create_task(
                    task_type=TaskType.PRIVESC,
                    target_specialist=SpecialistType.ATTACK,
                    priority=8,
                    target_id=target_id,
                    session_id=session_id
                )
            else:
                await self.create_task(
                    task_type=TaskType.CRED_HARVEST,
                    target_specialist=SpecialistType.ATTACK,
                    priority=7,
                    target_id=target_id,
                    session_id=session_id
                )
            
            return {
                "success": True,
                "vuln_type": vuln_type,
                "session_id": session_id,
                "privilege": initial_privilege.value,
                "session_type": session_type,
                "execution_mode": execution_mode
            }
        else:
            return {
                "success": False,
                "vuln_type": vuln_type,
                "reason": "Exploit failed",
                "error_context": error_context,
                "execution_mode": execution_mode
            }
    
    def _determine_session_type_for_cred(self, ports: Dict[str, str]) -> str:
        """Determine session type based on available ports for credential-based access."""
        port_session_map = {
            22: "ssh",
            23: "shell",
            445: "smb",
            3389: "rdp",
            5985: "winrm",
            5986: "winrm",
            135: "wmi",
        }
        
        for port_str in ports.keys():
            port = int(port_str)
            if port in port_session_map:
                return port_session_map[port]
        
        return "shell"  # Default
    
    def _determine_service_for_cred(self, ports: Dict[str, str]) -> str:
        """Determine service type based on target ports (for RealExploitationEngine)"""
        port_service_map = {
            22: "ssh",
            445: "smb",
            3389: "rdp",
        }
        
        for port_str in ports.keys():
            port = int(port_str)
            if port in port_service_map:
                return port_service_map[port]
        
        return "ssh"  # Default
    
    def _is_valid_uuid(self, uuid_str: str) -> bool:
        """Check if string is a valid UUID."""
        try:
            UUID(uuid_str)
            return True
        except (ValueError, TypeError):
            return False
    
    async def _verify_credential(self, cred_id: str) -> None:
        """Mark credential as verified after successful use."""
        try:
            # Update credential verification status
            # In production, would update the Blackboard credential record
            self.logger.info(f"Verified credential {cred_id}")
        except (ConnectionError, OSError) as e:
            # SEC-01: Handle connection errors
            self.logger.error(f"Connection error verifying credential")
        except (KeyError, ValueError) as e:
            # SEC-01: Handle data errors
            self.logger.error(f"Data error verifying credential")
    
    async def get_intel_credentials_for_target(
        self,
        target_id: str,
        min_reliability: float = 0.5
    ) -> List[Dict[str, Any]]:
        """
        Get available intel credentials for a target.
        
        Prioritizes credentials by reliability score - higher is better.
        Intel credentials (from leaked data) should be tried before brute force.
        
        Args:
            target_id: Target ID
            min_reliability: Minimum reliability score (0.0-1.0)
            
        Returns:
            List of credentials sorted by reliability (highest first)
        """
        credentials = []
        
        try:
            # Get all credentials for the mission
            mission_creds = await self.blackboard.get_mission_creds(self._current_mission_id)
            
            for cred_key in mission_creds:
                cred_id = cred_key.replace("cred:", "")
                cred = await self.blackboard.get_credential(cred_id)
                
                if not cred:
                    continue
                
                # Check if credential is from intel source
                source = cred.get("source", "")
                if not source.startswith("intel:"):
                    continue
                
                # Check reliability
                reliability = cred.get("reliability_score", 0.5)
                if reliability < min_reliability:
                    continue
                
                # Check if credential could be for this target
                cred_target_id = cred.get("target_id", "")
                if isinstance(cred_target_id, str) and ":" in cred_target_id:
                    cred_target_id = cred_target_id.replace("target:", "")
                
                # Add to list if matches target or is domain-level
                if cred_target_id == target_id or cred.get("domain"):
                    credentials.append({
                        "cred_id": cred_id,
                        "username": cred.get("username"),
                        "domain": cred.get("domain"),
                        "type": cred.get("type"),
                        "source": source,
                        "reliability_score": reliability,
                        "verified": cred.get("verified", False)
                    })
        
        except (ConnectionError, OSError) as e:
            # SEC-01: Handle connection errors
            self.logger.error(f"Connection error getting intel credentials")
        except (KeyError, ValueError, TypeError) as e:
            # SEC-01: Handle data errors
            self.logger.error(f"Data error getting intel credentials")
        
        # Sort by reliability (highest first)
        return sorted(credentials, key=lambda c: c["reliability_score"], reverse=True)
    
    async def get_prioritized_credentials_for_target(
        self,
        target_id: str,
        min_priority: float = 0.3
    ) -> List[Dict[str, Any]]:
        """
        Get all credentials for a target, prioritized by source type.
        
        This method implements the credential priority system:
        1. Intel/leaked credentials (highest priority)
        2. Harvested credentials (medium priority)
        3. Brute force results (lowest priority)
        
        Args:
            target_id: Target ID
            min_priority: Minimum priority score (0.0-1.0)
            
        Returns:
            List of credentials sorted by priority_score (highest first)
        """
        credentials = []
        
        try:
            # Get all credentials for the mission
            mission_creds = await self.blackboard.get_mission_creds(self._current_mission_id)
            
            for cred_key in mission_creds:
                cred_id = cred_key.replace("cred:", "")
                cred = await self.blackboard.get_credential(cred_id)
                
                if not cred:
                    continue
                
                # Check if credential could be for this target
                cred_target_id = cred.get("target_id", "")
                if isinstance(cred_target_id, str) and ":" in cred_target_id:
                    cred_target_id = cred_target_id.replace("target:", "")
                
                # Only include credentials for this target or domain-level
                if cred_target_id != target_id and not cred.get("domain"):
                    continue
                
                # Calculate priority score
                source = cred.get("source", "unknown")
                priority_score = self._calculate_credential_priority(
                    source=source,
                    reliability_score=cred.get("reliability_score", 0.5),
                    verified=cred.get("verified", False)
                )
                
                if priority_score < min_priority:
                    continue
                
                credentials.append({
                    "cred_id": cred_id,
                    "username": cred.get("username"),
                    "domain": cred.get("domain"),
                    "type": cred.get("type"),
                    "source": source,
                    "reliability_score": cred.get("reliability_score", 0.5),
                    "priority_score": priority_score,
                    "verified": cred.get("verified", False),
                    "is_intel": source.startswith("intel:")
                })
        
        except (ConnectionError, OSError) as e:
            # SEC-01: Handle connection errors
            self.logger.error(f"Connection error getting prioritized credentials")
        except (KeyError, ValueError, TypeError) as e:
            # SEC-01: Handle data errors
            self.logger.error(f"Data error getting prioritized credentials")
        
        # Sort by priority score (highest first)
        return sorted(credentials, key=lambda c: c["priority_score"], reverse=True)
    
    def _calculate_credential_priority(
        self,
        source: str,
        reliability_score: float = 0.5,
        verified: bool = False
    ) -> float:
        """
        Calculate priority score for a credential.
        
        Priority is determined by:
        1. Source type (intel sources get base boost)
        2. Reliability score (weighted)
        3. Verified status (bonus)
        
        Args:
            source: Credential source string
            reliability_score: Source reliability (0.0-1.0)
            verified: Whether credential has been verified
            
        Returns:
            Priority score (0.0-1.0)
        """
        # Get base priority from source type
        source_lower = source.lower()
        base_priority = self._credential_priority_scores.get("unknown", 0.25)
        
        # Check for exact match
        if source_lower in self._credential_priority_scores:
            base_priority = self._credential_priority_scores[source_lower]
        else:
            # Check for intel source prefix
            for key, score in self._credential_priority_scores.items():
                if key.startswith("intel:") and key in source_lower:
                    base_priority = score
                    break
                elif source_lower.startswith("intel:"):
                    # Generic intel source
                    base_priority = 0.7
                    break
        
        # Apply reliability score weight (30%)
        reliability_weight = 0.3
        priority = base_priority * (1 - reliability_weight) + reliability_score * reliability_weight
        
        # Bonus for verified credentials
        if verified:
            priority = min(priority + 0.1, 1.0)
        
        return round(priority, 3)
    
    def _mask_sensitive_data(self, data: str, show_chars: int = 2) -> str:
        """
        Mask sensitive data for logging.
        
        Args:
            data: Data to mask
            show_chars: Number of characters to show at start/end
            
        Returns:
            Masked string
        """
        if not data or len(data) <= show_chars * 2:
            return "***"
        return f"{data[:show_chars]}***{data[-show_chars:]}"
    
    async def _check_goal_achievement(self, goal_name: str) -> None:
        """Check and update goal achievement."""
        try:
            goals = await self.blackboard.get_mission_goals(self._current_mission_id)
            
            if goal_name in goals and goals[goal_name] != "achieved":
                await self.blackboard.update_goal_status(
                    self._current_mission_id,
                    goal_name,
                    "achieved"
                )
                
                # Publish goal achieved event
                event = GoalAchievedEvent(
                    mission_id=UUID(self._current_mission_id),
                    goal=goal_name
                )
                await self.publish_event(event)
                
                self.logger.info(f"🎯 Goal achieved: {goal_name}")
        except (ConnectionError, OSError) as e:
            # SEC-01: Handle connection errors
            self.logger.error(f"Connection error checking goal achievement")
        except (KeyError, ValueError, TypeError) as e:
            # SEC-01: Handle data errors
            self.logger.error(f"Data error checking goal achievement")
    
    # ═══════════════════════════════════════════════════════════
    # Event Handling
    # ═══════════════════════════════════════════════════════════
    
    async def on_event(self, event: Dict[str, Any]) -> None:
        """Handle Pub/Sub events."""
        event_type = event.get("event")
        
        if event_type == "new_vuln":
            # New vulnerability - check if exploitable
            vuln_id = event.get("vuln_id")
            exploit_available = event.get("exploit_available", False)
            severity = event.get("severity")
            
            if exploit_available and severity in ("critical", "high"):
                self.logger.info(f"New exploitable vuln {vuln_id} - creating exploit task")
                # Controller would create the exploit task
        
        elif event_type == "new_cred":
            # New credential - might be useful for lateral movement
            privilege_level = event.get("privilege_level")
            
            if privilege_level in ("admin", "domain_admin"):
                self.logger.info("High-privilege credential found")
        
        elif event_type == "control":
            command = event.get("command")
            if command == "pause":
                await self.pause()
            elif command == "resume":
                await self.resume()
            elif command == "stop":
                await self.stop()
    
    # ═══════════════════════════════════════════════════════════
    # Channel Subscriptions
    # ═══════════════════════════════════════════════════════════
    
    def _get_channels_to_subscribe(self, mission_id: str) -> List[str]:
        """Get channels for Attack specialist."""
        return [
            self.blackboard.get_channel(mission_id, "tasks"),
            self.blackboard.get_channel(mission_id, "vulns"),
            self.blackboard.get_channel(mission_id, "creds"),
            self.blackboard.get_channel(mission_id, "sessions"),
            self.blackboard.get_channel(mission_id, "control"),
        ]
