# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Analysis Specialist
# Reflexion Logic specialist for failure analysis and adaptive learning
# With LLM Integration for intelligent decision making
# ═══════════════════════════════════════════════════════════════

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, TYPE_CHECKING
from uuid import UUID, uuid4

from .base import BaseSpecialist
from ..core.models import (
    TaskType, SpecialistType, TaskStatus, Severity, Priority,
    Task, ErrorContext, ExecutionLog,
    TaskFailedEvent, TaskAnalysisRequestEvent, TaskAnalysisResultEvent,
    BlackboardEvent,
    # HITL Models
    ApprovalAction, ApprovalStatus, ApprovalRequestEvent,
    ActionType, RiskLevel
)
from ..core.blackboard import Blackboard
from ..core.config import Settings, get_settings
from ..core.knowledge import EmbeddedKnowledge

# LLM imports
if TYPE_CHECKING:
    from ..core.llm.service import LLMService
    from ..core.llm.base import LLMProvider


class AnalysisSpecialist(BaseSpecialist):
    """
    Analysis Specialist - Handles failure analysis and reflexion logic.
    
    This specialist implements the Reflexion Logic pattern:
    1. Receives failed task events with full error context
    2. Analyzes the failure to understand root cause
    3. Determines appropriate next action (retry, skip, escalate, modify)
    4. Creates modified retry tasks or escalates to human/LLM
    
    Responsibilities:
    - Analyzing failed exploitation attempts
    - Understanding why attacks failed (AV detection, firewall, etc.)
    - Suggesting alternative techniques or modules
    - Learning from failures to improve future attempts
    - Preparing context for LLM decision-making
    
    Task Types Handled:
    - ANALYSIS: Analyze a failed task and determine next steps
    
    Reads From Blackboard:
    - Failed tasks with error_context
    - Execution logs
    - Target information (for context)
    - Vulnerability details
    
    Writes To Blackboard:
    - Analysis results
    - Modified retry tasks
    - Escalation events
    - Learning insights
    
    Reflexion Logic Flow:
    ┌────────────────┐     ┌───────────────────┐     ┌─────────────────┐
    │  Task Failed   │────▶│ AnalysisSpecialist│────▶│   Decision      │
    │  (with context)│     │   (Reflexion)     │     │ retry/skip/mod  │
    └────────────────┘     └───────────────────┘     └─────────────────┘
                                    │
                                    ▼
                           ┌─────────────────┐
                           │  Knowledge Base │
                           │  (alternatives) │
                           └─────────────────┘
    """
    
    # Error type mappings for analysis
    ERROR_CATEGORIES = {
        "connection_refused": "network",
        "connection_timeout": "network",
        "port_closed": "network",
        "firewall_blocked": "network",
        "av_detected": "defense",
        "edr_blocked": "defense",
        "sandbox_detected": "defense",
        "credential_mismatch": "defense",
        "auth_failed": "authentication",
        "access_denied": "authentication",
        "permission_denied": "authentication",
        "target_patched": "vulnerability",
        "exploit_failed": "vulnerability",
        "module_error": "technical",
        "timeout": "technical",
        "crash": "technical",
        "unknown": "unknown"
    }
    
    # Retry strategies based on error category
    RETRY_STRATEGIES = {
        "network": {
            "max_retries": 3,
            "retry_delay": 60,  # seconds
            "recommendations": [
                "Try alternative ports",
                "Use proxy/tunnel",
                "Wait and retry (network transient)",
            ]
        },
        "defense": {
            "max_retries": 1,
            "retry_delay": 300,  # 5 minutes
            "recommendations": [
                "Use evasion techniques",
                "Try living-off-the-land binaries",
                "Use encoded payloads",
                "Try alternative exploit chain"
            ]
        },
        "authentication": {
            "max_retries": 2,
            "retry_delay": 30,
            "recommendations": [
                "Try credential spraying",
                "Harvest more credentials",
                "Try kerberoasting"
            ]
        },
        "vulnerability": {
            "max_retries": 0,
            "retry_delay": 0,
            "recommendations": [
                "Target may be patched - skip",
                "Try different vulnerability",
                "Enumerate for new vulns"
            ]
        },
        "technical": {
            "max_retries": 2,
            "retry_delay": 10,
            "recommendations": [
                "Check module configuration",
                "Try alternative module",
                "Verify target availability"
            ]
        },
        "unknown": {
            "max_retries": 1,
            "retry_delay": 30,
            "recommendations": [
                "Collect more information",
                "Escalate for manual review"
            ]
        }
    }
    
    def __init__(
        self,
        blackboard: Optional[Blackboard] = None,
        settings: Optional[Settings] = None,
        worker_id: Optional[str] = None,
        knowledge: Optional[EmbeddedKnowledge] = None,
        llm_enabled: Optional[bool] = None,
        llm_service: Optional["LLMService"] = None,
    ):
        super().__init__(
            specialist_type=SpecialistType.ANALYSIS,
            blackboard=blackboard,
            settings=settings,
            worker_id=worker_id,
            knowledge=knowledge
        )
        
        # Load settings if not provided
        self._settings = settings or get_settings()
        
        # LLM configuration from settings or explicit parameter
        self.llm_enabled = llm_enabled if llm_enabled is not None else self._settings.llm_enabled
        self._llm_service = llm_service
        self._llm_initialized = False
        
        # Analysis history for learning
        self._analysis_history: List[Dict[str, Any]] = []
        
        # Currently no specific task types - analysis works on events
        self._supported_task_types = set()
        
        # Statistics
        self._stats = {
            "analyses_performed": 0,
            "retries_recommended": 0,
            "skips_recommended": 0,
            "escalations": 0,
            "modifications_recommended": 0,
            "llm_analyses": 0,
            "llm_failures": 0,
            "rule_based_fallbacks": 0,
            "safety_limit_breaches": 0,
        }
        
        # Safety limits tracking (per mission)
        self._mission_llm_requests = 0
        self._mission_tokens_used = 0
        self._mission_estimated_cost = 0.0
        self._daily_llm_requests = 0
        self._daily_reset_date = datetime.utcnow().date()
    
    def _check_safety_limits(self) -> tuple[bool, str]:
        """
        Check if safety limits have been reached.
        
        Returns:
            Tuple of (is_safe, reason_if_not_safe)
        """
        if not self._settings.llm_safety_mode:
            return True, ""
        
        # Reset daily counter if new day
        today = datetime.utcnow().date()
        if today > self._daily_reset_date:
            self._daily_llm_requests = 0
            self._daily_reset_date = today
        
        # Check mission request limit
        if self._mission_llm_requests >= self._settings.llm_mission_requests_limit:
            return False, f"Mission LLM request limit reached ({self._settings.llm_mission_requests_limit})"
        
        # Check daily request limit
        if self._daily_llm_requests >= self._settings.llm_daily_requests_limit:
            return False, f"Daily LLM request limit reached ({self._settings.llm_daily_requests_limit})"
        
        # Check cost limit
        if self._mission_estimated_cost >= self._settings.llm_max_cost_limit:
            return False, f"Mission cost limit reached (${self._settings.llm_max_cost_limit:.2f})"
        
        return True, ""
    
    def _update_usage_tracking(self, tokens_used: int = 0) -> None:
        """Update usage tracking after an LLM call."""
        self._mission_llm_requests += 1
        self._daily_llm_requests += 1
        self._mission_tokens_used += tokens_used
        
        # Estimate cost
        cost_per_token = self._settings.llm_cost_per_1k_tokens / 1000
        self._mission_estimated_cost += tokens_used * cost_per_token
    
    def reset_mission_limits(self) -> None:
        """Reset mission-specific limits (call when starting new mission)."""
        self._mission_llm_requests = 0
        self._mission_tokens_used = 0
        self._mission_estimated_cost = 0.0
    
    def get_usage_stats(self) -> Dict[str, Any]:
        """Get current usage statistics."""
        return {
            "mission_llm_requests": self._mission_llm_requests,
            "mission_tokens_used": self._mission_tokens_used,
            "mission_estimated_cost_usd": round(self._mission_estimated_cost, 4),
            "daily_llm_requests": self._daily_llm_requests,
            "limits": {
                "mission_requests_limit": self._settings.llm_mission_requests_limit,
                "daily_requests_limit": self._settings.llm_daily_requests_limit,
                "max_cost_limit_usd": self._settings.llm_max_cost_limit,
            }
        }
    
    def _safe_uuid(self, value: str) -> UUID:
        """Safely convert a string to UUID, generating new one if invalid."""
        try:
            return UUID(value) if value and len(value) == 36 else uuid4()
        except (ValueError, TypeError):
            return uuid4()
    
    async def _ensure_llm_service(self) -> Optional["LLMService"]:
        """
        Ensure LLM service is initialized.
        
        Lazily initializes the LLM service if not already done.
        
        Returns:
            LLMService instance or None if LLM is disabled
        """
        if not self.llm_enabled:
            return None
        
        if self._llm_service is not None:
            return self._llm_service
        
        if self._llm_initialized:
            return self._llm_service
        
        self._llm_initialized = True
        
        try:
            from ..core.llm.service import LLMService, get_llm_service
            from ..core.llm.base import LLMConfig, ProviderType
            
            # Try to get global service first
            service = get_llm_service()
            
            # If no providers registered, try to set up from config
            if not service.providers:
                await self._setup_llm_from_config(service)
            
            self._llm_service = service
            self.logger.info(f"LLM service initialized with providers: {list(service.providers.keys())}")
            return service
            
        except Exception as e:
            self.logger.warning(f"Failed to initialize LLM service: {e}")
            self.llm_enabled = False
            return None
    
    async def _setup_llm_from_config(self, service: "LLMService") -> None:
        """Setup LLM providers from configuration."""
        from ..core.llm.base import LLMConfig, ProviderType
        
        provider_type = self._settings.llm_provider.lower()
        
        if provider_type == "openai" and self._settings.effective_llm_api_key:
            from ..core.llm.openai_provider import OpenAIProvider
            config = LLMConfig(
                provider_type=ProviderType.OPENAI,
                api_key=self._settings.effective_llm_api_key,
                api_base=self._settings.llm_api_base,
                model=self._settings.llm_model,
                temperature=self._settings.llm_temperature,
                max_tokens=self._settings.llm_max_tokens,
                timeout=self._settings.llm_timeout,
                max_retries=self._settings.llm_max_retries,
            )
            service.register_provider("openai", OpenAIProvider(config), set_as_default=True)
            self.logger.info("✅ OpenAI provider configured")
        
        elif provider_type == "blackbox" and self._settings.effective_llm_api_key:
            from ..core.llm.blackbox_provider import BlackboxAIProvider
            api_base = self._settings.llm_api_base or "https://api.blackbox.ai"
            config = LLMConfig(
                api_key=self._settings.effective_llm_api_key,
                api_base=api_base,
                model=self._settings.llm_model,
                temperature=self._settings.llm_temperature,
                max_tokens=self._settings.llm_max_tokens,
                timeout=self._settings.llm_timeout,
                max_retries=self._settings.llm_max_retries,
            )
            service.register_provider("blackbox", BlackboxAIProvider(config), set_as_default=True)
            self.logger.info("✅ BlackboxAI provider configured")
            
        elif provider_type == "local" and self._settings.llm_api_base:
            from ..core.llm.local_provider import LocalLLMProvider
            config = LLMConfig(
                provider_type=ProviderType.LOCAL,
                api_base=self._settings.llm_api_base,
                api_key=self._settings.effective_llm_api_key,  # Optional for some local servers
                model=self._settings.llm_model,
                temperature=self._settings.llm_temperature,
                max_tokens=self._settings.llm_max_tokens,
                timeout=self._settings.llm_timeout,
                max_retries=self._settings.llm_max_retries,
            )
            service.register_provider("local", LocalLLMProvider(config), set_as_default=True)
            self.logger.info("✅ Local LLM provider configured")
            
        elif provider_type == "mock":
            from ..core.llm.mock_provider import MockLLMProvider
            mock = MockLLMProvider()
            mock.setup_analysis_responses()
            service.register_provider("mock", mock, set_as_default=True)
            self.logger.info("✅ Mock LLM provider configured (for testing)")
        
        else:
            self.logger.warning(
                f"⚠️ LLM provider '{provider_type}' requires additional configuration. "
                "Set LLM_API_KEY for OpenAI/BlackboxAI or LLM_API_BASE for local providers."
            )
    
    # ═══════════════════════════════════════════════════════════
    # Task Execution (for analysis tasks)
    # ═══════════════════════════════════════════════════════════
    
    async def execute_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute an analysis task.
        
        Analysis tasks contain the failed task data and require
        determining the next course of action.
        """
        self.logger.info(f"Executing analysis task: {task.get('id')}")
        
        # Extract the original failed task information
        failed_task_id = task.get("result_data", {}).get("original_task_id")
        error_context = task.get("result_data", {}).get("error_context", {})
        execution_logs = task.get("result_data", {}).get("execution_logs", [])
        
        if not failed_task_id:
            return {"error": "No original task ID provided", "decision": "skip"}
        
        # Perform analysis
        analysis_result = await self.analyze_failure(
            task_id=failed_task_id,
            error_context=error_context,
            execution_logs=execution_logs
        )
        
        return analysis_result
    
    # ═══════════════════════════════════════════════════════════
    # Core Analysis Methods
    # ═══════════════════════════════════════════════════════════
    
    async def analyze_failure(
        self,
        task_id: str,
        error_context: Dict[str, Any],
        execution_logs: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Analyze a failed task and determine next steps.
        
        This is the core Reflexion Logic implementation.
        
        Args:
            task_id: ID of the failed task
            error_context: ErrorContext data from the failed task
            execution_logs: Execution logs from the task
            
        Returns:
            Analysis result with decision and reasoning
        """
        self.logger.info(f"Analyzing failure for task {task_id}")
        self._stats["analyses_performed"] += 1
        
        # Get the original task
        original_task = await self.blackboard.get_task(task_id)
        if not original_task:
            return {
                "decision": "skip",
                "reasoning": "Original task not found",
                "task_id": task_id
            }
        
        # Categorize the error
        error_type = error_context.get("error_type", "unknown")
        category = self._categorize_error(error_type)
        
        # Get retry strategy for this category
        strategy = self.RETRY_STRATEGIES.get(category, self.RETRY_STRATEGIES["unknown"])
        
        # Check retry count
        retry_count = original_task.get("retry_count", 0)
        max_retries = original_task.get("max_retries", strategy["max_retries"])
        
        # Gather context for decision
        context = await self._gather_analysis_context(original_task, error_context)
        
        # Make decision
        decision = await self._make_decision(
            original_task=original_task,
            error_context=error_context,
            execution_logs=execution_logs,
            category=category,
            strategy=strategy,
            context=context,
            retry_count=retry_count,
            max_retries=max_retries
        )
        
        # Record analysis
        analysis_record = {
            "task_id": task_id,
            "error_type": error_type,
            "category": category,
            "decision": decision["decision"],
            "timestamp": datetime.utcnow().isoformat()
        }
        self._analysis_history.append(analysis_record)
        
        # Publish analysis result event
        await self._publish_analysis_result(task_id, original_task, decision)
        
        return decision
    
    def _categorize_error(self, error_type: str) -> str:
        """Categorize an error type into a broader category."""
        return self.ERROR_CATEGORIES.get(error_type.lower(), "unknown")
    
    async def _gather_analysis_context(
        self,
        task: Dict[str, Any],
        error_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Gather additional context for analysis.
        
        This includes target information, vulnerability details,
        and knowledge base recommendations.
        """
        context = {
            "target_info": None,
            "vuln_info": None,
            "alternative_modules": [],
            "alternative_techniques": [],
            "detected_defenses": error_context.get("detected_defenses", [])
        }
        
        # Get target info
        target_id = task.get("target_id")
        if target_id:
            if isinstance(target_id, str) and target_id.startswith("target:"):
                target_id = target_id.replace("target:", "")
            context["target_info"] = await self.blackboard.get_target(target_id)
        
        # Get vulnerability info
        vuln_id = task.get("vuln_id")
        if vuln_id:
            if isinstance(vuln_id, str) and vuln_id.startswith("vuln:"):
                vuln_id = vuln_id.replace("vuln:", "")
            context["vuln_info"] = await self.blackboard.get_vulnerability(vuln_id)
        
        # Query knowledge base for alternatives
        if self.knowledge and self.knowledge.is_loaded():
            # Get alternative modules for the same technique
            technique_id = error_context.get("technique_id")
            if technique_id:
                alt_modules = self.get_technique_modules(
                    technique_id=technique_id,
                    platform=self._get_target_platform(context["target_info"])
                )
                # Exclude the one that failed
                failed_module = error_context.get("module_used")
                context["alternative_modules"] = [
                    m for m in alt_modules 
                    if m.get("rx_module_id") != failed_module
                ][:5]  # Limit to top 5
            
            # Get alternative techniques if defenses detected
            if context["detected_defenses"]:
                # Search for evasion modules
                evasion_modules = self.search_modules(
                    query="evasion bypass defense",
                    platform=self._get_target_platform(context["target_info"]),
                    limit=5
                )
                context["alternative_techniques"] = [
                    m.get("technique_id") for m in evasion_modules if m.get("technique_id")
                ]
        
        return context
    
    def _get_target_platform(self, target_info: Optional[Dict[str, Any]]) -> Optional[str]:
        """Extract platform from target info."""
        if not target_info:
            return None
        
        os_info = (target_info.get("os") or "").lower()
        if "windows" in os_info:
            return "windows"
        elif "linux" in os_info:
            return "linux"
        elif "macos" in os_info or "darwin" in os_info:
            return "macos"
        return None
    
    async def _make_decision(
        self,
        original_task: Dict[str, Any],
        error_context: Dict[str, Any],
        execution_logs: List[Dict[str, Any]],
        category: str,
        strategy: Dict[str, Any],
        context: Dict[str, Any],
        retry_count: int,
        max_retries: int
    ) -> Dict[str, Any]:
        """
        Make a decision about how to handle the failed task.
        
        Decision options:
        - retry: Retry the same task
        - modify_approach: Retry with different parameters/module
        - skip: Skip this task and move on
        - escalate: Escalate for human/LLM review
        - ask_approval: HITL - Request user approval for high-risk action
        """
        # ═══════════════════════════════════════════════════════════
        # HITL: Check if this is a high-risk action requiring approval
        # ═══════════════════════════════════════════════════════════
        is_high_risk, risk_reason, risk_level = self._is_high_risk_action(original_task, context)
        if is_high_risk:
            self.logger.warning(f"⚠️ High-risk action detected: {risk_reason}")
            return await self._create_approval_request(
                original_task, context, risk_reason, risk_level
            )
        
        # Check if LLM analysis is available and needed
        if self.llm_enabled and self._needs_llm_analysis(category, context):
            return await self._llm_decision(
                original_task, error_context, execution_logs, context
            )
        
        # Rule-based decision making
        detected_defenses = context.get("detected_defenses", [])
        
        # Defense detected - try alternatives or skip
        if category == "defense":
            if context["alternative_modules"]:
                self._stats["modifications_recommended"] += 1
                return {
                    "decision": "modify_approach",
                    "reasoning": f"Defense detected ({detected_defenses}). Trying alternative module.",
                    "new_module": context["alternative_modules"][0].get("rx_module_id"),
                    "modified_parameters": {
                        "use_evasion": True,
                        "encode_payload": True
                    },
                    "recommendations": strategy["recommendations"]
                }
            else:
                self._stats["skips_recommended"] += 1
                return {
                    "decision": "skip",
                    "reasoning": f"Defense detected ({detected_defenses}) and no alternatives available.",
                    "recommendations": strategy["recommendations"]
                }
        
        # Vulnerability patched - skip
        if category == "vulnerability":
            self._stats["skips_recommended"] += 1
            return {
                "decision": "skip",
                "reasoning": "Target appears to be patched or not vulnerable.",
                "recommendations": strategy["recommendations"]
            }
        
        # Network issues - retry if within limits
        if category == "network" and retry_count < max_retries:
            self._stats["retries_recommended"] += 1
            return {
                "decision": "retry",
                "reasoning": f"Network issue - retry attempt {retry_count + 1}/{max_retries}",
                "delay_seconds": strategy["retry_delay"],
                "recommendations": strategy["recommendations"]
            }
        
        # Authentication failed - try different approach
        if category == "authentication":
            if retry_count < max_retries:
                self._stats["retries_recommended"] += 1
                return {
                    "decision": "retry",
                    "reasoning": "Authentication failed - may be transient",
                    "delay_seconds": strategy["retry_delay"],
                    "recommendations": strategy["recommendations"]
                }
            else:
                self._stats["modifications_recommended"] += 1
                return {
                    "decision": "modify_approach",
                    "reasoning": "Authentication persistently failing - need different credentials",
                    "modified_parameters": {
                        "harvest_more_creds": True
                    },
                    "recommendations": strategy["recommendations"]
                }
        
        # Technical error - retry or escalate
        if category == "technical":
            if retry_count < max_retries:
                self._stats["retries_recommended"] += 1
                return {
                    "decision": "retry",
                    "reasoning": "Technical error - may be transient",
                    "delay_seconds": strategy["retry_delay"],
                    "recommendations": strategy["recommendations"]
                }
            else:
                self._stats["escalations"] += 1
                return {
                    "decision": "escalate",
                    "reasoning": "Persistent technical error - needs manual review",
                    "escalation_reason": error_context.get("error_message", "Unknown error"),
                    "recommendations": strategy["recommendations"]
                }
        
        # Unknown error - escalate
        self._stats["escalations"] += 1
        return {
            "decision": "escalate",
            "reasoning": "Unknown error type - needs investigation",
            "escalation_reason": error_context.get("error_message", "Unknown error"),
            "recommendations": strategy["recommendations"]
        }
    
    def _needs_llm_analysis(self, category: str, context: Dict[str, Any]) -> bool:
        """Determine if this failure needs LLM analysis."""
        # Complex defense scenarios benefit from LLM reasoning
        if category == "defense" and len(context.get("detected_defenses", [])) > 1:
            return True
        
        # Multiple alternatives need intelligent selection
        if len(context.get("alternative_modules", [])) > 3:
            return True
        
        return False
    
    def _is_high_risk_action(self, task: Dict[str, Any], context: Dict[str, Any]) -> tuple[bool, str, RiskLevel]:
        """
        Determine if an action is high-risk and requires user approval.
        
        HITL: This is used to identify actions that should trigger ASK_APPROVAL.
        
        Returns:
            Tuple of (is_high_risk, reason, risk_level)
        """
        task_type = task.get("type", "")
        module = task.get("rx_module", "") or ""
        
        # Critical risk: Destructive operations
        destructive_modules = [
            "delete", "wipe", "destroy", "format", "ransom",
            "rm -rf", "diskpart", "fdisk"
        ]
        if any(d in module.lower() for d in destructive_modules):
            return True, "Potentially destructive operation", RiskLevel.CRITICAL
        
        # High risk: Persistence mechanisms
        persistence_modules = [
            "persistence", "backdoor", "rootkit", "scheduled_task",
            "registry", "startup", "service"
        ]
        if any(p in module.lower() for p in persistence_modules):
            return True, "Installing persistence mechanism", RiskLevel.HIGH
        
        # High risk: Privilege escalation to SYSTEM/root
        if task_type == "privesc":
            return True, "Privilege escalation attempt", RiskLevel.HIGH
        
        # High risk: Data exfiltration
        exfil_modules = [
            "exfil", "upload", "transfer", "extract", "dump",
            "copy_data", "steal"
        ]
        if any(e in module.lower() for e in exfil_modules):
            return True, "Data extraction/exfiltration", RiskLevel.HIGH
        
        # Medium risk: Lateral movement
        if task_type == "lateral":
            return True, "Lateral movement to new target", RiskLevel.MEDIUM
        
        # Medium risk: Write operations on target
        write_modules = [
            "write", "create", "modify", "change", "edit",
            "append", "patch"
        ]
        if any(w in module.lower() for w in write_modules):
            return True, "Write operation on target system", RiskLevel.MEDIUM
        
        # Not high-risk
        return False, "", RiskLevel.LOW
    
    async def _create_approval_request(
        self,
        original_task: Dict[str, Any],
        context: Dict[str, Any],
        risk_reason: str,
        risk_level: RiskLevel
    ) -> Dict[str, Any]:
        """
        Create an approval request for a high-risk action.
        
        This is the HITL integration point where we pause execution
        and wait for user consent.
        """
        self.logger.info(f"🔐 Creating approval request: {risk_reason}")
        
        # Determine action type from task
        task_type = original_task.get("type", "")
        if "exploit" in task_type.lower():
            action_type = ActionType.EXPLOIT
        elif "lateral" in task_type.lower():
            action_type = ActionType.LATERAL_MOVEMENT
        elif "privesc" in task_type.lower():
            action_type = ActionType.PRIVILEGE_ESCALATION
        elif "persistence" in task_type.lower():
            action_type = ActionType.PERSISTENCE
        else:
            action_type = ActionType.WRITE_OPERATION
        
        # Get target info
        target_info = context.get("target_info") or {}
        
        # Create approval action
        approval_action = ApprovalAction(
            mission_id=self._safe_uuid(self._current_mission_id) if self._current_mission_id else uuid4(),
            task_id=self._safe_uuid(original_task["id"].replace("task:", "")) if original_task.get("id") else None,
            action_type=action_type,
            action_description=f"{task_type}: {risk_reason}",
            target_ip=target_info.get("ip"),
            target_hostname=target_info.get("hostname"),
            risk_level=risk_level,
            risk_reasons=[risk_reason],
            potential_impact=f"This action may {risk_reason.lower()}. Please review before proceeding.",
            module_to_execute=original_task.get("rx_module"),
            command_preview=original_task.get("result_data", {}).get("command_preview"),
            parameters=original_task.get("result_data", {})
        )
        
        # Publish approval request event
        if self.blackboard and self._current_mission_id:
            event = ApprovalRequestEvent(
                mission_id=self._safe_uuid(self._current_mission_id),
                action_id=approval_action.id,
                action_type=action_type,
                action_description=approval_action.action_description,
                target_ip=approval_action.target_ip,
                target_hostname=approval_action.target_hostname,
                risk_level=risk_level,
                risk_reasons=approval_action.risk_reasons,
                potential_impact=approval_action.potential_impact,
                command_preview=approval_action.command_preview
            )
            
            channel = self.blackboard.get_channel(self._current_mission_id, "approvals")
            await self.blackboard.publish_event(channel, event)
            
            self.logger.info(f"📡 Published approval request: {approval_action.id}")
        
        # Return decision to wait for approval
        return {
            "decision": "ask_approval",
            "reasoning": f"High-risk action detected: {risk_reason}. Waiting for user approval.",
            "requires_approval": True,
            "approval_action_id": str(approval_action.id),
            "risk_level": risk_level.value,
            "risk_reason": risk_reason,
            "recommendations": [
                "Review the proposed action carefully",
                "Consider the potential impact on the target system",
                "Approve only if the action aligns with mission objectives"
            ]
        }
    
    async def _llm_decision(
        self,
        original_task: Dict[str, Any],
        error_context: Dict[str, Any],
        execution_logs: List[Dict[str, Any]],
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Make decision using LLM analysis.
        
        Uses the LLM service to analyze the failure and recommend
        the best course of action.
        
        Includes safety checks to prevent runaway API costs.
        """
        self.logger.info("🧠 Performing LLM-assisted analysis...")
        
        # ═══════════════════════════════════════════════════════════
        # SAFETY CHECK - Verify limits before calling LLM API
        # ═══════════════════════════════════════════════════════════
        is_safe, reason = self._check_safety_limits()
        if not is_safe:
            self.logger.warning(f"⚠️ Safety limit reached: {reason}")
            self.logger.warning("⚠️ Falling back to rule-based analysis to prevent cost overrun")
            self._stats["safety_limit_breaches"] += 1
            self._stats["rule_based_fallbacks"] += 1
            return self._rule_based_fallback(original_task, error_context, context)
        
        # Get LLM service
        llm_service = await self._ensure_llm_service()
        if not llm_service or not llm_service.providers:
            self.logger.warning("LLM service not available, falling back to rule-based")
            self._stats["rule_based_fallbacks"] += 1
            return self._rule_based_fallback(original_task, error_context, context)
        
        try:
            # Build analysis request
            from ..core.llm.models import (
                AnalysisRequest,
                TaskContext,
                ExecutionContext,
                ErrorDetails,
                AvailableModule,
            )
            
            # Extract target info
            target_info = context.get("target_info") or {}
            
            # Build request
            request = AnalysisRequest(
                task=TaskContext(
                    task_id=original_task.get("id", "unknown"),
                    task_type=original_task.get("type", "UNKNOWN"),
                    target_ip=target_info.get("ip"),
                    target_hostname=target_info.get("hostname"),
                    target_os=target_info.get("os"),
                    target_platform=self._get_target_platform(target_info),
                ),
                execution=ExecutionContext(
                    module_used=error_context.get("module_used"),
                    technique_id=error_context.get("technique_id"),
                    command_executed=error_context.get("command"),
                    exit_code=error_context.get("exit_code"),
                    duration_ms=error_context.get("duration_ms"),
                ),
                error=ErrorDetails(
                    error_type=error_context.get("error_type", "unknown"),
                    error_message=error_context.get("error_message", ""),
                    stderr=error_context.get("stderr"),
                    stdout=error_context.get("stdout"),
                    detected_defenses=context.get("detected_defenses", []),
                ),
                retry_count=original_task.get("retry_count", 0),
                max_retries=original_task.get("max_retries", 3),
                available_modules=[
                    AvailableModule(
                        rx_module_id=m.get("rx_module_id", m.get("id", "")),
                        name=m.get("name", ""),
                        description=m.get("description"),
                        technique_id=m.get("technique_id"),
                        supports_evasion=m.get("supports_evasion", False),
                        success_rate=m.get("success_rate"),
                    )
                    for m in context.get("alternative_modules", [])
                ],
                mission_goals=self._get_mission_goals(),
            )
            
            # Call LLM service
            self.logger.info(f"📡 Calling LLM API (request #{self._mission_llm_requests + 1})...")
            response = await llm_service.analyze_failure(request)
            
            # Update usage tracking AFTER successful call
            tokens_used = response.tokens_used if response.tokens_used else 0
            self._update_usage_tracking(tokens_used)
            
            # Log usage info
            self.logger.info(
                f"🧠 LLM Response received: "
                f"tokens={tokens_used}, "
                f"latency={response.latency_ms:.0f}ms, "
                f"model={response.model_used}"
            )
            self.logger.info(
                f"💰 Usage: requests={self._mission_llm_requests}/{self._settings.llm_mission_requests_limit}, "
                f"est_cost=${self._mission_estimated_cost:.4f}/${self._settings.llm_max_cost_limit:.2f}"
            )
            
            if response.success and response.analysis:
                self._stats["llm_analyses"] += 1
                
                # Convert LLM response to decision dict
                analysis = response.analysis
                action = analysis.recommended_action
                
                decision = {
                    "decision": action.decision.value,
                    "reasoning": action.reasoning,
                    "delay_seconds": action.delay_seconds,
                    "recommendations": analysis.additional_recommendations,
                    "lessons_learned": analysis.lessons_learned,
                    "llm_analysis": True,
                    "model_used": response.model_used,
                    "tokens_used": tokens_used,
                    "latency_ms": response.latency_ms,
                    "estimated_cost_usd": round(self._mission_estimated_cost, 4),
                    "root_cause": {
                        "category": analysis.analysis.category.value,
                        "cause": analysis.analysis.root_cause,
                        "confidence": analysis.analysis.confidence.value,
                        "detected_defenses": [d.value for d in analysis.analysis.detected_defenses],
                    }
                }
                
                # Add decision-specific fields
                if action.decision.value == "modify_approach" and action.alternative_module:
                    decision["new_module"] = action.alternative_module.rx_module_id
                    decision["modified_parameters"] = action.modified_parameters
                    decision["evasion_techniques"] = action.alternative_module.evasion_techniques
                    self._stats["modifications_recommended"] += 1
                    
                elif action.decision.value == "retry":
                    self._stats["retries_recommended"] += 1
                    
                elif action.decision.value == "skip":
                    self._stats["skips_recommended"] += 1
                    
                elif action.decision.value == "escalate":
                    decision["escalation_reason"] = action.escalation_reason
                    decision["human_guidance_needed"] = action.human_guidance_needed
                    self._stats["escalations"] += 1
                    
                elif action.decision.value == "pivot":
                    decision["new_attack_vector"] = action.new_attack_vector
                    decision["new_technique_id"] = action.new_technique_id
                
                # Handle knowledge update if recommended
                if analysis.should_update_knowledge and analysis.knowledge_update:
                    await self._update_knowledge(analysis.knowledge_update)
                
                return decision
            
            else:
                # LLM failed, fall back to rules
                self.logger.warning(f"LLM analysis failed: {response.error}")
                self._stats["llm_failures"] += 1
                self._stats["rule_based_fallbacks"] += 1
                return self._rule_based_fallback(original_task, error_context, context)
            
        except Exception as e:
            self.logger.error(f"LLM analysis error: {e}")
            self._stats["llm_failures"] += 1
            self._stats["rule_based_fallbacks"] += 1
            return self._rule_based_fallback(original_task, error_context, context)
    
    def _rule_based_fallback(
        self,
        original_task: Dict[str, Any],
        error_context: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Rule-based fallback when LLM is unavailable or fails.
        """
        category = self._categorize_error(error_context.get("error_type", "unknown"))
        strategy = self.RETRY_STRATEGIES.get(category, self.RETRY_STRATEGIES["unknown"])
        
        # Simple rule-based decision
        if context.get("alternative_modules"):
            self._stats["modifications_recommended"] += 1
            return {
                "decision": "modify_approach",
                "reasoning": f"LLM unavailable. Rule-based: trying alternative module for {category} error.",
                "new_module": context["alternative_modules"][0].get("rx_module_id"),
                "recommendations": strategy["recommendations"],
                "llm_analysis": False,
            }
        
        retry_count = original_task.get("retry_count", 0)
        max_retries = strategy["max_retries"]
        
        if retry_count < max_retries:
            self._stats["retries_recommended"] += 1
            return {
                "decision": "retry",
                "reasoning": f"LLM unavailable. Rule-based: retry {retry_count + 1}/{max_retries}",
                "delay_seconds": strategy["retry_delay"],
                "recommendations": strategy["recommendations"],
                "llm_analysis": False,
            }
        
        self._stats["escalations"] += 1
        return {
            "decision": "escalate",
            "reasoning": "LLM unavailable and retries exhausted. Escalating for review.",
            "escalation_reason": error_context.get("error_message", "Unknown error"),
            "recommendations": strategy["recommendations"],
            "llm_analysis": False,
        }
    
    def _get_mission_goals(self) -> List[str]:
        """Get current mission goals."""
        # This would be fetched from the blackboard in production
        return [
            "Gain initial access to target network",
            "Achieve persistence on compromised hosts",
            "Harvest credentials for lateral movement",
        ]
    
    async def _update_knowledge(self, knowledge_update: str) -> None:
        """Update knowledge base with learned information."""
        self.logger.info(f"Knowledge update: {knowledge_update}")
        # In production, this would update the knowledge base
        # For now, just log it
        if self.blackboard and self._current_mission_id:
            await self.blackboard.log_result(
                self._current_mission_id,
                "knowledge_update",
                {"update": knowledge_update}
            )
    
    async def _publish_analysis_result(
        self,
        original_task_id: str,
        original_task: Dict[str, Any],
        decision: Dict[str, Any]
    ) -> None:
        """Publish analysis result event."""
        if not self._current_mission_id:
            return
        
        event = TaskAnalysisResultEvent(
            mission_id=UUID(self._current_mission_id),
            original_task_id=UUID(original_task_id.replace("task:", "")),
            decision=decision["decision"],
            reasoning=decision["reasoning"],
            modified_parameters=decision.get("modified_parameters", {}),
            escalation_reason=decision.get("escalation_reason")
        )
        
        await self.publish_event(event)
    
    # ═══════════════════════════════════════════════════════════
    # Event Handling
    # ═══════════════════════════════════════════════════════════
    
    async def on_event(self, event: Dict[str, Any]) -> None:
        """Handle Pub/Sub events."""
        event_type = event.get("event")
        
        if event_type == "task_failed":
            # Task failed - analyze it
            await self._handle_task_failed(event)
        
        elif event_type == "analysis_request":
            # Explicit analysis request
            await self._handle_analysis_request(event)
        
        elif event_type == "control":
            command = event.get("command")
            if command == "pause":
                await self.pause()
            elif command == "resume":
                await self.resume()
            elif command == "stop":
                await self.stop()
    
    async def _handle_task_failed(self, event: Dict[str, Any]) -> None:
        """Handle a TaskFailedEvent."""
        task_id = event.get("task_id")
        if not task_id:
            return
        
        self.logger.info(f"Received task_failed event for task {task_id}")
        
        # Extract error context from event
        error_context = {
            "error_type": event.get("error_type", "unknown"),
            "error_message": event.get("error_message", ""),
            "technique_id": event.get("technique_id"),
            "module_used": event.get("module_used"),
            "detected_defenses": event.get("detected_defenses", [])
        }
        
        # Perform analysis
        result = await self.analyze_failure(
            task_id=str(task_id),
            error_context=error_context,
            execution_logs=[]  # Would be fetched from task
        )
        
        self.logger.info(f"Analysis complete for task {task_id}: {result['decision']}")
        
        # Handle the decision
        await self._execute_decision(task_id, result)
    
    async def _handle_analysis_request(self, event: Dict[str, Any]) -> None:
        """Handle a TaskAnalysisRequestEvent."""
        task_id = event.get("task_id")
        if not task_id:
            return
        
        self.logger.info(f"Received analysis_request for task {task_id}")
        
        # Perform analysis
        result = await self.analyze_failure(
            task_id=str(task_id),
            error_context=event.get("error_context", {}),
            execution_logs=event.get("execution_logs", [])
        )
        
        # Handle the decision
        await self._execute_decision(task_id, result)
    
    async def _execute_decision(
        self,
        original_task_id: str,
        decision: Dict[str, Any]
    ) -> None:
        """
        Execute the analysis decision.
        
        This creates retry tasks, updates task status, etc.
        """
        decision_type = decision["decision"]
        
        if decision_type == "retry":
            await self._create_retry_task(original_task_id, decision)
        
        elif decision_type == "modify_approach":
            await self._create_modified_task(original_task_id, decision)
        
        elif decision_type == "skip":
            self.logger.info(f"Skipping task {original_task_id}: {decision['reasoning']}")
        
        elif decision_type == "escalate":
            await self._escalate_task(original_task_id, decision)
        
        elif decision_type == "ask_approval":
            # HITL: Waiting for user approval - no action needed here
            # The approval request has already been published
            self.logger.info(
                f"🔐 Task {original_task_id} awaiting user approval: "
                f"{decision.get('risk_reason', 'High-risk action')}"
            )
    
    async def _create_retry_task(
        self,
        original_task_id: str,
        decision: Dict[str, Any]
    ) -> None:
        """Create a retry task."""
        original_task = await self.blackboard.get_task(original_task_id)
        if not original_task:
            return
        
        # Schedule retry with delay
        delay = decision.get("delay_seconds", 30)
        
        self.logger.info(
            f"Scheduling retry for task {original_task_id} in {delay}s"
        )
        
        # Create new task with incremented retry count
        retry_count = original_task.get("retry_count", 0) + 1
        
        await self.create_task(
            task_type=TaskType(original_task["type"]),
            target_specialist=SpecialistType(original_task["specialist"]),
            priority=original_task.get("priority", 5),
            target_id=original_task.get("target_id"),
            vuln_id=original_task.get("vuln_id"),
            cred_id=original_task.get("cred_id"),
            rx_module=original_task.get("rx_module"),
            retry_count=retry_count,
            parent_task_id=original_task_id
        )
    
    async def _create_modified_task(
        self,
        original_task_id: str,
        decision: Dict[str, Any]
    ) -> None:
        """Create a modified retry task with different parameters."""
        original_task = await self.blackboard.get_task(original_task_id)
        if not original_task:
            return
        
        # Get modifications
        new_module = decision.get("new_module")
        modified_params = decision.get("modified_parameters", {})
        
        self.logger.info(
            f"Creating modified task for {original_task_id} with module {new_module}"
        )
        
        await self.create_task(
            task_type=TaskType(original_task["type"]),
            target_specialist=SpecialistType(original_task["specialist"]),
            priority=original_task.get("priority", 5) + 1,  # Slight priority boost
            target_id=original_task.get("target_id"),
            vuln_id=original_task.get("vuln_id"),
            cred_id=original_task.get("cred_id"),
            rx_module=new_module or original_task.get("rx_module"),
            parent_task_id=original_task_id,
            **modified_params
        )
    
    async def _escalate_task(
        self,
        original_task_id: str,
        decision: Dict[str, Any]
    ) -> None:
        """Escalate a task for manual/LLM review."""
        self.logger.warning(
            f"Escalating task {original_task_id}: {decision.get('escalation_reason')}"
        )
        
        # Log the escalation
        await self.blackboard.log_result(
            self._current_mission_id,
            "task_escalated",
            {
                "task_id": original_task_id,
                "reason": decision.get("escalation_reason"),
                "reasoning": decision["reasoning"],
                "recommendations": decision.get("recommendations", [])
            }
        )
    
    # ═══════════════════════════════════════════════════════════
    # Channel Subscriptions
    # ═══════════════════════════════════════════════════════════
    
    def _get_channels_to_subscribe(self, mission_id: str) -> List[str]:
        """Get channels for Analysis specialist."""
        return [
            self.blackboard.get_channel(mission_id, "tasks"),
            self.blackboard.get_channel(mission_id, "failures"),  # Task failures
            self.blackboard.get_channel(mission_id, "analysis"),  # Analysis requests
            self.blackboard.get_channel(mission_id, "control"),
        ]
    
    # ═══════════════════════════════════════════════════════════
    # Statistics and Reporting
    # ═══════════════════════════════════════════════════════════
    
    def get_stats(self) -> Dict[str, Any]:
        """Get analysis statistics."""
        return {
            **self._stats,
            "analysis_history_size": len(self._analysis_history)
        }
    
    def get_recent_analyses(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent analysis records."""
        return self._analysis_history[-limit:]
    
    def clear_history(self) -> None:
        """Clear analysis history."""
        self._analysis_history.clear()
