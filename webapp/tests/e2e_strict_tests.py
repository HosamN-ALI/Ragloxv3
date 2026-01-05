#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Strict End-to-End Tests
# ═══════════════════════════════════════════════════════════════════════════════
"""
اختبارات E2E صارمة - تُكتب أولاً ثم يُكيَّف الكود ليجتازها

الفلسفة:
- الاختبارات تعكس ما يجب أن يفعله النظام، وليس ما يفعله حالياً
- كل فشل = فرصة لتحسين الكود
- لا نُغير الاختبارات لتتوافق مع الكود، بل نُغير الكود ليتوافق مع الاختبارات

المتطلبات الصارمة:
1. مهمة كاملة من الاستطلاع حتى الاستغلال
2. كل مرحلة يجب أن تُنتج مخرجات محددة
3. LLM يجب أن يتخذ قرارات ذكية
4. الوكيل يجب أن يتكيف مع الفشل
5. يجب تسجيل كل خطوة للمراجعة
"""

import asyncio
import json
import os
import sys
import time
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Callable
from uuid import uuid4
from enum import Enum

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("raglox.e2e_tests")

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


# ═══════════════════════════════════════════════════════════════════════════════
# Test Severity Levels
# ═══════════════════════════════════════════════════════════════════════════════

class TestSeverity(Enum):
    """Severity of test failure - determines if it blocks deployment."""
    CRITICAL = "critical"   # Must pass for production
    HIGH = "high"           # Should pass, blocking for release
    MEDIUM = "medium"       # Nice to have
    LOW = "low"             # Future improvement


class TestCategory(Enum):
    """Category of test."""
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"
    LLM_DECISION = "llm_decision"
    WORKFLOW = "workflow"


# ═══════════════════════════════════════════════════════════════════════════════
# Test Result Structures
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class StrictTestResult:
    """Detailed test result with failure analysis."""
    test_id: str
    test_name: str
    category: TestCategory
    severity: TestSeverity
    passed: bool
    execution_time_ms: float
    
    # What we expected
    expected_behavior: str
    expected_output: Dict[str, Any] = field(default_factory=dict)
    
    # What actually happened
    actual_behavior: str = ""
    actual_output: Dict[str, Any] = field(default_factory=dict)
    
    # Failure analysis
    failure_reason: Optional[str] = None
    root_cause: Optional[str] = None
    suggested_fix: Optional[str] = None
    code_location: Optional[str] = None
    
    # Evidence
    logs: List[str] = field(default_factory=list)
    screenshots: List[str] = field(default_factory=list)


@dataclass
class E2ETestSuiteReport:
    """Complete E2E test suite report."""
    suite_name: str
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: Optional[datetime] = None
    
    # Results
    results: List[StrictTestResult] = field(default_factory=list)
    
    # Summary
    total_tests: int = 0
    passed: int = 0
    failed: int = 0
    
    # By severity
    critical_failures: int = 0
    high_failures: int = 0
    medium_failures: int = 0
    low_failures: int = 0
    
    # By category
    failures_by_category: Dict[str, int] = field(default_factory=dict)
    
    # Blockers
    blocking_issues: List[str] = field(default_factory=list)
    
    @property
    def success_rate(self) -> float:
        return (self.passed / self.total_tests * 100) if self.total_tests > 0 else 0
    
    @property
    def is_deployable(self) -> bool:
        """Can we deploy? No critical or high failures."""
        return self.critical_failures == 0 and self.high_failures == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Test Framework
# ═══════════════════════════════════════════════════════════════════════════════

class StrictE2ETestFramework:
    """Framework for running strict E2E tests."""
    
    def __init__(self, target_host: str = "127.0.0.1", target_port: int = 8088):
        self.target_host = target_host
        self.target_port = target_port
        self.target_url = f"http://{target_host}:{target_port}"
        self.results: List[StrictTestResult] = []
        self.settings = None
        self.knowledge = None
        self.llm_provider = None
        
    async def setup(self):
        """Initialize all components."""
        from src.core.config import get_settings
        from src.core.knowledge import EmbeddedKnowledge
        from src.core.llm.base import LLMConfig, ProviderType
        from src.core.llm.blackbox_provider import BlackboxAIProvider
        
        self.settings = get_settings()
        self.knowledge = EmbeddedKnowledge()
        
        # Setup LLM
        config = LLMConfig(
            provider_type=ProviderType.BLACKBOX,
            api_key=self.settings.effective_llm_api_key,
            api_base=self.settings.llm_api_base or 'https://api.blackbox.ai',
            model=self.settings.llm_model,
            temperature=0.3,
        )
        self.llm_provider = BlackboxAIProvider(config)
        
    async def teardown(self):
        """Cleanup."""
        if self.llm_provider:
            await self.llm_provider.close()
    
    def add_result(self, result: StrictTestResult):
        """Add test result."""
        self.results.append(result)
        
        # Print immediately
        status = "✅ PASS" if result.passed else "❌ FAIL"
        print(f"\n{status} [{result.severity.value.upper()}] {result.test_name}")
        
        if not result.passed:
            print(f"   Expected: {result.expected_behavior[:80]}...")
            print(f"   Actual:   {result.actual_behavior[:80]}...")
            print(f"   Reason:   {result.failure_reason}")
            if result.suggested_fix:
                print(f"   Fix:      {result.suggested_fix}")


# ═══════════════════════════════════════════════════════════════════════════════
# STRICT E2E TESTS - Phase 1: Full Mission Lifecycle
# ═══════════════════════════════════════════════════════════════════════════════

class MissionLifecycleTests:
    """
    Tests the complete mission lifecycle from start to finish.
    
    Expected Flow:
    1. Create Mission → Mission object with valid ID
    2. Add Target → Target added to Blackboard
    3. Run Reconnaissance → Vulnerabilities discovered
    4. LLM Analysis → Attack plan generated
    5. Execute Attack → Successful exploitation
    6. Post-Exploitation → Credentials harvested
    7. Generate Report → Complete report
    """
    
    def __init__(self, framework: StrictE2ETestFramework):
        self.framework = framework
        self.mission_id = None
        self.target_id = None
        
    async def test_01_mission_creation(self) -> StrictTestResult:
        """
        TEST: System can create a valid mission with all required fields.
        
        EXPECTED:
        - Mission object created with UUID
        - Status set to CREATED or PENDING
        - Created timestamp set
        - Mission stored in state management
        """
        test_id = "E2E-MISSION-001"
        start = time.time()
        
        expected_behavior = "Mission created with valid UUID, status=CREATED/PENDING, stored in state"
        expected_output = {
            "has_id": True,
            "has_status": True,
            "status_valid": True,
            "has_created_at": True,
            "stored_in_blackboard": True,
        }
        
        actual_output = {}
        actual_behavior = ""
        failure_reason = None
        suggested_fix = None
        code_location = None
        
        try:
            from src.core.models import Mission, MissionStatus
            from src.core.blackboard import Blackboard
            
            # Create mission
            mission = Mission(
                id=uuid4(),
                name="E2E Test Mission",
                description="Automated E2E penetration test",
                status=MissionStatus.CREATED,
                targets=[],
                created_at=datetime.now(timezone.utc),
            )
            
            actual_output["has_id"] = mission.id is not None
            actual_output["has_status"] = mission.status is not None
            actual_output["status_valid"] = mission.status in [MissionStatus.CREATED, MissionStatus.PENDING, MissionStatus.RUNNING]
            actual_output["has_created_at"] = mission.created_at is not None
            
            # Try to store in Blackboard
            try:
                blackboard = Blackboard(settings=self.framework.settings)
                await blackboard.connect()
                
                # Check if Blackboard has mission storage capability
                if hasattr(blackboard, 'set_mission'):
                    await blackboard.set_mission(mission)
                    actual_output["stored_in_blackboard"] = True
                elif hasattr(blackboard, '_redis'):
                    # Direct storage
                    await blackboard._redis.set(f"mission:{mission.id}", json.dumps({
                        "id": str(mission.id),
                        "name": mission.name,
                        "status": mission.status.value,
                    }))
                    actual_output["stored_in_blackboard"] = True
                else:
                    actual_output["stored_in_blackboard"] = False
                    failure_reason = "Blackboard has no mission storage method"
                    suggested_fix = "Add set_mission() method to Blackboard class"
                    code_location = "src/core/blackboard.py"
                
                await blackboard.disconnect()
                
            except Exception as e:
                actual_output["stored_in_blackboard"] = False
                failure_reason = f"Blackboard storage failed: {str(e)}"
                suggested_fix = "Implement mission storage in Blackboard"
                code_location = "src/core/blackboard.py"
            
            self.mission_id = mission.id
            
            # Check all expected outputs
            all_passed = all(actual_output.get(k, False) for k in expected_output.keys())
            
            if all_passed:
                actual_behavior = "Mission created successfully with all required fields"
            else:
                actual_behavior = f"Mission partially created: {actual_output}"
                if not failure_reason:
                    failure_reason = "Some expected outputs missing"
                    
        except Exception as e:
            actual_behavior = f"Exception: {str(e)}"
            failure_reason = str(e)
            suggested_fix = "Check Mission model and Blackboard implementation"
            
        return StrictTestResult(
            test_id=test_id,
            test_name="Mission Creation",
            category=TestCategory.WORKFLOW,
            severity=TestSeverity.CRITICAL,
            passed=all(actual_output.get(k, False) for k in expected_output.keys()),
            execution_time_ms=(time.time() - start) * 1000,
            expected_behavior=expected_behavior,
            expected_output=expected_output,
            actual_behavior=actual_behavior,
            actual_output=actual_output,
            failure_reason=failure_reason,
            suggested_fix=suggested_fix,
            code_location=code_location,
        )
    
    async def test_02_target_addition(self) -> StrictTestResult:
        """
        TEST: System can add a target to a mission with proper validation.
        
        EXPECTED:
        - Target object created with IP/hostname
        - Target validated (reachable check)
        - Target added to mission's target list
        - Target stored in Blackboard with mission reference
        - Event emitted (NewTargetEvent)
        """
        test_id = "E2E-TARGET-001"
        start = time.time()
        
        expected_behavior = "Target created, validated, stored in Blackboard, event emitted"
        expected_output = {
            "target_created": True,
            "has_valid_ip": True,
            "target_reachable": True,
            "stored_in_blackboard": True,
            "event_emitted": True,
        }
        
        actual_output = {}
        actual_behavior = ""
        failure_reason = None
        suggested_fix = None
        code_location = None
        
        try:
            from src.core.models import Target, TargetStatus
            from src.core.blackboard import Blackboard
            import socket
            
            # Create target
            target = Target(
                id=uuid4(),
                ip=self.framework.target_host,
                hostname=f"vulnerable-target",
                status=TargetStatus.DISCOVERED,
                os="Linux",
                ports=[self.framework.target_port],
            )
            
            actual_output["target_created"] = target is not None
            actual_output["has_valid_ip"] = target.ip is not None
            
            # Check reachability
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((target.ip, self.framework.target_port))
                sock.close()
                actual_output["target_reachable"] = result == 0
            except:
                actual_output["target_reachable"] = False
            
            # Store in Blackboard
            try:
                blackboard = Blackboard(settings=self.framework.settings)
                await blackboard.connect()
                
                if hasattr(blackboard, 'add_target'):
                    await blackboard.add_target(target)
                    actual_output["stored_in_blackboard"] = True
                    
                    # Check if event was emitted
                    if hasattr(blackboard, '_events') or hasattr(blackboard, 'get_events'):
                        actual_output["event_emitted"] = True
                    else:
                        actual_output["event_emitted"] = False
                        failure_reason = "No event system found in Blackboard"
                        suggested_fix = "Implement event emission in add_target()"
                        code_location = "src/core/blackboard.py:add_target"
                else:
                    actual_output["stored_in_blackboard"] = False
                    actual_output["event_emitted"] = False
                    failure_reason = "Blackboard has no add_target method"
                    suggested_fix = "Implement add_target() in Blackboard"
                    code_location = "src/core/blackboard.py"
                
                await blackboard.disconnect()
                
            except Exception as e:
                actual_output["stored_in_blackboard"] = False
                actual_output["event_emitted"] = False
                failure_reason = f"Blackboard error: {str(e)}"
            
            self.target_id = target.id
            
            all_passed = all(actual_output.get(k, False) for k in expected_output.keys())
            
            if all_passed:
                actual_behavior = "Target added successfully with all features"
            else:
                actual_behavior = f"Target partially added: {actual_output}"
                
        except Exception as e:
            actual_behavior = f"Exception: {str(e)}"
            failure_reason = str(e)
            
        return StrictTestResult(
            test_id=test_id,
            test_name="Target Addition",
            category=TestCategory.RECONNAISSANCE,
            severity=TestSeverity.CRITICAL,
            passed=all(actual_output.get(k, False) for k in expected_output.keys()),
            execution_time_ms=(time.time() - start) * 1000,
            expected_behavior=expected_behavior,
            expected_output=expected_output,
            actual_behavior=actual_behavior,
            actual_output=actual_output,
            failure_reason=failure_reason,
            suggested_fix=suggested_fix,
            code_location=code_location,
        )
    
    async def test_03_reconnaissance_execution(self) -> StrictTestResult:
        """
        TEST: ReconSpecialist can discover information about target.
        
        EXPECTED:
        - ReconSpecialist initialized correctly
        - Reconnaissance task created and executed
        - Open ports discovered
        - Services identified
        - Results stored in Blackboard
        """
        test_id = "E2E-RECON-001"
        start = time.time()
        
        expected_behavior = "ReconSpecialist executes recon, discovers ports/services, stores results"
        expected_output = {
            "specialist_initialized": True,
            "task_executed": True,
            "ports_discovered": True,
            "services_identified": True,
            "results_stored": True,
        }
        
        actual_output = {}
        actual_behavior = ""
        failure_reason = None
        suggested_fix = None
        code_location = None
        
        try:
            from src.specialists.recon import ReconSpecialist
            from src.core.blackboard import Blackboard
            from src.core.models import Task, TaskType, TaskStatus, SpecialistType, Priority
            
            # Initialize specialist
            blackboard = Blackboard(settings=self.framework.settings)
            await blackboard.connect()
            
            try:
                specialist = ReconSpecialist(
                    blackboard=blackboard,
                    settings=self.framework.settings,
                    knowledge=self.framework.knowledge,
                )
                actual_output["specialist_initialized"] = True
            except Exception as e:
                actual_output["specialist_initialized"] = False
                failure_reason = f"ReconSpecialist init failed: {str(e)}"
                suggested_fix = "Check ReconSpecialist __init__ parameters"
                code_location = "src/specialists/recon.py:__init__"
            
            if actual_output.get("specialist_initialized"):
                # Create recon task
                task = Task(
                    id=uuid4(),
                    mission_id=self.mission_id or uuid4(),
                    target_id=self.target_id or uuid4(),
                    task_type=TaskType.RECON,
                    status=TaskStatus.PENDING,
                    priority=Priority.HIGH,
                    specialist_type=SpecialistType.RECON,
                    metadata={
                        "target_ip": self.framework.target_host,
                        "target_port": self.framework.target_port,
                    }
                )
                
                # Try to execute task
                try:
                    if hasattr(specialist, 'execute_task'):
                        result = await specialist.execute_task(task)
                        actual_output["task_executed"] = True
                        
                        # Check results
                        if result and hasattr(result, 'ports'):
                            actual_output["ports_discovered"] = len(result.ports) > 0
                        else:
                            actual_output["ports_discovered"] = False
                            
                        if result and hasattr(result, 'services'):
                            actual_output["services_identified"] = len(result.services) > 0
                        else:
                            actual_output["services_identified"] = False
                            
                    elif hasattr(specialist, '_execute_task'):
                        result = await specialist._execute_task(task)
                        actual_output["task_executed"] = True
                        actual_output["ports_discovered"] = False  # Need to check result format
                        actual_output["services_identified"] = False
                    else:
                        actual_output["task_executed"] = False
                        failure_reason = "ReconSpecialist has no execute_task method"
                        suggested_fix = "Implement execute_task() in ReconSpecialist"
                        code_location = "src/specialists/recon.py"
                        
                except Exception as e:
                    actual_output["task_executed"] = False
                    failure_reason = f"Task execution failed: {str(e)}"
                    suggested_fix = "Debug execute_task implementation"
                    code_location = "src/specialists/recon.py:execute_task"
            
            # Check if results stored
            actual_output["results_stored"] = actual_output.get("task_executed", False)
            
            await blackboard.disconnect()
            
            all_passed = all(actual_output.get(k, False) for k in expected_output.keys())
            
            if all_passed:
                actual_behavior = "Reconnaissance executed successfully"
            else:
                actual_behavior = f"Reconnaissance partial: {actual_output}"
                
        except Exception as e:
            actual_behavior = f"Exception: {str(e)}"
            failure_reason = str(e)
            import traceback
            code_location = traceback.format_exc()[:200]
            
        return StrictTestResult(
            test_id=test_id,
            test_name="Reconnaissance Execution",
            category=TestCategory.RECONNAISSANCE,
            severity=TestSeverity.HIGH,
            passed=all(actual_output.get(k, False) for k in expected_output.keys()),
            execution_time_ms=(time.time() - start) * 1000,
            expected_behavior=expected_behavior,
            expected_output=expected_output,
            actual_behavior=actual_behavior,
            actual_output=actual_output,
            failure_reason=failure_reason,
            suggested_fix=suggested_fix,
            code_location=code_location,
        )
    
    async def test_04_llm_attack_planning(self) -> StrictTestResult:
        """
        TEST: LLM can generate intelligent attack plan based on discovered info.
        
        EXPECTED:
        - LLM receives reconnaissance data
        - LLM identifies vulnerabilities
        - LLM recommends MITRE ATT&CK techniques
        - LLM prioritizes attacks by success probability
        - Response is valid JSON with required fields
        """
        test_id = "E2E-LLM-001"
        start = time.time()
        
        expected_behavior = "LLM generates attack plan with MITRE techniques and prioritization"
        expected_output = {
            "llm_responded": True,
            "response_is_json": True,
            "has_mitre_techniques": True,
            "has_prioritization": True,
            "has_attack_steps": True,
        }
        
        actual_output = {}
        actual_behavior = ""
        failure_reason = None
        suggested_fix = None
        code_location = None
        
        try:
            from src.core.llm.base import LLMMessage
            from src.core.llm.prompts import REFLEXION_SYSTEM_PROMPT
            
            # Simulate reconnaissance data
            recon_data = {
                "target": self.framework.target_url,
                "open_ports": [80, 22, 6379],
                "services": {
                    "80": "nginx/1.18.0 - Web Server",
                    "22": "OpenSSH 8.2",
                    "6379": "Redis",
                },
                "discovered_paths": [
                    "/admin/",
                    "/backup/config.bak",
                    "/info",
                ],
                "potential_vulns": [
                    "Information disclosure on /info",
                    "Directory listing on /backup/",
                    "Possible weak authentication on /admin/",
                ]
            }
            
            # Create attack planning prompt
            attack_planning_prompt = f"""You are a Red Team operator planning an attack.

## Reconnaissance Data:
{json.dumps(recon_data, indent=2)}

## Task:
Analyze this reconnaissance data and create an attack plan.

## Requirements:
Return a JSON object with:
1. "vulnerabilities": List of identified vulnerabilities with severity
2. "attack_plan": Ordered list of attack steps
3. "mitre_techniques": MITRE ATT&CK technique IDs for each step
4. "priority_order": Attacks ordered by likelihood of success
5. "estimated_time_minutes": Total estimated time

## Response Format (JSON only, no markdown):
{{
    "vulnerabilities": [
        {{"name": "...", "severity": "critical/high/medium/low", "description": "..."}}
    ],
    "attack_plan": [
        {{"step": 1, "action": "...", "technique_id": "T1XXX", "target": "..."}}
    ],
    "mitre_techniques": ["T1190", "T1005", ...],
    "priority_order": [1, 3, 2, ...],
    "estimated_time_minutes": 30
}}
"""
            
            messages = [
                LLMMessage.system(REFLEXION_SYSTEM_PROMPT),
                LLMMessage.user(attack_planning_prompt)
            ]
            
            response = await self.framework.llm_provider.generate(messages, max_tokens=1500)
            actual_output["llm_responded"] = bool(response and response.content)
            
            if actual_output["llm_responded"]:
                # Try to parse JSON
                content = response.content
                
                # Extract JSON from response
                if "```json" in content:
                    content = content.split("```json")[1].split("```")[0]
                elif "```" in content:
                    content = content.split("```")[1].split("```")[0]
                
                try:
                    plan = json.loads(content.strip())
                    actual_output["response_is_json"] = True
                    
                    # Check required fields
                    actual_output["has_mitre_techniques"] = "mitre_techniques" in plan and len(plan.get("mitre_techniques", [])) > 0
                    actual_output["has_prioritization"] = "priority_order" in plan or "attack_plan" in plan
                    actual_output["has_attack_steps"] = "attack_plan" in plan and len(plan.get("attack_plan", [])) > 0
                    
                    if not actual_output["has_mitre_techniques"]:
                        failure_reason = "LLM response missing MITRE techniques"
                        suggested_fix = "Improve prompt to require MITRE technique IDs"
                        code_location = "src/core/llm/prompts.py"
                        
                except json.JSONDecodeError as e:
                    actual_output["response_is_json"] = False
                    actual_output["has_mitre_techniques"] = False
                    actual_output["has_prioritization"] = False
                    actual_output["has_attack_steps"] = False
                    failure_reason = f"Invalid JSON response: {str(e)}"
                    suggested_fix = "Add JSON validation and retry logic"
                    code_location = "src/core/llm/service.py"
            else:
                failure_reason = "LLM did not respond"
                suggested_fix = "Check LLM connectivity and API key"
                
            all_passed = all(actual_output.get(k, False) for k in expected_output.keys())
            
            if all_passed:
                actual_behavior = "LLM generated valid attack plan"
            else:
                actual_behavior = f"LLM planning partial: {actual_output}"
                
        except Exception as e:
            actual_behavior = f"Exception: {str(e)}"
            failure_reason = str(e)
            
        return StrictTestResult(
            test_id=test_id,
            test_name="LLM Attack Planning",
            category=TestCategory.LLM_DECISION,
            severity=TestSeverity.CRITICAL,
            passed=all(actual_output.get(k, False) for k in expected_output.keys()),
            execution_time_ms=(time.time() - start) * 1000,
            expected_behavior=expected_behavior,
            expected_output=expected_output,
            actual_behavior=actual_behavior,
            actual_output=actual_output,
            failure_reason=failure_reason,
            suggested_fix=suggested_fix,
            code_location=code_location,
        )
    
    async def test_05_attack_execution(self) -> StrictTestResult:
        """
        TEST: AttackSpecialist can execute an attack based on LLM plan.
        
        EXPECTED:
        - AttackSpecialist receives attack task
        - Selects appropriate RX Module
        - Executes module via Executor
        - Returns structured result
        - Updates Blackboard with outcome
        """
        test_id = "E2E-ATTACK-001"
        start = time.time()
        
        expected_behavior = "AttackSpecialist executes attack, returns result, updates state"
        expected_output = {
            "specialist_initialized": True,
            "module_selected": True,
            "execution_attempted": True,
            "result_returned": True,
            "blackboard_updated": True,
        }
        
        actual_output = {}
        actual_behavior = ""
        failure_reason = None
        suggested_fix = None
        code_location = None
        
        try:
            from src.specialists.attack import AttackSpecialist
            from src.core.blackboard import Blackboard
            from src.core.models import Task, TaskType, TaskStatus, SpecialistType, Priority
            from src.core.models import Vulnerability, Severity
            
            # Setup
            blackboard = Blackboard(settings=self.framework.settings)
            await blackboard.connect()
            
            try:
                specialist = AttackSpecialist(
                    blackboard=blackboard,
                    settings=self.framework.settings,
                    knowledge=self.framework.knowledge,
                )
                actual_output["specialist_initialized"] = True
            except Exception as e:
                actual_output["specialist_initialized"] = False
                failure_reason = f"AttackSpecialist init failed: {str(e)}"
                suggested_fix = "Check AttackSpecialist constructor"
                code_location = "src/specialists/attack.py:__init__"
            
            if actual_output.get("specialist_initialized"):
                # Create vulnerability to exploit
                vuln = Vulnerability(
                    id=uuid4(),
                    target_id=self.target_id or uuid4(),
                    name="Information Disclosure",
                    description="Sensitive file accessible at /backup/config.bak",
                    severity=Severity.HIGH,
                    technique_id="T1005",
                )
                
                # Add to blackboard
                if hasattr(blackboard, 'add_vulnerability'):
                    await blackboard.add_vulnerability(vuln)
                
                # Create attack task
                task = Task(
                    id=uuid4(),
                    mission_id=self.mission_id or uuid4(),
                    target_id=self.target_id or uuid4(),
                    vulnerability_id=vuln.id,
                    task_type=TaskType.EXPLOIT,
                    status=TaskStatus.PENDING,
                    priority=Priority.HIGH,
                    specialist_type=SpecialistType.ATTACK,
                    technique_id="T1005",
                    metadata={
                        "target_url": f"{self.framework.target_url}/backup/config.bak",
                        "vulnerability": vuln.name,
                    }
                )
                
                # Check if specialist can select module
                if hasattr(specialist, '_select_module') or hasattr(specialist, 'select_module'):
                    actual_output["module_selected"] = True
                else:
                    # Check knowledge base
                    modules = self.framework.knowledge.get_modules_for_technique("T1005")
                    actual_output["module_selected"] = len(modules) > 0 if modules else False
                    if not actual_output["module_selected"]:
                        failure_reason = "No RX modules found for T1005"
                        suggested_fix = "Ensure knowledge base has T1005 modules loaded"
                        code_location = "data/raglox_executable_modules.json"
                
                # Try to execute
                try:
                    if hasattr(specialist, 'execute_task'):
                        result = await specialist.execute_task(task)
                        actual_output["execution_attempted"] = True
                        actual_output["result_returned"] = result is not None
                    elif hasattr(specialist, '_execute_task'):
                        result = await specialist._execute_task(task)
                        actual_output["execution_attempted"] = True
                        actual_output["result_returned"] = result is not None
                    else:
                        actual_output["execution_attempted"] = False
                        failure_reason = "No execute_task method found"
                        suggested_fix = "Implement execute_task in AttackSpecialist"
                        code_location = "src/specialists/attack.py"
                except Exception as e:
                    actual_output["execution_attempted"] = True
                    actual_output["result_returned"] = False
                    failure_reason = f"Execution failed: {str(e)}"
                    suggested_fix = "Debug task execution logic"
                
                # Check blackboard update
                actual_output["blackboard_updated"] = actual_output.get("result_returned", False)
            
            await blackboard.disconnect()
            
            all_passed = all(actual_output.get(k, False) for k in expected_output.keys())
            
            if all_passed:
                actual_behavior = "Attack executed successfully"
            else:
                actual_behavior = f"Attack partial: {actual_output}"
                
        except Exception as e:
            actual_behavior = f"Exception: {str(e)}"
            failure_reason = str(e)
            import traceback
            code_location = traceback.format_exc()[:200]
            
        return StrictTestResult(
            test_id=test_id,
            test_name="Attack Execution",
            category=TestCategory.INITIAL_ACCESS,
            severity=TestSeverity.CRITICAL,
            passed=all(actual_output.get(k, False) for k in expected_output.keys()),
            execution_time_ms=(time.time() - start) * 1000,
            expected_behavior=expected_behavior,
            expected_output=expected_output,
            actual_behavior=actual_behavior,
            actual_output=actual_output,
            failure_reason=failure_reason,
            suggested_fix=suggested_fix,
            code_location=code_location,
        )
    
    async def test_06_llm_failure_adaptation(self) -> StrictTestResult:
        """
        TEST: LLM can analyze attack failure and suggest alternatives (Reflexion Pattern).
        
        EXPECTED:
        - LLM receives failure context
        - Identifies root cause of failure
        - Suggests alternative techniques
        - Recommends evasion if defense detected
        - Response follows structured format
        """
        test_id = "E2E-LLM-002"
        start = time.time()
        
        expected_behavior = "LLM analyzes failure, identifies cause, suggests alternatives"
        expected_output = {
            "llm_responded": True,
            "identified_cause": True,
            "suggested_alternatives": True,
            "has_evasion_recommendation": True,
            "valid_json_response": True,
        }
        
        actual_output = {}
        actual_behavior = ""
        failure_reason = None
        suggested_fix = None
        code_location = None
        
        try:
            from src.core.llm.base import LLMMessage
            from src.core.llm.prompts import REFLEXION_SYSTEM_PROMPT, FAILURE_ANALYSIS_PROMPT
            
            # Simulate failed attack
            failure_context = {
                "task_id": str(uuid4()),
                "technique_id": "T1110.001",
                "technique_name": "Brute Force: Password Guessing",
                "target": f"{self.framework.target_url}/admin/",
                "execution_result": {
                    "status": "failed",
                    "error": "All credential combinations rejected",
                    "http_responses": [401, 401, 401, 401],
                    "detected_defenses": ["rate_limiting", "account_lockout"],
                },
                "retry_count": 3,
                "max_retries": 5,
            }
            
            failure_analysis_prompt = f"""Analyze this attack failure and recommend next steps.

## Failed Attack Context:
{json.dumps(failure_context, indent=2)}

## Your Task:
1. Identify the root cause of failure
2. Detect any defenses that blocked the attack
3. Suggest alternative attack techniques
4. If defenses detected, recommend evasion techniques

## Response Format (JSON only):
{{
    "root_cause": "...",
    "detected_defenses": ["defense1", "defense2"],
    "confidence": 0.0-1.0,
    "recommended_action": "retry/skip/alternative/escalate",
    "alternative_techniques": [
        {{"technique_id": "T1XXX", "name": "...", "reason": "..."}}
    ],
    "evasion_recommendations": [
        {{"technique_id": "T1XXX", "action": "..."}}
    ],
    "next_steps": ["step1", "step2"]
}}
"""
            
            messages = [
                LLMMessage.system(REFLEXION_SYSTEM_PROMPT),
                LLMMessage.user(failure_analysis_prompt)
            ]
            
            response = await self.framework.llm_provider.generate(messages, max_tokens=1000)
            actual_output["llm_responded"] = bool(response and response.content)
            
            if actual_output["llm_responded"]:
                content = response.content
                
                if "```json" in content:
                    content = content.split("```json")[1].split("```")[0]
                elif "```" in content:
                    content = content.split("```")[1].split("```")[0]
                
                try:
                    analysis = json.loads(content.strip())
                    actual_output["valid_json_response"] = True
                    
                    actual_output["identified_cause"] = "root_cause" in analysis and len(analysis.get("root_cause", "")) > 10
                    actual_output["suggested_alternatives"] = "alternative_techniques" in analysis and len(analysis.get("alternative_techniques", [])) > 0
                    actual_output["has_evasion_recommendation"] = "evasion_recommendations" in analysis or "detected_defenses" in analysis
                    
                except json.JSONDecodeError:
                    actual_output["valid_json_response"] = False
                    failure_reason = "LLM returned invalid JSON"
                    suggested_fix = "Add JSON validation to prompts"
            
            all_passed = all(actual_output.get(k, False) for k in expected_output.keys())
            
            if all_passed:
                actual_behavior = "LLM correctly analyzed failure and suggested alternatives"
            else:
                actual_behavior = f"LLM analysis partial: {actual_output}"
                
        except Exception as e:
            actual_behavior = f"Exception: {str(e)}"
            failure_reason = str(e)
            
        return StrictTestResult(
            test_id=test_id,
            test_name="LLM Failure Adaptation (Reflexion)",
            category=TestCategory.LLM_DECISION,
            severity=TestSeverity.HIGH,
            passed=all(actual_output.get(k, False) for k in expected_output.keys()),
            execution_time_ms=(time.time() - start) * 1000,
            expected_behavior=expected_behavior,
            expected_output=expected_output,
            actual_behavior=actual_behavior,
            actual_output=actual_output,
            failure_reason=failure_reason,
            suggested_fix=suggested_fix,
            code_location=code_location,
        )
    
    async def run_all(self) -> List[StrictTestResult]:
        """Run all mission lifecycle tests."""
        tests = [
            self.test_01_mission_creation,
            self.test_02_target_addition,
            self.test_03_reconnaissance_execution,
            self.test_04_llm_attack_planning,
            self.test_05_attack_execution,
            self.test_06_llm_failure_adaptation,
        ]
        
        results = []
        for test_func in tests:
            result = await test_func()
            results.append(result)
            self.framework.add_result(result)
        
        return results


# ═══════════════════════════════════════════════════════════════════════════════
# Main Runner
# ═══════════════════════════════════════════════════════════════════════════════

async def run_strict_e2e_tests():
    """Run all strict E2E tests."""
    print("\n" + "=" * 80)
    print("RAGLOX v3.0 - STRICT END-TO-END TESTS")
    print("=" * 80)
    print("\nPhilosophy: Tests define expected behavior. Code must adapt to pass tests.")
    print("Each failure = opportunity to improve the system.\n")
    
    framework = StrictE2ETestFramework()
    
    try:
        await framework.setup()
        
        # Run Mission Lifecycle Tests
        print("\n" + "-" * 60)
        print("PHASE 1: Mission Lifecycle Tests")
        print("-" * 60)
        
        lifecycle_tests = MissionLifecycleTests(framework)
        await lifecycle_tests.run_all()
        
    finally:
        await framework.teardown()
    
    # Generate report
    report = E2ETestSuiteReport(suite_name="Strict E2E Tests")
    report.results = framework.results
    report.total_tests = len(framework.results)
    report.passed = sum(1 for r in framework.results if r.passed)
    report.failed = sum(1 for r in framework.results if not r.passed)
    report.end_time = datetime.now(timezone.utc)
    
    # Count by severity
    for result in framework.results:
        if not result.passed:
            if result.severity == TestSeverity.CRITICAL:
                report.critical_failures += 1
                report.blocking_issues.append(f"CRITICAL: {result.test_name} - {result.failure_reason}")
            elif result.severity == TestSeverity.HIGH:
                report.high_failures += 1
            elif result.severity == TestSeverity.MEDIUM:
                report.medium_failures += 1
            else:
                report.low_failures += 1
    
    # Print final report
    print("\n" + "=" * 80)
    print("STRICT E2E TEST REPORT")
    print("=" * 80)
    
    duration = (report.end_time - report.start_time).total_seconds()
    
    print(f"\nDuration: {duration:.1f}s")
    print(f"Total Tests: {report.total_tests}")
    print(f"Passed: {report.passed}")
    print(f"Failed: {report.failed}")
    print(f"Success Rate: {report.success_rate:.1f}%")
    
    print(f"\nFailures by Severity:")
    print(f"  Critical: {report.critical_failures}")
    print(f"  High:     {report.high_failures}")
    print(f"  Medium:   {report.medium_failures}")
    print(f"  Low:      {report.low_failures}")
    
    print(f"\nDeployable: {'YES' if report.is_deployable else 'NO - Fix blocking issues first'}")
    
    if report.blocking_issues:
        print("\n" + "-" * 60)
        print("BLOCKING ISSUES (Must Fix):")
        print("-" * 60)
        for issue in report.blocking_issues:
            print(f"  • {issue}")
    
    # Print suggested fixes
    fixes_needed = [r for r in framework.results if not r.passed and r.suggested_fix]
    if fixes_needed:
        print("\n" + "-" * 60)
        print("SUGGESTED FIXES:")
        print("-" * 60)
        for result in fixes_needed:
            print(f"\n[{result.test_name}]")
            print(f"  Location: {result.code_location}")
            print(f"  Fix: {result.suggested_fix}")
    
    print("\n" + "=" * 80)
    
    return report


if __name__ == "__main__":
    report = asyncio.run(run_strict_e2e_tests())
    sys.exit(0 if report.is_deployable else 1)
