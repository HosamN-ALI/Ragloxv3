#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Offensive E2E Testing Framework
# End-to-End Tests for Real Agent Capabilities
# 
# Purpose: Test ACTUAL agent capabilities, not just code paths
# Philosophy: Tests should FAIL if agent is weak, not pass regardless
# ═══════════════════════════════════════════════════════════════════════════════

"""
RAGLOX Offensive E2E Testing Framework

This framework tests the REAL capabilities of RAGLOX agents through:
1. Progressive Difficulty Levels (Basic → Expert)
2. LLM Decision Quality Assessment
3. Specialist Chain Integration
4. Real Attack Execution Validation

Test Categories:
- LEVEL 1 (Basic): Simple reconnaissance and single-step exploits
- LEVEL 2 (Intermediate): Multi-step attacks with credential chaining
- LEVEL 3 (Advanced): Defense evasion and adaptive attacks  
- LEVEL 4 (Expert): Complex APT simulation and full kill chains

Quality Metrics:
- Decision Accuracy: Does the LLM make correct tactical decisions?
- Context Understanding: Does the agent understand attack context?
- Adaptation: Does the agent adapt to failed attacks?
- Efficiency: How many steps to achieve objectives?
"""

import asyncio
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4, UUID

# Setup path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("e2e_offensive_tests")


# ═══════════════════════════════════════════════════════════════════════════════
# Test Result Models
# ═══════════════════════════════════════════════════════════════════════════════

class TestDifficulty(Enum):
    """Test difficulty levels"""
    BASIC = "basic"           # Level 1: Single-step operations
    INTERMEDIATE = "intermediate"  # Level 2: Multi-step operations
    ADVANCED = "advanced"     # Level 3: Defense evasion required
    EXPERT = "expert"         # Level 4: Full APT simulation


class TestOutcome(Enum):
    """Test outcome types"""
    PASSED = "passed"
    FAILED = "failed"
    PARTIAL = "partial"
    SKIPPED = "skipped"
    ERROR = "error"


class CapabilityGap(Enum):
    """Types of capability gaps that can be identified"""
    LLM_DECISION_QUALITY = "llm_decision_quality"
    CONTEXT_UNDERSTANDING = "context_understanding"
    ATTACK_ADAPTATION = "attack_adaptation"
    SPECIALIST_COORDINATION = "specialist_coordination"
    KNOWLEDGE_BASE_COVERAGE = "knowledge_base_coverage"
    EXECUTION_RELIABILITY = "execution_reliability"
    DEFENSE_EVASION = "defense_evasion"
    PROMPT_ENGINEERING = "prompt_engineering"


@dataclass
class TestMetrics:
    """Metrics collected during test execution"""
    llm_calls: int = 0
    llm_tokens: int = 0
    llm_latency_ms: float = 0.0
    decisions_made: int = 0
    correct_decisions: int = 0
    tasks_created: int = 0
    tasks_completed: int = 0
    tasks_failed: int = 0
    retries_needed: int = 0
    execution_time_ms: float = 0.0
    
    @property
    def decision_accuracy(self) -> float:
        return self.correct_decisions / max(self.decisions_made, 1)
    
    @property
    def task_success_rate(self) -> float:
        total = self.tasks_completed + self.tasks_failed
        return self.tasks_completed / max(total, 1)


@dataclass
class CapabilityGapReport:
    """Report of a detected capability gap"""
    gap_type: CapabilityGap
    severity: str  # critical, high, medium, low
    description: str
    evidence: List[str]
    recommended_fix: str
    affected_tests: List[str]


@dataclass
class TestResult:
    """Result of a single test"""
    test_id: str
    test_name: str
    difficulty: TestDifficulty
    outcome: TestOutcome
    duration_ms: float
    metrics: TestMetrics
    expected_behavior: str
    actual_behavior: str
    capability_gaps: List[CapabilityGapReport] = field(default_factory=list)
    error_details: Optional[str] = None
    llm_responses: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


@dataclass
class TestSuiteResult:
    """Result of a complete test suite"""
    suite_name: str
    difficulty: TestDifficulty
    total_tests: int
    passed: int
    failed: int
    partial: int
    skipped: int
    errors: int
    duration_ms: float
    results: List[TestResult]
    aggregate_metrics: TestMetrics
    capability_gaps: List[CapabilityGapReport]
    
    @property
    def success_rate(self) -> float:
        return self.passed / max(self.total_tests, 1)


# ═══════════════════════════════════════════════════════════════════════════════
# Mock Components for Testing
# ═══════════════════════════════════════════════════════════════════════════════

class MockBlackboard:
    """Mock Blackboard for isolated testing"""
    
    def __init__(self):
        self.data = {
            "targets": {},
            "vulns": {},
            "creds": {},
            "sessions": {},
            "tasks": {},
            "missions": {},
            "events": [],
        }
        self._connected = False
    
    async def connect(self):
        self._connected = True
    
    async def disconnect(self):
        self._connected = False
    
    async def add_target(self, target) -> str:
        target_id = str(uuid4())
        self.data["targets"][target_id] = target.__dict__ if hasattr(target, '__dict__') else target
        return target_id
    
    async def get_target(self, target_id: str) -> Optional[Dict]:
        return self.data["targets"].get(target_id)
    
    async def add_vulnerability(self, vuln) -> str:
        vuln_id = str(uuid4())
        self.data["vulns"][vuln_id] = vuln.__dict__ if hasattr(vuln, '__dict__') else vuln
        return vuln_id
    
    async def get_vulnerability(self, vuln_id: str) -> Optional[Dict]:
        return self.data["vulns"].get(vuln_id)
    
    async def add_credential(self, cred) -> str:
        cred_id = str(uuid4())
        self.data["creds"][cred_id] = cred.__dict__ if hasattr(cred, '__dict__') else cred
        return cred_id
    
    async def get_credential(self, cred_id: str) -> Optional[Dict]:
        return self.data["creds"].get(cred_id)
    
    async def add_task(self, task) -> str:
        task_id = str(uuid4())
        self.data["tasks"][task_id] = task.__dict__ if hasattr(task, '__dict__') else task
        return task_id
    
    async def get_task(self, task_id: str) -> Optional[Dict]:
        return self.data["tasks"].get(task_id)
    
    async def get_mission(self, mission_id: str) -> Optional[Dict]:
        return self.data["missions"].get(mission_id, {
            "scope": ["192.168.1.0/24"],
            "goals": ["domain_admin", "data_exfil"]
        })
    
    async def get_target_ports(self, target_id: str) -> Dict[str, str]:
        target = self.data["targets"].get(target_id, {})
        return target.get("ports", {"22": "ssh", "80": "http", "443": "https"})
    
    async def get_mission_targets(self, mission_id: str) -> List[str]:
        return [f"target:{tid}" for tid in self.data["targets"].keys()]
    
    async def get_mission_vulns(self, mission_id: str) -> List[str]:
        return [f"vuln:{vid}" for vid in self.data["vulns"].keys()]
    
    async def get_mission_creds(self, mission_id: str) -> List[str]:
        return [f"cred:{cid}" for cid in self.data["creds"].keys()]
    
    async def update_target_status(self, target_id: str, status) -> None:
        if target_id in self.data["targets"]:
            self.data["targets"][target_id]["status"] = status.value if hasattr(status, 'value') else status
    
    async def update_vuln_status(self, vuln_id: str, status: str) -> None:
        if vuln_id in self.data["vulns"]:
            self.data["vulns"][vuln_id]["status"] = status
    
    async def add_target_ports(self, target_id: str, ports: Dict[str, str]) -> None:
        if target_id in self.data["targets"]:
            self.data["targets"][target_id]["ports"] = ports
    
    async def log_result(self, mission_id: str, event_type: str, data: Dict) -> None:
        self.data["events"].append({
            "mission_id": mission_id,
            "event_type": event_type,
            "data": data,
            "timestamp": datetime.utcnow().isoformat()
        })
    
    async def subscribe(self, *channels) -> None:
        pass
    
    async def publish(self, channel: str, event) -> None:
        self.data["events"].append({
            "channel": channel,
            "event": event.__dict__ if hasattr(event, '__dict__') else event
        })
    
    def get_channel(self, mission_id: str, channel_type: str) -> str:
        return f"mission:{mission_id}:{channel_type}"
    
    async def claim_task(self, mission_id: str, worker_id: str, specialist_type: str) -> Optional[str]:
        return None
    
    async def complete_task(self, mission_id: str, task_id: str, status: str, result: Dict) -> None:
        if task_id in self.data["tasks"]:
            self.data["tasks"][task_id]["status"] = status
            self.data["tasks"][task_id]["result"] = result
    
    async def fail_task(self, mission_id: str, task_id: str, error: str) -> None:
        if task_id in self.data["tasks"]:
            self.data["tasks"][task_id]["status"] = "failed"
            self.data["tasks"][task_id]["error"] = error
    
    async def send_heartbeat(self, mission_id: str, worker_id: str) -> None:
        pass
    
    async def get_message(self, timeout: float = 1.0) -> Optional[Dict]:
        return None
    
    async def add_session(self, session) -> str:
        session_id = str(uuid4())
        self.data["sessions"][session_id] = session.__dict__ if hasattr(session, '__dict__') else session
        return session_id


# ═══════════════════════════════════════════════════════════════════════════════
# Test Scenarios
# ═══════════════════════════════════════════════════════════════════════════════

class TestScenario:
    """Base class for test scenarios"""
    
    def __init__(
        self,
        name: str,
        difficulty: TestDifficulty,
        description: str,
        expected_behavior: str,
        mitre_techniques: List[str],
    ):
        self.name = name
        self.difficulty = difficulty
        self.description = description
        self.expected_behavior = expected_behavior
        self.mitre_techniques = mitre_techniques
        self.metrics = TestMetrics()
        self.llm_responses: List[Dict] = []
        self.capability_gaps: List[CapabilityGapReport] = []
    
    async def setup(self) -> None:
        """Setup test environment"""
        pass
    
    async def execute(self) -> Tuple[TestOutcome, str]:
        """Execute test and return outcome"""
        raise NotImplementedError
    
    async def teardown(self) -> None:
        """Cleanup after test"""
        pass
    
    def _record_llm_response(self, response: Dict) -> None:
        """Record LLM response for analysis"""
        self.llm_responses.append(response)
        self.metrics.llm_calls += 1
        self.metrics.llm_tokens += response.get("tokens", 0)
        self.metrics.llm_latency_ms += response.get("latency_ms", 0)
    
    def _add_capability_gap(
        self,
        gap_type: CapabilityGap,
        severity: str,
        description: str,
        evidence: List[str],
        fix: str
    ) -> None:
        """Record a detected capability gap"""
        self.capability_gaps.append(CapabilityGapReport(
            gap_type=gap_type,
            severity=severity,
            description=description,
            evidence=evidence,
            recommended_fix=fix,
            affected_tests=[self.name]
        ))


# ═══════════════════════════════════════════════════════════════════════════════
# LEVEL 1: Basic Tests
# ═══════════════════════════════════════════════════════════════════════════════

class BasicReconTest(TestScenario):
    """Test basic reconnaissance capabilities"""
    
    def __init__(self):
        super().__init__(
            name="Basic Reconnaissance",
            difficulty=TestDifficulty.BASIC,
            description="Test ReconSpecialist's ability to discover hosts and enumerate services",
            expected_behavior="Agent should discover targets, scan ports, and identify services with >80% accuracy",
            mitre_techniques=["T1046", "T1592", "T1083"]
        )
        self.blackboard = MockBlackboard()
    
    async def setup(self):
        await self.blackboard.connect()
        # Pre-populate with test mission
        self.blackboard.data["missions"]["test-mission"] = {
            "scope": ["192.168.1.0/24"],
            "goals": ["recon_complete"]
        }
    
    async def execute(self) -> Tuple[TestOutcome, str]:
        from src.specialists.recon import ReconSpecialist
        from src.core.config import get_settings
        
        try:
            settings = get_settings()
            specialist = ReconSpecialist(
                blackboard=self.blackboard,
                settings=settings
            )
            specialist._current_mission_id = "test-mission"
            
            # Test 1: Network Scan
            self.metrics.decisions_made += 1
            task = {"type": "network_scan", "id": str(uuid4())}
            result = await specialist._execute_network_scan(task)
            
            if result.get("hosts_discovered", 0) > 0:
                self.metrics.correct_decisions += 1
                self.metrics.tasks_completed += 1
            else:
                self.metrics.tasks_failed += 1
                self._add_capability_gap(
                    CapabilityGap.EXECUTION_RELIABILITY,
                    "high",
                    "Network scan failed to discover any hosts",
                    ["hosts_discovered = 0"],
                    "Check network scanning module and target reachability"
                )
            
            # Test 2: Port Scan on discovered target
            if self.blackboard.data["targets"]:
                target_id = list(self.blackboard.data["targets"].keys())[0]
                self.metrics.decisions_made += 1
                
                task = {"type": "port_scan", "id": str(uuid4()), "target_id": target_id}
                result = await specialist._execute_port_scan(task)
                
                if result.get("ports_found", 0) > 0:
                    self.metrics.correct_decisions += 1
                    self.metrics.tasks_completed += 1
                else:
                    self.metrics.tasks_failed += 1
            
            # Test 3: Service Enumeration
            if self.blackboard.data["targets"]:
                target_id = list(self.blackboard.data["targets"].keys())[0]
                self.metrics.decisions_made += 1
                
                task = {"type": "service_enum", "id": str(uuid4()), "target_id": target_id}
                result = await specialist._execute_service_enum(task)
                
                if result.get("services_found", 0) > 0:
                    self.metrics.correct_decisions += 1
                    self.metrics.tasks_completed += 1
                else:
                    self.metrics.tasks_failed += 1
            
            # Evaluate outcome
            success_rate = self.metrics.decision_accuracy
            if success_rate >= 0.8:
                return TestOutcome.PASSED, f"Reconnaissance successful ({success_rate:.0%} accuracy)"
            elif success_rate >= 0.5:
                return TestOutcome.PARTIAL, f"Partial success ({success_rate:.0%} accuracy)"
            else:
                return TestOutcome.FAILED, f"Reconnaissance failed ({success_rate:.0%} accuracy)"
                
        except Exception as e:
            logger.error(f"Test error: {e}")
            return TestOutcome.ERROR, str(e)
    
    async def teardown(self):
        await self.blackboard.disconnect()


class BasicExploitTest(TestScenario):
    """Test basic exploitation capabilities"""
    
    def __init__(self):
        super().__init__(
            name="Basic Exploitation",
            difficulty=TestDifficulty.BASIC,
            description="Test AttackSpecialist's ability to exploit a known vulnerability",
            expected_behavior="Agent should successfully exploit CVE-2021-44228 (Log4Shell) on a vulnerable target",
            mitre_techniques=["T1190", "T1059"]
        )
        self.blackboard = MockBlackboard()
    
    async def setup(self):
        await self.blackboard.connect()
        
        # Create test target
        target_id = await self.blackboard.add_target({
            "ip": "192.168.1.100",
            "hostname": "vuln-server",
            "os": "Linux",
            "ports": {"80": "http", "443": "https"},
            "status": "scanned"
        })
        self.target_id = target_id
        
        # Create test vulnerability
        vuln_id = await self.blackboard.add_vulnerability({
            "target_id": target_id,
            "type": "CVE-2021-44228",
            "name": "Log4Shell",
            "severity": "critical",
            "cvss": 10.0,
            "exploit_available": True,
            "status": "discovered"
        })
        self.vuln_id = vuln_id
        
        self.blackboard.data["missions"]["test-mission"] = {
            "scope": ["192.168.1.0/24"],
            "goals": ["initial_access"]
        }
    
    async def execute(self) -> Tuple[TestOutcome, str]:
        from src.specialists.attack import AttackSpecialist
        from src.core.config import get_settings
        
        try:
            settings = get_settings()
            specialist = AttackSpecialist(
                blackboard=self.blackboard,
                settings=settings
            )
            specialist._current_mission_id = "test-mission"
            
            # Test exploit execution
            self.metrics.decisions_made += 1
            task = {
                "type": "exploit",
                "id": str(uuid4()),
                "target_id": self.target_id,
                "vuln_id": self.vuln_id
            }
            
            result = await specialist._execute_exploit(task)
            
            if result.get("success"):
                self.metrics.correct_decisions += 1
                self.metrics.tasks_completed += 1
                
                # Verify session was created
                if self.blackboard.data["sessions"]:
                    return TestOutcome.PASSED, "Exploit successful, session established"
                else:
                    return TestOutcome.PARTIAL, "Exploit reported success but no session created"
            else:
                self.metrics.tasks_failed += 1
                reason = result.get("reason", "Unknown")
                
                # Analyze why it failed
                if "execution_mode" in result and result["execution_mode"] == "simulated":
                    self._add_capability_gap(
                        CapabilityGap.EXECUTION_RELIABILITY,
                        "medium",
                        "Exploit ran in simulated mode",
                        [f"execution_mode: {result.get('execution_mode')}"],
                        "Ensure RXModuleRunner is properly configured for real execution"
                    )
                
                return TestOutcome.FAILED, f"Exploit failed: {reason}"
                
        except Exception as e:
            logger.error(f"Test error: {e}")
            return TestOutcome.ERROR, str(e)
    
    async def teardown(self):
        await self.blackboard.disconnect()


class BasicLLMDecisionTest(TestScenario):
    """Test LLM decision quality for basic scenarios"""
    
    def __init__(self):
        super().__init__(
            name="LLM Decision Quality - Basic",
            difficulty=TestDifficulty.BASIC,
            description="Test LLM's ability to make correct decisions for simple failure scenarios",
            expected_behavior="LLM should correctly categorize failures and recommend appropriate actions",
            mitre_techniques=["T1059"]
        )
        self.blackboard = MockBlackboard()
    
    async def setup(self):
        await self.blackboard.connect()
        
        # Create test mission
        self.blackboard.data["missions"]["test-mission"] = {
            "scope": ["192.168.1.0/24"],
            "goals": ["initial_access"]
        }
        
        # Create test task
        task_id = await self.blackboard.add_task({
            "type": "exploit",
            "target_id": "target-001",
            "vuln_id": "vuln-001",
            "rx_module": "rx-log4shell-001",
            "retry_count": 0
        })
        self.task_id = task_id
        
        # Create test target
        await self.blackboard.add_target({
            "ip": "192.168.1.100",
            "hostname": "target-server",
            "os": "Linux"
        })
    
    async def execute(self) -> Tuple[TestOutcome, str]:
        from src.specialists.analysis import AnalysisSpecialist
        from src.core.config import get_settings
        
        try:
            settings = get_settings()
            specialist = AnalysisSpecialist(
                blackboard=self.blackboard,
                settings=settings,
                llm_enabled=True
            )
            specialist._current_mission_id = "test-mission"
            
            test_cases = [
                # (error_type, expected_decision)
                ("connection_timeout", "retry"),
                ("av_detected", "modify_approach"),
                ("target_patched", "skip"),
                ("auth_failed", "retry"),
            ]
            
            for error_type, expected_decision in test_cases:
                self.metrics.decisions_made += 1
                
                error_context = {
                    "error_type": error_type,
                    "error_message": f"Simulated {error_type} error",
                    "module_used": "rx-test-module"
                }
                
                result = await specialist.analyze_failure(
                    task_id=self.task_id,
                    error_context=error_context,
                    execution_logs=[]
                )
                
                actual_decision = result.get("decision")
                
                if actual_decision == expected_decision:
                    self.metrics.correct_decisions += 1
                    logger.info(f"✓ {error_type} → {actual_decision} (correct)")
                else:
                    logger.warning(f"✗ {error_type} → {actual_decision} (expected {expected_decision})")
                    self._add_capability_gap(
                        CapabilityGap.LLM_DECISION_QUALITY,
                        "high",
                        f"Incorrect decision for {error_type}",
                        [f"Expected: {expected_decision}, Got: {actual_decision}"],
                        f"Improve prompt for handling {error_type} errors"
                    )
                
                # Record LLM response if available
                if result.get("llm_analysis"):
                    self._record_llm_response({
                        "error_type": error_type,
                        "decision": actual_decision,
                        "tokens": result.get("tokens_used", 0),
                        "latency_ms": result.get("latency_ms", 0)
                    })
            
            # Evaluate outcome
            accuracy = self.metrics.decision_accuracy
            if accuracy >= 0.75:
                return TestOutcome.PASSED, f"LLM decisions accurate ({accuracy:.0%})"
            elif accuracy >= 0.5:
                return TestOutcome.PARTIAL, f"LLM partially accurate ({accuracy:.0%})"
            else:
                return TestOutcome.FAILED, f"LLM decisions poor ({accuracy:.0%})"
                
        except Exception as e:
            logger.error(f"Test error: {e}")
            return TestOutcome.ERROR, str(e)
    
    async def teardown(self):
        await self.blackboard.disconnect()


# ═══════════════════════════════════════════════════════════════════════════════
# LEVEL 2: Intermediate Tests
# ═══════════════════════════════════════════════════════════════════════════════

class CredentialChainTest(TestScenario):
    """Test credential harvesting and reuse chain"""
    
    def __init__(self):
        super().__init__(
            name="Credential Chain Attack",
            difficulty=TestDifficulty.INTERMEDIATE,
            description="Test ability to harvest credentials and use them for lateral movement",
            expected_behavior="Agent should harvest creds from compromised host and use them for lateral movement",
            mitre_techniques=["T1003", "T1021", "T1078"]
        )
        self.blackboard = MockBlackboard()
    
    async def setup(self):
        await self.blackboard.connect()
        
        # Create compromised target
        target1_id = await self.blackboard.add_target({
            "ip": "192.168.1.100",
            "hostname": "compromised-server",
            "os": "Windows Server 2019",
            "status": "exploited"
        })
        self.target1_id = target1_id
        
        # Create lateral target
        target2_id = await self.blackboard.add_target({
            "ip": "192.168.1.101",
            "hostname": "lateral-target",
            "os": "Windows Server 2019",
            "status": "scanned"
        })
        self.target2_id = target2_id
        
        # Create existing session on target1
        await self.blackboard.add_session({
            "target_id": target1_id,
            "type": "shell",
            "user": "SYSTEM",
            "privilege": "system",
            "status": "active"
        })
        
        self.blackboard.data["missions"]["test-mission"] = {
            "scope": ["192.168.1.0/24"],
            "goals": ["domain_admin", "lateral_movement"]
        }
    
    async def execute(self) -> Tuple[TestOutcome, str]:
        from src.specialists.attack import AttackSpecialist
        from src.core.config import get_settings
        
        try:
            settings = get_settings()
            specialist = AttackSpecialist(
                blackboard=self.blackboard,
                settings=settings
            )
            specialist._current_mission_id = "test-mission"
            
            # Phase 1: Credential Harvesting
            self.metrics.decisions_made += 1
            harvest_task = {
                "type": "cred_harvest",
                "id": str(uuid4()),
                "target_id": self.target1_id
            }
            
            harvest_result = await specialist._execute_cred_harvest(harvest_task)
            
            creds_found = harvest_result.get("creds_found", 0)
            if creds_found > 0:
                self.metrics.correct_decisions += 1
                self.metrics.tasks_completed += 1
                logger.info(f"✓ Harvested {creds_found} credentials")
            else:
                self.metrics.tasks_failed += 1
                self._add_capability_gap(
                    CapabilityGap.EXECUTION_RELIABILITY,
                    "high",
                    "Credential harvesting found no credentials",
                    ["creds_found = 0"],
                    "Improve credential extraction modules"
                )
                return TestOutcome.FAILED, "No credentials harvested"
            
            # Phase 2: Lateral Movement
            if self.blackboard.data["creds"]:
                cred_id = list(self.blackboard.data["creds"].keys())[0]
                self.metrics.decisions_made += 1
                
                lateral_task = {
                    "type": "lateral",
                    "id": str(uuid4()),
                    "target_id": self.target1_id,
                    "cred_id": cred_id
                }
                
                lateral_result = await specialist._execute_lateral(lateral_task)
                
                if lateral_result.get("success"):
                    self.metrics.correct_decisions += 1
                    self.metrics.tasks_completed += 1
                    laterals = lateral_result.get("laterals_succeeded", 0)
                    logger.info(f"✓ Lateral movement successful to {laterals} target(s)")
                    return TestOutcome.PASSED, f"Credential chain successful: {creds_found} creds → {laterals} laterals"
                else:
                    self.metrics.tasks_failed += 1
                    return TestOutcome.PARTIAL, f"Harvested {creds_found} creds but lateral movement failed"
            
            return TestOutcome.PARTIAL, "Credentials harvested but none suitable for lateral movement"
            
        except Exception as e:
            logger.error(f"Test error: {e}")
            return TestOutcome.ERROR, str(e)
    
    async def teardown(self):
        await self.blackboard.disconnect()


class MultiStepExploitTest(TestScenario):
    """Test multi-step exploitation flow"""
    
    def __init__(self):
        super().__init__(
            name="Multi-Step Exploitation",
            difficulty=TestDifficulty.INTERMEDIATE,
            description="Test the full Recon → Exploit → PrivEsc → Cred Harvest chain",
            expected_behavior="Agent should execute complete attack chain with proper specialist coordination",
            mitre_techniques=["T1046", "T1190", "T1068", "T1003"]
        )
        self.blackboard = MockBlackboard()
    
    async def setup(self):
        await self.blackboard.connect()
        self.blackboard.data["missions"]["test-mission"] = {
            "scope": ["192.168.1.0/24"],
            "goals": ["initial_access", "privilege_escalation", "credential_access"]
        }
    
    async def execute(self) -> Tuple[TestOutcome, str]:
        from src.specialists.recon import ReconSpecialist
        from src.specialists.attack import AttackSpecialist
        from src.core.config import get_settings
        
        try:
            settings = get_settings()
            
            recon_specialist = ReconSpecialist(
                blackboard=self.blackboard,
                settings=settings
            )
            recon_specialist._current_mission_id = "test-mission"
            
            attack_specialist = AttackSpecialist(
                blackboard=self.blackboard,
                settings=settings
            )
            attack_specialist._current_mission_id = "test-mission"
            
            phases_completed = []
            
            # Phase 1: Network Scan
            self.metrics.decisions_made += 1
            scan_result = await recon_specialist._execute_network_scan({"type": "network_scan", "id": str(uuid4())})
            if scan_result.get("hosts_discovered", 0) > 0:
                self.metrics.correct_decisions += 1
                phases_completed.append("network_scan")
                logger.info(f"✓ Phase 1: Discovered {scan_result['hosts_discovered']} hosts")
            
            # Phase 2: Port Scan
            if self.blackboard.data["targets"]:
                target_id = list(self.blackboard.data["targets"].keys())[0]
                self.metrics.decisions_made += 1
                
                port_result = await recon_specialist._execute_port_scan({
                    "type": "port_scan", 
                    "id": str(uuid4()), 
                    "target_id": target_id
                })
                
                if port_result.get("ports_found", 0) > 0:
                    self.metrics.correct_decisions += 1
                    phases_completed.append("port_scan")
                    logger.info(f"✓ Phase 2: Found {port_result['ports_found']} open ports")
                
                # Phase 3: Service Enumeration
                self.metrics.decisions_made += 1
                enum_result = await recon_specialist._execute_service_enum({
                    "type": "service_enum",
                    "id": str(uuid4()),
                    "target_id": target_id
                })
                
                if enum_result.get("services_found", 0) > 0:
                    self.metrics.correct_decisions += 1
                    phases_completed.append("service_enum")
                    logger.info(f"✓ Phase 3: Enumerated {enum_result['services_found']} services")
                
                # Phase 4: Create vulnerability for exploitation
                vuln_id = await self.blackboard.add_vulnerability({
                    "target_id": target_id,
                    "type": "CVE-2021-44228",
                    "name": "Log4Shell",
                    "severity": "critical",
                    "exploit_available": True
                })
                
                # Phase 5: Exploitation
                self.metrics.decisions_made += 1
                exploit_result = await attack_specialist._execute_exploit({
                    "type": "exploit",
                    "id": str(uuid4()),
                    "target_id": target_id,
                    "vuln_id": vuln_id
                })
                
                if exploit_result.get("success"):
                    self.metrics.correct_decisions += 1
                    phases_completed.append("exploit")
                    logger.info(f"✓ Phase 5: Exploitation successful")
                    
                    # Phase 6: Privilege Escalation
                    if exploit_result.get("privilege") == "user":
                        self.metrics.decisions_made += 1
                        privesc_result = await attack_specialist._execute_privesc({
                            "type": "privesc",
                            "id": str(uuid4()),
                            "target_id": target_id
                        })
                        
                        if privesc_result.get("success"):
                            self.metrics.correct_decisions += 1
                            phases_completed.append("privesc")
                            logger.info(f"✓ Phase 6: PrivEsc successful → {privesc_result.get('new_privilege')}")
                    
                    # Phase 7: Credential Harvesting
                    self.metrics.decisions_made += 1
                    harvest_result = await attack_specialist._execute_cred_harvest({
                        "type": "cred_harvest",
                        "id": str(uuid4()),
                        "target_id": target_id
                    })
                    
                    if harvest_result.get("creds_found", 0) > 0:
                        self.metrics.correct_decisions += 1
                        phases_completed.append("cred_harvest")
                        logger.info(f"✓ Phase 7: Harvested {harvest_result['creds_found']} credentials")
            
            # Evaluate outcome
            total_phases = 7
            completed_ratio = len(phases_completed) / total_phases
            
            if completed_ratio >= 0.85:
                return TestOutcome.PASSED, f"Multi-step attack complete ({len(phases_completed)}/{total_phases} phases)"
            elif completed_ratio >= 0.5:
                return TestOutcome.PARTIAL, f"Partial completion ({len(phases_completed)}/{total_phases} phases: {phases_completed})"
            else:
                return TestOutcome.FAILED, f"Attack chain failed ({len(phases_completed)}/{total_phases} phases)"
                
        except Exception as e:
            logger.error(f"Test error: {e}")
            return TestOutcome.ERROR, str(e)
    
    async def teardown(self):
        await self.blackboard.disconnect()


# ═══════════════════════════════════════════════════════════════════════════════
# LEVEL 3: Advanced Tests
# ═══════════════════════════════════════════════════════════════════════════════

class DefenseEvasionTest(TestScenario):
    """Test defense evasion capabilities"""
    
    def __init__(self):
        super().__init__(
            name="Defense Evasion",
            difficulty=TestDifficulty.ADVANCED,
            description="Test agent's ability to detect defenses and adapt attack approach",
            expected_behavior="Agent should detect AV/EDR and recommend evasion techniques",
            mitre_techniques=["T1027", "T1036", "T1562"]
        )
        self.blackboard = MockBlackboard()
    
    async def setup(self):
        await self.blackboard.connect()
        
        # Create defended target
        target_id = await self.blackboard.add_target({
            "ip": "192.168.1.200",
            "hostname": "defended-server",
            "os": "Windows Server 2022",
            "defenses": ["windows_defender", "crowdstrike_edr"]
        })
        self.target_id = target_id
        
        # Create failed task
        task_id = await self.blackboard.add_task({
            "type": "exploit",
            "target_id": target_id,
            "rx_module": "rx-mimikatz-001",
            "retry_count": 0
        })
        self.task_id = task_id
        
        self.blackboard.data["missions"]["test-mission"] = {
            "scope": ["192.168.1.0/24"],
            "goals": ["credential_access"]
        }
    
    async def execute(self) -> Tuple[TestOutcome, str]:
        from src.specialists.analysis import AnalysisSpecialist
        from src.core.config import get_settings
        
        try:
            settings = get_settings()
            specialist = AnalysisSpecialist(
                blackboard=self.blackboard,
                settings=settings,
                llm_enabled=True
            )
            specialist._current_mission_id = "test-mission"
            
            # Simulate defense detection failure
            self.metrics.decisions_made += 1
            error_context = {
                "error_type": "av_detected",
                "error_message": "Payload blocked by Windows Defender",
                "module_used": "rx-mimikatz-001",
                "detected_defenses": ["windows_defender", "amsi"]
            }
            
            result = await specialist.analyze_failure(
                task_id=self.task_id,
                error_context=error_context,
                execution_logs=[{
                    "command": "mimikatz.exe",
                    "stdout": "",
                    "stderr": "Operation did not complete successfully because the file contains a virus or potentially unwanted software"
                }]
            )
            
            decision = result.get("decision")
            reasoning = result.get("reasoning", "")
            
            # Verify evasion recommendations
            evasion_keywords = ["evasion", "obfuscate", "encode", "living-off-the-land", "lolbin", "bypass"]
            has_evasion_rec = any(kw in reasoning.lower() for kw in evasion_keywords)
            
            if decision == "modify_approach":
                self.metrics.correct_decisions += 1
                
                # Check if evasion techniques are recommended
                modified_params = result.get("modified_parameters", {})
                new_module = result.get("new_module", "")
                
                if modified_params.get("use_evasion") or has_evasion_rec:
                    logger.info(f"✓ Agent recommended evasion: {reasoning[:100]}...")
                    
                    # Verify quality of evasion recommendation
                    if result.get("llm_analysis"):
                        self._record_llm_response({
                            "decision": decision,
                            "has_evasion": True,
                            "tokens": result.get("tokens_used", 0),
                            "latency_ms": result.get("latency_ms", 0)
                        })
                    
                    return TestOutcome.PASSED, f"Defense evasion recommendation: {decision} with evasion"
                else:
                    self._add_capability_gap(
                        CapabilityGap.DEFENSE_EVASION,
                        "high",
                        "Agent modified approach but didn't recommend specific evasion techniques",
                        [f"Decision: {decision}", f"Reasoning: {reasoning[:200]}"],
                        "Improve prompts to include specific evasion technique recommendations"
                    )
                    return TestOutcome.PARTIAL, "Modified approach but no specific evasion techniques"
            
            elif decision == "skip":
                # Skipping defended target is acceptable but not optimal
                return TestOutcome.PARTIAL, "Agent chose to skip defended target (acceptable but not optimal)"
            
            else:
                self._add_capability_gap(
                    CapabilityGap.DEFENSE_EVASION,
                    "critical",
                    f"Agent failed to adapt to defense detection",
                    [f"Decision: {decision}", f"Expected: modify_approach"],
                    "Agent needs to recognize AV detection and recommend evasion"
                )
                return TestOutcome.FAILED, f"Failed to adapt: {decision}"
                
        except Exception as e:
            logger.error(f"Test error: {e}")
            return TestOutcome.ERROR, str(e)
    
    async def teardown(self):
        await self.blackboard.disconnect()


class AdaptiveRetryTest(TestScenario):
    """Test adaptive retry with learning from failures"""
    
    def __init__(self):
        super().__init__(
            name="Adaptive Retry with Learning",
            difficulty=TestDifficulty.ADVANCED,
            description="Test agent's ability to learn from repeated failures and adapt strategy",
            expected_behavior="Agent should track failures, learn patterns, and improve approach over retries",
            mitre_techniques=["T1059"]
        )
        self.blackboard = MockBlackboard()
    
    async def setup(self):
        await self.blackboard.connect()
        
        # Create target
        target_id = await self.blackboard.add_target({
            "ip": "192.168.1.150",
            "hostname": "retry-target",
            "os": "Linux"
        })
        self.target_id = target_id
        
        self.blackboard.data["missions"]["test-mission"] = {
            "scope": ["192.168.1.0/24"],
            "goals": ["initial_access"]
        }
    
    async def execute(self) -> Tuple[TestOutcome, str]:
        from src.specialists.analysis import AnalysisSpecialist
        from src.core.config import get_settings
        
        try:
            settings = get_settings()
            specialist = AnalysisSpecialist(
                blackboard=self.blackboard,
                settings=settings,
                llm_enabled=True
            )
            specialist._current_mission_id = "test-mission"
            
            # Simulate multiple failures with escalating retry counts
            failure_scenarios = [
                {"retry_count": 0, "error_type": "connection_timeout", "expected": "retry"},
                {"retry_count": 1, "error_type": "connection_timeout", "expected": "retry"},
                {"retry_count": 2, "error_type": "connection_timeout", "expected": "modify_approach"},
                {"retry_count": 3, "error_type": "av_detected", "expected": "modify_approach"},
            ]
            
            decisions = []
            for scenario in failure_scenarios:
                task_id = await self.blackboard.add_task({
                    "type": "exploit",
                    "target_id": self.target_id,
                    "rx_module": "rx-test-module",
                    "retry_count": scenario["retry_count"],
                    "max_retries": 3
                })
                
                self.metrics.decisions_made += 1
                result = await specialist.analyze_failure(
                    task_id=task_id,
                    error_context={
                        "error_type": scenario["error_type"],
                        "error_message": f"Simulated {scenario['error_type']}",
                        "module_used": "rx-test-module"
                    },
                    execution_logs=[]
                )
                
                decision = result.get("decision")
                decisions.append(decision)
                
                if decision == scenario["expected"]:
                    self.metrics.correct_decisions += 1
                    logger.info(f"✓ Retry {scenario['retry_count']}: {decision} (correct)")
                else:
                    logger.warning(f"✗ Retry {scenario['retry_count']}: {decision} (expected {scenario['expected']})")
                
                # Check if recommendations evolve
                recs = result.get("recommendations", [])
                if scenario["retry_count"] > 1 and not any("alternative" in r.lower() for r in recs):
                    self._add_capability_gap(
                        CapabilityGap.ATTACK_ADAPTATION,
                        "medium",
                        "Agent doesn't recommend alternatives after multiple retries",
                        [f"Retry count: {scenario['retry_count']}", f"Recommendations: {recs}"],
                        "Improve retry logic to suggest alternatives after 2+ failures"
                    )
            
            # Verify learning progression
            should_escalate = decisions[2] in ["modify_approach", "escalate"] and decisions[3] in ["modify_approach", "skip"]
            
            accuracy = self.metrics.decision_accuracy
            if accuracy >= 0.75 and should_escalate:
                return TestOutcome.PASSED, f"Adaptive retry working ({accuracy:.0%} accuracy, proper escalation)"
            elif accuracy >= 0.5:
                return TestOutcome.PARTIAL, f"Partial adaptation ({accuracy:.0%} accuracy)"
            else:
                return TestOutcome.FAILED, f"Poor adaptation ({accuracy:.0%} accuracy)"
                
        except Exception as e:
            logger.error(f"Test error: {e}")
            return TestOutcome.ERROR, str(e)
    
    async def teardown(self):
        await self.blackboard.disconnect()


# ═══════════════════════════════════════════════════════════════════════════════
# LEVEL 4: Expert Tests
# ═══════════════════════════════════════════════════════════════════════════════

class APTSimulationTest(TestScenario):
    """Full APT simulation test"""
    
    def __init__(self):
        super().__init__(
            name="APT29 Kill Chain Simulation",
            difficulty=TestDifficulty.EXPERT,
            description="Simulate APT29 (Cozy Bear) attack chain with full TTPs",
            expected_behavior="Agent should execute realistic APT kill chain: Initial Access → Persistence → Defense Evasion → Cred Access → Discovery → Lateral → Collection → Exfil",
            mitre_techniques=["T1566", "T1547", "T1027", "T1003", "T1082", "T1021", "T1560", "T1041"]
        )
        self.blackboard = MockBlackboard()
    
    async def setup(self):
        await self.blackboard.connect()
        
        # Create enterprise environment
        targets = [
            {"ip": "192.168.1.10", "hostname": "dc01.corp.local", "os": "Windows Server 2019", "role": "domain_controller"},
            {"ip": "192.168.1.20", "hostname": "web01.corp.local", "os": "Windows Server 2019", "role": "web_server"},
            {"ip": "192.168.1.30", "hostname": "db01.corp.local", "os": "Windows Server 2019", "role": "database"},
            {"ip": "192.168.1.100", "hostname": "ws01.corp.local", "os": "Windows 10", "role": "workstation"},
        ]
        
        self.target_ids = []
        for target in targets:
            tid = await self.blackboard.add_target(target)
            self.target_ids.append(tid)
        
        self.blackboard.data["missions"]["apt-mission"] = {
            "scope": ["192.168.1.0/24"],
            "goals": ["domain_admin", "data_exfiltration", "persistence"],
            "apt_profile": "APT29"
        }
    
    async def execute(self) -> Tuple[TestOutcome, str]:
        """
        Execute APT29-style kill chain
        
        Phases:
        1. Initial Access (Spearphishing/Web Exploit)
        2. Execution (PowerShell, WMI)
        3. Persistence (Registry, Scheduled Tasks)
        4. Defense Evasion (Obfuscation, AMSI Bypass)
        5. Credential Access (Mimikatz, LSASS Dump)
        6. Discovery (AD Enumeration)
        7. Lateral Movement (Pass-the-Hash, WMI)
        8. Collection (Data Staging)
        9. Exfiltration (Encrypted Channel)
        """
        from src.specialists.recon import ReconSpecialist
        from src.specialists.attack import AttackSpecialist
        from src.specialists.analysis import AnalysisSpecialist
        from src.core.config import get_settings
        
        try:
            settings = get_settings()
            
            recon = ReconSpecialist(blackboard=self.blackboard, settings=settings)
            attack = AttackSpecialist(blackboard=self.blackboard, settings=settings)
            analysis = AnalysisSpecialist(blackboard=self.blackboard, settings=settings, llm_enabled=True)
            
            for specialist in [recon, attack, analysis]:
                specialist._current_mission_id = "apt-mission"
            
            kill_chain_phases = []
            
            # Phase 1: Initial Access via Web Server
            logger.info("═" * 50)
            logger.info("APT29 Phase 1: Initial Access")
            logger.info("═" * 50)
            
            web_target = self.target_ids[1]  # web01
            
            # Create web vulnerability
            vuln_id = await self.blackboard.add_vulnerability({
                "target_id": web_target,
                "type": "CVE-2021-34473",  # ProxyShell
                "name": "Microsoft Exchange ProxyShell",
                "severity": "critical",
                "exploit_available": True
            })
            
            self.metrics.decisions_made += 1
            exploit_result = await attack._execute_exploit({
                "type": "exploit",
                "id": str(uuid4()),
                "target_id": web_target,
                "vuln_id": vuln_id
            })
            
            if exploit_result.get("success"):
                self.metrics.correct_decisions += 1
                kill_chain_phases.append("initial_access")
                logger.info(f"✓ Initial access achieved on web server")
            else:
                logger.warning("✗ Initial access failed")
                
                # Test analysis specialist's handling of failure
                error_ctx = {"error_type": "exploit_failed", "module_used": "rx-proxyshell"}
                analysis_result = await analysis.analyze_failure(
                    task_id=str(uuid4()),
                    error_context=error_ctx,
                    execution_logs=[]
                )
                
                if analysis_result.get("decision") in ["modify_approach", "retry"]:
                    self.metrics.correct_decisions += 1
                    logger.info(f"✓ Analysis recommended: {analysis_result.get('decision')}")
            
            # Phase 2: Privilege Escalation
            logger.info("═" * 50)
            logger.info("APT29 Phase 2: Privilege Escalation")
            logger.info("═" * 50)
            
            self.metrics.decisions_made += 1
            privesc_result = await attack._execute_privesc({
                "type": "privesc",
                "id": str(uuid4()),
                "target_id": web_target
            })
            
            if privesc_result.get("success"):
                self.metrics.correct_decisions += 1
                kill_chain_phases.append("privilege_escalation")
                logger.info(f"✓ PrivEsc: {privesc_result.get('new_privilege')}")
            
            # Phase 3: Credential Harvesting
            logger.info("═" * 50)
            logger.info("APT29 Phase 3: Credential Access")
            logger.info("═" * 50)
            
            self.metrics.decisions_made += 1
            harvest_result = await attack._execute_cred_harvest({
                "type": "cred_harvest",
                "id": str(uuid4()),
                "target_id": web_target
            })
            
            if harvest_result.get("creds_found", 0) > 0:
                self.metrics.correct_decisions += 1
                kill_chain_phases.append("credential_access")
                logger.info(f"✓ Harvested {harvest_result['creds_found']} credentials")
            
            # Phase 4: Lateral Movement to DC
            logger.info("═" * 50)
            logger.info("APT29 Phase 4: Lateral Movement")
            logger.info("═" * 50)
            
            if self.blackboard.data["creds"]:
                cred_id = list(self.blackboard.data["creds"].keys())[0]
                self.metrics.decisions_made += 1
                
                lateral_result = await attack._execute_lateral({
                    "type": "lateral",
                    "id": str(uuid4()),
                    "target_id": web_target,
                    "cred_id": cred_id
                })
                
                if lateral_result.get("success"):
                    self.metrics.correct_decisions += 1
                    kill_chain_phases.append("lateral_movement")
                    logger.info(f"✓ Lateral movement: {lateral_result.get('laterals_succeeded', 0)} targets")
            
            # Phase 5: Domain Controller Takeover (if lateral succeeded)
            if "lateral_movement" in kill_chain_phases:
                logger.info("═" * 50)
                logger.info("APT29 Phase 5: DC Takeover")
                logger.info("═" * 50)
                
                dc_target = self.target_ids[0]  # dc01
                
                self.metrics.decisions_made += 1
                dc_harvest = await attack._execute_cred_harvest({
                    "type": "cred_harvest",
                    "id": str(uuid4()),
                    "target_id": dc_target
                })
                
                domain_admin_creds = [
                    c for c in self.blackboard.data["creds"].values()
                    if c.get("privilege") in ["domain_admin", "admin"]
                ]
                
                if domain_admin_creds:
                    self.metrics.correct_decisions += 1
                    kill_chain_phases.append("domain_admin")
                    logger.info("✓ Domain Admin credentials obtained!")
            
            # Calculate results
            total_phases = 5
            completed = len(kill_chain_phases)
            accuracy = self.metrics.decision_accuracy
            
            logger.info("═" * 50)
            logger.info(f"APT29 Simulation Complete")
            logger.info(f"Phases: {completed}/{total_phases}")
            logger.info(f"Kill Chain: {' → '.join(kill_chain_phases)}")
            logger.info("═" * 50)
            
            if completed >= 4 and "domain_admin" in kill_chain_phases:
                return TestOutcome.PASSED, f"APT simulation successful: {kill_chain_phases}"
            elif completed >= 3:
                return TestOutcome.PARTIAL, f"Partial APT simulation: {completed}/{total_phases} phases"
            else:
                self._add_capability_gap(
                    CapabilityGap.SPECIALIST_COORDINATION,
                    "critical",
                    "Agent failed to complete APT kill chain",
                    [f"Completed phases: {kill_chain_phases}"],
                    "Improve specialist coordination and attack chain planning"
                )
                return TestOutcome.FAILED, f"APT simulation failed: only {completed}/{total_phases} phases"
                
        except Exception as e:
            logger.error(f"Test error: {e}")
            return TestOutcome.ERROR, str(e)
    
    async def teardown(self):
        await self.blackboard.disconnect()


# ═══════════════════════════════════════════════════════════════════════════════
# Test Runner
# ═══════════════════════════════════════════════════════════════════════════════

class OffensiveTestRunner:
    """Runner for offensive E2E tests"""
    
    def __init__(self):
        self.results: List[TestSuiteResult] = []
        self.all_capability_gaps: List[CapabilityGapReport] = []
    
    def get_test_suites(self) -> Dict[TestDifficulty, List[TestScenario]]:
        """Get all test suites organized by difficulty"""
        return {
            TestDifficulty.BASIC: [
                BasicReconTest(),
                BasicExploitTest(),
                BasicLLMDecisionTest(),
            ],
            TestDifficulty.INTERMEDIATE: [
                CredentialChainTest(),
                MultiStepExploitTest(),
            ],
            TestDifficulty.ADVANCED: [
                DefenseEvasionTest(),
                AdaptiveRetryTest(),
            ],
            TestDifficulty.EXPERT: [
                APTSimulationTest(),
            ],
        }
    
    async def run_suite(
        self, 
        difficulty: TestDifficulty,
        tests: List[TestScenario]
    ) -> TestSuiteResult:
        """Run a single test suite"""
        logger.info(f"\n{'═' * 60}")
        logger.info(f"Running {difficulty.value.upper()} Test Suite ({len(tests)} tests)")
        logger.info(f"{'═' * 60}")
        
        suite_start = time.time()
        results = []
        aggregate_metrics = TestMetrics()
        capability_gaps = []
        
        for test in tests:
            logger.info(f"\n▶ {test.name}")
            logger.info(f"  Description: {test.description}")
            logger.info(f"  MITRE: {', '.join(test.mitre_techniques)}")
            
            test_start = time.time()
            
            try:
                await test.setup()
                outcome, details = await test.execute()
                await test.teardown()
            except Exception as e:
                logger.error(f"Test execution error: {e}")
                outcome = TestOutcome.ERROR
                details = str(e)
            
            test_duration = (time.time() - test_start) * 1000
            
            # Create result
            result = TestResult(
                test_id=str(uuid4()),
                test_name=test.name,
                difficulty=test.difficulty,
                outcome=outcome,
                duration_ms=test_duration,
                metrics=test.metrics,
                expected_behavior=test.expected_behavior,
                actual_behavior=details,
                capability_gaps=test.capability_gaps,
                llm_responses=test.llm_responses
            )
            results.append(result)
            
            # Aggregate metrics
            aggregate_metrics.llm_calls += test.metrics.llm_calls
            aggregate_metrics.llm_tokens += test.metrics.llm_tokens
            aggregate_metrics.llm_latency_ms += test.metrics.llm_latency_ms
            aggregate_metrics.decisions_made += test.metrics.decisions_made
            aggregate_metrics.correct_decisions += test.metrics.correct_decisions
            aggregate_metrics.tasks_completed += test.metrics.tasks_completed
            aggregate_metrics.tasks_failed += test.metrics.tasks_failed
            
            # Collect capability gaps
            capability_gaps.extend(test.capability_gaps)
            
            # Log result
            status_emoji = {
                TestOutcome.PASSED: "✅",
                TestOutcome.FAILED: "❌",
                TestOutcome.PARTIAL: "⚠️",
                TestOutcome.SKIPPED: "⏭️",
                TestOutcome.ERROR: "💥",
            }
            logger.info(f"  {status_emoji[outcome]} {outcome.value}: {details}")
            logger.info(f"  Duration: {test_duration:.0f}ms")
        
        suite_duration = (time.time() - suite_start) * 1000
        
        # Count outcomes
        passed = sum(1 for r in results if r.outcome == TestOutcome.PASSED)
        failed = sum(1 for r in results if r.outcome == TestOutcome.FAILED)
        partial = sum(1 for r in results if r.outcome == TestOutcome.PARTIAL)
        skipped = sum(1 for r in results if r.outcome == TestOutcome.SKIPPED)
        errors = sum(1 for r in results if r.outcome == TestOutcome.ERROR)
        
        suite_result = TestSuiteResult(
            suite_name=f"{difficulty.value}_tests",
            difficulty=difficulty,
            total_tests=len(tests),
            passed=passed,
            failed=failed,
            partial=partial,
            skipped=skipped,
            errors=errors,
            duration_ms=suite_duration,
            results=results,
            aggregate_metrics=aggregate_metrics,
            capability_gaps=capability_gaps
        )
        
        # Log summary
        logger.info(f"\n{'─' * 40}")
        logger.info(f"Suite Summary: {passed}/{len(tests)} passed ({suite_result.success_rate:.0%})")
        logger.info(f"Decision Accuracy: {aggregate_metrics.decision_accuracy:.0%}")
        if capability_gaps:
            logger.info(f"Capability Gaps Found: {len(capability_gaps)}")
        
        return suite_result
    
    async def run_all(
        self, 
        min_difficulty: TestDifficulty = TestDifficulty.BASIC,
        max_difficulty: TestDifficulty = TestDifficulty.EXPERT
    ) -> None:
        """Run all test suites within difficulty range"""
        difficulties = [TestDifficulty.BASIC, TestDifficulty.INTERMEDIATE, 
                       TestDifficulty.ADVANCED, TestDifficulty.EXPERT]
        
        # Filter to range
        run_difficulties = []
        in_range = False
        for d in difficulties:
            if d == min_difficulty:
                in_range = True
            if in_range:
                run_difficulties.append(d)
            if d == max_difficulty:
                break
        
        suites = self.get_test_suites()
        
        for difficulty in run_difficulties:
            tests = suites.get(difficulty, [])
            if tests:
                result = await self.run_suite(difficulty, tests)
                self.results.append(result)
                self.all_capability_gaps.extend(result.capability_gaps)
        
        # Print final report
        self._print_final_report()
    
    def _print_final_report(self) -> None:
        """Print comprehensive final report"""
        print("\n")
        print("═" * 70)
        print("RAGLOX v3.0 Offensive E2E Test Report")
        print("═" * 70)
        
        total_tests = sum(r.total_tests for r in self.results)
        total_passed = sum(r.passed for r in self.results)
        total_failed = sum(r.failed for r in self.results)
        total_partial = sum(r.partial for r in self.results)
        total_errors = sum(r.errors for r in self.results)
        
        print(f"\n📊 Overall Results:")
        print(f"   Total Tests: {total_tests}")
        print(f"   ✅ Passed:   {total_passed} ({total_passed/max(total_tests,1)*100:.1f}%)")
        print(f"   ❌ Failed:   {total_failed} ({total_failed/max(total_tests,1)*100:.1f}%)")
        print(f"   ⚠️ Partial:  {total_partial} ({total_partial/max(total_tests,1)*100:.1f}%)")
        print(f"   💥 Errors:   {total_errors}")
        
        print(f"\n📈 By Difficulty Level:")
        for result in self.results:
            emoji = "🟢" if result.success_rate >= 0.8 else "🟡" if result.success_rate >= 0.5 else "🔴"
            print(f"   {emoji} {result.difficulty.value.upper()}: {result.passed}/{result.total_tests} ({result.success_rate:.0%})")
        
        # Aggregate metrics
        total_decisions = sum(r.aggregate_metrics.decisions_made for r in self.results)
        correct_decisions = sum(r.aggregate_metrics.correct_decisions for r in self.results)
        total_llm_calls = sum(r.aggregate_metrics.llm_calls for r in self.results)
        total_tokens = sum(r.aggregate_metrics.llm_tokens for r in self.results)
        
        print(f"\n🧠 Decision Quality:")
        print(f"   Total Decisions: {total_decisions}")
        print(f"   Correct: {correct_decisions} ({correct_decisions/max(total_decisions,1)*100:.1f}%)")
        print(f"   LLM Calls: {total_llm_calls}")
        print(f"   Tokens Used: {total_tokens}")
        
        # Capability gaps
        if self.all_capability_gaps:
            print(f"\n⚠️ Capability Gaps Identified ({len(self.all_capability_gaps)}):")
            
            # Group by type
            gaps_by_type = {}
            for gap in self.all_capability_gaps:
                if gap.gap_type not in gaps_by_type:
                    gaps_by_type[gap.gap_type] = []
                gaps_by_type[gap.gap_type].append(gap)
            
            for gap_type, gaps in gaps_by_type.items():
                print(f"\n   📍 {gap_type.value}:")
                for gap in gaps[:3]:  # Show top 3 per type
                    severity_emoji = "🔴" if gap.severity == "critical" else "🟠" if gap.severity == "high" else "🟡"
                    print(f"      {severity_emoji} [{gap.severity}] {gap.description}")
                    print(f"         Fix: {gap.recommended_fix}")
        
        # Recommendations
        print(f"\n💡 Improvement Recommendations:")
        recommendations = self._generate_recommendations()
        for i, rec in enumerate(recommendations[:5], 1):
            print(f"   {i}. {rec}")
        
        print("\n" + "═" * 70)
    
    def _generate_recommendations(self) -> List[str]:
        """Generate improvement recommendations based on test results"""
        recs = []
        
        # Analyze capability gaps
        gap_counts = {}
        for gap in self.all_capability_gaps:
            if gap.gap_type not in gap_counts:
                gap_counts[gap.gap_type] = 0
            gap_counts[gap.gap_type] += 1
        
        # Generate recommendations based on gaps
        if CapabilityGap.LLM_DECISION_QUALITY in gap_counts:
            recs.append("Improve LLM prompts for better decision accuracy - see PROMPT_ENGINEERING.md")
        
        if CapabilityGap.DEFENSE_EVASION in gap_counts:
            recs.append("Add specific evasion technique recommendations to analysis prompts")
        
        if CapabilityGap.SPECIALIST_COORDINATION in gap_counts:
            recs.append("Improve inter-specialist communication and task chaining")
        
        if CapabilityGap.EXECUTION_RELIABILITY in gap_counts:
            recs.append("Ensure RXModuleRunner is properly configured for real execution")
        
        if CapabilityGap.ATTACK_ADAPTATION in gap_counts:
            recs.append("Implement better failure pattern learning in Operational Memory")
        
        # Add based on success rates
        for result in self.results:
            if result.success_rate < 0.5:
                recs.append(f"Focus on {result.difficulty.value} level capabilities - currently at {result.success_rate:.0%}")
        
        return recs if recs else ["All tests passing - consider adding more complex scenarios"]
    
    def export_results(self, filepath: str) -> None:
        """Export results to JSON"""
        import json
        
        export_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "summary": {
                "total_tests": sum(r.total_tests for r in self.results),
                "passed": sum(r.passed for r in self.results),
                "failed": sum(r.failed for r in self.results),
                "partial": sum(r.partial for r in self.results),
                "errors": sum(r.errors for r in self.results),
            },
            "suites": [],
            "capability_gaps": [],
        }
        
        for result in self.results:
            suite_data = {
                "name": result.suite_name,
                "difficulty": result.difficulty.value,
                "total_tests": result.total_tests,
                "passed": result.passed,
                "failed": result.failed,
                "success_rate": result.success_rate,
                "duration_ms": result.duration_ms,
                "tests": []
            }
            
            for test_result in result.results:
                test_data = {
                    "name": test_result.test_name,
                    "outcome": test_result.outcome.value,
                    "duration_ms": test_result.duration_ms,
                    "expected": test_result.expected_behavior,
                    "actual": test_result.actual_behavior,
                    "decision_accuracy": test_result.metrics.decision_accuracy,
                }
                suite_data["tests"].append(test_data)
            
            export_data["suites"].append(suite_data)
        
        for gap in self.all_capability_gaps:
            export_data["capability_gaps"].append({
                "type": gap.gap_type.value,
                "severity": gap.severity,
                "description": gap.description,
                "fix": gap.recommended_fix,
            })
        
        with open(filepath, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        logger.info(f"Results exported to {filepath}")


# ═══════════════════════════════════════════════════════════════════════════════
# Main Entry Point
# ═══════════════════════════════════════════════════════════════════════════════

async def main():
    """Main entry point for E2E tests"""
    import argparse
    
    parser = argparse.ArgumentParser(description="RAGLOX Offensive E2E Tests")
    parser.add_argument("--min-level", choices=["basic", "intermediate", "advanced", "expert"],
                       default="basic", help="Minimum difficulty level")
    parser.add_argument("--max-level", choices=["basic", "intermediate", "advanced", "expert"],
                       default="expert", help="Maximum difficulty level")
    parser.add_argument("--export", type=str, help="Export results to JSON file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Map string to enum
    level_map = {
        "basic": TestDifficulty.BASIC,
        "intermediate": TestDifficulty.INTERMEDIATE,
        "advanced": TestDifficulty.ADVANCED,
        "expert": TestDifficulty.EXPERT,
    }
    
    runner = OffensiveTestRunner()
    await runner.run_all(
        min_difficulty=level_map[args.min_level],
        max_difficulty=level_map[args.max_level]
    )
    
    if args.export:
        runner.export_results(args.export)


if __name__ == "__main__":
    asyncio.run(main())
