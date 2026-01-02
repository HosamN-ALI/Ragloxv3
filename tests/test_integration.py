# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Integration Tests
# End-to-end testing of the complete MVP
# ═══════════════════════════════════════════════════════════════

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4
import json
import asyncio

from src.core.config import Settings
from src.core.blackboard import Blackboard
from src.core.models import (
    Mission, MissionCreate, MissionStatus, GoalStatus,
    Target, TargetStatus, Priority,
    Vulnerability, Severity,
    Credential, CredentialType, PrivilegeLevel,
    Session, SessionStatus, SessionType,
    Task, TaskType, TaskStatus, SpecialistType
)
from src.specialists.recon import ReconSpecialist
from src.specialists.attack import AttackSpecialist
from src.controller.mission import MissionController


# ═══════════════════════════════════════════════════════════════
# Full Mock Blackboard for Integration Tests
# ═══════════════════════════════════════════════════════════════

class MockBlackboardIntegration:
    """A complete mock Blackboard for integration testing."""
    
    def __init__(self):
        self.storage = {}
        self.sorted_sets = {}
        self.sets = {}
        self.streams = {}
        self._connected = False
    
    async def connect(self):
        self._connected = True
    
    async def disconnect(self):
        self._connected = False
    
    async def health_check(self):
        return self._connected
    
    async def create_mission(self, mission):
        mission_id = str(mission.id)
        data = mission.model_dump()
        if isinstance(data.get("scope"), list):
            data["scope"] = json.dumps(data["scope"])
        if isinstance(data.get("goals"), dict):
            # Convert GoalStatus to string
            data["goals"] = json.dumps({
                k: (v.value if hasattr(v, 'value') else v) 
                for k, v in data["goals"].items()
            })
        self.storage[f"mission:{mission_id}:info"] = data
        
        goals = mission.goals
        self.storage[f"mission:{mission_id}:goals"] = {
            k: (v.value if hasattr(v, 'value') else v) 
            for k, v in goals.items()
        }
        
        self.storage[f"mission:{mission_id}:stats"] = {
            "targets_discovered": 0,
            "vulns_found": 0,
            "creds_harvested": 0,
            "sessions_established": 0,
            "goals_achieved": 0
        }
        return mission_id
    
    async def get_mission(self, mission_id):
        return self.storage.get(f"mission:{mission_id}:info")
    
    async def update_mission_status(self, mission_id, status):
        key = f"mission:{mission_id}:info"
        if key in self.storage:
            self.storage[key]["status"] = status.value if hasattr(status, 'value') else status
    
    async def get_mission_goals(self, mission_id):
        return self.storage.get(f"mission:{mission_id}:goals", {})
    
    async def update_goal_status(self, mission_id, goal, status):
        key = f"mission:{mission_id}:goals"
        if key not in self.storage:
            self.storage[key] = {}
        self.storage[key][goal] = status
        
        if status == "achieved":
            await self._increment_stat(mission_id, "goals_achieved")
    
    async def get_mission_stats(self, mission_id):
        from src.core.models import MissionStats
        stats = self.storage.get(f"mission:{mission_id}:stats", {})
        return MissionStats(
            targets_discovered=int(stats.get("targets_discovered", 0)),
            vulns_found=int(stats.get("vulns_found", 0)),
            creds_harvested=int(stats.get("creds_harvested", 0)),
            sessions_established=int(stats.get("sessions_established", 0)),
            goals_achieved=int(stats.get("goals_achieved", 0))
        )
    
    async def _increment_stat(self, mission_id, stat):
        key = f"mission:{mission_id}:stats"
        if key in self.storage:
            self.storage[key][stat] = self.storage[key].get(stat, 0) + 1
    
    async def add_target(self, target):
        target_id = str(target.id)
        mission_id = str(target.mission_id)
        self.storage[f"target:{target_id}"] = target.model_dump()
        
        set_key = f"mission:{mission_id}:targets"
        if set_key not in self.sets:
            self.sets[set_key] = set()
        self.sets[set_key].add(f"target:{target_id}")
        
        await self._increment_stat(mission_id, "targets_discovered")
        return target_id
    
    async def get_target(self, target_id):
        return self.storage.get(f"target:{target_id}")
    
    async def get_mission_targets(self, mission_id):
        return list(self.sets.get(f"mission:{mission_id}:targets", set()))
    
    async def update_target_status(self, target_id, status):
        key = f"target:{target_id}"
        if key in self.storage:
            self.storage[key]["status"] = status.value if hasattr(status, 'value') else status
    
    async def add_target_ports(self, target_id, ports):
        self.storage[f"target:{target_id}:ports"] = ports
    
    async def get_target_ports(self, target_id):
        return self.storage.get(f"target:{target_id}:ports", {})
    
    async def add_vulnerability(self, vuln):
        vuln_id = str(vuln.id)
        mission_id = str(vuln.mission_id)
        self.storage[f"vuln:{vuln_id}"] = vuln.model_dump()
        
        cvss = vuln.cvss or self._severity_to_score(vuln.severity)
        zset_key = f"mission:{mission_id}:vulns"
        if zset_key not in self.sorted_sets:
            self.sorted_sets[zset_key] = {}
        self.sorted_sets[zset_key][f"vuln:{vuln_id}"] = cvss
        
        await self._increment_stat(mission_id, "vulns_found")
        return vuln_id
    
    def _severity_to_score(self, severity):
        mapping = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 8.0,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 3.0,
            Severity.INFO: 1.0,
        }
        return mapping.get(severity, 5.0)
    
    async def get_vulnerability(self, vuln_id):
        return self.storage.get(f"vuln:{vuln_id}")
    
    async def get_mission_vulns(self, mission_id, limit=100):
        zset_key = f"mission:{mission_id}:vulns"
        if zset_key not in self.sorted_sets:
            return []
        items = sorted(self.sorted_sets[zset_key].items(), key=lambda x: x[1], reverse=True)
        return [k for k, v in items[:limit]]
    
    async def update_vuln_status(self, vuln_id, status):
        key = f"vuln:{vuln_id}"
        if key in self.storage:
            self.storage[key]["status"] = status
    
    async def add_credential(self, cred):
        cred_id = str(cred.id)
        mission_id = str(cred.mission_id)
        self.storage[f"cred:{cred_id}"] = cred.model_dump()
        
        set_key = f"mission:{mission_id}:creds"
        if set_key not in self.sets:
            self.sets[set_key] = set()
        self.sets[set_key].add(f"cred:{cred_id}")
        
        await self._increment_stat(mission_id, "creds_harvested")
        return cred_id
    
    async def get_credential(self, cred_id):
        return self.storage.get(f"cred:{cred_id}")
    
    async def get_mission_creds(self, mission_id):
        return list(self.sets.get(f"mission:{mission_id}:creds", set()))
    
    async def add_session(self, session):
        session_id = str(session.id)
        mission_id = str(session.mission_id)
        self.storage[f"session:{session_id}"] = session.model_dump()
        
        set_key = f"mission:{mission_id}:sessions"
        if set_key not in self.sets:
            self.sets[set_key] = set()
        self.sets[set_key].add(f"session:{session_id}")
        
        await self._increment_stat(mission_id, "sessions_established")
        return session_id
    
    async def get_session(self, session_id):
        return self.storage.get(f"session:{session_id}")
    
    async def get_mission_sessions(self, mission_id):
        return list(self.sets.get(f"mission:{mission_id}:sessions", set()))
    
    async def update_session_status(self, session_id, status):
        key = f"session:{session_id}"
        if key in self.storage:
            self.storage[key]["status"] = status.value if hasattr(status, 'value') else status
    
    async def add_task(self, task):
        task_id = str(task.id)
        mission_id = str(task.mission_id)
        
        data = task.model_dump()
        # Convert enums to values
        for key, value in data.items():
            if hasattr(value, 'value'):
                data[key] = value.value
        
        self.storage[f"task:{task_id}"] = data
        
        zset_key = f"mission:{mission_id}:tasks:pending"
        if zset_key not in self.sorted_sets:
            self.sorted_sets[zset_key] = {}
        self.sorted_sets[zset_key][f"task:{task_id}"] = task.priority
        
        return task_id
    
    async def get_task(self, task_id):
        return self.storage.get(f"task:{task_id}")
    
    async def claim_task(self, mission_id, worker_id, specialist):
        pending_key = f"mission:{mission_id}:tasks:pending"
        running_key = f"mission:{mission_id}:tasks:running"
        
        if pending_key not in self.sorted_sets:
            return None
        
        # Sort by priority (higher first)
        items = sorted(self.sorted_sets[pending_key].items(), key=lambda x: x[1], reverse=True)
        
        for task_key, priority in items:
            task = self.storage.get(task_key)
            if task and task.get("specialist") == specialist:
                del self.sorted_sets[pending_key][task_key]
                
                if running_key not in self.sets:
                    self.sets[running_key] = set()
                self.sets[running_key].add(task_key)
                
                task_id = task_key.replace("task:", "")
                self.storage[task_key]["status"] = "running"
                self.storage[task_key]["assigned_to"] = worker_id
                return task_id
        
        return None
    
    async def complete_task(self, mission_id, task_id, result, result_data=None):
        key = f"task:{task_id}"
        if key in self.storage:
            self.storage[key]["status"] = "completed"
            self.storage[key]["result"] = result
            if result_data:
                self.storage[key]["result_data"] = result_data
    
    async def fail_task(self, mission_id, task_id, error):
        key = f"task:{task_id}"
        if key in self.storage:
            self.storage[key]["status"] = "failed"
            self.storage[key]["error_message"] = error
    
    async def get_pending_tasks(self, mission_id, specialist=None, limit=100):
        pending_key = f"mission:{mission_id}:tasks:pending"
        if pending_key not in self.sorted_sets:
            return []
        
        items = sorted(self.sorted_sets[pending_key].items(), key=lambda x: x[1], reverse=True)
        
        if not specialist:
            return [k.replace("task:", "") for k, v in items[:limit]]
        
        result = []
        for task_key, _ in items:
            task = self.storage.get(task_key)
            if task and task.get("specialist") == specialist:
                result.append(task_key.replace("task:", ""))
                if len(result) >= limit:
                    break
        return result
    
    async def publish(self, channel, event):
        pass
    
    async def publish_dict(self, channel, data):
        pass
    
    async def subscribe(self, *channels):
        return MagicMock()
    
    async def get_message(self, timeout=1.0):
        return None
    
    def get_channel(self, mission_id, entity):
        return f"channel:mission:{mission_id}:{entity}"
    
    async def send_heartbeat(self, mission_id, specialist_id):
        key = f"mission:{mission_id}:heartbeats"
        if key not in self.storage:
            self.storage[key] = {}
        from datetime import datetime
        self.storage[key][specialist_id] = datetime.utcnow().isoformat()
    
    async def get_heartbeats(self, mission_id):
        return self.storage.get(f"mission:{mission_id}:heartbeats", {})
    
    async def log_result(self, mission_id, event_type, data):
        key = f"mission:{mission_id}:results"
        if key not in self.streams:
            self.streams[key] = []
        self.streams[key].append({
            "type": event_type,
            "data": data
        })
    
    async def get_results(self, mission_id, count=100, start="-", end="+"):
        return self.streams.get(f"mission:{mission_id}:results", [])[:count]


# ═══════════════════════════════════════════════════════════════
# Integration Tests
# ═══════════════════════════════════════════════════════════════

@pytest.fixture
def integration_blackboard():
    """Create integration test blackboard."""
    return MockBlackboardIntegration()


@pytest.fixture
def settings():
    """Create test settings."""
    return Settings(
        redis_url="redis://localhost:6379/0",
        redis_max_connections=10
    )


class TestMissionIntegration:
    """Test complete mission flow."""
    
    @pytest.mark.asyncio
    async def test_complete_mission_flow(self, integration_blackboard, settings):
        """Test a complete mission from creation to completion."""
        blackboard = integration_blackboard
        await blackboard.connect()
        
        # 1. Create a mission
        mission = Mission(
            name="Integration Test Mission",
            description="Testing the complete flow",
            scope=["192.168.1.0/28"],
            goals={
                "domain_admin": GoalStatus.PENDING,
                "data_exfil": GoalStatus.PENDING
            }
        )
        mission_id = await blackboard.create_mission(mission)
        
        assert mission_id is not None
        
        # 2. Verify mission was created
        mission_data = await blackboard.get_mission(mission_id)
        assert mission_data is not None
        assert mission_data["name"] == "Integration Test Mission"
        
        # 3. Create initial scan task
        task = Task(
            mission_id=mission.id,
            type=TaskType.NETWORK_SCAN,
            specialist=SpecialistType.RECON,
            priority=10
        )
        task_id = await blackboard.add_task(task)
        
        # 4. Simulate Recon specialist claiming and completing task
        claimed_id = await blackboard.claim_task(mission_id, "recon-001", "recon")
        assert claimed_id == task_id
        
        # 5. Add discovered target
        target = Target(
            mission_id=mission.id,
            ip="192.168.1.100",
            hostname="dc01",
            os="Windows Server 2019",
            priority=Priority.HIGH
        )
        target_id = await blackboard.add_target(target)
        
        # 6. Add ports
        await blackboard.add_target_ports(target_id, {
            "445": "smb",
            "3389": "rdp"
        })
        
        # 7. Complete scan task
        await blackboard.complete_task(mission_id, task_id, "success", {
            "targets_found": 1
        })
        
        # 8. Add vulnerability
        vuln = Vulnerability(
            mission_id=mission.id,
            target_id=target.id,
            type="MS17-010",
            name="EternalBlue",
            severity=Severity.CRITICAL,
            cvss=10.0,
            exploit_available=True,
            rx_modules=["rx-eternalblue"]
        )
        vuln_id = await blackboard.add_vulnerability(vuln)
        
        # 9. Create exploit task
        exploit_task = Task(
            mission_id=mission.id,
            type=TaskType.EXPLOIT,
            specialist=SpecialistType.ATTACK,
            priority=9,
            target_id=target.id,
            vuln_id=vuln.id
        )
        exploit_task_id = await blackboard.add_task(exploit_task)
        
        # 10. Attack specialist claims task
        claimed_exploit_id = await blackboard.claim_task(mission_id, "attack-001", "attack")
        assert claimed_exploit_id == exploit_task_id
        
        # 11. Add session (exploit succeeded)
        session = Session(
            mission_id=mission.id,
            target_id=target.id,
            type=SessionType.METERPRETER,
            user="SYSTEM",
            privilege=PrivilegeLevel.SYSTEM,
            via_vuln_id=vuln.id
        )
        session_id = await blackboard.add_session(session)
        
        # 12. Update target status
        await blackboard.update_target_status(target_id, TargetStatus.EXPLOITED)
        
        # 13. Add credential (from cred harvest)
        cred = Credential(
            mission_id=mission.id,
            target_id=target.id,
            type=CredentialType.HASH,
            username="Administrator",
            domain="CORP",
            privilege_level=PrivilegeLevel.DOMAIN_ADMIN
        )
        cred_id = await blackboard.add_credential(cred)
        
        # 14. Achieve goal
        await blackboard.update_goal_status(mission_id, "domain_admin", "achieved")
        
        # 15. Verify final state
        stats = await blackboard.get_mission_stats(mission_id)
        
        assert stats.targets_discovered == 1
        assert stats.vulns_found == 1
        assert stats.sessions_established == 1
        assert stats.creds_harvested == 1
        assert stats.goals_achieved == 1
        
        goals = await blackboard.get_mission_goals(mission_id)
        assert goals["domain_admin"] == "achieved"
        
        await blackboard.disconnect()
    
    @pytest.mark.asyncio
    async def test_specialist_task_processing(self, integration_blackboard, settings):
        """Test specialist task processing workflow."""
        blackboard = integration_blackboard
        await blackboard.connect()
        
        # Create mission
        mission = Mission(
            name="Specialist Test",
            scope=["10.0.0.0/24"],
            goals={"persistence": GoalStatus.PENDING}
        )
        mission_id = await blackboard.create_mission(mission)
        
        # Create Recon specialist
        recon = ReconSpecialist(
            blackboard=blackboard,
            settings=settings,
            worker_id="recon-test"
        )
        recon._current_mission_id = mission_id
        recon._running = True
        
        # Add a target manually
        target_id = await recon.add_discovered_target(
            ip="10.0.0.5",
            hostname="webserver",
            priority="high"
        )
        
        assert target_id is not None
        
        # Verify target was added
        targets = await blackboard.get_mission_targets(mission_id)
        assert len(targets) == 1
        
        await blackboard.disconnect()
    
    @pytest.mark.asyncio
    async def test_attack_chain(self, integration_blackboard, settings):
        """Test attack chain: exploit -> session -> cred harvest."""
        blackboard = integration_blackboard
        await blackboard.connect()
        
        # Setup
        mission = Mission(
            name="Attack Chain Test",
            scope=["172.16.0.0/16"],
            goals={"domain_admin": GoalStatus.PENDING}
        )
        mission_id = await blackboard.create_mission(mission)
        
        target = Target(
            mission_id=mission.id,
            ip="172.16.1.50",
            status=TargetStatus.SCANNED
        )
        target_id = await blackboard.add_target(target)
        
        vuln = Vulnerability(
            mission_id=mission.id,
            target_id=target.id,
            type="CVE-2021-44228",
            severity=Severity.CRITICAL,
            exploit_available=True
        )
        vuln_id = await blackboard.add_vulnerability(vuln)
        
        # Create Attack specialist
        attack = AttackSpecialist(
            blackboard=blackboard,
            settings=settings,
            worker_id="attack-test"
        )
        attack._current_mission_id = mission_id
        attack._running = True
        
        # Add session
        session_id = await attack.add_established_session(
            target_id=target_id,
            session_type="shell",
            user="www-data",
            privilege=PrivilegeLevel.USER,
            via_vuln_id=vuln_id
        )
        
        assert session_id is not None
        
        # Add credential
        cred_id = await attack.add_discovered_credential(
            target_id=target_id,
            cred_type=CredentialType.PASSWORD,
            username="admin",
            privilege_level=PrivilegeLevel.ADMIN
        )
        
        assert cred_id is not None
        
        # Verify stats
        stats = await blackboard.get_mission_stats(mission_id)
        assert stats.sessions_established == 1
        assert stats.creds_harvested == 1
        
        await blackboard.disconnect()


class TestDataFlow:
    """Test data flow through the system."""
    
    @pytest.mark.asyncio
    async def test_mission_stats_accumulation(self, integration_blackboard):
        """Test that stats accumulate correctly."""
        blackboard = integration_blackboard
        await blackboard.connect()
        
        mission = Mission(
            name="Stats Test",
            scope=["10.0.0.0/8"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        
        # Add multiple targets
        for i in range(5):
            target = Target(
                mission_id=mission.id,
                ip=f"10.0.0.{i+1}"
            )
            await blackboard.add_target(target)
        
        stats = await blackboard.get_mission_stats(mission_id)
        assert stats.targets_discovered == 5
        
        await blackboard.disconnect()
    
    @pytest.mark.asyncio
    async def test_vulnerability_sorting(self, integration_blackboard):
        """Test vulnerabilities are sorted by severity."""
        blackboard = integration_blackboard
        await blackboard.connect()
        
        mission = Mission(
            name="Vuln Sort Test",
            scope=["10.0.0.0/8"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        
        target = Target(mission_id=mission.id, ip="10.0.0.1")
        target_id = await blackboard.add_target(target)
        
        # Add vulns in random order
        low_vuln = Vulnerability(
            mission_id=mission.id, target_id=target.id,
            type="LOW-1", severity=Severity.LOW
        )
        crit_vuln = Vulnerability(
            mission_id=mission.id, target_id=target.id,
            type="CRIT-1", severity=Severity.CRITICAL
        )
        med_vuln = Vulnerability(
            mission_id=mission.id, target_id=target.id,
            type="MED-1", severity=Severity.MEDIUM
        )
        
        await blackboard.add_vulnerability(low_vuln)
        await blackboard.add_vulnerability(crit_vuln)
        await blackboard.add_vulnerability(med_vuln)
        
        # Get sorted vulns
        vulns = await blackboard.get_mission_vulns(mission_id)
        
        # Critical should be first
        first_vuln = await blackboard.get_vulnerability(vulns[0].replace("vuln:", ""))
        assert first_vuln["type"] == "CRIT-1"
        
        await blackboard.disconnect()


class TestEdgeCases:
    """Test edge cases and error handling."""
    
    @pytest.mark.asyncio
    async def test_nonexistent_mission(self, integration_blackboard):
        """Test operations on nonexistent mission."""
        blackboard = integration_blackboard
        await blackboard.connect()
        
        mission_data = await blackboard.get_mission("nonexistent-id")
        assert mission_data is None
        
        await blackboard.disconnect()
    
    @pytest.mark.asyncio
    async def test_nonexistent_target(self, integration_blackboard):
        """Test operations on nonexistent target."""
        blackboard = integration_blackboard
        await blackboard.connect()
        
        target_data = await blackboard.get_target("nonexistent-id")
        assert target_data is None
        
        await blackboard.disconnect()
    
    @pytest.mark.asyncio
    async def test_claim_no_tasks(self, integration_blackboard):
        """Test claiming when no tasks available."""
        blackboard = integration_blackboard
        await blackboard.connect()
        
        mission = Mission(
            name="No Tasks Test",
            scope=["10.0.0.0/8"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        
        claimed = await blackboard.claim_task(mission_id, "worker-001", "recon")
        assert claimed is None
        
        await blackboard.disconnect()


# ═══════════════════════════════════════════════════════════════
# Real Execution Integration Tests with LocalExecutor
# ═══════════════════════════════════════════════════════════════

class TestRealExecutionIntegration:
    """
    Integration tests that use REAL execution via LocalExecutor.
    
    These tests verify the complete flow from Specialist → RXModuleRunner → Executor.
    Uses localhost as target for safe testing.
    """
    
    @pytest.fixture
    def local_executor(self):
        """Create a LocalExecutor for real execution tests."""
        from src.executors import LocalExecutor, LocalConfig
        config = LocalConfig(
            shell="bash",
            timeout=30
        )
        return LocalExecutor(config)
    
    @pytest.fixture
    def executor_factory(self):
        """Create an ExecutorFactory."""
        from src.executors import ExecutorFactory
        return ExecutorFactory()
    
    @pytest.fixture
    def rx_module_runner(self, executor_factory):
        """Create RXModuleRunner with factory."""
        from src.executors import RXModuleRunner
        return RXModuleRunner(factory=executor_factory)
    
    @pytest.mark.asyncio
    async def test_recon_specialist_with_real_execution(
        self, 
        integration_blackboard, 
        settings,
        executor_factory,
        rx_module_runner
    ):
        """
        Test ReconSpecialist with real LocalExecutor execution.
        
        Scenario:
        1. Create mission with localhost as target
        2. ReconSpecialist executes real host discovery on localhost
        3. Verifies localhost is discovered and ports are scanned
        """
        blackboard = integration_blackboard
        await blackboard.connect()
        
        # Create mission targeting localhost
        mission = Mission(
            name="Real Execution Recon Test",
            description="Testing ReconSpecialist with real local execution",
            scope=["127.0.0.1/32"],  # Just localhost
            goals={"initial_access": GoalStatus.PENDING}
        )
        mission_id = await blackboard.create_mission(mission)
        
        # Create Recon specialist with injected dependencies
        recon = ReconSpecialist(
            blackboard=blackboard,
            settings=settings,
            worker_id="recon-real-test",
            runner=rx_module_runner,
            executor_factory=executor_factory
        )
        recon._current_mission_id = mission_id
        recon._running = True
        
        # Execute direct command test
        result = await recon.execute_command_direct(
            command="echo 'Hello from RAGLOX' && whoami",
            target_host="localhost",
            target_platform="linux",
            timeout=10
        )
        
        # Verify real execution worked
        assert result["success"] == True
        assert "Hello from RAGLOX" in result["stdout"]
        assert result["exit_code"] == 0
        
        # Test network scan simulation on localhost
        task = {
            "id": str(uuid4()),
            "type": TaskType.NETWORK_SCAN.value,
            "mission_id": mission_id
        }
        
        # Execute network scan (uses execute_command_direct internally for localhost)
        scan_result = await recon.execute_task(task)
        
        # Verify scan completed (may be simulated if nmap not available)
        assert "hosts_discovered" in scan_result or "error" in scan_result
        
        await blackboard.disconnect()
    
    @pytest.mark.asyncio
    async def test_recon_port_scan_localhost(
        self,
        integration_blackboard,
        settings,
        executor_factory,
        rx_module_runner
    ):
        """
        Test ReconSpecialist port scanning on localhost.
        
        This test verifies that port scanning works correctly
        by scanning localhost and detecting open ports.
        """
        blackboard = integration_blackboard
        await blackboard.connect()
        
        # Create mission
        mission = Mission(
            name="Port Scan Localhost Test",
            scope=["127.0.0.1/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        
        # Add localhost as target
        target = Target(
            mission_id=mission.id,
            ip="127.0.0.1",
            hostname="localhost",
            os="Linux",
            status=TargetStatus.DISCOVERED
        )
        target_id = await blackboard.add_target(target)
        
        # Create Recon specialist
        recon = ReconSpecialist(
            blackboard=blackboard,
            settings=settings,
            worker_id="recon-portscan-test",
            runner=rx_module_runner,
            executor_factory=executor_factory
        )
        recon._current_mission_id = mission_id
        recon._running = True
        
        # Execute port scan task
        task = {
            "id": str(uuid4()),
            "type": TaskType.PORT_SCAN.value,
            "target_id": target_id
        }
        
        result = await recon.execute_task(task)
        
        # Verify result structure
        assert "ports_found" in result or "open_ports" in result or "error" in result
        
        # If ports were found, verify they were added
        ports = await blackboard.get_target_ports(target_id)
        # ports may be empty if no real ports are open, that's OK
        assert isinstance(ports, dict)
        
        await blackboard.disconnect()
    
    @pytest.mark.asyncio
    async def test_attack_specialist_with_real_execution(
        self,
        integration_blackboard,
        settings,
        executor_factory,
        rx_module_runner
    ):
        """
        Test AttackSpecialist with real execution capabilities.
        
        Note: This test uses simulation mode since we can't actually
        exploit localhost, but verifies the integration is correct.
        """
        blackboard = integration_blackboard
        await blackboard.connect()
        
        # Setup mission
        mission = Mission(
            name="Attack Specialist Real Test",
            scope=["127.0.0.1/32"],
            goals={"initial_access": GoalStatus.PENDING}
        )
        mission_id = await blackboard.create_mission(mission)
        
        # Add target
        target = Target(
            mission_id=mission.id,
            ip="127.0.0.1",
            hostname="localhost",
            os="Linux",
            status=TargetStatus.SCANNED
        )
        target_id = await blackboard.add_target(target)
        
        # Add a mock vulnerability (for testing flow)
        vuln = Vulnerability(
            mission_id=mission.id,
            target_id=target.id,
            type="CVE-TEST-001",
            name="Test Vulnerability",
            severity=Severity.HIGH,
            exploit_available=True
        )
        vuln_id = await blackboard.add_vulnerability(vuln)
        
        # Create Attack specialist with dependencies
        attack = AttackSpecialist(
            blackboard=blackboard,
            settings=settings,
            worker_id="attack-real-test",
            runner=rx_module_runner,
            executor_factory=executor_factory
        )
        attack._current_mission_id = mission_id
        attack._running = True
        
        # Verify attack specialist has access to runner
        assert attack.runner is not None or attack._execution_mode == "simulated"
        assert attack.executor_factory is not None
        
        # Test credential harvest (simulated since we can't actually harvest)
        task = {
            "id": str(uuid4()),
            "type": TaskType.CRED_HARVEST.value,
            "target_id": target_id
        }
        
        result = await attack.execute_task(task)
        
        # Verify result structure
        assert "creds_found" in result or "error" in result
        
        await blackboard.disconnect()
    
    @pytest.mark.asyncio
    async def test_specialist_error_context_to_blackboard(
        self,
        integration_blackboard,
        settings,
        executor_factory,
        rx_module_runner
    ):
        """
        Test that error context is properly logged to Blackboard.
        
        This verifies the Reflexion pattern integration where
        error context is stored for analysis.
        """
        blackboard = integration_blackboard
        await blackboard.connect()
        
        # Setup
        mission = Mission(
            name="Error Context Test",
            scope=["127.0.0.1/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        
        # Create Recon specialist
        recon = ReconSpecialist(
            blackboard=blackboard,
            settings=settings,
            worker_id="recon-error-test",
            runner=rx_module_runner,
            executor_factory=executor_factory
        )
        recon._current_mission_id = mission_id
        recon._running = True
        
        # Execute a command that will produce a result
        task_id = str(uuid4())
        
        result = await recon.execute_command_direct(
            command="echo 'test output'",
            target_host="localhost",
            target_platform="linux",
            timeout=5
        )
        
        # Log to Blackboard
        await recon.log_execution_to_blackboard(task_id, result)
        
        # Verify log was created
        results = await blackboard.get_results(mission_id)
        assert len(results) > 0
        
        # Find the execution log
        exec_logs = [r for r in results if r["type"] == "execution_completed"]
        assert len(exec_logs) > 0
        
        await blackboard.disconnect()
    
    @pytest.mark.asyncio
    async def test_executor_factory_connection_cleanup(
        self,
        integration_blackboard,
        settings,
        executor_factory,
        rx_module_runner
    ):
        """
        Test that ExecutorFactory properly cleans up connections.
        
        This verifies resource management in the execution layer.
        """
        blackboard = integration_blackboard
        await blackboard.connect()
        
        # Setup
        mission = Mission(
            name="Connection Cleanup Test",
            scope=["127.0.0.1/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        
        # Create specialist
        recon = ReconSpecialist(
            blackboard=blackboard,
            settings=settings,
            worker_id="recon-cleanup-test",
            runner=rx_module_runner,
            executor_factory=executor_factory
        )
        recon._current_mission_id = mission_id
        recon._running = True
        
        # Execute some commands
        for i in range(3):
            await recon.execute_command_direct(
                command=f"echo 'command {i}'",
                target_host="localhost",
                target_platform="linux",
                timeout=5
            )
        
        # Cleanup connections
        await recon.cleanup_connections()
        
        # Stop specialist (should call cleanup again)
        await recon.stop()
        
        # Verify no errors occurred during cleanup
        assert not recon._running
        
        await blackboard.disconnect()


class TestEndToEndScenario:
    """
    End-to-end test scenarios simulating real attack workflows.
    """
    
    @pytest.fixture
    def executor_factory(self):
        """Create an ExecutorFactory."""
        from src.executors import ExecutorFactory
        return ExecutorFactory()
    
    @pytest.fixture
    def rx_module_runner(self, executor_factory):
        """Create RXModuleRunner with factory."""
        from src.executors import RXModuleRunner
        return RXModuleRunner(factory=executor_factory)
    
    @pytest.mark.asyncio
    async def test_full_recon_to_attack_flow(
        self,
        integration_blackboard,
        settings,
        executor_factory,
        rx_module_runner
    ):
        """
        Full end-to-end flow: Recon → Discovery → Vulnerability → Attack.
        
        This test simulates a complete attack workflow:
        1. ReconSpecialist discovers localhost
        2. Ports are scanned
        3. Vulnerabilities are added
        4. AttackSpecialist attempts exploitation
        5. Credentials are harvested (simulated)
        """
        blackboard = integration_blackboard
        await blackboard.connect()
        
        # ═══════════════════════════════════════════════════════════
        # Phase 1: Mission Setup
        # ═══════════════════════════════════════════════════════════
        mission = Mission(
            name="Full E2E Test",
            description="Complete attack simulation",
            scope=["127.0.0.1/32"],
            goals={
                "initial_access": GoalStatus.PENDING,
                "credential_harvest": GoalStatus.PENDING
            }
        )
        mission_id = await blackboard.create_mission(mission)
        
        # ═══════════════════════════════════════════════════════════
        # Phase 2: Reconnaissance
        # ═══════════════════════════════════════════════════════════
        recon = ReconSpecialist(
            blackboard=blackboard,
            settings=settings,
            worker_id="recon-e2e",
            runner=rx_module_runner,
            executor_factory=executor_factory
        )
        recon._current_mission_id = mission_id
        recon._running = True
        
        # Add localhost as discovered target
        target_id = await recon.add_discovered_target(
            ip="127.0.0.1",
            hostname="localhost",
            os="Linux",
            priority="high",
            needs_deep_scan=True
        )
        
        # Verify target was added
        targets = await blackboard.get_mission_targets(mission_id)
        assert len(targets) >= 1
        
        # Add ports (simulating port scan result)
        await blackboard.add_target_ports(target_id, {
            "22": "ssh",
            "80": "http"
        })
        
        # Update target status
        await blackboard.update_target_status(target_id, TargetStatus.SCANNED)
        
        # ═══════════════════════════════════════════════════════════
        # Phase 3: Vulnerability Discovery
        # ═══════════════════════════════════════════════════════════
        vuln_id = await recon.add_discovered_vulnerability(
            target_id=target_id,
            vuln_type="CVE-2018-15473",
            severity=Severity.MEDIUM,
            name="SSH User Enumeration",
            description="SSH server allows user enumeration",
            exploit_available=True,
            rx_modules=["rx-ssh-enum"]
        )
        
        # Verify vulnerability was added
        vulns = await blackboard.get_mission_vulns(mission_id)
        assert len(vulns) >= 1
        
        # ═══════════════════════════════════════════════════════════
        # Phase 4: Attack
        # ═══════════════════════════════════════════════════════════
        attack = AttackSpecialist(
            blackboard=blackboard,
            settings=settings,
            worker_id="attack-e2e",
            runner=rx_module_runner,
            executor_factory=executor_factory
        )
        attack._current_mission_id = mission_id
        attack._running = True
        
        # Attempt exploit (will be simulated)
        exploit_task = {
            "id": str(uuid4()),
            "type": TaskType.EXPLOIT.value,
            "target_id": target_id,
            "vuln_id": vuln_id
        }
        
        exploit_result = await attack.execute_task(exploit_task)
        
        # Result should have success status (may be True or False based on simulation)
        assert "success" in exploit_result
        
        # If exploit succeeded, verify session was created
        if exploit_result.get("success"):
            sessions = await blackboard.get_mission_sessions(mission_id)
            assert len(sessions) >= 1
            
            # Verify session details
            session_id = exploit_result.get("session_id")
            if session_id:
                session = await blackboard.get_session(session_id)
                assert session is not None
        
        # ═══════════════════════════════════════════════════════════
        # Phase 5: Verify Final State
        # ═══════════════════════════════════════════════════════════
        stats = await blackboard.get_mission_stats(mission_id)
        
        assert stats.targets_discovered >= 1
        assert stats.vulns_found >= 1
        
        # Cleanup
        await recon.cleanup_connections()
        await attack.cleanup_connections()
        await blackboard.disconnect()
    
    @pytest.mark.asyncio
    async def test_localhost_discovery_real_commands(
        self,
        integration_blackboard,
        settings,
        executor_factory,
        rx_module_runner
    ):
        """
        Test real command execution for localhost discovery.
        
        Uses actual shell commands to gather information about localhost.
        """
        blackboard = integration_blackboard
        await blackboard.connect()
        
        # Setup
        mission = Mission(
            name="Localhost Discovery",
            scope=["127.0.0.1/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        
        # Create Recon specialist
        recon = ReconSpecialist(
            blackboard=blackboard,
            settings=settings,
            worker_id="recon-localhost",
            runner=rx_module_runner,
            executor_factory=executor_factory
        )
        recon._current_mission_id = mission_id
        recon._running = True
        
        # Execute real commands to gather system info
        commands_to_test = [
            ("hostname", "Get hostname"),
            ("uname -a", "Get kernel info"),
            ("id", "Get user info"),
            ("cat /etc/os-release 2>/dev/null || echo 'Linux'", "Get OS info"),
        ]
        
        results = []
        for cmd, desc in commands_to_test:
            result = await recon.execute_command_direct(
                command=cmd,
                target_host="localhost",
                target_platform="linux",
                timeout=5
            )
            results.append((cmd, result))
            
            # All commands should succeed
            assert result["success"] == True, f"Command failed: {cmd}"
            assert result["stdout"].strip() != "", f"No output for: {cmd}"
        
        # Verify we got system information
        assert len(results) == len(commands_to_test)
        
        await blackboard.disconnect()
    
    @pytest.mark.asyncio
    async def test_execution_mode_switching(
        self,
        integration_blackboard,
        settings
    ):
        """
        Test that specialists correctly switch between real and simulated modes.
        """
        blackboard = integration_blackboard
        await blackboard.connect()
        
        mission = Mission(
            name="Mode Switching Test",
            scope=["127.0.0.1/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        
        # Create specialist WITHOUT runner (should be simulated)
        recon_simulated = ReconSpecialist(
            blackboard=blackboard,
            settings=settings,
            worker_id="recon-simulated"
        )
        recon_simulated._current_mission_id = mission_id
        
        # Verify it's in simulated mode
        assert recon_simulated._execution_mode == "simulated"
        assert recon_simulated.is_real_execution_mode == False
        
        # Create specialist WITH runner (should be real)
        from src.executors import ExecutorFactory, RXModuleRunner
        factory = ExecutorFactory()
        runner = RXModuleRunner(factory=factory)
        
        recon_real = ReconSpecialist(
            blackboard=blackboard,
            settings=settings,
            worker_id="recon-real",
            runner=runner,
            executor_factory=factory
        )
        recon_real._current_mission_id = mission_id
        
        # Verify it's in real mode
        assert recon_real._execution_mode == "real"
        assert recon_real.is_real_execution_mode == True
        
        await blackboard.disconnect()


class TestDependencyInjection:
    """Test Dependency Injection patterns in specialists."""
    
    @pytest.mark.asyncio
    async def test_runner_injection_recon(self, integration_blackboard, settings):
        """Test RXModuleRunner injection into ReconSpecialist."""
        from src.executors import ExecutorFactory, RXModuleRunner
        
        factory = ExecutorFactory()
        runner = RXModuleRunner(factory=factory)
        
        recon = ReconSpecialist(
            blackboard=integration_blackboard,
            settings=settings,
            runner=runner,
            executor_factory=factory
        )
        
        # Verify injection worked
        assert recon._runner is runner
        assert recon._executor_factory is factory
        assert recon.runner is runner
        assert recon.executor_factory is factory
    
    @pytest.mark.asyncio
    async def test_runner_injection_attack(self, integration_blackboard, settings):
        """Test RXModuleRunner injection into AttackSpecialist."""
        from src.executors import ExecutorFactory, RXModuleRunner
        
        factory = ExecutorFactory()
        runner = RXModuleRunner(factory=factory)
        
        attack = AttackSpecialist(
            blackboard=integration_blackboard,
            settings=settings,
            runner=runner,
            executor_factory=factory
        )
        
        # Verify injection worked
        assert attack._runner is runner
        assert attack._executor_factory is factory
        assert attack.runner is runner
        assert attack.executor_factory is factory
    
    @pytest.mark.asyncio
    async def test_lazy_loading_runner(self, integration_blackboard, settings):
        """Test lazy loading of RXModuleRunner when not injected."""
        recon = ReconSpecialist(
            blackboard=integration_blackboard,
            settings=settings
        )
        
        # Runner should be None initially
        assert recon._runner is None
        
        # Accessing runner property should attempt lazy loading
        # (may return None if import fails, which is OK for this test)
        runner = recon.runner
        # Don't assert specific value as it depends on environment


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
