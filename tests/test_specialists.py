# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Specialists Tests
# Testing specialist agents
# ═══════════════════════════════════════════════════════════════

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4
import json

from src.specialists.base import BaseSpecialist
from src.specialists.recon import ReconSpecialist
from src.specialists.attack import AttackSpecialist
from src.core.models import (
    Mission, MissionStatus, GoalStatus,
    Task, TaskType, TaskStatus, SpecialistType,
    Target, TargetStatus, Priority,
    Vulnerability, Severity,
    Credential, CredentialType, PrivilegeLevel,
    Session, SessionStatus
)
from src.core.config import Settings


# ═══════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════

@pytest.fixture
def settings():
    """Create test settings."""
    return Settings(
        redis_url="redis://localhost:6379/0",
        redis_max_connections=10
    )


@pytest.fixture
def mock_blackboard():
    """Create a mock Blackboard."""
    mock = AsyncMock()
    
    # Storage
    storage = {}
    sorted_sets = {}
    sets = {}
    
    # Mock methods
    async def mock_connect():
        pass
    
    async def mock_disconnect():
        pass
    
    async def mock_health_check():
        return True
    
    async def mock_create_mission(mission):
        mission_id = str(mission.id)
        storage[f"mission:{mission_id}:info"] = mission.model_dump()
        return mission_id
    
    async def mock_get_mission(mission_id):
        return storage.get(f"mission:{mission_id}:info")
    
    async def mock_get_mission_goals(mission_id):
        return storage.get(f"mission:{mission_id}:goals", {})
    
    async def mock_update_goal_status(mission_id, goal, status):
        if f"mission:{mission_id}:goals" not in storage:
            storage[f"mission:{mission_id}:goals"] = {}
        storage[f"mission:{mission_id}:goals"][goal] = status
    
    async def mock_add_target(target):
        target_id = str(target.id)
        storage[f"target:{target_id}"] = target.model_dump()
        mission_id = str(target.mission_id)
        if f"mission:{mission_id}:targets" not in sets:
            sets[f"mission:{mission_id}:targets"] = set()
        sets[f"mission:{mission_id}:targets"].add(f"target:{target_id}")
        return target_id
    
    async def mock_get_target(target_id):
        return storage.get(f"target:{target_id}")
    
    async def mock_get_mission_targets(mission_id):
        return list(sets.get(f"mission:{mission_id}:targets", set()))
    
    async def mock_update_target_status(target_id, status):
        key = f"target:{target_id}"
        if key in storage:
            storage[key]["status"] = status.value
    
    async def mock_add_target_ports(target_id, ports):
        storage[f"target:{target_id}:ports"] = ports
    
    async def mock_get_target_ports(target_id):
        return storage.get(f"target:{target_id}:ports", {})
    
    async def mock_add_vulnerability(vuln):
        vuln_id = str(vuln.id)
        storage[f"vuln:{vuln_id}"] = vuln.model_dump()
        return vuln_id
    
    async def mock_get_vulnerability(vuln_id):
        return storage.get(f"vuln:{vuln_id}")
    
    async def mock_get_mission_vulns(mission_id, limit=100):
        return [k for k in storage.keys() if k.startswith("vuln:")]
    
    async def mock_update_vuln_status(vuln_id, status):
        key = f"vuln:{vuln_id}"
        if key in storage:
            storage[key]["status"] = status
    
    async def mock_add_credential(cred):
        cred_id = str(cred.id)
        storage[f"cred:{cred_id}"] = cred.model_dump()
        return cred_id
    
    async def mock_get_credential(cred_id):
        return storage.get(f"cred:{cred_id}")
    
    async def mock_add_session(session):
        session_id = str(session.id)
        storage[f"session:{session_id}"] = session.model_dump()
        return session_id
    
    async def mock_get_session(session_id):
        return storage.get(f"session:{session_id}")
    
    async def mock_add_task(task):
        task_id = str(task.id)
        storage[f"task:{task_id}"] = task.model_dump()
        mission_id = str(task.mission_id)
        if f"mission:{mission_id}:tasks:pending" not in sorted_sets:
            sorted_sets[f"mission:{mission_id}:tasks:pending"] = {}
        sorted_sets[f"mission:{mission_id}:tasks:pending"][f"task:{task_id}"] = task.priority
        return task_id
    
    async def mock_get_task(task_id):
        return storage.get(f"task:{task_id}")
    
    async def mock_claim_task(mission_id, worker_id, specialist):
        pending_key = f"mission:{mission_id}:tasks:pending"
        if pending_key not in sorted_sets:
            return None
        
        for task_key, priority in sorted_sets[pending_key].items():
            task = storage.get(task_key)
            if task and task.get("specialist") == specialist:
                del sorted_sets[pending_key][task_key]
                task_id = task_key.replace("task:", "")
                storage[task_key]["status"] = "running"
                return task_id
        return None
    
    async def mock_complete_task(mission_id, task_id, result, result_data=None):
        key = f"task:{task_id}"
        if key in storage:
            storage[key]["status"] = "completed"
            storage[key]["result"] = result
    
    async def mock_fail_task(mission_id, task_id, error):
        key = f"task:{task_id}"
        if key in storage:
            storage[key]["status"] = "failed"
            storage[key]["error_message"] = error
    
    async def mock_subscribe(*channels):
        return MagicMock()
    
    async def mock_publish(channel, event):
        pass
    
    async def mock_get_message(timeout=1.0):
        return None
    
    def mock_get_channel(mission_id, entity):
        return f"channel:mission:{mission_id}:{entity}"
    
    async def mock_send_heartbeat(mission_id, specialist_id):
        pass
    
    async def mock_get_heartbeats(mission_id):
        return {}
    
    async def mock_log_result(mission_id, event_type, data):
        pass
    
    # Assign mocks
    mock.connect = mock_connect
    mock.disconnect = mock_disconnect
    mock.health_check = mock_health_check
    mock.create_mission = mock_create_mission
    mock.get_mission = mock_get_mission
    mock.get_mission_goals = mock_get_mission_goals
    mock.update_goal_status = mock_update_goal_status
    mock.add_target = mock_add_target
    mock.get_target = mock_get_target
    mock.get_mission_targets = mock_get_mission_targets
    mock.update_target_status = mock_update_target_status
    mock.add_target_ports = mock_add_target_ports
    mock.get_target_ports = mock_get_target_ports
    mock.add_vulnerability = mock_add_vulnerability
    mock.get_vulnerability = mock_get_vulnerability
    mock.get_mission_vulns = mock_get_mission_vulns
    mock.update_vuln_status = mock_update_vuln_status
    mock.add_credential = mock_add_credential
    mock.get_credential = mock_get_credential
    mock.add_session = mock_add_session
    mock.get_session = mock_get_session
    mock.add_task = mock_add_task
    mock.get_task = mock_get_task
    mock.claim_task = mock_claim_task
    mock.complete_task = mock_complete_task
    mock.fail_task = mock_fail_task
    mock.subscribe = mock_subscribe
    mock.publish = mock_publish
    mock.get_message = mock_get_message
    mock.get_channel = mock_get_channel
    mock.send_heartbeat = mock_send_heartbeat
    mock.get_heartbeats = mock_get_heartbeats
    mock.log_result = mock_log_result
    
    return mock


# ═══════════════════════════════════════════════════════════════
# Base Specialist Tests
# ═══════════════════════════════════════════════════════════════

class TestBaseSpecialist:
    """Test BaseSpecialist base class."""
    
    def test_specialist_initialization(self, settings, mock_blackboard):
        """Test specialist initializes correctly."""
        specialist = ReconSpecialist(
            blackboard=mock_blackboard,
            settings=settings,
            worker_id="test-worker-001"
        )
        
        assert specialist.specialist_type == SpecialistType.RECON
        assert specialist.worker_id == "test-worker-001"
        assert not specialist.is_running
        assert specialist.current_mission is None
    
    def test_auto_worker_id_generation(self, settings, mock_blackboard):
        """Test worker ID is auto-generated."""
        specialist = ReconSpecialist(
            blackboard=mock_blackboard,
            settings=settings
        )
        
        assert specialist.worker_id is not None
        assert specialist.worker_id.startswith("recon-")
    
    def test_supported_task_types(self, settings, mock_blackboard):
        """Test specialist reports supported task types."""
        recon = ReconSpecialist(blackboard=mock_blackboard, settings=settings)
        attack = AttackSpecialist(blackboard=mock_blackboard, settings=settings)
        
        assert TaskType.NETWORK_SCAN in recon.supported_task_types
        assert TaskType.PORT_SCAN in recon.supported_task_types
        assert TaskType.EXPLOIT in attack.supported_task_types
        assert TaskType.PRIVESC in attack.supported_task_types


# ═══════════════════════════════════════════════════════════════
# Recon Specialist Tests
# ═══════════════════════════════════════════════════════════════

class TestReconSpecialist:
    """Test ReconSpecialist."""
    
    @pytest.fixture
    def recon_specialist(self, settings, mock_blackboard):
        """Create a ReconSpecialist for testing."""
        specialist = ReconSpecialist(
            blackboard=mock_blackboard,
            settings=settings,
            worker_id="recon-test-001"
        )
        specialist._current_mission_id = str(uuid4())
        specialist._running = True
        return specialist
    
    @pytest.mark.asyncio
    async def test_execute_network_scan(self, recon_specialist, mock_blackboard):
        """Test network scan execution."""
        mission_id = recon_specialist._current_mission_id
        
        # Setup mission with scope
        mission = Mission(
            name="Test Mission",
            scope=["192.168.1.0/28"],  # Small range for testing
            goals={"domain_admin": GoalStatus.PENDING}
        )
        await mock_blackboard.create_mission(mission)
        
        # Override mission_id
        recon_specialist._current_mission_id = str(mission.id)
        
        # Execute network scan
        task = {
            "type": TaskType.NETWORK_SCAN.value,
            "mission_id": str(mission.id)
        }
        
        result = await recon_specialist.execute_task(task)
        
        assert "hosts_discovered" in result
        assert "scope_scanned" in result
    
    @pytest.mark.asyncio
    async def test_execute_port_scan(self, recon_specialist, mock_blackboard):
        """Test port scan execution."""
        mission_id = recon_specialist._current_mission_id
        
        # Create a target
        target = Target(
            mission_id=uuid4(),
            ip="192.168.1.100",
            hostname="test-server"
        )
        target_id = await mock_blackboard.add_target(target)
        
        # Execute port scan
        task = {
            "type": TaskType.PORT_SCAN.value,
            "target_id": target_id
        }
        
        result = await recon_specialist.execute_task(task)
        
        assert "ports_found" in result
        assert "target_ip" in result
        assert result["target_ip"] == "192.168.1.100"
    
    @pytest.mark.asyncio
    async def test_execute_service_enum(self, recon_specialist, mock_blackboard):
        """Test service enumeration execution."""
        # Create target with ports
        target = Target(
            mission_id=uuid4(),
            ip="10.0.0.5"
        )
        target_id = await mock_blackboard.add_target(target)
        await mock_blackboard.add_target_ports(target_id, {22: "ssh", 80: "http"})
        
        # Execute service enum
        task = {
            "type": TaskType.SERVICE_ENUM.value,
            "target_id": target_id
        }
        
        result = await recon_specialist.execute_task(task)
        
        assert "services_found" in result
        assert result["services_found"] >= 0
    
    @pytest.mark.asyncio
    async def test_add_discovered_target(self, recon_specialist, mock_blackboard):
        """Test adding discovered target."""
        target_id = await recon_specialist.add_discovered_target(
            ip="192.168.1.50",
            hostname="server-50",
            os="Linux",
            priority="high"
        )
        
        assert target_id is not None
        
        # Verify target was added
        target = await mock_blackboard.get_target(target_id)
        assert target is not None
        assert target["ip"] == "192.168.1.50"
    
    @pytest.mark.asyncio
    async def test_add_discovered_vulnerability(self, recon_specialist, mock_blackboard):
        """Test adding discovered vulnerability."""
        # First create a target
        target = Target(
            mission_id=uuid4(),
            ip="10.0.0.1"
        )
        target_id = await mock_blackboard.add_target(target)
        
        # Add vulnerability
        vuln_id = await recon_specialist.add_discovered_vulnerability(
            target_id=target_id,
            vuln_type="CVE-2021-44228",
            severity=Severity.CRITICAL,
            cvss=10.0,
            name="Log4Shell",
            exploit_available=True
        )
        
        assert vuln_id is not None


# ═══════════════════════════════════════════════════════════════
# Attack Specialist Tests
# ═══════════════════════════════════════════════════════════════

class TestAttackSpecialist:
    """Test AttackSpecialist."""
    
    @pytest.fixture
    def attack_specialist(self, settings, mock_blackboard):
        """Create an AttackSpecialist for testing."""
        specialist = AttackSpecialist(
            blackboard=mock_blackboard,
            settings=settings,
            worker_id="attack-test-001"
        )
        specialist._current_mission_id = str(uuid4())
        specialist._running = True
        return specialist
    
    @pytest.mark.asyncio
    async def test_execute_exploit(self, attack_specialist, mock_blackboard):
        """Test exploit execution."""
        # Create target and vulnerability
        target = Target(
            mission_id=uuid4(),
            ip="10.0.0.5"
        )
        target_id = await mock_blackboard.add_target(target)
        
        vuln = Vulnerability(
            mission_id=uuid4(),
            target_id=uuid4(),
            type="MS17-010",
            severity=Severity.CRITICAL
        )
        vuln_id = await mock_blackboard.add_vulnerability(vuln)
        
        # Execute exploit
        task = {
            "type": TaskType.EXPLOIT.value,
            "vuln_id": vuln_id,
            "target_id": target_id
        }
        
        result = await attack_specialist.execute_task(task)
        
        assert "success" in result
        assert "vuln_type" in result
    
    @pytest.mark.asyncio
    async def test_execute_cred_harvest(self, attack_specialist, mock_blackboard):
        """Test credential harvesting."""
        # Create target
        target = Target(
            mission_id=uuid4(),
            ip="10.0.0.5"
        )
        target_id = await mock_blackboard.add_target(target)
        
        # Execute cred harvest
        task = {
            "type": TaskType.CRED_HARVEST.value,
            "target_id": target_id
        }
        
        result = await attack_specialist.execute_task(task)
        
        assert "creds_found" in result
        assert result["creds_found"] >= 0
    
    @pytest.mark.asyncio
    async def test_add_established_session(self, attack_specialist, mock_blackboard):
        """Test adding established session."""
        # Create target
        target = Target(
            mission_id=uuid4(),
            ip="10.0.0.5"
        )
        target_id = await mock_blackboard.add_target(target)
        
        # Add session
        session_id = await attack_specialist.add_established_session(
            target_id=target_id,
            session_type="meterpreter",
            user="SYSTEM",
            privilege=PrivilegeLevel.SYSTEM
        )
        
        assert session_id is not None
    
    @pytest.mark.asyncio
    async def test_add_discovered_credential(self, attack_specialist, mock_blackboard):
        """Test adding discovered credential."""
        # Create target
        target = Target(
            mission_id=uuid4(),
            ip="10.0.0.5"
        )
        target_id = await mock_blackboard.add_target(target)
        
        # Add credential
        cred_id = await attack_specialist.add_discovered_credential(
            target_id=target_id,
            cred_type=CredentialType.HASH,
            username="Administrator",
            domain="CORP",
            privilege_level=PrivilegeLevel.DOMAIN_ADMIN
        )
        
        assert cred_id is not None


# ═══════════════════════════════════════════════════════════════
# Event Handling Tests
# ═══════════════════════════════════════════════════════════════

class TestEventHandling:
    """Test event handling for specialists."""
    
    @pytest.mark.asyncio
    async def test_recon_handles_control_events(self, settings, mock_blackboard):
        """Test recon specialist handles control events."""
        specialist = ReconSpecialist(
            blackboard=mock_blackboard,
            settings=settings
        )
        specialist._current_mission_id = str(uuid4())
        specialist._running = True
        
        # Send pause event
        await specialist.on_event({"event": "control", "command": "pause"})
        assert not specialist._running
        
        # Send resume event
        await specialist.on_event({"event": "control", "command": "resume"})
        assert specialist._running
    
    @pytest.mark.asyncio
    async def test_attack_handles_new_vuln_event(self, settings, mock_blackboard):
        """Test attack specialist handles new vulnerability events."""
        specialist = AttackSpecialist(
            blackboard=mock_blackboard,
            settings=settings
        )
        specialist._current_mission_id = str(uuid4())
        specialist._running = True
        
        # Send new vuln event - should log but not crash
        await specialist.on_event({
            "event": "new_vuln",
            "vuln_id": str(uuid4()),
            "severity": "critical",
            "exploit_available": True
        })


# ═══════════════════════════════════════════════════════════════
# Task Creation Tests
# ═══════════════════════════════════════════════════════════════

class TestTaskCreation:
    """Test task creation between specialists."""
    
    @pytest.mark.asyncio
    async def test_recon_creates_task_for_attack(self, settings, mock_blackboard):
        """Test recon can create tasks for attack specialist."""
        recon = ReconSpecialist(
            blackboard=mock_blackboard,
            settings=settings
        )
        recon._current_mission_id = str(uuid4())
        recon._running = True
        
        # Create a target first
        target = Target(
            mission_id=uuid4(),
            ip="10.0.0.5"
        )
        target_id = await mock_blackboard.add_target(target)
        
        # Recon creates an exploit task
        task_id = await recon.create_task(
            task_type=TaskType.EXPLOIT,
            target_specialist=SpecialistType.ATTACK,
            priority=9,
            target_id=target_id
        )
        
        assert task_id is not None
        
        # Verify task was created
        task = await mock_blackboard.get_task(task_id)
        assert task is not None
        assert task["type"] == TaskType.EXPLOIT.value
        assert task["specialist"] == SpecialistType.ATTACK.value


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
