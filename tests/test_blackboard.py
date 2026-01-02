# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Blackboard Tests
# Testing Redis-backed shared state operations
# ═══════════════════════════════════════════════════════════════

import pytest
import pytest_asyncio
import asyncio
from datetime import datetime
from uuid import uuid4
from unittest.mock import AsyncMock, MagicMock, patch

from src.core.blackboard import Blackboard
from src.core.models import (
    Mission, MissionStatus, MissionStats, GoalStatus,
    Target, TargetStatus, Priority,
    Vulnerability, Severity,
    Credential, CredentialType, PrivilegeLevel,
    Session, SessionStatus, SessionType,
    Task, TaskStatus, TaskType, SpecialistType,
    BlackboardEvent, NewTargetEvent
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
def mock_redis():
    """Create a mock Redis client."""
    mock = AsyncMock()
    
    # Storage for mock data
    storage = {}
    sorted_sets = {}
    sets = {}
    streams = {}
    
    # Mock hset - supports both hset(key, field, value) and hset(key, mapping={...})
    async def mock_hset(key, field=None, value=None, mapping=None, **kwargs):
        if key not in storage:
            storage[key] = {}
        
        # Handle hset(key, field, value) format
        if field is not None and value is not None:
            storage[key][field] = value
            return 1
        
        # Handle hset(key, mapping={...}) format
        if mapping is not None:
            storage[key].update(mapping)
            return len(mapping)
        
        # Handle kwargs as mapping
        if kwargs:
            storage[key].update(kwargs)
            return len(kwargs)
        
        return 0
    
    # Mock hgetall
    async def mock_hgetall(key):
        return storage.get(key, {})
    
    # Mock hincrby
    async def mock_hincrby(key, field, amount=1):
        if key not in storage:
            storage[key] = {}
        if field not in storage[key]:
            storage[key][field] = 0
        storage[key][field] = int(storage[key][field]) + amount
        return storage[key][field]
    
    # Mock sadd
    async def mock_sadd(key, *values):
        if key not in sets:
            sets[key] = set()
        for v in values:
            sets[key].add(v)
        return len(values)
    
    # Mock smembers
    async def mock_smembers(key):
        return sets.get(key, set())
    
    # Mock srem
    async def mock_srem(key, *values):
        if key in sets:
            for v in values:
                sets[key].discard(v)
        return len(values)
    
    # Mock zadd
    async def mock_zadd(key, mapping):
        if key not in sorted_sets:
            sorted_sets[key] = {}
        sorted_sets[key].update(mapping)
        return len(mapping)
    
    # Mock zrevrange
    async def mock_zrevrange(key, start, end):
        if key not in sorted_sets:
            return []
        items = sorted(sorted_sets[key].items(), key=lambda x: x[1], reverse=True)
        if end == -1:
            return [item[0] for item in items[start:]]
        return [item[0] for item in items[start:end+1]]
    
    # Mock zrem
    async def mock_zrem(key, *members):
        if key in sorted_sets:
            for m in members:
                sorted_sets[key].pop(m, None)
        return len(members)
    
    # Mock lpush
    async def mock_lpush(key, *values):
        if key not in storage:
            storage[key] = []
        for v in values:
            storage[key].insert(0, v)
        return len(storage[key])
    
    # Mock xadd
    async def mock_xadd(key, fields):
        if key not in streams:
            streams[key] = []
        entry_id = f"{len(streams[key])+1}-0"
        streams[key].append((entry_id, fields))
        return entry_id
    
    # Mock xrange
    async def mock_xrange(key, min="-", max="+", count=100):
        return streams.get(key, [])[:count]
    
    # Mock delete
    async def mock_delete(key):
        storage.pop(key, None)
        return 1
    
    # Mock ping
    async def mock_ping():
        return True
    
    # Mock publish
    async def mock_publish(channel, message):
        return 1
    
    # Mock pubsub
    def mock_pubsub():
        pubsub = AsyncMock()
        pubsub.subscribe = AsyncMock()
        pubsub.get_message = AsyncMock(return_value=None)
        pubsub.close = AsyncMock()
        return pubsub
    
    mock.hset = mock_hset
    mock.hgetall = mock_hgetall
    mock.hincrby = mock_hincrby
    mock.sadd = mock_sadd
    mock.smembers = mock_smembers
    mock.srem = mock_srem
    mock.zadd = mock_zadd
    mock.zrevrange = mock_zrevrange
    mock.zrem = mock_zrem
    mock.lpush = mock_lpush
    mock.xadd = mock_xadd
    mock.xrange = mock_xrange
    mock.delete = mock_delete
    mock.ping = mock_ping
    mock.publish = mock_publish
    mock.pubsub = mock_pubsub
    
    return mock


@pytest_asyncio.fixture
async def blackboard(settings, mock_redis):
    """Create Blackboard with mocked Redis."""
    bb = Blackboard(settings=settings)
    bb._redis = mock_redis
    bb._connected = True
    return bb


# ═══════════════════════════════════════════════════════════════
# Connection Tests
# ═══════════════════════════════════════════════════════════════

class TestConnection:
    """Test connection management."""
    
    @pytest.mark.asyncio
    async def test_redis_property_raises_when_not_connected(self, settings):
        """Test redis property raises error when not connected."""
        bb = Blackboard(settings=settings)
        with pytest.raises(RuntimeError, match="not connected"):
            _ = bb.redis
    
    @pytest.mark.asyncio
    async def test_health_check_returns_false_when_not_connected(self, settings):
        """Test health check fails when not connected."""
        bb = Blackboard(settings=settings)
        assert await bb.health_check() == False
    
    @pytest.mark.asyncio
    async def test_health_check_returns_true_when_connected(self, blackboard):
        """Test health check succeeds when connected."""
        assert await blackboard.health_check() == True


# ═══════════════════════════════════════════════════════════════
# Mission Tests
# ═══════════════════════════════════════════════════════════════

class TestMissionOperations:
    """Test mission CRUD operations."""
    
    @pytest.mark.asyncio
    async def test_create_mission(self, blackboard):
        """Test creating a new mission."""
        mission = Mission(
            name="Test Mission",
            scope=["192.168.1.0/24"],
            goals={"domain_admin": GoalStatus.PENDING, "data_exfil": GoalStatus.PENDING}
        )
        
        mission_id = await blackboard.create_mission(mission)
        
        assert mission_id == str(mission.id)
    
    @pytest.mark.asyncio
    async def test_get_mission(self, blackboard):
        """Test retrieving a mission."""
        mission = Mission(
            name="Retrieve Test",
            scope=["10.0.0.0/8"],
            goals={"persistence": GoalStatus.PENDING}
        )
        
        await blackboard.create_mission(mission)
        retrieved = await blackboard.get_mission(str(mission.id))
        
        assert retrieved is not None
        assert retrieved["name"] == "Retrieve Test"
    
    @pytest.mark.asyncio
    async def test_update_mission_status(self, blackboard):
        """Test updating mission status."""
        mission = Mission(
            name="Status Test",
            scope=["192.168.0.0/16"],
            goals={}
        )
        
        await blackboard.create_mission(mission)
        await blackboard.update_mission_status(str(mission.id), MissionStatus.RUNNING)
        
        retrieved = await blackboard.get_mission(str(mission.id))
        assert retrieved["status"] == "running"
    
    @pytest.mark.asyncio
    async def test_mission_stats_initialization(self, blackboard):
        """Test mission statistics are initialized to zero."""
        mission = Mission(
            name="Stats Test",
            scope=["10.0.0.0/8"],
            goals={}
        )
        
        await blackboard.create_mission(mission)
        stats = await blackboard.get_mission_stats(str(mission.id))
        
        assert stats.targets_discovered == 0
        assert stats.vulns_found == 0
        assert stats.creds_harvested == 0
        assert stats.sessions_established == 0
        assert stats.goals_achieved == 0
    
    @pytest.mark.asyncio
    async def test_goal_status_update(self, blackboard):
        """Test updating goal status."""
        mission = Mission(
            name="Goal Test",
            scope=["10.0.0.0/8"],
            goals={"domain_admin": GoalStatus.PENDING}
        )
        
        await blackboard.create_mission(mission)
        await blackboard.update_goal_status(
            str(mission.id), 
            "domain_admin", 
            "achieved"
        )
        
        goals = await blackboard.get_mission_goals(str(mission.id))
        assert goals.get("domain_admin") == "achieved"


# ═══════════════════════════════════════════════════════════════
# Target Tests
# ═══════════════════════════════════════════════════════════════

class TestTargetOperations:
    """Test target CRUD operations."""
    
    @pytest.mark.asyncio
    async def test_add_target(self, blackboard):
        """Test adding a new target."""
        mission = Mission(name="Target Test", scope=["10.0.0.0/8"], goals={})
        await blackboard.create_mission(mission)
        
        target = Target(
            mission_id=mission.id,
            ip="192.168.1.100",
            hostname="server01",
            priority=Priority.HIGH
        )
        
        target_id = await blackboard.add_target(target)
        
        assert target_id == str(target.id)
    
    @pytest.mark.asyncio
    async def test_get_target(self, blackboard):
        """Test retrieving a target."""
        mission = Mission(name="Test", scope=["10.0.0.0/8"], goals={})
        await blackboard.create_mission(mission)
        
        target = Target(
            mission_id=mission.id,
            ip="10.0.0.50"
        )
        
        await blackboard.add_target(target)
        retrieved = await blackboard.get_target(str(target.id))
        
        assert retrieved is not None
        assert retrieved["ip"] == "10.0.0.50"
    
    @pytest.mark.asyncio
    async def test_target_increments_stats(self, blackboard):
        """Test adding target increments mission stats."""
        mission = Mission(name="Test", scope=["10.0.0.0/8"], goals={})
        await blackboard.create_mission(mission)
        
        target1 = Target(mission_id=mission.id, ip="10.0.0.1")
        target2 = Target(mission_id=mission.id, ip="10.0.0.2")
        
        await blackboard.add_target(target1)
        await blackboard.add_target(target2)
        
        stats = await blackboard.get_mission_stats(str(mission.id))
        assert stats.targets_discovered == 2
    
    @pytest.mark.asyncio
    async def test_update_target_status(self, blackboard):
        """Test updating target status."""
        mission = Mission(name="Test", scope=["10.0.0.0/8"], goals={})
        await blackboard.create_mission(mission)
        
        target = Target(mission_id=mission.id, ip="10.0.0.1")
        await blackboard.add_target(target)
        
        await blackboard.update_target_status(str(target.id), TargetStatus.SCANNED)
        
        retrieved = await blackboard.get_target(str(target.id))
        assert retrieved["status"] == "scanned"


# ═══════════════════════════════════════════════════════════════
# Vulnerability Tests
# ═══════════════════════════════════════════════════════════════

class TestVulnerabilityOperations:
    """Test vulnerability operations."""
    
    @pytest.mark.asyncio
    async def test_add_vulnerability(self, blackboard):
        """Test adding a vulnerability."""
        mission = Mission(name="Test", scope=["10.0.0.0/8"], goals={})
        await blackboard.create_mission(mission)
        
        target = Target(mission_id=mission.id, ip="10.0.0.1")
        await blackboard.add_target(target)
        
        vuln = Vulnerability(
            mission_id=mission.id,
            target_id=target.id,
            type="CVE-2021-44228",
            severity=Severity.CRITICAL,
            cvss=10.0
        )
        
        vuln_id = await blackboard.add_vulnerability(vuln)
        
        assert vuln_id == str(vuln.id)
    
    @pytest.mark.asyncio
    async def test_vulnerability_sorted_by_cvss(self, blackboard):
        """Test vulnerabilities are sorted by CVSS score."""
        mission = Mission(name="Test", scope=["10.0.0.0/8"], goals={})
        await blackboard.create_mission(mission)
        
        target = Target(mission_id=mission.id, ip="10.0.0.1")
        await blackboard.add_target(target)
        
        # Add vulns with different severities
        vuln_low = Vulnerability(
            mission_id=mission.id,
            target_id=target.id,
            type="LOW-VULN",
            severity=Severity.LOW
        )
        vuln_crit = Vulnerability(
            mission_id=mission.id,
            target_id=target.id,
            type="CRITICAL-VULN",
            severity=Severity.CRITICAL
        )
        
        await blackboard.add_vulnerability(vuln_low)
        await blackboard.add_vulnerability(vuln_crit)
        
        vulns = await blackboard.get_mission_vulns(str(mission.id))
        
        # Critical should come first
        assert len(vulns) == 2
        assert f"vuln:{vuln_crit.id}" in vulns[0]


# ═══════════════════════════════════════════════════════════════
# Credential Tests
# ═══════════════════════════════════════════════════════════════

class TestCredentialOperations:
    """Test credential operations."""
    
    @pytest.mark.asyncio
    async def test_add_credential(self, blackboard):
        """Test adding a credential."""
        mission = Mission(name="Test", scope=["10.0.0.0/8"], goals={})
        await blackboard.create_mission(mission)
        
        target = Target(mission_id=mission.id, ip="10.0.0.1")
        await blackboard.add_target(target)
        
        cred = Credential(
            mission_id=mission.id,
            target_id=target.id,
            type=CredentialType.PASSWORD,
            username="admin",
            privilege_level=PrivilegeLevel.ADMIN
        )
        
        cred_id = await blackboard.add_credential(cred)
        
        assert cred_id == str(cred.id)
    
    @pytest.mark.asyncio
    async def test_credential_increments_stats(self, blackboard):
        """Test adding credential increments stats."""
        mission = Mission(name="Test", scope=["10.0.0.0/8"], goals={})
        await blackboard.create_mission(mission)
        
        target = Target(mission_id=mission.id, ip="10.0.0.1")
        await blackboard.add_target(target)
        
        cred = Credential(
            mission_id=mission.id,
            target_id=target.id,
            type=CredentialType.HASH,
            username="admin"
        )
        
        await blackboard.add_credential(cred)
        
        stats = await blackboard.get_mission_stats(str(mission.id))
        assert stats.creds_harvested == 1


# ═══════════════════════════════════════════════════════════════
# Session Tests
# ═══════════════════════════════════════════════════════════════

class TestSessionOperations:
    """Test session operations."""
    
    @pytest.mark.asyncio
    async def test_add_session(self, blackboard):
        """Test adding a session."""
        mission = Mission(name="Test", scope=["10.0.0.0/8"], goals={})
        await blackboard.create_mission(mission)
        
        target = Target(mission_id=mission.id, ip="10.0.0.1")
        await blackboard.add_target(target)
        
        session = Session(
            mission_id=mission.id,
            target_id=target.id,
            type=SessionType.METERPRETER,
            user="SYSTEM",
            privilege=PrivilegeLevel.SYSTEM
        )
        
        session_id = await blackboard.add_session(session)
        
        assert session_id == str(session.id)
    
    @pytest.mark.asyncio
    async def test_update_session_status(self, blackboard):
        """Test updating session status."""
        mission = Mission(name="Test", scope=["10.0.0.0/8"], goals={})
        await blackboard.create_mission(mission)
        
        target = Target(mission_id=mission.id, ip="10.0.0.1")
        await blackboard.add_target(target)
        
        session = Session(
            mission_id=mission.id,
            target_id=target.id,
            type=SessionType.SSH
        )
        
        await blackboard.add_session(session)
        await blackboard.update_session_status(str(session.id), SessionStatus.DEAD)
        
        retrieved = await blackboard.get_session(str(session.id))
        assert retrieved["status"] == "dead"


# ═══════════════════════════════════════════════════════════════
# Task Tests
# ═══════════════════════════════════════════════════════════════

class TestTaskOperations:
    """Test task queue operations."""
    
    @pytest.mark.asyncio
    async def test_add_task(self, blackboard):
        """Test adding a task."""
        mission = Mission(name="Test", scope=["10.0.0.0/8"], goals={})
        await blackboard.create_mission(mission)
        
        task = Task(
            mission_id=mission.id,
            type=TaskType.PORT_SCAN,
            specialist=SpecialistType.RECON,
            priority=8
        )
        
        task_id = await blackboard.add_task(task)
        
        assert task_id == str(task.id)
    
    @pytest.mark.asyncio
    async def test_claim_task(self, blackboard):
        """Test claiming a task."""
        mission = Mission(name="Test", scope=["10.0.0.0/8"], goals={})
        await blackboard.create_mission(mission)
        
        task = Task(
            mission_id=mission.id,
            type=TaskType.PORT_SCAN,
            specialist=SpecialistType.RECON,
            priority=8
        )
        
        await blackboard.add_task(task)
        
        claimed_id = await blackboard.claim_task(
            str(mission.id),
            "worker-001",
            "recon"
        )
        
        assert claimed_id == str(task.id)
    
    @pytest.mark.asyncio
    async def test_complete_task(self, blackboard):
        """Test completing a task."""
        mission = Mission(name="Test", scope=["10.0.0.0/8"], goals={})
        await blackboard.create_mission(mission)
        
        task = Task(
            mission_id=mission.id,
            type=TaskType.PORT_SCAN,
            specialist=SpecialistType.RECON
        )
        
        await blackboard.add_task(task)
        await blackboard.claim_task(str(mission.id), "worker-001", "recon")
        
        await blackboard.complete_task(
            str(mission.id),
            str(task.id),
            "success",
            {"ports_found": 5}
        )
        
        retrieved = await blackboard.get_task(str(task.id))
        assert retrieved["status"] == "completed"
        assert retrieved["result"] == "success"


# ═══════════════════════════════════════════════════════════════
# Pub/Sub Tests
# ═══════════════════════════════════════════════════════════════

class TestPubSubOperations:
    """Test Pub/Sub operations."""
    
    @pytest.mark.asyncio
    async def test_publish_event(self, blackboard):
        """Test publishing an event."""
        event = NewTargetEvent(
            mission_id=uuid4(),
            target_id=uuid4(),
            ip="10.0.0.100"
        )
        
        channel = blackboard.get_channel(str(event.mission_id), "targets")
        
        # Should not raise
        await blackboard.publish(channel, event)
    
    def test_get_channel_name(self, blackboard):
        """Test channel name generation."""
        mission_id = "test-mission-123"
        
        assert blackboard.get_channel(mission_id, "targets") == "channel:mission:test-mission-123:targets"
        assert blackboard.get_channel(mission_id, "vulns") == "channel:mission:test-mission-123:vulns"


# ═══════════════════════════════════════════════════════════════
# Results Stream Tests
# ═══════════════════════════════════════════════════════════════

class TestResultsStream:
    """Test results stream operations."""
    
    @pytest.mark.asyncio
    async def test_log_result(self, blackboard):
        """Test logging a result."""
        mission_id = str(uuid4())
        
        await blackboard.log_result(
            mission_id,
            "target_discovered",
            {"ip": "10.0.0.1", "hostname": "server01"}
        )
        
        results = await blackboard.get_results(mission_id)
        
        assert len(results) == 1
        assert results[0]["type"] == "target_discovered"


# ═══════════════════════════════════════════════════════════════
# Heartbeat Tests
# ═══════════════════════════════════════════════════════════════

class TestHeartbeat:
    """Test heartbeat operations."""
    
    @pytest.mark.asyncio
    async def test_send_heartbeat(self, blackboard):
        """Test sending a heartbeat."""
        mission_id = str(uuid4())
        specialist_id = "recon-worker-001"
        
        await blackboard.send_heartbeat(mission_id, specialist_id)
        
        heartbeats = await blackboard.get_heartbeats(mission_id)
        
        assert specialist_id in heartbeats


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
