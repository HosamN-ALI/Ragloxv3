# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Controller Tests
# Testing mission controller
# ═══════════════════════════════════════════════════════════════

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4
import json

from src.controller.mission import MissionController
from src.core.models import (
    Mission, MissionCreate, MissionStatus, MissionStats,
    GoalStatus, TaskType, SpecialistType
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
    """Create a mock Blackboard for testing."""
    mock = AsyncMock()
    
    # Storage
    storage = {}
    sorted_sets = {}
    sets = {}
    
    async def mock_connect():
        pass
    
    async def mock_disconnect():
        pass
    
    async def mock_health_check():
        return True
    
    async def mock_create_mission(mission):
        mission_id = str(mission.id)
        data = mission.model_dump()
        # Ensure scope is stored as JSON string for consistency
        if isinstance(data.get("scope"), list):
            data["scope"] = json.dumps(data["scope"])
        storage[f"mission:{mission_id}:info"] = data
        storage[f"mission:{mission_id}:goals"] = {
            k: v.value if hasattr(v, 'value') else v 
            for k, v in mission.goals.items()
        }
        storage[f"mission:{mission_id}:stats"] = {
            "targets_discovered": "0",
            "vulns_found": "0",
            "creds_harvested": "0",
            "sessions_established": "0",
            "goals_achieved": "0"
        }
        return mission_id
    
    async def mock_get_mission(mission_id):
        return storage.get(f"mission:{mission_id}:info")
    
    async def mock_update_mission_status(mission_id, status):
        key = f"mission:{mission_id}:info"
        if key in storage:
            storage[key]["status"] = status.value if hasattr(status, 'value') else status
    
    async def mock_get_mission_goals(mission_id):
        return storage.get(f"mission:{mission_id}:goals", {})
    
    async def mock_update_goal_status(mission_id, goal, status):
        key = f"mission:{mission_id}:goals"
        if key not in storage:
            storage[key] = {}
        storage[key][goal] = status
    
    async def mock_get_mission_stats(mission_id):
        stats_data = storage.get(f"mission:{mission_id}:stats", {})
        return MissionStats(
            targets_discovered=int(stats_data.get("targets_discovered", 0)),
            vulns_found=int(stats_data.get("vulns_found", 0)),
            creds_harvested=int(stats_data.get("creds_harvested", 0)),
            sessions_established=int(stats_data.get("sessions_established", 0)),
            goals_achieved=int(stats_data.get("goals_achieved", 0))
        )
    
    async def mock_get_mission_targets(mission_id):
        return list(sets.get(f"mission:{mission_id}:targets", set()))
    
    async def mock_get_mission_vulns(mission_id, limit=100):
        return [k for k in storage.keys() if k.startswith("vuln:")]
    
    async def mock_get_vulnerability(vuln_id):
        return storage.get(f"vuln:{vuln_id}")
    
    async def mock_update_vuln_status(vuln_id, status):
        key = f"vuln:{vuln_id}"
        if key in storage:
            storage[key]["status"] = status
    
    async def mock_add_task(task):
        task_id = str(task.id)
        storage[f"task:{task_id}"] = task.model_dump()
        return task_id
    
    async def mock_get_heartbeats(mission_id):
        return storage.get(f"mission:{mission_id}:heartbeats", {})
    
    async def mock_publish(channel, event):
        pass
    
    async def mock_publish_dict(channel, data):
        pass
    
    def mock_get_channel(mission_id, entity):
        return f"channel:mission:{mission_id}:{entity}"
    
    mock.connect = mock_connect
    mock.disconnect = mock_disconnect
    mock.health_check = mock_health_check
    mock.create_mission = mock_create_mission
    mock.get_mission = mock_get_mission
    mock.update_mission_status = mock_update_mission_status
    mock.get_mission_goals = mock_get_mission_goals
    mock.update_goal_status = mock_update_goal_status
    mock.get_mission_stats = mock_get_mission_stats
    mock.get_mission_targets = mock_get_mission_targets
    mock.get_mission_vulns = mock_get_mission_vulns
    mock.get_vulnerability = mock_get_vulnerability
    mock.update_vuln_status = mock_update_vuln_status
    mock.add_task = mock_add_task
    mock.get_heartbeats = mock_get_heartbeats
    mock.publish = mock_publish
    mock.publish_dict = mock_publish_dict
    mock.get_channel = mock_get_channel
    
    return mock


# ═══════════════════════════════════════════════════════════════
# Mission Lifecycle Tests
# ═══════════════════════════════════════════════════════════════

class TestMissionLifecycle:
    """Test mission lifecycle operations."""
    
    @pytest.mark.asyncio
    async def test_create_mission(self, settings, mock_blackboard):
        """Test creating a new mission."""
        controller = MissionController(
            blackboard=mock_blackboard,
            settings=settings
        )
        
        mission_data = MissionCreate(
            name="Test Pentest",
            description="Testing mission creation",
            scope=["192.168.1.0/24", "10.0.0.0/8"],
            goals=["domain_admin", "data_exfil"],
            constraints={"stealth": True}
        )
        
        mission_id = await controller.create_mission(mission_data)
        
        assert mission_id is not None
        assert mission_id in controller._active_missions
    
    @pytest.mark.asyncio
    async def test_start_mission(self, settings, mock_blackboard):
        """Test starting a mission."""
        controller = MissionController(
            blackboard=mock_blackboard,
            settings=settings
        )
        
        # Create mission first
        mission_data = MissionCreate(
            name="Start Test",
            scope=["192.168.1.0/24"],
            goals=["domain_admin"]
        )
        mission_id = await controller.create_mission(mission_data)
        
        # Mock specialist start to avoid actual async loops
        with patch.object(controller, '_start_specialists', new_callable=AsyncMock):
            result = await controller.start_mission(mission_id)
        
        assert result == True
        
        # Verify status was updated
        mission = await mock_blackboard.get_mission(mission_id)
        assert mission["status"] == "running"
    
    @pytest.mark.asyncio
    async def test_start_nonexistent_mission(self, settings, mock_blackboard):
        """Test starting a mission that doesn't exist."""
        controller = MissionController(
            blackboard=mock_blackboard,
            settings=settings
        )
        
        result = await controller.start_mission("nonexistent-id")
        
        assert result == False
    
    @pytest.mark.asyncio
    async def test_pause_mission(self, settings, mock_blackboard):
        """Test pausing a running mission."""
        controller = MissionController(
            blackboard=mock_blackboard,
            settings=settings
        )
        
        # Create and start mission
        mission_data = MissionCreate(
            name="Pause Test",
            scope=["192.168.1.0/24"],
            goals=["domain_admin"]
        )
        mission_id = await controller.create_mission(mission_data)
        
        with patch.object(controller, '_start_specialists', new_callable=AsyncMock):
            await controller.start_mission(mission_id)
        
        # Pause mission
        result = await controller.pause_mission(mission_id)
        
        assert result == True
        mission = await mock_blackboard.get_mission(mission_id)
        assert mission["status"] == "paused"
    
    @pytest.mark.asyncio
    async def test_resume_mission(self, settings, mock_blackboard):
        """Test resuming a paused mission."""
        controller = MissionController(
            blackboard=mock_blackboard,
            settings=settings
        )
        
        # Create, start, and pause mission
        mission_data = MissionCreate(
            name="Resume Test",
            scope=["192.168.1.0/24"],
            goals=["domain_admin"]
        )
        mission_id = await controller.create_mission(mission_data)
        
        with patch.object(controller, '_start_specialists', new_callable=AsyncMock):
            await controller.start_mission(mission_id)
        
        await controller.pause_mission(mission_id)
        
        # Resume mission
        result = await controller.resume_mission(mission_id)
        
        assert result == True
        mission = await mock_blackboard.get_mission(mission_id)
        assert mission["status"] == "running"
    
    @pytest.mark.asyncio
    async def test_stop_mission(self, settings, mock_blackboard):
        """Test stopping a mission."""
        controller = MissionController(
            blackboard=mock_blackboard,
            settings=settings
        )
        
        # Create and start mission
        mission_data = MissionCreate(
            name="Stop Test",
            scope=["192.168.1.0/24"],
            goals=["domain_admin"]
        )
        mission_id = await controller.create_mission(mission_data)
        
        with patch.object(controller, '_start_specialists', new_callable=AsyncMock):
            await controller.start_mission(mission_id)
        
        # Stop mission
        with patch.object(controller, '_stop_specialists', new_callable=AsyncMock):
            result = await controller.stop_mission(mission_id)
        
        assert result == True
        mission = await mock_blackboard.get_mission(mission_id)
        # Status can be 'stopped' or 'completed' depending on implementation
        assert mission["status"] in ["stopped", "completed"]
        assert mission_id not in controller._active_missions


# ═══════════════════════════════════════════════════════════════
# Mission Status Tests
# ═══════════════════════════════════════════════════════════════

class TestMissionStatus:
    """Test mission status retrieval."""
    
    @pytest.mark.asyncio
    async def test_get_mission_status(self, settings, mock_blackboard):
        """Test getting comprehensive mission status."""
        controller = MissionController(
            blackboard=mock_blackboard,
            settings=settings
        )
        
        # Create mission
        mission_data = MissionCreate(
            name="Status Test",
            scope=["192.168.1.0/24"],
            goals=["domain_admin", "data_exfil"]
        )
        mission_id = await controller.create_mission(mission_data)
        
        # Get status
        status = await controller.get_mission_status(mission_id)
        
        assert status is not None
        assert status["mission_id"] == mission_id
        assert status["name"] == "Status Test"
        assert status["status"] == "created"
        assert "statistics" in status
        assert "goals" in status
    
    @pytest.mark.asyncio
    async def test_get_nonexistent_mission_status(self, settings, mock_blackboard):
        """Test getting status of nonexistent mission."""
        controller = MissionController(
            blackboard=mock_blackboard,
            settings=settings
        )
        
        status = await controller.get_mission_status("nonexistent-id")
        
        assert status is None


# ═══════════════════════════════════════════════════════════════
# Task Creation Tests
# ═══════════════════════════════════════════════════════════════

class TestTaskCreation:
    """Test task creation by controller."""
    
    @pytest.mark.asyncio
    async def test_create_initial_scan_task(self, settings, mock_blackboard):
        """Test creating initial network scan task."""
        controller = MissionController(
            blackboard=mock_blackboard,
            settings=settings
        )
        
        # Create mission
        mission_data = MissionCreate(
            name="Scan Task Test",
            scope=["192.168.1.0/24"],
            goals=["domain_admin"]
        )
        mission_id = await controller.create_mission(mission_data)
        
        # Create initial scan task
        task_id = await controller._create_initial_scan_task(mission_id)
        
        assert task_id is not None


# ═══════════════════════════════════════════════════════════════
# Active Mission Tests
# ═══════════════════════════════════════════════════════════════

class TestActiveMissions:
    """Test active mission tracking."""
    
    @pytest.mark.asyncio
    async def test_get_active_missions(self, settings, mock_blackboard):
        """Test getting list of active missions."""
        controller = MissionController(
            blackboard=mock_blackboard,
            settings=settings
        )
        
        # Initially empty
        active = await controller.get_active_missions()
        assert len(active) == 0
        
        # Create mission
        mission_data = MissionCreate(
            name="Active Test",
            scope=["192.168.1.0/24"],
            goals=["domain_admin"]
        )
        mission_id = await controller.create_mission(mission_data)
        
        # Now has one active
        active = await controller.get_active_missions()
        assert len(active) == 1
        assert mission_id in active
    
    @pytest.mark.asyncio
    async def test_multiple_active_missions(self, settings, mock_blackboard):
        """Test tracking multiple active missions."""
        controller = MissionController(
            blackboard=mock_blackboard,
            settings=settings
        )
        
        # Create multiple missions
        ids = []
        for i in range(3):
            mission_data = MissionCreate(
                name=f"Mission {i}",
                scope=["192.168.1.0/24"],
                goals=["domain_admin"]
            )
            mission_id = await controller.create_mission(mission_data)
            ids.append(mission_id)
        
        active = await controller.get_active_missions()
        assert len(active) == 3
        for mission_id in ids:
            assert mission_id in active


# ═══════════════════════════════════════════════════════════════
# Shutdown Tests
# ═══════════════════════════════════════════════════════════════

class TestShutdown:
    """Test controller shutdown."""
    
    @pytest.mark.asyncio
    async def test_shutdown(self, settings, mock_blackboard):
        """Test graceful shutdown."""
        controller = MissionController(
            blackboard=mock_blackboard,
            settings=settings
        )
        
        # Create a mission
        mission_data = MissionCreate(
            name="Shutdown Test",
            scope=["192.168.1.0/24"],
            goals=["domain_admin"]
        )
        mission_id = await controller.create_mission(mission_data)
        
        # Shutdown
        with patch.object(controller, '_stop_specialists', new_callable=AsyncMock):
            await controller.shutdown()
        
        assert controller._running == False
        assert len(controller._active_missions) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
