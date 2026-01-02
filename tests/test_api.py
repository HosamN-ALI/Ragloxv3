# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - API Tests
# Testing REST API endpoints
# ═══════════════════════════════════════════════════════════════

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from fastapi.testclient import TestClient
from httpx import AsyncClient, ASGITransport

from src.core.models import MissionStats, GoalStatus


# ═══════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════

@pytest.fixture
def mock_blackboard():
    """Create a mock Blackboard."""
    mock = AsyncMock()
    mock.health_check = AsyncMock(return_value=True)
    mock.connect = AsyncMock()
    mock.disconnect = AsyncMock()
    return mock


@pytest.fixture
def mock_controller(mock_blackboard):
    """Create a mock Controller."""
    controller = AsyncMock()
    controller.blackboard = mock_blackboard
    controller.shutdown = AsyncMock()
    controller.get_active_missions = AsyncMock(return_value=[])
    controller.create_mission = AsyncMock(return_value=str(uuid4()))
    controller.start_mission = AsyncMock(return_value=True)
    controller.pause_mission = AsyncMock(return_value=True)
    controller.resume_mission = AsyncMock(return_value=True)
    controller.stop_mission = AsyncMock(return_value=True)
    controller.get_mission_status = AsyncMock(return_value={
        "mission_id": str(uuid4()),
        "name": "Test Mission",
        "status": "created",
        "scope": ["192.168.1.0/24"],
        "goals": {"domain_admin": "pending"},
        "statistics": {
            "targets_discovered": 0,
            "vulns_found": 0,
            "creds_harvested": 0,
            "sessions_established": 0,
            "goals_achieved": 0
        },
        "target_count": 0,
        "vuln_count": 0
    })
    return controller


@pytest.fixture
def app_with_mocks(mock_blackboard, mock_controller):
    """Create app with mocked dependencies."""
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    from src.api.routes import router
    from src.api.websocket import websocket_router
    
    # Create app without lifespan to avoid connection issues
    app = FastAPI(
        title="RAGLOX",
        version="3.0.0"
    )
    
    # Add root endpoints directly
    @app.get("/")
    async def root():
        return {
            "name": "RAGLOX",
            "version": "3.0.0",
            "architecture": "Blackboard",
            "status": "operational"
        }
    
    @app.get("/health")
    async def health():
        blackboard_healthy = await mock_blackboard.health_check()
        return {
            "status": "healthy" if blackboard_healthy else "degraded",
            "components": {
                "api": "healthy",
                "blackboard": "healthy" if blackboard_healthy else "unhealthy"
            }
        }
    
    # Include routers
    app.include_router(router, prefix="/api/v1")
    app.include_router(websocket_router)
    
    # Override app state
    app.state.blackboard = mock_blackboard
    app.state.controller = mock_controller
    
    return app


@pytest.fixture
def client(app_with_mocks):
    """Create test client."""
    return TestClient(app_with_mocks)


# ═══════════════════════════════════════════════════════════════
# Root and Health Tests
# ═══════════════════════════════════════════════════════════════

class TestRootEndpoints:
    """Test root endpoints."""
    
    def test_root_endpoint(self, client):
        """Test root endpoint returns API info."""
        response = client.get("/")
        
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "RAGLOX"
        assert data["version"] == "3.0.0"
        assert data["architecture"] == "Blackboard"
    
    def test_health_endpoint(self, client, mock_blackboard):
        """Test health check endpoint."""
        response = client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "components" in data


# ═══════════════════════════════════════════════════════════════
# Mission API Tests
# ═══════════════════════════════════════════════════════════════

class TestMissionAPI:
    """Test mission CRUD endpoints."""
    
    def test_create_mission(self, client, mock_controller):
        """Test creating a new mission."""
        response = client.post(
            "/api/v1/missions",
            json={
                "name": "Test Pentest",
                "description": "API test mission",
                "scope": ["192.168.1.0/24"],
                "goals": ["domain_admin"],
                "constraints": {}
            }
        )
        
        assert response.status_code == 201
        data = response.json()
        assert "mission_id" in data
        assert data["status"] == "created"
        assert data["message"] == "Mission created successfully"
    
    def test_create_mission_invalid_data(self, client):
        """Test creating mission with invalid data."""
        response = client.post(
            "/api/v1/missions",
            json={
                "name": "",  # Empty name should fail
                "scope": [],  # Empty scope should fail
                "goals": []  # Empty goals should fail
            }
        )
        
        assert response.status_code == 422  # Validation error
    
    def test_list_missions(self, client, mock_controller):
        """Test listing active missions."""
        mock_controller.get_active_missions.return_value = [
            str(uuid4()),
            str(uuid4())
        ]
        
        response = client.get("/api/v1/missions")
        
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 2
    
    def test_get_mission(self, client, mock_controller):
        """Test getting mission details."""
        mission_id = str(uuid4())
        
        response = client.get(f"/api/v1/missions/{mission_id}")
        
        assert response.status_code == 200
        data = response.json()
        assert "mission_id" in data
        assert "name" in data
        assert "status" in data
        assert "statistics" in data
    
    def test_get_nonexistent_mission(self, client, mock_controller):
        """Test getting a mission that doesn't exist."""
        mock_controller.get_mission_status.return_value = None
        
        response = client.get("/api/v1/missions/nonexistent-id")
        
        assert response.status_code == 404
    
    def test_start_mission(self, client, mock_controller):
        """Test starting a mission."""
        mission_id = str(uuid4())
        
        response = client.post(f"/api/v1/missions/{mission_id}/start")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "running"
        assert data["message"] == "Mission started successfully"
    
    def test_start_mission_failure(self, client, mock_controller):
        """Test starting mission that fails."""
        mock_controller.start_mission.return_value = False
        
        response = client.post("/api/v1/missions/some-id/start")
        
        assert response.status_code == 400
    
    def test_pause_mission(self, client, mock_controller):
        """Test pausing a mission."""
        mission_id = str(uuid4())
        
        response = client.post(f"/api/v1/missions/{mission_id}/pause")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "paused"
    
    def test_resume_mission(self, client, mock_controller):
        """Test resuming a mission."""
        mission_id = str(uuid4())
        
        response = client.post(f"/api/v1/missions/{mission_id}/resume")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "running"
    
    def test_stop_mission(self, client, mock_controller):
        """Test stopping a mission."""
        mission_id = str(uuid4())
        
        response = client.post(f"/api/v1/missions/{mission_id}/stop")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "completed"


# ═══════════════════════════════════════════════════════════════
# Target API Tests
# ═══════════════════════════════════════════════════════════════

class TestTargetAPI:
    """Test target endpoints."""
    
    def test_list_targets(self, client, mock_controller, mock_blackboard):
        """Test listing targets for a mission."""
        mission_id = str(uuid4())
        target_id = str(uuid4())
        
        mock_blackboard.get_mission_targets.return_value = [f"target:{target_id}"]
        mock_blackboard.get_target.return_value = {
            "ip": "192.168.1.100",
            "hostname": "test-server",
            "os": "Linux",
            "status": "scanned",
            "priority": "high"
        }
        mock_blackboard.get_target_ports.return_value = {"22": "ssh", "80": "http"}
        
        response = client.get(f"/api/v1/missions/{mission_id}/targets")
        
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        if len(data) > 0:
            assert "target_id" in data[0]
            assert "ip" in data[0]
    
    def test_get_single_target(self, client, mock_controller, mock_blackboard):
        """Test getting a single target."""
        mission_id = str(uuid4())
        target_id = str(uuid4())
        
        mock_blackboard.get_target.return_value = {
            "ip": "10.0.0.5",
            "hostname": "server-05",
            "status": "exploited",
            "priority": "critical"
        }
        mock_blackboard.get_target_ports.return_value = {"443": "https"}
        
        response = client.get(f"/api/v1/missions/{mission_id}/targets/{target_id}")
        
        assert response.status_code == 200
        data = response.json()
        assert data["ip"] == "10.0.0.5"
    
    def test_get_nonexistent_target(self, client, mock_controller, mock_blackboard):
        """Test getting a target that doesn't exist."""
        mock_blackboard.get_target.return_value = None
        
        response = client.get("/api/v1/missions/x/targets/nonexistent")
        
        assert response.status_code == 404


# ═══════════════════════════════════════════════════════════════
# Vulnerability API Tests
# ═══════════════════════════════════════════════════════════════

class TestVulnerabilityAPI:
    """Test vulnerability endpoints."""
    
    def test_list_vulnerabilities(self, client, mock_controller, mock_blackboard):
        """Test listing vulnerabilities for a mission."""
        mission_id = str(uuid4())
        vuln_id = str(uuid4())
        
        mock_blackboard.get_mission_vulns.return_value = [f"vuln:{vuln_id}"]
        mock_blackboard.get_vulnerability.return_value = {
            "target_id": str(uuid4()),
            "type": "CVE-2021-44228",
            "name": "Log4Shell",
            "severity": "critical",
            "cvss": 10.0,
            "status": "discovered",
            "exploit_available": True
        }
        
        response = client.get(f"/api/v1/missions/{mission_id}/vulnerabilities")
        
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)


# ═══════════════════════════════════════════════════════════════
# Statistics API Tests
# ═══════════════════════════════════════════════════════════════

class TestStatisticsAPI:
    """Test statistics endpoint."""
    
    def test_get_mission_stats(self, client, mock_controller, mock_blackboard):
        """Test getting mission statistics."""
        mission_id = str(uuid4())
        
        mock_blackboard.get_mission_stats.return_value = MissionStats(
            targets_discovered=5,
            vulns_found=10,
            creds_harvested=3,
            sessions_established=2,
            goals_achieved=1
        )
        mock_blackboard.get_mission_goals.return_value = {
            "domain_admin": "achieved",
            "data_exfil": "pending"
        }
        
        response = client.get(f"/api/v1/missions/{mission_id}/stats")
        
        assert response.status_code == 200
        data = response.json()
        assert data["targets_discovered"] == 5
        assert data["vulns_found"] == 10
        assert data["goals_achieved"] == 1
        assert data["goals_total"] == 2
        assert data["completion_percentage"] == 50.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
