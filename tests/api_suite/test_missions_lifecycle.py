"""
Tests for mission lifecycle: CRUD operations and state transitions.
"""

import pytest
import httpx
from typing import Dict, Any


class TestMissionCRUD:
    """Test cases for mission CRUD operations."""

    def test_list_missions_success(self, client: httpx.Client) -> None:
        """Test that GET /api/v1/missions returns 200 OK with a list."""
        response = client.get("/api/v1/missions")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        # Each item should be a string (mission ID)
        for mission_id in data:
            assert isinstance(mission_id, str)

    def test_create_mission_success(self, client: httpx.Client, sample_mission_create: Dict[str, Any]) -> None:
        """Test that POST /api/v1/missions with valid data returns 201 Created."""
        response = client.post("/api/v1/missions", json=sample_mission_create)
        assert response.status_code == 201
        data = response.json()
        
        # Verify response structure
        assert "mission_id" in data
        assert "name" in data
        assert "status" in data
        assert "message" in data
        
        # Verify values
        assert data["name"] == sample_mission_create["name"]
        assert data["status"] == "created"
        assert isinstance(data["mission_id"], str)

    def test_create_mission_minimal_success(self, client: httpx.Client, sample_mission_create_minimal: Dict[str, Any]) -> None:
        """Test creating a mission with minimal required fields."""
        response = client.post("/api/v1/missions", json=sample_mission_create_minimal)
        assert response.status_code == 201
        data = response.json()
        
        assert "mission_id" in data
        assert data["name"] == sample_mission_create_minimal["name"]
        assert data["status"] == "created"

    def test_create_mission_validation_error_missing_fields(self, client: httpx.Client) -> None:
        """Test that POST /api/v1/missions with missing fields returns 422."""
        # Missing required fields
        response = client.post("/api/v1/missions", json={})
        assert response.status_code == 422
        
        # Missing name
        response = client.post("/api/v1/missions", json={"scope": ["192.168.1.0/24"], "goals": ["recon"]})
        assert response.status_code == 422
        
        # Missing scope
        response = client.post("/api/v1/missions", json={"name": "Test", "goals": ["recon"]})
        assert response.status_code == 422
        
        # Missing goals
        response = client.post("/api/v1/missions", json={"name": "Test", "scope": ["192.168.1.0/24"]})
        assert response.status_code == 422

    def test_create_mission_validation_error_empty_scope(self, client: httpx.Client) -> None:
        """Test that creating a mission with empty scope returns 422."""
        response = client.post("/api/v1/missions", json={
            "name": "Test Mission",
            "scope": [],  # Empty scope violates minItems constraint
            "goals": ["recon"]
        })
        assert response.status_code == 422

    def test_create_mission_validation_error_empty_goals(self, client: httpx.Client) -> None:
        """Test that creating a mission with empty goals returns 422."""
        response = client.post("/api/v1/missions", json={
            "name": "Test Mission",
            "scope": ["192.168.1.0/24"],
            "goals": []  # Empty goals violates minItems constraint
        })
        assert response.status_code == 422

    def test_create_mission_validation_error_name_too_long(self, client: httpx.Client) -> None:
        """Test that creating a mission with name > 255 chars returns 422."""
        long_name = "a" * 256  # Exceeds maxLength of 255
        response = client.post("/api/v1/missions", json={
            "name": long_name,
            "scope": ["192.168.1.0/24"],
            "goals": ["recon"]
        })
        assert response.status_code == 422

    def test_get_mission_success(self, client: httpx.Client, created_mission: Dict[str, Any]) -> None:
        """Test that GET /api/v1/missions/{mission_id} returns 200 OK."""
        mission_id = created_mission["mission_id"]
        response = client.get(f"/api/v1/missions/{mission_id}")
        assert response.status_code == 200
        data = response.json()
        
        # Verify response structure
        assert "mission_id" in data
        assert "name" in data
        assert "status" in data
        assert "scope" in data
        assert "goals" in data
        assert "statistics" in data
        assert "target_count" in data
        assert "vuln_count" in data
        
        # Verify values
        assert data["mission_id"] == mission_id
        assert data["status"] == "created"

    def test_get_mission_not_found(self, client: httpx.Client, mission_id: str) -> None:
        """Test that GET with non-existent mission ID returns 404."""
        response = client.get(f"/api/v1/missions/{mission_id}")
        assert response.status_code == 404

    def test_get_mission_invalid_id(self, client: httpx.Client) -> None:
        """Test that GET with invalid mission ID format returns 422."""
        response = client.get("/api/v1/missions/invalid-uuid-format")
        assert response.status_code == 422


class TestMissionStateTransitions:
    """Test cases for mission state transitions."""

    def test_start_mission_success(self, client: httpx.Client, created_mission: Dict[str, Any]) -> None:
        """Test that POST /api/v1/missions/{mission_id}/start returns 200 OK."""
        mission_id = created_mission["mission_id"]
        response = client.post(f"/api/v1/missions/{mission_id}/start")
        assert response.status_code == 200
        data = response.json()
        
        assert data["mission_id"] == mission_id
        assert data["status"] == "running"

    def test_start_mission_not_found(self, client: httpx.Client, mission_id: str) -> None:
        """Test that starting a non-existent mission returns 404."""
        response = client.post(f"/api/v1/missions/{mission_id}/start")
        assert response.status_code == 404

    def test_pause_mission_success(self, client: httpx.Client, running_mission: Dict[str, Any]) -> None:
        """Test that POST /api/v1/missions/{mission_id}/pause returns 200 OK."""
        mission_id = running_mission["mission_id"]
        response = client.post(f"/api/v1/missions/{mission_id}/pause")
        assert response.status_code == 200
        data = response.json()
        
        assert data["mission_id"] == mission_id
        assert data["status"] == "paused"

    def test_pause_mission_not_running(self, client: httpx.Client, created_mission: Dict[str, Any]) -> None:
        """Test that pausing a non-running mission returns appropriate error."""
        mission_id = created_mission["mission_id"]
        response = client.post(f"/api/v1/missions/{mission_id}/pause")
        # Should return 400 or 422 depending on implementation
        assert response.status_code in [400, 422]

    def test_resume_mission_success(self, client: httpx.Client, paused_mission: Dict[str, Any]) -> None:
        """Test that POST /api/v1/missions/{mission_id}/resume returns 200 OK."""
        mission_id = paused_mission["mission_id"]
        response = client.post(f"/api/v1/missions/{mission_id}/resume")
        assert response.status_code == 200
        data = response.json()
        
        assert data["mission_id"] == mission_id
        assert data["status"] == "running"

    def test_resume_mission_not_paused(self, client: httpx.Client, running_mission: Dict[str, Any]) -> None:
        """Test that resuming a non-paused mission returns appropriate error."""
        mission_id = running_mission["mission_id"]
        response = client.post(f"/api/v1/missions/{mission_id}/resume")
        # Should return 400 or 422 depending on implementation
        assert response.status_code in [400, 422]

    def test_stop_mission_success(self, client: httpx.Client, running_mission: Dict[str, Any]) -> None:
        """Test that POST /api/v1/missions/{mission_id}/stop returns 200 OK."""
        mission_id = running_mission["mission_id"]
        response = client.post(f"/api/v1/missions/{mission_id}/stop")
        assert response.status_code == 200
        data = response.json()
        
        assert data["mission_id"] == mission_id
        assert data["status"] == "stopped"

    def test_stop_mission_not_found(self, client: httpx.Client, mission_id: str) -> None:
        """Test that stopping a non-existent mission returns 404."""
        response = client.post(f"/api/v1/missions/{mission_id}/stop")
        assert response.status_code == 404


class TestMissionWorkflow:
    """Test cases for complete mission workflow (Flow A)."""

    def test_complete_mission_lifecycle(self, client: httpx.Client, sample_mission_create: Dict[str, Any]) -> None:
        """Test the complete mission lifecycle: create -> start -> pause -> resume -> stop."""
        # 1. Create mission
        response = client.post("/api/v1/missions", json=sample_mission_create)
        assert response.status_code == 201
        mission_data = response.json()
        mission_id = mission_data["mission_id"]
        assert mission_data["status"] == "created"
        
        # 2. Verify created status
        response = client.get(f"/api/v1/missions/{mission_id}")
        assert response.status_code == 200
        mission_status = response.json()
        assert mission_status["status"] == "created"
        
        # 3. Start mission
        response = client.post(f"/api/v1/missions/{mission_id}/start")
        assert response.status_code == 200
        mission_data = response.json()
        assert mission_data["status"] == "running"
        
        # 4. Verify running status
        response = client.get(f"/api/v1/missions/{mission_id}")
        assert response.status_code == 200
        mission_status = response.json()
        assert mission_status["status"] == "running"
        
        # 5. Pause mission
        response = client.post(f"/api/v1/missions/{mission_id}/pause")
        assert response.status_code == 200
        mission_data = response.json()
        assert mission_data["status"] == "paused"
        
        # 6. Verify paused status
        response = client.get(f"/api/v1/missions/{mission_id}")
        assert response.status_code == 200
        mission_status = response.json()
        assert mission_status["status"] == "paused"
        
        # 7. Resume mission
        response = client.post(f"/api/v1/missions/{mission_id}/resume")
        assert response.status_code == 200
        mission_data = response.json()
        assert mission_data["status"] == "running"
        
        # 8. Stop mission
        response = client.post(f"/api/v1/missions/{mission_id}/stop")
        assert response.status_code == 200
        mission_data = response.json()
        assert mission_data["status"] == "stopped"
        
        # 9. Verify stopped status
        response = client.get(f"/api/v1/missions/{mission_id}")
        assert response.status_code == 200
        mission_status = response.json()
        assert mission_status["status"] == "stopped"