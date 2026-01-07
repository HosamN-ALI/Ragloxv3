"""
Tests for mission lifecycle: CRUD operations and state transitions.
"""

import pytest
import httpx
from typing import Dict, Any


class TestMissionCRUD:
    """Test cases for mission CRUD operations."""

    def test_list_missions_success(self, authenticated_client: httpx.Client) -> None:
        """Test that GET /api/v1/missions returns 200 OK with a list."""
        response = authenticated_client.get("/api/v1/missions")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        # Each item should be a string (mission ID)
        for mission_id in data:
            assert isinstance(mission_id, str)

    def test_create_mission_success(self, authenticated_client: httpx.Client, sample_mission_create: Dict[str, Any]) -> None:
        """Test that POST /api/v1/missions with valid data returns 201 Created."""
        response = authenticated_client.post("/api/v1/missions", json=sample_mission_create)
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

    def test_create_mission_minimal_success(self, authenticated_client: httpx.Client, sample_mission_create_minimal: Dict[str, Any]) -> None:
        """Test creating a mission with minimal required fields."""
        response = authenticated_client.post("/api/v1/missions", json=sample_mission_create_minimal)
        assert response.status_code == 201
        data = response.json()
        
        assert "mission_id" in data
        assert data["name"] == sample_mission_create_minimal["name"]
        assert data["status"] == "created"

    def test_create_mission_validation_error_missing_fields(self, authenticated_client: httpx.Client) -> None:
        """Test that POST /api/v1/missions with missing fields returns 422."""
        # Missing required fields
        response = authenticated_client.post("/api/v1/missions", json={})
        assert response.status_code == 422
        
        # Missing name
        response = authenticated_client.post("/api/v1/missions", json={"scope": ["192.168.1.0/24"], "goals": ["recon"]})
        assert response.status_code == 422
        
        # Missing scope
        response = authenticated_client.post("/api/v1/missions", json={"name": "Test", "goals": ["recon"]})
        assert response.status_code == 422
        
        # Missing goals
        response = authenticated_client.post("/api/v1/missions", json={"name": "Test", "scope": ["192.168.1.0/24"]})
        assert response.status_code == 422

    def test_create_mission_validation_error_empty_scope(self, authenticated_client: httpx.Client) -> None:
        """Test that creating a mission with empty scope returns 422."""
        response = authenticated_client.post("/api/v1/missions", json={
            "name": "Test Mission",
            "scope": [],  # Empty scope violates minItems constraint
            "goals": ["recon"]
        })
        assert response.status_code == 422

    def test_create_mission_validation_error_empty_goals(self, authenticated_client: httpx.Client) -> None:
        """Test that creating a mission with empty goals returns 422."""
        response = authenticated_client.post("/api/v1/missions", json={
            "name": "Test Mission",
            "scope": ["192.168.1.0/24"],
            "goals": []  # Empty goals violates minItems constraint
        })
        assert response.status_code == 422

    def test_create_mission_validation_error_name_too_long(self, authenticated_client: httpx.Client) -> None:
        """Test that creating a mission with name > 255 chars returns 422."""
        long_name = "a" * 256  # Exceeds maxLength of 255
        response = authenticated_client.post("/api/v1/missions", json={
            "name": long_name,
            "scope": ["192.168.1.0/24"],
            "goals": ["recon"]
        })
        assert response.status_code == 422

    def test_get_mission_success(self, authenticated_client: httpx.Client, created_mission: Dict[str, Any]) -> None:
        """Test that GET /api/v1/missions/{mission_id} returns 200 OK."""
        mission_id = created_mission["mission_id"]
        response = authenticated_client.get(f"/api/v1/missions/{mission_id}")
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

    def test_get_mission_not_found(self, authenticated_client: httpx.Client, mission_id: str) -> None:
        """Test that GET with non-existent mission ID returns 404."""
        response = authenticated_client.get(f"/api/v1/missions/{mission_id}")
        assert response.status_code == 404

    def test_get_mission_invalid_id(self, authenticated_client: httpx.Client) -> None:
        """Test that GET with invalid mission ID format returns 422."""
        response = authenticated_client.get("/api/v1/missions/invalid-uuid-format")
        assert response.status_code == 422


class TestMissionStateTransitions:
    """Test cases for mission state transitions."""

    def test_start_mission_success(self, authenticated_client: httpx.Client, created_mission: Dict[str, Any]) -> None:
        """Test that POST /api/v1/missions/{mission_id}/start returns 200 OK."""
        mission_id = created_mission["mission_id"]
        response = authenticated_client.post(f"/api/v1/missions/{mission_id}/start", json={})
        assert response.status_code == 200
        data = response.json()
        
        assert data["mission_id"] == mission_id
        assert data["status"] == "running"

    def test_start_mission_not_found(self, authenticated_client: httpx.Client, mission_id: str) -> None:
        """Test that starting a non-existent mission returns 404."""
        response = authenticated_client.post(f"/api/v1/missions/{mission_id}/start", json={})
        assert response.status_code == 404

    def test_pause_mission_success(self, authenticated_client: httpx.Client, running_mission: Dict[str, Any]) -> None:
        """Test that POST /api/v1/missions/{mission_id}/pause returns 200 OK."""
        mission_id = running_mission["mission_id"]
        response = authenticated_client.post(f"/api/v1/missions/{mission_id}/pause", json={})
        assert response.status_code == 200
        data = response.json()
        
        assert data["mission_id"] == mission_id
        assert data["status"] == "paused"

    def test_pause_mission_not_running(self, authenticated_client: httpx.Client, created_mission: Dict[str, Any]) -> None:
        """Test that pausing a non-running mission returns appropriate error."""
        mission_id = created_mission["mission_id"]
        response = authenticated_client.post(f"/api/v1/missions/{mission_id}/pause", json={})
        # Should return 400 or 422 depending on implementation
        assert response.status_code in [400, 422]

    def test_resume_mission_success(self, authenticated_client: httpx.Client, paused_mission: Dict[str, Any]) -> None:
        """Test that POST /api/v1/missions/{mission_id}/resume returns 200 OK."""
        mission_id = paused_mission["mission_id"]
        response = authenticated_client.post(f"/api/v1/missions/{mission_id}/resume", json={})
        assert response.status_code == 200
        data = response.json()
        
        assert data["mission_id"] == mission_id
        assert data["status"] == "running"

    def test_resume_mission_not_paused(self, authenticated_client: httpx.Client, running_mission: Dict[str, Any]) -> None:
        """Test that resuming a non-paused mission returns appropriate error."""
        mission_id = running_mission["mission_id"]
        response = authenticated_client.post(f"/api/v1/missions/{mission_id}/resume", json={})
        # Should return 400 or 422 depending on implementation
        assert response.status_code in [400, 422]

    @pytest.mark.skip(reason="Requires fresh organization - limit reached in existing test data")
    def test_stop_mission_success(self, authenticated_client: httpx.Client, created_mission_class: Dict[str, Any]) -> None:
        """Test that POST /api/v1/missions/{mission_id}/stop returns 200 OK."""
        mission_id = created_mission_class["mission_id"]
        
        # Start the mission first
        start_response = authenticated_client.post(f"/api/v1/missions/{mission_id}/start", json={})
        assert start_response.status_code == 200, f"Failed to start mission: {start_response.status_code}"
        
        # Now stop it
        response = authenticated_client.post(f"/api/v1/missions/{mission_id}/stop", json={})
        assert response.status_code == 200
        data = response.json()
        
        assert data["mission_id"] == mission_id
        assert data["status"] == "stopped"

    def test_stop_mission_not_found(self, authenticated_client: httpx.Client, mission_id: str) -> None:
        """Test that stopping a non-existent mission returns 404."""
        response = authenticated_client.post(f"/api/v1/missions/{mission_id}/stop", json={})
        assert response.status_code == 404


class TestMissionWorkflow:
    """Test cases for complete mission workflow (Flow A)."""

    def test_complete_mission_lifecycle(self, authenticated_client: httpx.Client, sample_mission_create: Dict[str, Any]) -> None:
        """Test the complete mission lifecycle: create -> start -> pause -> resume -> stop."""
        # 1. Create mission
        response = authenticated_client.post("/api/v1/missions", json=sample_mission_create)
        assert response.status_code == 201
        mission_data = response.json()
        mission_id = mission_data["mission_id"]
        assert mission_data["status"] == "created"
        
        # 2. Verify created status
        response = authenticated_client.get(f"/api/v1/missions/{mission_id}")
        assert response.status_code == 200
        mission_status = response.json()
        assert mission_status["status"] == "created"
        
        # 3. Start mission
        response = authenticated_client.post(f"/api/v1/missions/{mission_id}/start", json={})
        assert response.status_code == 200
        mission_data = response.json()
        assert mission_data["status"] == "running"
        
        # 4. Verify running status
        response = authenticated_client.get(f"/api/v1/missions/{mission_id}")
        assert response.status_code == 200
        mission_status = response.json()
        assert mission_status["status"] == "running"
        
        # 5. Pause mission
        response = authenticated_client.post(f"/api/v1/missions/{mission_id}/pause", json={})
        assert response.status_code == 200
        mission_data = response.json()
        assert mission_data["status"] == "paused"
        
        # 6. Verify paused status
        response = authenticated_client.get(f"/api/v1/missions/{mission_id}")
        assert response.status_code == 200
        mission_status = response.json()
        assert mission_status["status"] == "paused"
        
        # 7. Resume mission
        response = authenticated_client.post(f"/api/v1/missions/{mission_id}/resume", json={})
        assert response.status_code == 200
        mission_data = response.json()
        assert mission_data["status"] == "running"
        
        # 8. Stop mission
        response = authenticated_client.post(f"/api/v1/missions/{mission_id}/stop", json={})
        assert response.status_code == 200
        mission_data = response.json()
        assert mission_data["status"] == "stopped"
        
        # 9. Verify stopped status
        response = authenticated_client.get(f"/api/v1/missions/{mission_id}")
        assert response.status_code == 200
        mission_status = response.json()
        assert mission_status["status"] == "stopped"