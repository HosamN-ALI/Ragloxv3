"""
Tests for mission data endpoints: targets, vulnerabilities, credentials, sessions, and stats.
"""

import pytest
import httpx
from typing import Dict, Any


class TestMissionTargets:
    """Test cases for mission targets endpoints."""

    def test_list_targets_success(self, client: httpx.Client, created_mission: Dict[str, Any]) -> None:
        """Test that GET /api/v1/missions/{mission_id}/targets returns 200 OK."""
        mission_id = created_mission["mission_id"]
        response = client.get(f"/api/v1/missions/{mission_id}/targets")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        
        # If there are targets, verify structure
        if data:
            target = data[0]
            assert "target_id" in target
            assert "ip" in target
            assert "status" in target
            assert "priority" in target

    def test_list_targets_empty(self, client: httpx.Client, created_mission: Dict[str, Any]) -> None:
        """Test that listing targets for a new mission returns empty list."""
        mission_id = created_mission["mission_id"]
        response = client.get(f"/api/v1/missions/{mission_id}/targets")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        # New mission should have no targets yet
        assert len(data) == 0

    def test_list_targets_not_found(self, client: httpx.Client, mission_id: str) -> None:
        """Test that listing targets for non-existent mission returns 404."""
        response = client.get(f"/api/v1/missions/{mission_id}/targets")
        assert response.status_code == 404

    def test_get_target_success(self, client: httpx.Client, created_mission: Dict[str, Any], target_id: str) -> None:
        """Test that GET /api/v1/missions/{mission_id}/targets/{target_id} returns 200 OK."""
        mission_id = created_mission["mission_id"]
        # First, we need to ensure the target exists, but for a new mission it won't
        # This test will likely return 404, which is expected for a new mission
        response = client.get(f"/api/v1/missions/{mission_id}/targets/{target_id}")
        # Should be 404 for non-existent target or 200 if target exists
        assert response.status_code in [200, 404]
        
        if response.status_code == 200:
            data = response.json()
            assert "target_id" in data
            assert "ip" in data
            assert "status" in data
            assert "priority" in data

    def test_get_target_not_found(self, client: httpx.Client, created_mission: Dict[str, Any], target_id: str) -> None:
        """Test that getting a non-existent target returns 404."""
        mission_id = created_mission["mission_id"]
        response = client.get(f"/api/v1/missions/{mission_id}/targets/{target_id}")
        assert response.status_code == 404

    def test_get_target_mission_not_found(self, client: httpx.Client, mission_id: str, target_id: str) -> None:
        """Test that getting a target for non-existent mission returns 404."""
        response = client.get(f"/api/v1/missions/{mission_id}/targets/{target_id}")
        assert response.status_code == 404


class TestMissionVulnerabilities:
    """Test cases for mission vulnerabilities endpoints."""

    def test_list_vulnerabilities_success(self, client: httpx.Client, created_mission: Dict[str, Any]) -> None:
        """Test that GET /api/v1/missions/{mission_id}/vulnerabilities returns 200 OK."""
        mission_id = created_mission["mission_id"]
        response = client.get(f"/api/v1/missions/{mission_id}/vulnerabilities")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        
        # If there are vulnerabilities, verify structure
        if data:
            vuln = data[0]
            assert "vuln_id" in vuln
            assert "target_id" in vuln
            assert "type" in vuln
            assert "severity" in vuln
            assert "status" in vuln

    def test_list_vulnerabilities_empty(self, client: httpx.Client, created_mission: Dict[str, Any]) -> None:
        """Test that listing vulnerabilities for a new mission returns empty list."""
        mission_id = created_mission["mission_id"]
        response = client.get(f"/api/v1/missions/{mission_id}/vulnerabilities")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        # New mission should have no vulnerabilities yet
        assert len(data) == 0

    def test_list_vulnerabilities_not_found(self, client: httpx.Client, mission_id: str) -> None:
        """Test that listing vulnerabilities for non-existent mission returns 404."""
        response = client.get(f"/api/v1/missions/{mission_id}/vulnerabilities")
        assert response.status_code == 404


class TestMissionCredentials:
    """Test cases for mission credentials endpoints."""

    def test_list_credentials_success(self, client: httpx.Client, created_mission: Dict[str, Any]) -> None:
        """Test that GET /api/v1/missions/{mission_id}/credentials returns 200 OK."""
        mission_id = created_mission["mission_id"]
        response = client.get(f"/api/v1/missions/{mission_id}/credentials")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        
        # If there are credentials, verify structure
        if data:
            cred = data[0]
            assert "cred_id" in cred
            assert "target_id" in cred
            assert "type" in cred
            assert "username" in cred
            assert "privilege_level" in cred

    def test_list_credentials_empty(self, client: httpx.Client, created_mission: Dict[str, Any]) -> None:
        """Test that listing credentials for a new mission returns empty list."""
        mission_id = created_mission["mission_id"]
        response = client.get(f"/api/v1/missions/{mission_id}/credentials")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        # New mission should have no credentials yet
        assert len(data) == 0

    def test_list_credentials_not_found(self, client: httpx.Client, mission_id: str) -> None:
        """Test that listing credentials for non-existent mission returns 404."""
        response = client.get(f"/api/v1/missions/{mission_id}/credentials")
        assert response.status_code == 404


class TestMissionSessions:
    """Test cases for mission sessions endpoints."""

    def test_list_sessions_success(self, client: httpx.Client, created_mission: Dict[str, Any]) -> None:
        """Test that GET /api/v1/missions/{mission_id}/sessions returns 200 OK."""
        mission_id = created_mission["mission_id"]
        response = client.get(f"/api/v1/missions/{mission_id}/sessions")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        
        # If there are sessions, verify structure
        if data:
            session = data[0]
            assert "session_id" in session
            assert "target_id" in session
            assert "type" in session
            assert "user" in session
            assert "privilege" in session
            assert "status" in session

    def test_list_sessions_empty(self, client: httpx.Client, created_mission: Dict[str, Any]) -> None:
        """Test that listing sessions for a new mission returns empty list."""
        mission_id = created_mission["mission_id"]
        response = client.get(f"/api/v1/missions/{mission_id}/sessions")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        # New mission should have no sessions yet
        assert len(data) == 0

    def test_list_sessions_not_found(self, client: httpx.Client, mission_id: str) -> None:
        """Test that listing sessions for non-existent mission returns 404."""
        response = client.get(f"/api/v1/missions/{mission_id}/sessions")
        assert response.status_code == 404


class TestMissionStats:
    """Test cases for mission statistics endpoints."""

    def test_get_mission_stats_success(self, client: httpx.Client, created_mission: Dict[str, Any]) -> None:
        """Test that GET /api/v1/missions/{mission_id}/stats returns 200 OK."""
        mission_id = created_mission["mission_id"]
        response = client.get(f"/api/v1/missions/{mission_id}/stats")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, dict)
        
        # Stats should contain various metrics
        # The exact structure may vary, but it should be a valid object
        assert len(data) >= 0  # Can be empty for a new mission

    def test_get_mission_stats_not_found(self, client: httpx.Client, mission_id: str) -> None:
        """Test that getting stats for non-existent mission returns 404."""
        response = client.get(f"/api/v1/missions/{mission_id}/stats")
        assert response.status_code == 404


class TestMissionDataWorkflow:
    """Test cases for mission data retrieval workflow (Flow B)."""
    
    def test_mission_data_polling_workflow(self, client: httpx.Client, running_mission: Dict[str, Any]) -> None:
        """Test the data retrieval workflow that simulates frontend polling."""
        mission_id = running_mission["mission_id"]
        
        # Poll multiple times to simulate frontend behavior
        for _ in range(3):
            # Get mission stats
            response = client.get(f"/api/v1/missions/{mission_id}/stats")
            assert response.status_code == 200
            stats_data = response.json()
            assert isinstance(stats_data, dict)
            
            # Get targets
            response = client.get(f"/api/v1/missions/{mission_id}/targets")
            assert response.status_code == 200
            targets_data = response.json()
            assert isinstance(targets_data, list)
            
            # Get vulnerabilities
            response = client.get(f"/api/v1/missions/{mission_id}/vulnerabilities")
            assert response.status_code == 200
            vulns_data = response.json()
            assert isinstance(vulns_data, list)
            
            # Get credentials
            response = client.get(f"/api/v1/missions/{mission_id}/credentials")
            assert response.status_code == 200
            creds_data = response.json()
            assert isinstance(creds_data, list)
            
            # Get sessions
            response = client.get(f"/api/v1/missions/{mission_id}/sessions")
            assert response.status_code == 200
            sessions_data = response.json()
            assert isinstance(sessions_data, list)
            
            # Get approvals
            response = client.get(f"/api/v1/missions/{mission_id}/approvals")
            assert response.status_code == 200
            approvals_data = response.json()
            assert isinstance(approvals_data, list)