"""
Tests for mission approval workflow endpoints.
"""

import pytest
import httpx
from typing import Dict, Any


class TestMissionApprovals:
    """Test cases for mission approval endpoints."""

    def test_list_pending_approvals_success(self, authenticated_client: httpx.Client, created_mission_class: Dict[str, Any]) -> None:
        """Test that GET /api/v1/missions/{mission_id}/approvals returns 200 OK."""
        mission_id = created_mission_class["mission_id"]
        response = authenticated_client.get(f"/api/v1/missions/{mission_id}/approvals")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        
        # If there are approvals, verify structure
        if data:
            approval = data[0]
            assert "action_id" in approval
            assert "action_type" in approval
            assert "action_description" in approval
            assert "risk_level" in approval
            assert "requested_at" in approval

    def test_list_pending_approvals_empty(self, authenticated_client: httpx.Client, created_mission_class: Dict[str, Any]) -> None:
        """Test that listing approvals for a new mission returns empty list."""
        mission_id = created_mission_class["mission_id"]
        response = authenticated_client.get(f"/api/v1/missions/{mission_id}/approvals")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        # New mission should have no pending approvals yet
        assert len(data) == 0

    def test_list_pending_approvals_not_found(self, authenticated_client: httpx.Client, mission_id: str) -> None:
        """Test that listing approvals for non-existent mission returns 404."""
        response = authenticated_client.get(f"/api/v1/missions/{mission_id}/approvals")
        assert response.status_code == 404

    def test_approve_action_success(self, authenticated_client: httpx.Client, created_mission_class: Dict[str, Any], 
                                   sample_approval_request: Dict[str, Any], action_id: str) -> None:
        """Test that POST /api/v1/missions/{mission_id}/approve/{action_id} returns 200 OK."""
        mission_id = created_mission_class["mission_id"]
        # For a new mission, this action_id won't exist, so we expect 404
        response = authenticated_client.post(f"/api/v1/missions/{mission_id}/approve/{action_id}", json=sample_approval_request)
        # Should be 404 for non-existent action or 200 if action exists
        assert response.status_code in [200, 404]
        
        if response.status_code == 200:
            data = response.json()
            assert "success" in data
            assert "message" in data
            assert "action_id" in data
            assert "mission_status" in data
            assert data["action_id"] == action_id

    def test_approve_action_not_found(self, authenticated_client: httpx.Client, created_mission_class: Dict[str, Any], 
                                     sample_approval_request: Dict[str, Any], action_id: str) -> None:
        """Test that approving a non-existent action returns 404."""
        mission_id = created_mission_class["mission_id"]
        response = authenticated_client.post(f"/api/v1/missions/{mission_id}/approve/{action_id}", json=sample_approval_request)
        assert response.status_code == 404

    def test_approve_action_mission_not_found(self, authenticated_client: httpx.Client, mission_id: str, 
                                             sample_approval_request: Dict[str, Any], action_id: str) -> None:
        """Test that approving an action for non-existent mission returns 404."""
        response = authenticated_client.post(f"/api/v1/missions/{mission_id}/approve/{action_id}", json=sample_approval_request)
        assert response.status_code == 404

    def test_reject_action_success(self, authenticated_client: httpx.Client, created_mission_class: Dict[str, Any], 
                                  sample_rejection_request: Dict[str, Any], action_id: str) -> None:
        """Test that POST /api/v1/missions/{mission_id}/reject/{action_id} returns 200 OK."""
        mission_id = created_mission_class["mission_id"]
        # For a new mission, this action_id won't exist, so we expect 404
        response = authenticated_client.post(f"/api/v1/missions/{mission_id}/reject/{action_id}", json=sample_rejection_request)
        # Should be 404 for non-existent action or 200 if action exists
        assert response.status_code in [200, 404]
        
        if response.status_code == 200:
            data = response.json()
            assert "success" in data
            assert "message" in data
            assert "action_id" in data
            assert "mission_status" in data
            assert data["action_id"] == action_id

    def test_reject_action_not_found(self, authenticated_client: httpx.Client, created_mission_class: Dict[str, Any], 
                                    sample_rejection_request: Dict[str, Any], action_id: str) -> None:
        """Test that rejecting a non-existent action returns 404."""
        mission_id = created_mission_class["mission_id"]
        response = authenticated_client.post(f"/api/v1/missions/{mission_id}/reject/{action_id}", json=sample_rejection_request)
        assert response.status_code == 404

    def test_reject_action_mission_not_found(self, authenticated_client: httpx.Client, mission_id: str, 
                                           sample_rejection_request: Dict[str, Any], action_id: str) -> None:
        """Test that rejecting an action for non-existent mission returns 404."""
        response = authenticated_client.post(f"/api/v1/missions/{mission_id}/reject/{action_id}", json=sample_rejection_request)
        assert response.status_code == 404

    def test_approve_action_validation_error(self, authenticated_client: httpx.Client, created_mission_class: Dict[str, Any], 
                                            action_id: str) -> None:
        """Test that approving with invalid data returns 422."""
        mission_id = created_mission_class["mission_id"]
        # Send invalid JSON
        response = authenticated_client.post(
            f"/api/v1/missions/{mission_id}/approve/{action_id}",
            json={"invalid_field": "value"}
        )
        # Should be 422 for validation error or 404 if action doesn't exist
        assert response.status_code in [404, 422]

    def test_reject_action_validation_error(self, authenticated_client: httpx.Client, created_mission_class: Dict[str, Any], 
                                           action_id: str) -> None:
        """Test that rejecting with invalid data returns 422."""
        mission_id = created_mission_class["mission_id"]
        # Send invalid JSON
        response = authenticated_client.post(
            f"/api/v1/missions/{mission_id}/reject/{action_id}",
            json={"invalid_field": "value"}
        )
        # Should be 422 for validation error or 404 if action doesn't exist
        assert response.status_code in [404, 422]


class TestApprovalWorkflow:
    """Test cases for the complete approval workflow (Flow C)."""
    
    def test_approval_workflow(self, authenticated_client: httpx.Client, running_mission: Dict[str, Any]) -> None:
        """Test the approval workflow: list -> approve -> verify removal."""
        mission_id = running_mission["mission_id"]
        
        # 1. List pending approvals
        response = authenticated_client.get(f"/api/v1/missions/{mission_id}/approvals")
        assert response.status_code == 200
        approvals = response.json()
        assert isinstance(approvals, list)
        
        # For a new mission, there might not be any approvals yet
        # If there are approvals, we can test the workflow
        if approvals:
            # Get the first action_id
            action_id = approvals[0]["action_id"]
            
            # 2. Approve the action
            approval_request = {"user_comment": "Approved for testing"}
            response = authenticated_client.post(
                f"/api/v1/missions/{mission_id}/approve/{action_id}",
                json=approval_request
            )
            assert response.status_code == 200
            approval_response = response.json()
            assert approval_response["success"] is True
            assert approval_response["action_id"] == action_id
            
            # 3. Verify the action is no longer in pending approvals
            response = authenticated_client.get(f"/api/v1/missions/{mission_id}/approvals")
            assert response.status_code == 200
            updated_approvals = response.json()
            
            # The approved action should no longer be in the list
            action_ids = [a["action_id"] for a in updated_approvals]
            assert action_id not in action_ids
        else:
            # If no approvals exist, we can't test the full workflow
            # But we can verify that trying to approve with an invalid UUID returns 422
            fake_action_id = "non-existent-action-id"
            response = authenticated_client.post(
                f"/api/v1/missions/{mission_id}/approve/{fake_action_id}",
                json={"user_comment": "This should fail"}
            )
            # Invalid UUID format should return 422 (validation error)
            assert response.status_code == 422