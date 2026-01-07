"""
Tests for mission chat endpoints.
"""

import pytest
import httpx
from typing import Dict, Any


class TestMissionChat:
    """Test cases for mission chat endpoints."""

    def test_send_chat_message_success(self, authenticated_client: httpx.Client, created_mission: Dict[str, Any], 
                                      sample_chat_request: Dict[str, Any]) -> None:
        """Test that POST /api/v1/missions/{mission_id}/chat returns 200 OK."""
        mission_id = created_mission["mission_id"]
        response = authenticated_client.post(f"/api/v1/missions/{mission_id}/chat", json=sample_chat_request)
        assert response.status_code == 200
        data = response.json()
        
        # Verify response structure
        assert "id" in data
        assert "role" in data
        assert "content" in data
        assert "timestamp" in data
        
        # Verify values
        assert data["role"] in ["user", "assistant", "system"]
        assert isinstance(data["id"], str)
        assert isinstance(data["timestamp"], str)

    def test_send_chat_message_with_related_ids(self, authenticated_client: httpx.Client, created_mission: Dict[str, Any]) -> None:
        """Test sending a chat message with related task and action IDs."""
        mission_id = created_mission["mission_id"]
        chat_request = {
            "content": "Status update for this task",
            "related_task_id": "task-123",
            "related_action_id": "action-456"
        }
        response = authenticated_client.post(f"/api/v1/missions/{mission_id}/chat", json=chat_request)
        assert response.status_code == 200
        data = response.json()
        
        assert "id" in data
        assert "role" in data
        assert "content" in data
        assert "timestamp" in data
        # API returns mission status report instead of echoing input
        assert isinstance(data["content"], str)
        assert len(data["content"]) > 0

    def test_send_chat_message_validation_error(self, authenticated_client: httpx.Client, created_mission: Dict[str, Any]) -> None:
        """Test that sending a chat message with invalid data returns 422."""
        mission_id = created_mission["mission_id"]
        
        # Missing required content field
        response = authenticated_client.post(f"/api/v1/missions/{mission_id}/chat", json={})
        assert response.status_code == 422
        
        # Empty content
        response = authenticated_client.post(f"/api/v1/missions/{mission_id}/chat", json={"content": ""})
        assert response.status_code == 422
        
        # Content too long (exceeds 4096 chars)
        long_content = "a" * 4097
        response = authenticated_client.post(f"/api/v1/missions/{mission_id}/chat", json={"content": long_content})
        assert response.status_code == 422

    def test_send_chat_message_mission_not_found(self, authenticated_client: httpx.Client, mission_id: str, 
                                                sample_chat_request: Dict[str, Any]) -> None:
        """Test that sending a chat message to non-existent mission returns 404."""
        response = authenticated_client.post(f"/api/v1/missions/{mission_id}/chat", json=sample_chat_request)
        assert response.status_code == 404

    def test_get_chat_history_success(self, authenticated_client: httpx.Client, created_mission: Dict[str, Any]) -> None:
        """Test that GET /api/v1/missions/{mission_id}/chat returns 200 OK."""
        mission_id = created_mission["mission_id"]
        response = authenticated_client.get(f"/api/v1/missions/{mission_id}/chat")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        
        # If there are messages, verify structure
        if data:
            message = data[0]
            assert "id" in message
            assert "role" in message
            assert "content" in message
            assert "timestamp" in message

    def test_get_chat_history_with_limit(self, authenticated_client: httpx.Client, created_mission: Dict[str, Any]) -> None:
        """Test getting chat history with a limit parameter."""
        mission_id = created_mission["mission_id"]
        response = authenticated_client.get(f"/api/v1/missions/{mission_id}/chat?limit=5")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        # Should not exceed the limit
        assert len(data) <= 5

    def test_get_chat_history_validation_error(self, authenticated_client: httpx.Client, created_mission: Dict[str, Any]) -> None:
        """Test that getting chat history with invalid limit returns 422."""
        mission_id = created_mission["mission_id"]
        
        # Negative limit
        response = authenticated_client.get(f"/api/v1/missions/{mission_id}/chat?limit=-1")
        assert response.status_code == 422
        
        # Zero limit (not allowed)
        response = authenticated_client.get(f"/api/v1/missions/{mission_id}/chat?limit=0")
        assert response.status_code == 422
        
        # Non-integer limit
        response = authenticated_client.get(f"/api/v1/missions/{mission_id}/chat?limit=abc")
        assert response.status_code == 422

    def test_get_chat_history_mission_not_found(self, authenticated_client: httpx.Client, mission_id: str) -> None:
        """Test that getting chat history for non-existent mission returns 404."""
        response = authenticated_client.get(f"/api/v1/missions/{mission_id}/chat")
        assert response.status_code == 404


class TestChatWorkflow:
    """Test cases for the complete chat workflow (Flow D)."""
    
    def test_chat_interaction_workflow(self, authenticated_client: httpx.Client, running_mission: Dict[str, Any]) -> None:
        """Test the chat interaction workflow: send message -> verify response -> get history."""
        mission_id = running_mission["mission_id"]
        
        # 1. Send a message
        message_content = "Status report"
        chat_request = {
            "content": message_content,
            "related_task_id": None,
            "related_action_id": None
        }
        response = authenticated_client.post(f"/api/v1/missions/{mission_id}/chat", json=chat_request)
        assert response.status_code == 200
        message_response = response.json()
        
        # Verify response structure
        assert "id" in message_response
        assert "role" in message_response
        assert "content" in message_response
        assert "timestamp" in message_response
        # API returns mission status report instead of echoing input
        assert isinstance(message_response["content"], str)
        assert len(message_response["content"]) > 0
        
        # Store the message ID for later verification
        sent_message_id = message_response["id"]
        
        # 2. Get chat history
        response = authenticated_client.get(f"/api/v1/missions/{mission_id}/chat")
        assert response.status_code == 200
        chat_history = response.json()
        assert isinstance(chat_history, list)
        
        # 3. Verify the sent message appears in history
        message_ids = [msg["id"] for msg in chat_history]
        assert sent_message_id in message_ids
        
        # Find our message in the history
        sent_message = next((msg for msg in chat_history if msg["id"] == sent_message_id), None)
        assert sent_message is not None
        # API chat may include status reports in content
        assert isinstance(sent_message["content"], str)
        
        # 4. Send another message with related IDs
        second_message = "What's the current status of task-123?"
        second_request = {
            "content": second_message,
            "related_task_id": "task-123",
            "related_action_id": None
        }
        response = authenticated_client.post(f"/api/v1/missions/{mission_id}/chat", json=second_request)
        assert response.status_code == 200
        second_response = response.json()
        # API returns mission status instead of echoing input
        assert isinstance(second_response["content"], str)
        assert len(second_response["content"]) > 0
        
        # 5. Verify the second message appears in history
        response = authenticated_client.get(f"/api/v1/missions/{mission_id}/chat")
        assert response.status_code == 200
        updated_history = response.json()
        message_ids = [msg["id"] for msg in updated_history]
        assert second_response["id"] in message_ids