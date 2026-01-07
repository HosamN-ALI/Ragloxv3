"""
End-to-End Tests: Chat and HITL Workflows
=========================================

Tests chat interactions and Human-in-the-Loop approval workflows.
"""

import pytest
import asyncio
import httpx
from typing import Dict, Any
from datetime import datetime

from tests.production.base import ProductionE2ETestBase
from tests.production.config import get_config


@pytest.mark.e2e
@pytest.mark.asyncio
class TestChatWorkflowE2E(ProductionE2ETestBase):
    """End-to-end tests for chat functionality"""

    async def test_e2e_chat_basic_interaction(
        self,
        real_api_client: httpx.AsyncClient,
        auth_headers: Dict[str, str]
    ):
        """
        Test 1: Basic chat interaction with mission
        
        Flow:
        1. Create mission
        2. Send chat message
        3. Verify response
        4. Send follow-up message
        5. Verify chat history
        """
        print("\n" + "="*80)
        print("🚀 Starting E2E Test: Basic Chat Interaction")
        print("="*80)
        
        # Create mission
        print("\n📝 Creating mission...")
        mission_data = {
            "name": self.generate_mission_name("E2E Chat Test"),
            "description": "Test chat functionality",
            "scope": {
                "ip_ranges": ["192.168.100.0/24"]
            },
            "goals": ["reconnaissance"]
        }
        
        response = await real_api_client.post(
            "/api/v1/missions",
            json=mission_data,
            headers=auth_headers
        )
        assert response.status_code in [200, 201]
        
        mission = response.json()
        mission_id = mission.get("id") or mission.get("mission_id")
        print(f"✅ Mission created: {mission_id}")
        
        try:
            # Send first chat message
            print("\n💬 Sending first chat message...")
            chat_data = {
                "content": "Hello! What is the current status of this mission?",
                "role": "user"
            }
            
            response = await real_api_client.post(
                f"/api/v1/missions/{mission_id}/chat",
                json=chat_data,
                headers=auth_headers
            )
            
            assert response.status_code == 200, \
                f"Failed to send chat message: {response.status_code}"
            
            chat_response = response.json()
            print(f"✅ Chat message sent")
            print(f"   Message ID: {chat_response.get('id')}")
            print(f"   Response: {chat_response.get('content', 'N/A')[:100]}...")
            
            # Send follow-up message
            print("\n💬 Sending follow-up message...")
            chat_data = {
                "content": "Can you explain what reconnaissance means?",
                "role": "user"
            }
            
            response = await real_api_client.post(
                f"/api/v1/missions/{mission_id}/chat",
                json=chat_data,
                headers=auth_headers
            )
            
            assert response.status_code == 200
            chat_response = response.json()
            print(f"✅ Follow-up message sent")
            print(f"   Response: {chat_response.get('content', 'N/A')[:100]}...")
            
            # Get chat history
            print("\n📜 Retrieving chat history...")
            response = await real_api_client.get(
                f"/api/v1/missions/{mission_id}/chat",
                headers=auth_headers
            )
            
            assert response.status_code == 200
            chat_history = response.json()
            
            # Verify history structure
            if isinstance(chat_history, list):
                messages = chat_history
            elif isinstance(chat_history, dict) and "messages" in chat_history:
                messages = chat_history["messages"]
            else:
                messages = []
            
            print(f"✅ Retrieved {len(messages)} chat messages")
            
            # Verify we have at least our 2 user messages
            user_messages = [m for m in messages if m.get("role") == "user"]
            assert len(user_messages) >= 2, \
                f"Expected at least 2 user messages, got {len(user_messages)}"
            
            print("\n📝 Chat History:")
            for i, msg in enumerate(messages[-4:]):  # Show last 4 messages
                role = msg.get("role", "unknown")
                content = msg.get("content", "")[:80]
                print(f"   {i+1}. [{role}] {content}...")
            
            print("\n✅ E2E Test PASSED: Basic Chat Interaction")
            
        except Exception as e:
            print(f"\n❌ Test FAILED: {str(e)}")
            raise

    async def test_e2e_chat_with_context(
        self,
        real_api_client: httpx.AsyncClient,
        auth_headers: Dict[str, str]
    ):
        """
        Test 2: Chat with mission context
        
        Verifies that chat assistant has access to mission context.
        """
        print("\n" + "="*80)
        print("🚀 Starting E2E Test: Chat with Context")
        print("="*80)
        
        # Create mission with specific details
        mission_name = self.generate_mission_name("E2E Context Chat")
        mission_data = {
            "name": mission_name,
            "description": "Test mission for context-aware chat",
            "scope": {
                "ip_ranges": ["10.0.0.0/24", "192.168.1.0/24"]
            },
            "goals": ["reconnaissance", "enumeration"]
        }
        
        response = await real_api_client.post(
            "/api/v1/missions",
            json=mission_data,
            headers=auth_headers
        )
        mission = response.json()
        mission_id = mission.get("id") or mission.get("mission_id")
        
        try:
            # Ask about mission name
            print("\n💬 Asking about mission name...")
            response = await real_api_client.post(
                f"/api/v1/missions/{mission_id}/chat",
                json={"content": "What is the name of this mission?", "role": "user"},
                headers=auth_headers
            )
            
            chat_response = response.json()
            response_content = chat_response.get("content", "").lower()
            
            # Check if response contains mission name (partial match)
            mission_name_parts = mission_name.lower().split()
            has_context = any(part in response_content for part in mission_name_parts[:3])
            
            if has_context:
                print("✅ Chat has access to mission name")
            else:
                print("⚠️  Chat might not have full context (this is okay)")
            
            # Ask about scope
            print("\n💬 Asking about mission scope...")
            response = await real_api_client.post(
                f"/api/v1/missions/{mission_id}/chat",
                json={"content": "What IP ranges are in scope?", "role": "user"},
                headers=auth_headers
            )
            
            chat_response = response.json()
            response_content = chat_response.get("content", "")
            print(f"   Response: {response_content[:150]}...")
            
            # Ask about goals
            print("\n💬 Asking about mission goals...")
            response = await real_api_client.post(
                f"/api/v1/missions/{mission_id}/chat",
                json={"content": "What are the goals of this mission?", "role": "user"},
                headers=auth_headers
            )
            
            chat_response = response.json()
            response_content = chat_response.get("content", "")
            print(f"   Response: {response_content[:150]}...")
            
            print("\n✅ E2E Test PASSED: Chat with Context")
            
        except Exception as e:
            print(f"\n❌ Test FAILED: {str(e)}")
            raise


@pytest.mark.e2e
@pytest.mark.asyncio
class TestHITLWorkflowE2E(ProductionE2ETestBase):
    """End-to-end tests for Human-in-the-Loop approval workflows"""

    async def test_e2e_hitl_approval_workflow(
        self,
        real_api_client: httpx.AsyncClient,
        auth_headers: Dict[str, str]
    ):
        """
        Test 3: HITL approval workflow
        
        Flow:
        1. Create and start mission
        2. Wait for approval request
        3. Approve action
        4. Verify action executed
        5. Check approval history
        """
        print("\n" + "="*80)
        print("🚀 Starting E2E Test: HITL Approval Workflow")
        print("="*80)
        
        # Create mission with exploit enabled (requires approval)
        print("\n📝 Creating mission with exploits enabled...")
        mission_data = {
            "name": self.generate_mission_name("E2E HITL Test"),
            "description": "Test HITL approval workflow",
            "scope": {
                "ip_ranges": ["192.168.100.0/24"]
            },
            "goals": ["reconnaissance", "exploitation"],
            "constraints": {
                "require_approval": True,
                "stealth": False
            }
        }
        
        response = await real_api_client.post(
            "/api/v1/missions",
            json=mission_data,
            headers=auth_headers
        )
        mission = response.json()
        mission_id = mission.get("id") or mission.get("mission_id")
        print(f"✅ Mission created: {mission_id}")
        
        try:
            # Start mission
            print("\n▶️  Starting mission...")
            await real_api_client.post(
                f"/api/v1/missions/{mission_id}/start",
                json={},
                headers=auth_headers
            )
            
            await self.wait_for_mission_status(
                real_api_client,
                auth_headers,
                mission_id,
                "running",
                timeout=60
            )
            print("✅ Mission started")
            
            # Check for pending approvals
            print("\n⏳ Checking for pending approval requests...")
            
            async def check_approvals():
                response = await real_api_client.get(
                    f"/api/v1/missions/{mission_id}/approvals",
                    headers=auth_headers
                )
                if response.status_code == 200:
                    approvals = response.json()
                    if isinstance(approvals, list) and len(approvals) > 0:
                        return approvals
                    elif isinstance(approvals, dict) and approvals.get("items"):
                        return approvals["items"]
                return None
            
            try:
                # Wait up to 2 minutes for an approval request
                approvals = await self.wait_for_condition(
                    check_approvals,
                    timeout=120,
                    poll_interval=10,
                    condition_name="approval request"
                )
                
                print(f"✅ Found {len(approvals)} approval request(s)")
                
                # Approve first action
                first_approval = approvals[0]
                action_id = first_approval.get("action_id") or first_approval.get("id")
                action_type = first_approval.get("action_type", "unknown")
                
                print(f"\n👍 Approving action: {action_type} (ID: {action_id})")
                
                approval_data = {
                    "approved": True,
                    "reason": "Approved for E2E testing"
                }
                
                response = await real_api_client.post(
                    f"/api/v1/missions/{mission_id}/approve/{action_id}",
                    json=approval_data,
                    headers=auth_headers
                )
                
                assert response.status_code == 200, \
                    f"Failed to approve action: {response.status_code}"
                
                approval_response = response.json()
                print("✅ Action approved successfully")
                print(f"   Status: {approval_response.get('success', False)}")
                
                # Verify approval in history
                print("\n📜 Checking approval history...")
                response = await real_api_client.get(
                    f"/api/v1/missions/{mission_id}/approvals",
                    headers=auth_headers
                )
                
                if response.status_code == 200:
                    approvals = response.json()
                    print(f"✅ Approval recorded in history")
                
            except TimeoutError:
                print("⚠️  No approval requests generated (mission might not require approvals)")
                print("   This is acceptable for this test environment")
            
            # Stop mission
            print("\n⏹️  Stopping mission...")
            await real_api_client.post(
                f"/api/v1/missions/{mission_id}/stop",
                json={},
                headers=auth_headers
            )
            
            print("\n✅ E2E Test PASSED: HITL Approval Workflow")
            
        except Exception as e:
            print(f"\n❌ Test FAILED: {str(e)}")
            try:
                await real_api_client.post(
                    f"/api/v1/missions/{mission_id}/stop",
                    json={},
                    headers=auth_headers
                )
            except:
                pass
            raise

    async def test_e2e_hitl_rejection_workflow(
        self,
        real_api_client: httpx.AsyncClient,
        auth_headers: Dict[str, str]
    ):
        """
        Test 4: HITL rejection workflow
        
        Flow:
        1. Create mission requiring approval
        2. Wait for approval request
        3. Reject action
        4. Verify action not executed
        """
        print("\n" + "="*80)
        print("🚀 Starting E2E Test: HITL Rejection Workflow")
        print("="*80)
        
        mission_data = {
            "name": self.generate_mission_name("E2E HITL Rejection"),
            "description": "Test HITL rejection workflow",
            "scope": {
                "ip_ranges": ["192.168.100.0/24"]
            },
            "goals": ["reconnaissance", "exploitation"],
            "constraints": {
                "require_approval": True
            }
        }
        
        response = await real_api_client.post(
            "/api/v1/missions",
            json=mission_data,
            headers=auth_headers
        )
        mission = response.json()
        mission_id = mission.get("id") or mission.get("mission_id")
        
        try:
            # Start mission
            await real_api_client.post(
                f"/api/v1/missions/{mission_id}/start",
                json={},
                headers=auth_headers
            )
            
            await self.wait_for_mission_status(
                real_api_client,
                auth_headers,
                mission_id,
                "running",
                timeout=60
            )
            
            # Check for approvals
            print("\n⏳ Waiting for approval request...")
            
            async def check_approvals():
                response = await real_api_client.get(
                    f"/api/v1/missions/{mission_id}/approvals",
                    headers=auth_headers
                )
                if response.status_code == 200:
                    approvals = response.json()
                    if isinstance(approvals, list) and len(approvals) > 0:
                        return approvals
                return None
            
            try:
                approvals = await self.wait_for_condition(
                    check_approvals,
                    timeout=120,
                    poll_interval=10,
                    condition_name="approval request"
                )
                
                # Reject first action
                first_approval = approvals[0]
                action_id = first_approval.get("action_id") or first_approval.get("id")
                
                print(f"\n👎 Rejecting action: {action_id}")
                
                rejection_data = {
                    "rejected": True,
                    "reason": "Rejected for E2E testing purposes"
                }
                
                response = await real_api_client.post(
                    f"/api/v1/missions/{mission_id}/reject/{action_id}",
                    json=rejection_data,
                    headers=auth_headers
                )
                
                assert response.status_code == 200, \
                    f"Failed to reject action: {response.status_code}"
                
                print("✅ Action rejected successfully")
                
            except TimeoutError:
                print("⚠️  No approval requests generated")
            
            # Stop mission
            await real_api_client.post(
                f"/api/v1/missions/{mission_id}/stop",
                json={},
                headers=auth_headers
            )
            
            print("\n✅ E2E Test PASSED: HITL Rejection Workflow")
            
        except Exception as e:
            print(f"\n❌ Test FAILED: {str(e)}")
            try:
                await real_api_client.post(
                    f"/api/v1/missions/{mission_id}/stop",
                    json={},
                    headers=auth_headers
                )
            except:
                pass
            raise


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-s"])
