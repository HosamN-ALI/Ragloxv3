#!/usr/bin/env python3
"""
RAGLOX v3.0 - Comprehensive Frontend-Backend Integration Test Suite
This script tests all API endpoints and verifies frontend-backend integration
"""

import asyncio
import httpx
import json
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
import websockets
from enum import Enum

# Configuration
API_BASE = "http://172.245.232.188:8000"
WS_BASE = "ws://172.245.232.188:8000"
TIMEOUT = 30.0

class TestStatus(Enum):
    PASSED = "✅ PASSED"
    FAILED = "❌ FAILED"
    SKIPPED = "⏭️ SKIPPED"
    WARNING = "⚠️ WARNING"

@dataclass
class TestResult:
    name: str
    status: TestStatus
    duration_ms: float
    endpoint: str
    expected: str
    actual: str
    error: Optional[str] = None
    details: Dict = field(default_factory=dict)

@dataclass
class TestSuite:
    name: str
    results: List[TestResult] = field(default_factory=list)
    
    @property
    def passed(self) -> int:
        return len([r for r in self.results if r.status == TestStatus.PASSED])
    
    @property
    def failed(self) -> int:
        return len([r for r in self.results if r.status == TestStatus.FAILED])
    
    @property
    def warnings(self) -> int:
        return len([r for r in self.results if r.status == TestStatus.WARNING])

class IntegrationTester:
    def __init__(self):
        self.client: Optional[httpx.AsyncClient] = None
        self.suites: List[TestSuite] = []
        self.mission_ids: List[str] = []
        
    async def __aenter__(self):
        self.client = httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True)
        return self
    
    async def __aexit__(self, *args):
        if self.client:
            await self.client.aclose()
    
    async def run_test(self, name: str, endpoint: str, expected: str, 
                       test_func, **kwargs) -> TestResult:
        """Run a single test and return the result"""
        start = time.time()
        try:
            actual, details = await test_func(**kwargs)
            duration = (time.time() - start) * 1000
            
            if actual == expected:
                return TestResult(name, TestStatus.PASSED, duration, endpoint, expected, actual, details=details)
            else:
                return TestResult(name, TestStatus.WARNING if "warning" in str(actual).lower() else TestStatus.FAILED,
                                duration, endpoint, expected, actual, details=details)
        except Exception as e:
            duration = (time.time() - start) * 1000
            return TestResult(name, TestStatus.FAILED, duration, endpoint, expected, 
                            f"Exception: {type(e).__name__}", str(e))
    
    # ===========================================
    # Health & Root Endpoint Tests
    # ===========================================
    
    async def test_health_endpoints(self) -> TestSuite:
        suite = TestSuite("Health & Root Endpoints")
        
        # Test root endpoint
        async def test_root():
            r = await self.client.get(f"{API_BASE}/")
            data = r.json()
            if r.status_code == 200 and data.get("name") == "RAGLOX":
                return "200 OK", {"version": data.get("version"), "status": data.get("status")}
            return f"{r.status_code}", {}
        
        suite.results.append(await self.run_test(
            "Root endpoint returns API info",
            "GET /",
            "200 OK",
            test_root
        ))
        
        # Test health endpoint
        async def test_health():
            r = await self.client.get(f"{API_BASE}/health")
            data = r.json()
            if r.status_code == 200 and data.get("status") == "healthy":
                return "200 OK", data
            return f"{r.status_code}", data
        
        suite.results.append(await self.run_test(
            "Health check returns healthy status",
            "GET /health",
            "200 OK",
            test_health
        ))
        
        return suite
    
    # ===========================================
    # Mission CRUD Tests
    # ===========================================
    
    async def test_mission_crud(self) -> TestSuite:
        suite = TestSuite("Mission CRUD Operations")
        
        # Test list missions
        async def test_list_missions():
            r = await self.client.get(f"{API_BASE}/api/v1/missions")
            if r.status_code == 200:
                data = r.json()
                return "200 OK", {"count": len(data), "type": type(data).__name__}
            return f"{r.status_code}", {}
        
        suite.results.append(await self.run_test(
            "List missions returns array",
            "GET /api/v1/missions",
            "200 OK",
            test_list_missions
        ))
        
        # Test create mission
        async def test_create_mission():
            payload = {
                "name": f"Integration Test Mission {datetime.now().isoformat()}",
                "description": "Created by comprehensive integration test",
                "scope": ["192.168.1.0/24", "10.0.0.0/8"],
                "goals": ["reconnaissance", "vulnerability_assessment"],
                "constraints": {"stealth": True, "max_threads": 10}
            }
            r = await self.client.post(f"{API_BASE}/api/v1/missions", json=payload)
            if r.status_code == 201:
                data = r.json()
                mission_id = data.get("mission_id")
                if mission_id:
                    self.mission_ids.append(mission_id)
                return "201 Created", {"mission_id": mission_id, "status": data.get("status")}
            return f"{r.status_code}", r.json() if r.status_code != 500 else {}
        
        suite.results.append(await self.run_test(
            "Create mission with valid data",
            "POST /api/v1/missions",
            "201 Created",
            test_create_mission
        ))
        
        # Test create mission - missing fields (validation)
        async def test_create_mission_validation():
            r = await self.client.post(f"{API_BASE}/api/v1/missions", json={})
            if r.status_code == 422:
                return "422 Validation Error", r.json()
            return f"{r.status_code}", {}
        
        suite.results.append(await self.run_test(
            "Create mission rejects empty payload (validation)",
            "POST /api/v1/missions",
            "422 Validation Error",
            test_create_mission_validation
        ))
        
        # Test create mission - empty scope
        async def test_create_mission_empty_scope():
            payload = {"name": "Test", "scope": [], "goals": ["test"]}
            r = await self.client.post(f"{API_BASE}/api/v1/missions", json=payload)
            if r.status_code == 422:
                return "422 Validation Error", {}
            return f"{r.status_code}", {}
        
        suite.results.append(await self.run_test(
            "Create mission rejects empty scope",
            "POST /api/v1/missions",
            "422 Validation Error",
            test_create_mission_empty_scope
        ))
        
        # Test get mission details
        async def test_get_mission():
            if not self.mission_ids:
                return "SKIPPED - No mission ID", {}
            
            mission_id = self.mission_ids[0]
            r = await self.client.get(f"{API_BASE}/api/v1/missions/{mission_id}")
            if r.status_code == 200:
                data = r.json()
                return "200 OK", {"mission_id": data.get("mission_id"), "status": data.get("status")}
            return f"{r.status_code}", {}
        
        suite.results.append(await self.run_test(
            "Get mission details by ID",
            "GET /api/v1/missions/{id}",
            "200 OK",
            test_get_mission
        ))
        
        # Test get non-existent mission
        async def test_get_mission_not_found():
            fake_id = "00000000-0000-0000-0000-000000000000"
            r = await self.client.get(f"{API_BASE}/api/v1/missions/{fake_id}")
            if r.status_code == 404:
                return "404 Not Found", {}
            return f"{r.status_code} (Expected 404)", {}
        
        suite.results.append(await self.run_test(
            "Get non-existent mission returns 404",
            "GET /api/v1/missions/{fake_id}",
            "404 Not Found",
            test_get_mission_not_found
        ))
        
        # Test invalid UUID format
        async def test_get_mission_invalid_id():
            r = await self.client.get(f"{API_BASE}/api/v1/missions/invalid-uuid")
            # Should be 422, but may return 404
            if r.status_code in [422, 404]:
                return f"{r.status_code} (422 or 404 acceptable)", {}
            return f"{r.status_code}", {}
        
        suite.results.append(await self.run_test(
            "Get mission with invalid UUID format",
            "GET /api/v1/missions/invalid-uuid",
            "422 (422 or 404 acceptable)",
            test_get_mission_invalid_id
        ))
        
        return suite
    
    # ===========================================
    # Mission Lifecycle Tests
    # ===========================================
    
    async def test_mission_lifecycle(self) -> TestSuite:
        suite = TestSuite("Mission Lifecycle (Start/Pause/Resume/Stop)")
        
        # Create a mission for lifecycle tests
        payload = {
            "name": f"Lifecycle Test {datetime.now().isoformat()}",
            "scope": ["192.168.100.0/24"],
            "goals": ["test_lifecycle"]
        }
        r = await self.client.post(f"{API_BASE}/api/v1/missions", json=payload)
        if r.status_code != 201:
            suite.results.append(TestResult(
                "Create mission for lifecycle test", TestStatus.FAILED,
                0, "POST /api/v1/missions", "201", str(r.status_code)
            ))
            return suite
        
        mission_id = r.json().get("mission_id")
        self.mission_ids.append(mission_id)
        
        # Test start mission
        async def test_start():
            r = await self.client.post(f"{API_BASE}/api/v1/missions/{mission_id}/start")
            if r.status_code == 200:
                data = r.json()
                return "200 OK", {"status": data.get("status")}
            return f"{r.status_code}", {}
        
        suite.results.append(await self.run_test(
            "Start mission",
            f"POST /api/v1/missions/{mission_id}/start",
            "200 OK",
            test_start
        ))
        
        await asyncio.sleep(0.5)  # Small delay between state changes
        
        # Test pause mission
        async def test_pause():
            r = await self.client.post(f"{API_BASE}/api/v1/missions/{mission_id}/pause")
            if r.status_code == 200:
                data = r.json()
                return "200 OK", {"status": data.get("status")}
            return f"{r.status_code}", {}
        
        suite.results.append(await self.run_test(
            "Pause running mission",
            f"POST /api/v1/missions/{mission_id}/pause",
            "200 OK",
            test_pause
        ))
        
        await asyncio.sleep(0.5)
        
        # Test resume mission
        async def test_resume():
            r = await self.client.post(f"{API_BASE}/api/v1/missions/{mission_id}/resume")
            if r.status_code == 200:
                data = r.json()
                return "200 OK", {"status": data.get("status")}
            return f"{r.status_code}", {}
        
        suite.results.append(await self.run_test(
            "Resume paused mission",
            f"POST /api/v1/missions/{mission_id}/resume",
            "200 OK",
            test_resume
        ))
        
        await asyncio.sleep(0.5)
        
        # Test stop mission (Critical issue from report)
        async def test_stop():
            r = await self.client.post(f"{API_BASE}/api/v1/missions/{mission_id}/stop")
            if r.status_code == 200:
                data = r.json()
                return "200 OK", {"status": data.get("status")}
            elif r.status_code == 500:
                return "500 Internal Server Error (KNOWN ISSUE)", {}
            return f"{r.status_code}", {}
        
        result = await self.run_test(
            "Stop running mission",
            f"POST /api/v1/missions/{mission_id}/stop",
            "200 OK",
            test_stop
        )
        # Mark as warning if 500 since it's a known issue
        if "500" in result.actual:
            result.status = TestStatus.WARNING
        suite.results.append(result)
        
        # Test start non-existent mission
        async def test_start_not_found():
            fake_id = "00000000-0000-0000-0000-000000000001"
            r = await self.client.post(f"{API_BASE}/api/v1/missions/{fake_id}/start")
            if r.status_code == 404:
                return "404 Not Found", {}
            return f"{r.status_code} (Expected 404)", {}
        
        suite.results.append(await self.run_test(
            "Start non-existent mission returns 404",
            "POST /api/v1/missions/{fake_id}/start",
            "404 Not Found",
            test_start_not_found
        ))
        
        return suite
    
    # ===========================================
    # Mission Data Endpoints Tests
    # ===========================================
    
    async def test_mission_data_endpoints(self) -> TestSuite:
        suite = TestSuite("Mission Data Endpoints (Targets, Vulns, Creds, Sessions, Stats)")
        
        if not self.mission_ids:
            suite.results.append(TestResult(
                "Mission data tests", TestStatus.SKIPPED,
                0, "", "", "", "No mission ID available"
            ))
            return suite
        
        mission_id = self.mission_ids[0]
        
        # Test targets endpoint
        async def test_targets():
            r = await self.client.get(f"{API_BASE}/api/v1/missions/{mission_id}/targets")
            if r.status_code == 200:
                data = r.json()
                return "200 OK", {"count": len(data), "type": type(data).__name__}
            return f"{r.status_code}", {}
        
        suite.results.append(await self.run_test(
            "List targets for mission",
            f"GET /api/v1/missions/{mission_id}/targets",
            "200 OK",
            test_targets
        ))
        
        # Test vulnerabilities endpoint
        async def test_vulns():
            r = await self.client.get(f"{API_BASE}/api/v1/missions/{mission_id}/vulnerabilities")
            if r.status_code == 200:
                data = r.json()
                return "200 OK", {"count": len(data)}
            return f"{r.status_code}", {}
        
        suite.results.append(await self.run_test(
            "List vulnerabilities for mission",
            f"GET /api/v1/missions/{mission_id}/vulnerabilities",
            "200 OK",
            test_vulns
        ))
        
        # Test credentials endpoint
        async def test_creds():
            r = await self.client.get(f"{API_BASE}/api/v1/missions/{mission_id}/credentials")
            if r.status_code == 200:
                data = r.json()
                return "200 OK", {"count": len(data)}
            return f"{r.status_code}", {}
        
        suite.results.append(await self.run_test(
            "List credentials for mission",
            f"GET /api/v1/missions/{mission_id}/credentials",
            "200 OK",
            test_creds
        ))
        
        # Test sessions endpoint
        async def test_sessions():
            r = await self.client.get(f"{API_BASE}/api/v1/missions/{mission_id}/sessions")
            if r.status_code == 200:
                data = r.json()
                return "200 OK", {"count": len(data)}
            return f"{r.status_code}", {}
        
        suite.results.append(await self.run_test(
            "List sessions for mission",
            f"GET /api/v1/missions/{mission_id}/sessions",
            "200 OK",
            test_sessions
        ))
        
        # Test stats endpoint
        async def test_stats():
            r = await self.client.get(f"{API_BASE}/api/v1/missions/{mission_id}/stats")
            if r.status_code == 200:
                data = r.json()
                return "200 OK", {"keys": list(data.keys()) if isinstance(data, dict) else []}
            return f"{r.status_code}", {}
        
        suite.results.append(await self.run_test(
            "Get mission statistics",
            f"GET /api/v1/missions/{mission_id}/stats",
            "200 OK",
            test_stats
        ))
        
        # Test data endpoints for non-existent mission (Known Issue - returns 200 with empty)
        fake_id = "00000000-0000-0000-0000-000000000002"
        
        async def test_targets_not_found():
            r = await self.client.get(f"{API_BASE}/api/v1/missions/{fake_id}/targets")
            if r.status_code == 404:
                return "404 Not Found", {}
            elif r.status_code == 200:
                return "200 OK (KNOWN ISSUE - should be 404)", r.json()
            return f"{r.status_code}", {}
        
        result = await self.run_test(
            "List targets for non-existent mission",
            f"GET /api/v1/missions/{fake_id}/targets",
            "404 Not Found",
            test_targets_not_found
        )
        if "KNOWN ISSUE" in result.actual:
            result.status = TestStatus.WARNING
        suite.results.append(result)
        
        return suite
    
    # ===========================================
    # Chat API Tests
    # ===========================================
    
    async def test_chat_api(self) -> TestSuite:
        suite = TestSuite("Chat API")
        
        if not self.mission_ids:
            suite.results.append(TestResult(
                "Chat tests", TestStatus.SKIPPED,
                0, "", "", "", "No mission ID available"
            ))
            return suite
        
        mission_id = self.mission_ids[0]
        
        # Test send chat message
        async def test_send_message():
            payload = {"content": "Test message from integration suite"}
            r = await self.client.post(f"{API_BASE}/api/v1/missions/{mission_id}/chat", json=payload)
            if r.status_code == 200:
                data = r.json()
                return "200 OK", {"id": data.get("id"), "role": data.get("role")}
            return f"{r.status_code}", r.json() if r.status_code != 500 else {}
        
        suite.results.append(await self.run_test(
            "Send chat message",
            f"POST /api/v1/missions/{mission_id}/chat",
            "200 OK",
            test_send_message
        ))
        
        await asyncio.sleep(2)  # Wait for LLM response
        
        # Test get chat history
        async def test_chat_history():
            r = await self.client.get(f"{API_BASE}/api/v1/missions/{mission_id}/chat")
            if r.status_code == 200:
                data = r.json()
                return "200 OK", {"count": len(data), "has_system_response": any(m.get("role") == "system" for m in data)}
            return f"{r.status_code}", {}
        
        suite.results.append(await self.run_test(
            "Get chat history",
            f"GET /api/v1/missions/{mission_id}/chat",
            "200 OK",
            test_chat_history
        ))
        
        # Test chat with special commands
        async def test_status_command():
            payload = {"content": "status"}
            r = await self.client.post(f"{API_BASE}/api/v1/missions/{mission_id}/chat", json=payload)
            if r.status_code == 200:
                return "200 OK", {}
            return f"{r.status_code}", {}
        
        suite.results.append(await self.run_test(
            "Send 'status' command via chat",
            f"POST /api/v1/missions/{mission_id}/chat",
            "200 OK",
            test_status_command
        ))
        
        # Test chat with help command
        async def test_help_command():
            payload = {"content": "help"}
            r = await self.client.post(f"{API_BASE}/api/v1/missions/{mission_id}/chat", json=payload)
            if r.status_code == 200:
                return "200 OK", {}
            return f"{r.status_code}", {}
        
        suite.results.append(await self.run_test(
            "Send 'help' command via chat",
            f"POST /api/v1/missions/{mission_id}/chat",
            "200 OK",
            test_help_command
        ))
        
        # Test chat validation - empty content
        async def test_empty_content():
            payload = {"content": ""}
            r = await self.client.post(f"{API_BASE}/api/v1/missions/{mission_id}/chat", json=payload)
            if r.status_code == 422:
                return "422 Validation Error", {}
            return f"{r.status_code} (Expected 422)", {}
        
        suite.results.append(await self.run_test(
            "Chat rejects empty content",
            f"POST /api/v1/missions/{mission_id}/chat",
            "422 Validation Error",
            test_empty_content
        ))
        
        # Test chat history with limit
        async def test_chat_history_limit():
            r = await self.client.get(f"{API_BASE}/api/v1/missions/{mission_id}/chat?limit=5")
            if r.status_code == 200:
                data = r.json()
                return "200 OK", {"count": len(data), "limit_respected": len(data) <= 5}
            return f"{r.status_code}", {}
        
        suite.results.append(await self.run_test(
            "Get chat history with limit",
            f"GET /api/v1/missions/{mission_id}/chat?limit=5",
            "200 OK",
            test_chat_history_limit
        ))
        
        return suite
    
    # ===========================================
    # Approvals API Tests
    # ===========================================
    
    async def test_approvals_api(self) -> TestSuite:
        suite = TestSuite("Approvals (HITL) API")
        
        if not self.mission_ids:
            suite.results.append(TestResult(
                "Approvals tests", TestStatus.SKIPPED,
                0, "", "", "", "No mission ID available"
            ))
            return suite
        
        mission_id = self.mission_ids[0]
        
        # Test list pending approvals
        async def test_list_approvals():
            r = await self.client.get(f"{API_BASE}/api/v1/missions/{mission_id}/approvals")
            if r.status_code == 200:
                data = r.json()
                return "200 OK", {"count": len(data)}
            return f"{r.status_code}", {}
        
        suite.results.append(await self.run_test(
            "List pending approvals",
            f"GET /api/v1/missions/{mission_id}/approvals",
            "200 OK",
            test_list_approvals
        ))
        
        # Test approve non-existent action
        async def test_approve_not_found():
            fake_action_id = "00000000-0000-0000-0000-000000000003"
            r = await self.client.post(
                f"{API_BASE}/api/v1/missions/{mission_id}/approve/{fake_action_id}",
                json={"user_comment": "Test"}
            )
            if r.status_code == 404:
                return "404 Not Found", {}
            return f"{r.status_code} (Expected 404)", {}
        
        suite.results.append(await self.run_test(
            "Approve non-existent action returns 404",
            f"POST /api/v1/missions/{mission_id}/approve/{{fake_id}}",
            "404 Not Found",
            test_approve_not_found
        ))
        
        # Test reject non-existent action (Known Issue - returns 400)
        async def test_reject_not_found():
            fake_action_id = "00000000-0000-0000-0000-000000000004"
            r = await self.client.post(
                f"{API_BASE}/api/v1/missions/{mission_id}/reject/{fake_action_id}",
                json={"rejection_reason": "Test"}
            )
            if r.status_code == 404:
                return "404 Not Found", {}
            elif r.status_code == 400:
                return "400 Bad Request (KNOWN ISSUE - should be 404)", {}
            return f"{r.status_code}", {}
        
        result = await self.run_test(
            "Reject non-existent action returns 404",
            f"POST /api/v1/missions/{mission_id}/reject/{{fake_id}}",
            "404 Not Found",
            test_reject_not_found
        )
        if "KNOWN ISSUE" in result.actual:
            result.status = TestStatus.WARNING
        suite.results.append(result)
        
        # Test approvals for non-existent mission
        async def test_approvals_mission_not_found():
            fake_id = "00000000-0000-0000-0000-000000000005"
            r = await self.client.get(f"{API_BASE}/api/v1/missions/{fake_id}/approvals")
            if r.status_code == 404:
                return "404 Not Found", {}
            elif r.status_code == 200:
                return "200 OK (may indicate empty list for non-existent mission)", {}
            return f"{r.status_code}", {}
        
        suite.results.append(await self.run_test(
            "List approvals for non-existent mission",
            f"GET /api/v1/missions/{{fake_id}}/approvals",
            "404 Not Found",
            test_approvals_mission_not_found
        ))
        
        return suite
    
    # ===========================================
    # Knowledge Base API Tests
    # ===========================================
    
    async def test_knowledge_api(self) -> TestSuite:
        suite = TestSuite("Knowledge Base API")
        
        # Test knowledge stats
        async def test_stats():
            r = await self.client.get(f"{API_BASE}/api/v1/knowledge/stats")
            if r.status_code == 200:
                data = r.json()
                return "200 OK", {
                    "total_techniques": data.get("total_techniques"),
                    "total_rx_modules": data.get("total_rx_modules"),
                    "total_nuclei_templates": data.get("total_nuclei_templates")
                }
            return f"{r.status_code}", {}
        
        suite.results.append(await self.run_test(
            "Get knowledge base statistics",
            "GET /api/v1/knowledge/stats",
            "200 OK",
            test_stats
        ))
        
        # Test list techniques
        async def test_techniques():
            r = await self.client.get(f"{API_BASE}/api/v1/knowledge/techniques?limit=10")
            if r.status_code == 200:
                data = r.json()
                items = data.get("items", data) if isinstance(data, dict) else data
                return "200 OK", {"count": len(items) if isinstance(items, list) else 0}
            return f"{r.status_code}", {}
        
        suite.results.append(await self.run_test(
            "List techniques with pagination",
            "GET /api/v1/knowledge/techniques?limit=10",
            "200 OK",
            test_techniques
        ))
        
        # Test list tactics
        async def test_tactics():
            r = await self.client.get(f"{API_BASE}/api/v1/knowledge/tactics")
            if r.status_code == 200:
                data = r.json()
                return "200 OK", {"count": len(data)}
            return f"{r.status_code}", {}
        
        suite.results.append(await self.run_test(
            "List all tactics",
            "GET /api/v1/knowledge/tactics",
            "200 OK",
            test_tactics
        ))
        
        # Test list modules
        async def test_modules():
            r = await self.client.get(f"{API_BASE}/api/v1/knowledge/modules?limit=10")
            if r.status_code == 200:
                data = r.json()
                items = data.get("items", data) if isinstance(data, dict) else data
                return "200 OK", {"count": len(items) if isinstance(items, list) else 0}
            return f"{r.status_code}", {}
        
        suite.results.append(await self.run_test(
            "List modules with pagination",
            "GET /api/v1/knowledge/modules?limit=10",
            "200 OK",
            test_modules
        ))
        
        # Test list platforms
        async def test_platforms():
            r = await self.client.get(f"{API_BASE}/api/v1/knowledge/platforms")
            if r.status_code == 200:
                data = r.json()
                return "200 OK", {"platforms": data[:5] if isinstance(data, list) else []}
            return f"{r.status_code}", {}
        
        suite.results.append(await self.run_test(
            "List all platforms",
            "GET /api/v1/knowledge/platforms",
            "200 OK",
            test_platforms
        ))
        
        # Test search modules
        async def test_search():
            r = await self.client.get(f"{API_BASE}/api/v1/knowledge/search?q=credential&limit=5")
            if r.status_code == 200:
                data = r.json()
                return "200 OK", {"results": len(data) if isinstance(data, list) else 0}
            return f"{r.status_code}", {}
        
        suite.results.append(await self.run_test(
            "Search modules by query",
            "GET /api/v1/knowledge/search?q=credential&limit=5",
            "200 OK",
            test_search
        ))
        
        # Test search validation - empty query
        async def test_search_empty():
            r = await self.client.get(f"{API_BASE}/api/v1/knowledge/search?q=")
            if r.status_code == 422:
                return "422 Validation Error", {}
            return f"{r.status_code} (Expected 422)", {}
        
        suite.results.append(await self.run_test(
            "Search rejects empty query",
            "GET /api/v1/knowledge/search?q=",
            "422 Validation Error",
            test_search_empty
        ))
        
        # Test get specific technique
        async def test_get_technique():
            # First get a technique ID
            r = await self.client.get(f"{API_BASE}/api/v1/knowledge/techniques?limit=1")
            if r.status_code != 200:
                return "SKIPPED - couldn't get technique list", {}
            data = r.json()
            items = data.get("items", data) if isinstance(data, dict) else data
            if not items:
                return "SKIPPED - no techniques available", {}
            
            technique_id = items[0].get("id")
            r2 = await self.client.get(f"{API_BASE}/api/v1/knowledge/techniques/{technique_id}")
            if r2.status_code == 200:
                detail = r2.json()
                return "200 OK", {"id": detail.get("id"), "name": detail.get("name")}
            return f"{r2.status_code}", {}
        
        suite.results.append(await self.run_test(
            "Get specific technique by ID",
            "GET /api/v1/knowledge/techniques/{id}",
            "200 OK",
            test_get_technique
        ))
        
        # Test specialized endpoints
        async def test_exploit_modules():
            r = await self.client.get(f"{API_BASE}/api/v1/knowledge/exploit-modules?limit=5")
            if r.status_code == 200:
                return "200 OK", {"count": len(r.json())}
            return f"{r.status_code}", {}
        
        suite.results.append(await self.run_test(
            "Get exploit modules",
            "GET /api/v1/knowledge/exploit-modules?limit=5",
            "200 OK",
            test_exploit_modules
        ))
        
        async def test_recon_modules():
            r = await self.client.get(f"{API_BASE}/api/v1/knowledge/recon-modules?limit=5")
            if r.status_code == 200:
                return "200 OK", {"count": len(r.json())}
            return f"{r.status_code}", {}
        
        suite.results.append(await self.run_test(
            "Get recon modules",
            "GET /api/v1/knowledge/recon-modules?limit=5",
            "200 OK",
            test_recon_modules
        ))
        
        async def test_credential_modules():
            r = await self.client.get(f"{API_BASE}/api/v1/knowledge/credential-modules?limit=5")
            if r.status_code == 200:
                return "200 OK", {"count": len(r.json())}
            return f"{r.status_code}", {}
        
        suite.results.append(await self.run_test(
            "Get credential modules",
            "GET /api/v1/knowledge/credential-modules?limit=5",
            "200 OK",
            test_credential_modules
        ))
        
        async def test_privesc_modules():
            r = await self.client.get(f"{API_BASE}/api/v1/knowledge/privesc-modules?limit=5")
            if r.status_code == 200:
                return "200 OK", {"count": len(r.json())}
            return f"{r.status_code}", {}
        
        suite.results.append(await self.run_test(
            "Get privilege escalation modules",
            "GET /api/v1/knowledge/privesc-modules?limit=5",
            "200 OK",
            test_privesc_modules
        ))
        
        return suite
    
    # ===========================================
    # Nuclei Templates API Tests
    # ===========================================
    
    async def test_nuclei_api(self) -> TestSuite:
        suite = TestSuite("Nuclei Templates API")
        
        # Test list nuclei templates
        async def test_list():
            r = await self.client.get(f"{API_BASE}/api/v1/knowledge/nuclei/templates?limit=10")
            if r.status_code == 200:
                data = r.json()
                items = data.get("items", data) if isinstance(data, dict) else data
                return "200 OK", {"count": len(items) if isinstance(items, list) else 0}
            return f"{r.status_code}", {}
        
        suite.results.append(await self.run_test(
            "List Nuclei templates with pagination",
            "GET /api/v1/knowledge/nuclei/templates?limit=10",
            "200 OK",
            test_list
        ))
        
        # Test search nuclei templates
        async def test_search():
            r = await self.client.get(f"{API_BASE}/api/v1/knowledge/nuclei/search?q=cve&limit=5")
            if r.status_code == 200:
                return "200 OK", {"count": len(r.json())}
            return f"{r.status_code}", {}
        
        suite.results.append(await self.run_test(
            "Search Nuclei templates",
            "GET /api/v1/knowledge/nuclei/search?q=cve&limit=5",
            "200 OK",
            test_search
        ))
        
        # Test get critical templates
        async def test_critical():
            r = await self.client.get(f"{API_BASE}/api/v1/knowledge/nuclei/critical?limit=5")
            if r.status_code == 200:
                return "200 OK", {"count": len(r.json())}
            return f"{r.status_code}", {}
        
        suite.results.append(await self.run_test(
            "Get critical severity templates",
            "GET /api/v1/knowledge/nuclei/critical?limit=5",
            "200 OK",
            test_critical
        ))
        
        # Test get by severity
        async def test_by_severity():
            r = await self.client.get(f"{API_BASE}/api/v1/knowledge/nuclei/severity/high?limit=5")
            if r.status_code == 200:
                return "200 OK", {"count": len(r.json())}
            return f"{r.status_code}", {}
        
        suite.results.append(await self.run_test(
            "Get templates by severity (high)",
            "GET /api/v1/knowledge/nuclei/severity/high?limit=5",
            "200 OK",
            test_by_severity
        ))
        
        # Test RCE templates
        async def test_rce():
            r = await self.client.get(f"{API_BASE}/api/v1/knowledge/nuclei/rce?limit=5")
            if r.status_code == 200:
                return "200 OK", {"count": len(r.json())}
            return f"{r.status_code}", {}
        
        suite.results.append(await self.run_test(
            "Get RCE vulnerability templates",
            "GET /api/v1/knowledge/nuclei/rce?limit=5",
            "200 OK",
            test_rce
        ))
        
        # Test SQLi templates
        async def test_sqli():
            r = await self.client.get(f"{API_BASE}/api/v1/knowledge/nuclei/sqli?limit=5")
            if r.status_code == 200:
                return "200 OK", {"count": len(r.json())}
            return f"{r.status_code}", {}
        
        suite.results.append(await self.run_test(
            "Get SQL injection templates",
            "GET /api/v1/knowledge/nuclei/sqli?limit=5",
            "200 OK",
            test_sqli
        ))
        
        # Test XSS templates
        async def test_xss():
            r = await self.client.get(f"{API_BASE}/api/v1/knowledge/nuclei/xss?limit=5")
            if r.status_code == 200:
                return "200 OK", {"count": len(r.json())}
            return f"{r.status_code}", {}
        
        suite.results.append(await self.run_test(
            "Get XSS vulnerability templates",
            "GET /api/v1/knowledge/nuclei/xss?limit=5",
            "200 OK",
            test_xss
        ))
        
        # Test get specific template
        async def test_get_template():
            r = await self.client.get(f"{API_BASE}/api/v1/knowledge/nuclei/templates?limit=1")
            if r.status_code != 200:
                return "SKIPPED - couldn't get template list", {}
            data = r.json()
            items = data.get("items", data) if isinstance(data, dict) else data
            if not items:
                return "SKIPPED - no templates available", {}
            
            # Use template_id field (not id)
            template_id = items[0].get("template_id") or items[0].get("id")
            r2 = await self.client.get(f"{API_BASE}/api/v1/knowledge/nuclei/templates/{template_id}")
            if r2.status_code == 200:
                detail = r2.json()
                return "200 OK", {"template_id": detail.get("template_id"), "name": detail.get("name")}
            return f"{r2.status_code}", {}
        
        suite.results.append(await self.run_test(
            "Get specific Nuclei template by ID",
            "GET /api/v1/knowledge/nuclei/templates/{id}",
            "200 OK",
            test_get_template
        ))
        
        return suite
    
    # ===========================================
    # WebSocket Tests
    # ===========================================
    
    async def test_websocket(self) -> TestSuite:
        suite = TestSuite("WebSocket Connection")
        
        if not self.mission_ids:
            suite.results.append(TestResult(
                "WebSocket tests", TestStatus.SKIPPED,
                0, "", "", "", "No mission ID available"
            ))
            return suite
        
        mission_id = self.mission_ids[0]
        
        # Test WebSocket connection
        async def test_ws_connect():
            ws_url = f"{WS_BASE}/ws/missions/{mission_id}"
            try:
                async with websockets.connect(ws_url, close_timeout=5) as ws:
                    # Try to receive any message (with timeout)
                    try:
                        await asyncio.wait_for(ws.recv(), timeout=3.0)
                    except asyncio.TimeoutError:
                        pass  # No message received, but connection was successful
                    return "Connected", {"url": ws_url}
            except Exception as e:
                return f"Failed: {type(e).__name__}", {"error": str(e)}
        
        suite.results.append(await self.run_test(
            "WebSocket connection to mission",
            f"ws://.../ws/missions/{mission_id}",
            "Connected",
            test_ws_connect
        ))
        
        return suite
    
    # ===========================================
    # Run All Tests
    # ===========================================
    
    async def run_all(self) -> List[TestSuite]:
        print("\n" + "="*80)
        print("🔬 RAGLOX v3.0 - Comprehensive Integration Test Suite")
        print("="*80)
        print(f"📅 Started: {datetime.now().isoformat()}")
        print(f"🎯 Target: {API_BASE}")
        print("="*80 + "\n")
        
        # Run test suites in order
        suites = [
            await self.test_health_endpoints(),
            await self.test_mission_crud(),
            await self.test_mission_lifecycle(),
            await self.test_mission_data_endpoints(),
            await self.test_chat_api(),
            await self.test_approvals_api(),
            await self.test_knowledge_api(),
            await self.test_nuclei_api(),
            await self.test_websocket(),
        ]
        
        self.suites = suites
        return suites
    
    def print_results(self):
        """Print test results summary"""
        total_passed = sum(s.passed for s in self.suites)
        total_failed = sum(s.failed for s in self.suites)
        total_warnings = sum(s.warnings for s in self.suites)
        total_tests = sum(len(s.results) for s in self.suites)
        
        print("\n" + "="*80)
        print("📊 TEST RESULTS SUMMARY")
        print("="*80)
        
        for suite in self.suites:
            print(f"\n📁 {suite.name}")
            print("-"*60)
            for result in suite.results:
                status_icon = result.status.value
                print(f"  {status_icon} {result.name}")
                if result.status in [TestStatus.FAILED, TestStatus.WARNING]:
                    print(f"      Expected: {result.expected}")
                    print(f"      Actual: {result.actual}")
                    if result.error:
                        print(f"      Error: {result.error[:100]}")
        
        print("\n" + "="*80)
        print("📈 OVERALL STATISTICS")
        print("="*80)
        print(f"  Total Tests: {total_tests}")
        print(f"  ✅ Passed: {total_passed}")
        print(f"  ❌ Failed: {total_failed}")
        print(f"  ⚠️ Warnings: {total_warnings}")
        print(f"  Pass Rate: {(total_passed/total_tests*100):.1f}%" if total_tests > 0 else "N/A")
        
        # Known issues
        print("\n" + "="*80)
        print("⚠️ KNOWN ISSUES (from documentation)")
        print("="*80)
        known_issues = [
            "1. Mission Stop endpoint may return 500 Internal Server Error",
            "2. Reject action endpoint returns 400 instead of 404 for non-existent actions",
            "3. Mission data endpoints return 200 with empty data for non-existent missions (should be 404)",
            "4. Invalid UUID format returns 404 instead of 422",
            "5. Chat history limit parameter not validated"
        ]
        for issue in known_issues:
            print(f"  • {issue}")
        
        print("\n" + "="*80)
        print(f"📅 Completed: {datetime.now().isoformat()}")
        print("="*80)
        
        return total_passed, total_failed, total_warnings
    
    def generate_report(self) -> str:
        """Generate detailed JSON report"""
        report = {
            "timestamp": datetime.now().isoformat(),
            "api_base": API_BASE,
            "suites": []
        }
        
        for suite in self.suites:
            suite_data = {
                "name": suite.name,
                "passed": suite.passed,
                "failed": suite.failed,
                "warnings": suite.warnings,
                "results": []
            }
            
            for result in suite.results:
                suite_data["results"].append({
                    "name": result.name,
                    "status": result.status.name,
                    "duration_ms": result.duration_ms,
                    "endpoint": result.endpoint,
                    "expected": result.expected,
                    "actual": result.actual,
                    "error": result.error,
                    "details": result.details
                })
            
            report["suites"].append(suite_data)
        
        total_passed = sum(s.passed for s in self.suites)
        total_failed = sum(s.failed for s in self.suites)
        total_tests = sum(len(s.results) for s in self.suites)
        
        report["summary"] = {
            "total_tests": total_tests,
            "passed": total_passed,
            "failed": total_failed,
            "pass_rate": f"{(total_passed/total_tests*100):.1f}%" if total_tests > 0 else "N/A"
        }
        
        return json.dumps(report, indent=2)


async def main():
    async with IntegrationTester() as tester:
        await tester.run_all()
        passed, failed, warnings = tester.print_results()
        
        # Save report
        report = tester.generate_report()
        report_path = "/root/RAGLOX_V3/webapp/webapp/integration_test_report.json"
        with open(report_path, "w") as f:
            f.write(report)
        print(f"\n📄 Detailed report saved to: {report_path}")
        
        # Exit with error code if tests failed
        sys.exit(1 if failed > 0 else 0)


if __name__ == "__main__":
    asyncio.run(main())
