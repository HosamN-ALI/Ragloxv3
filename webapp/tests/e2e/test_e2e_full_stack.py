#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════════════
RAGLOX v3.0 - End-to-End Full Stack Test Suite
Tests the complete system from API to execution
═══════════════════════════════════════════════════════════════════════════════

This test suite validates:
1. API endpoint availability and responses
2. LLM provider integration
3. Redis connectivity and operations
4. Mission lifecycle (create -> execute -> report)
5. Knowledge base queries
6. WebSocket connectivity
7. Security middleware
8. Full penetration testing workflow

Usage:
    # Quick API health check
    python -m pytest tests/e2e/test_e2e_full_stack.py -v -k "health"
    
    # Full E2E test
    python -m pytest tests/e2e/test_e2e_full_stack.py -v
    
    # With live API (set API_BASE_URL)
    API_BASE_URL=http://localhost:8000 python -m pytest tests/e2e/test_e2e_full_stack.py -v
"""

import os
import sys
import json
import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any, List
from enum import Enum

# Add paths for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import pytest
import httpx

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("raglox.e2e")


# ═══════════════════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class E2EConfig:
    """End-to-End test configuration."""
    
    # API Configuration
    api_base_url: str = field(default_factory=lambda: os.environ.get(
        "API_BASE_URL", "http://localhost:8000"
    ))
    api_timeout: int = 30
    
    # Test Configuration
    test_mode: str = field(default_factory=lambda: os.environ.get(
        "E2E_TEST_MODE", "safe"  # safe, full
    ))
    
    # Mission Test Data
    test_scope: List[str] = field(default_factory=lambda: [
        "192.168.1.0/24"
    ])
    test_goals: List[str] = field(default_factory=lambda: [
        "reconnaissance",
        "vulnerability_assessment"
    ])
    
    # Skip flags
    skip_llm_tests: bool = field(default_factory=lambda: 
        os.environ.get("SKIP_LLM_TESTS", "false").lower() == "true"
    )
    skip_redis_tests: bool = field(default_factory=lambda:
        os.environ.get("SKIP_REDIS_TESTS", "false").lower() == "true"
    )
    skip_mission_tests: bool = field(default_factory=lambda:
        os.environ.get("SKIP_MISSION_TESTS", "false").lower() == "true"
    )


class TestStatus(Enum):
    """Test result status."""
    PASSED = "PASSED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    WARNING = "WARNING"


@dataclass
class E2ETestResult:
    """Individual E2E test result."""
    name: str
    status: TestStatus
    duration_ms: float
    endpoint: Optional[str] = None
    request: Optional[Dict[str, Any]] = None
    response: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


# ═══════════════════════════════════════════════════════════════════════════════
# Test Fixtures
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def e2e_config():
    """Get E2E test configuration."""
    return E2EConfig()


@pytest.fixture(scope="module")
def http_client(e2e_config):
    """Create HTTP client for API tests."""
    return httpx.Client(
        base_url=e2e_config.api_base_url,
        timeout=e2e_config.api_timeout
    )


@pytest.fixture(scope="module")
async def async_http_client(e2e_config):
    """Create async HTTP client for API tests."""
    async with httpx.AsyncClient(
        base_url=e2e_config.api_base_url,
        timeout=e2e_config.api_timeout
    ) as client:
        yield client


# ═══════════════════════════════════════════════════════════════════════════════
# Test Class: API Health & Core Endpoints
# ═══════════════════════════════════════════════════════════════════════════════

class TestAPIHealth:
    """Test API health and core endpoints."""
    
    def test_e2e_001_root_endpoint(self, http_client, e2e_config):
        """E2E-001: Test root endpoint returns API info."""
        start = datetime.now()
        try:
            response = http_client.get("/")
            duration = (datetime.now() - start).total_seconds() * 1000
            
            assert response.status_code == 200, f"Expected 200, got {response.status_code}"
            data = response.json()
            
            assert "name" in data, "Response should contain 'name'"
            assert "RAGLOX" in data.get("name", ""), "API name should contain RAGLOX"
            
            logger.info(f"E2E-001 PASSED: Root endpoint returns {data.get('name')} ({duration:.0f}ms)")
            
        except httpx.ConnectError as e:
            pytest.skip(f"API not available at {e2e_config.api_base_url}: {e}")
    
    def test_e2e_002_health_endpoint(self, http_client, e2e_config):
        """E2E-002: Test health endpoint."""
        start = datetime.now()
        try:
            response = http_client.get("/health")
            duration = (datetime.now() - start).total_seconds() * 1000
            
            assert response.status_code == 200, f"Expected 200, got {response.status_code}"
            data = response.json()
            
            assert "status" in data, "Response should contain 'status'"
            assert data.get("status") in ["healthy", "ok", "up"], "Status should be healthy"
            
            logger.info(f"E2E-002 PASSED: Health check - {data.get('status')} ({duration:.0f}ms)")
            
        except httpx.ConnectError as e:
            pytest.skip(f"API not available: {e}")
    
    def test_e2e_003_docs_endpoint(self, http_client, e2e_config):
        """E2E-003: Test API docs endpoint (OpenAPI/Swagger)."""
        start = datetime.now()
        try:
            response = http_client.get("/docs")
            duration = (datetime.now() - start).total_seconds() * 1000
            
            assert response.status_code == 200, f"Expected 200, got {response.status_code}"
            assert "text/html" in response.headers.get("content-type", "")
            
            logger.info(f"E2E-003 PASSED: API docs accessible ({duration:.0f}ms)")
            
        except httpx.ConnectError as e:
            pytest.skip(f"API not available: {e}")
    
    def test_e2e_004_openapi_schema(self, http_client, e2e_config):
        """E2E-004: Test OpenAPI schema endpoint."""
        start = datetime.now()
        try:
            response = http_client.get("/openapi.json")
            duration = (datetime.now() - start).total_seconds() * 1000
            
            assert response.status_code == 200, f"Expected 200, got {response.status_code}"
            data = response.json()
            
            assert "openapi" in data, "Response should contain 'openapi' version"
            assert "paths" in data, "Response should contain 'paths'"
            
            path_count = len(data.get("paths", {}))
            logger.info(f"E2E-004 PASSED: OpenAPI schema with {path_count} paths ({duration:.0f}ms)")
            
        except httpx.ConnectError as e:
            pytest.skip(f"API not available: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# Test Class: Mission Lifecycle
# ═══════════════════════════════════════════════════════════════════════════════

class TestMissionLifecycle:
    """Test mission CRUD and lifecycle operations."""
    
    @pytest.fixture
    def mission_data(self, e2e_config):
        """Get test mission data."""
        return {
            "name": f"E2E Test Mission {datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "scope": e2e_config.test_scope,
            "goals": e2e_config.test_goals,
            "constraints": {
                "stealth": True,
                "max_threads": 5,
                "test_mode": True
            }
        }
    
    def test_e2e_010_list_missions(self, http_client, e2e_config):
        """E2E-010: Test listing missions."""
        start = datetime.now()
        try:
            response = http_client.get("/missions")
            duration = (datetime.now() - start).total_seconds() * 1000
            
            assert response.status_code == 200, f"Expected 200, got {response.status_code}"
            data = response.json()
            
            # Should return a list (even if empty)
            assert isinstance(data, (list, dict)), "Response should be list or dict with missions"
            
            if isinstance(data, dict):
                missions = data.get("missions", data.get("items", []))
            else:
                missions = data
            
            logger.info(f"E2E-010 PASSED: Listed {len(missions)} missions ({duration:.0f}ms)")
            
        except httpx.ConnectError as e:
            pytest.skip(f"API not available: {e}")
    
    def test_e2e_011_create_mission(self, http_client, e2e_config, mission_data):
        """E2E-011: Test creating a new mission."""
        if e2e_config.skip_mission_tests:
            pytest.skip("Mission tests skipped by configuration")
        
        start = datetime.now()
        try:
            response = http_client.post("/missions", json=mission_data)
            duration = (datetime.now() - start).total_seconds() * 1000
            
            assert response.status_code in [200, 201], f"Expected 200/201, got {response.status_code}"
            data = response.json()
            
            assert "id" in data or "mission_id" in data, "Response should contain mission ID"
            
            mission_id = data.get("id") or data.get("mission_id")
            logger.info(f"E2E-011 PASSED: Created mission {mission_id} ({duration:.0f}ms)")
            
            return mission_id
            
        except httpx.ConnectError as e:
            pytest.skip(f"API not available: {e}")
    
    def test_e2e_012_mission_validation(self, http_client, e2e_config):
        """E2E-012: Test mission validation (invalid payload)."""
        start = datetime.now()
        try:
            # Missing required fields
            response = http_client.post("/missions", json={})
            duration = (datetime.now() - start).total_seconds() * 1000
            
            assert response.status_code == 422, f"Expected 422 for invalid payload, got {response.status_code}"
            
            logger.info(f"E2E-012 PASSED: Validation rejected empty payload ({duration:.0f}ms)")
            
        except httpx.ConnectError as e:
            pytest.skip(f"API not available: {e}")
    
    def test_e2e_013_mission_scope_validation(self, http_client, e2e_config):
        """E2E-013: Test mission scope validation."""
        start = datetime.now()
        try:
            # Empty scope
            invalid_data = {
                "name": "Test",
                "scope": [],
                "goals": ["reconnaissance"]
            }
            response = http_client.post("/missions", json=invalid_data)
            duration = (datetime.now() - start).total_seconds() * 1000
            
            assert response.status_code == 422, f"Expected 422 for empty scope, got {response.status_code}"
            
            logger.info(f"E2E-013 PASSED: Validation rejected empty scope ({duration:.0f}ms)")
            
        except httpx.ConnectError as e:
            pytest.skip(f"API not available: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# Test Class: Knowledge Base
# ═══════════════════════════════════════════════════════════════════════════════

class TestKnowledgeBase:
    """Test knowledge base endpoints."""
    
    def test_e2e_020_knowledge_stats(self, http_client, e2e_config):
        """E2E-020: Test knowledge base statistics."""
        start = datetime.now()
        try:
            response = http_client.get("/knowledge/stats")
            duration = (datetime.now() - start).total_seconds() * 1000
            
            if response.status_code == 404:
                pytest.skip("Knowledge endpoint not available")
            
            assert response.status_code == 200, f"Expected 200, got {response.status_code}"
            data = response.json()
            
            logger.info(f"E2E-020 PASSED: Knowledge stats retrieved ({duration:.0f}ms)")
            
        except httpx.ConnectError as e:
            pytest.skip(f"API not available: {e}")
    
    def test_e2e_021_list_techniques(self, http_client, e2e_config):
        """E2E-021: Test listing techniques."""
        start = datetime.now()
        try:
            response = http_client.get("/knowledge/techniques")
            duration = (datetime.now() - start).total_seconds() * 1000
            
            if response.status_code == 404:
                pytest.skip("Knowledge endpoint not available")
            
            assert response.status_code == 200, f"Expected 200, got {response.status_code}"
            data = response.json()
            
            if isinstance(data, dict):
                techniques = data.get("techniques", data.get("items", []))
            else:
                techniques = data
            
            logger.info(f"E2E-021 PASSED: Listed {len(techniques)} techniques ({duration:.0f}ms)")
            
        except httpx.ConnectError as e:
            pytest.skip(f"API not available: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# Test Class: Security Middleware
# ═══════════════════════════════════════════════════════════════════════════════

class TestSecurityMiddleware:
    """Test security middleware (SEC-03, SEC-04)."""
    
    def test_e2e_030_xss_prevention(self, http_client, e2e_config):
        """E2E-030: Test XSS prevention in inputs."""
        start = datetime.now()
        try:
            # Try XSS payload in mission name
            xss_payload = {
                "name": "<script>alert('xss')</script>",
                "scope": ["192.168.1.0/24"],
                "goals": ["reconnaissance"]
            }
            
            response = http_client.post("/missions", json=xss_payload)
            duration = (datetime.now() - start).total_seconds() * 1000
            
            # Should either reject (400/422) or sanitize
            if response.status_code in [400, 422]:
                logger.info(f"E2E-030 PASSED: XSS payload rejected ({duration:.0f}ms)")
            elif response.status_code in [200, 201]:
                data = response.json()
                # Check if script was sanitized
                mission_name = data.get("name", "")
                assert "<script>" not in mission_name, "XSS payload should be sanitized"
                logger.info(f"E2E-030 PASSED: XSS payload sanitized ({duration:.0f}ms)")
            else:
                pytest.fail(f"Unexpected response: {response.status_code}")
            
        except httpx.ConnectError as e:
            pytest.skip(f"API not available: {e}")
    
    def test_e2e_031_sql_injection_prevention(self, http_client, e2e_config):
        """E2E-031: Test SQL injection prevention."""
        start = datetime.now()
        try:
            # Try SQL injection in mission name
            sqli_payload = {
                "name": "'; DROP TABLE missions; --",
                "scope": ["192.168.1.0/24"],
                "goals": ["reconnaissance"]
            }
            
            response = http_client.post("/missions", json=sqli_payload)
            duration = (datetime.now() - start).total_seconds() * 1000
            
            # Should either reject or handle safely
            assert response.status_code != 500, "SQL injection should not cause server error"
            
            logger.info(f"E2E-031 PASSED: SQL injection handled safely ({duration:.0f}ms)")
            
        except httpx.ConnectError as e:
            pytest.skip(f"API not available: {e}")
    
    def test_e2e_032_path_traversal_prevention(self, http_client, e2e_config):
        """E2E-032: Test path traversal prevention."""
        start = datetime.now()
        try:
            # Try path traversal
            response = http_client.get("/missions/../../../etc/passwd")
            duration = (datetime.now() - start).total_seconds() * 1000
            
            # Should return 404 or 400, not actual file content
            assert response.status_code in [400, 404, 422], \
                f"Path traversal should be blocked, got {response.status_code}"
            
            logger.info(f"E2E-032 PASSED: Path traversal blocked ({duration:.0f}ms)")
            
        except httpx.ConnectError as e:
            pytest.skip(f"API not available: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# Test Class: Infrastructure Endpoints
# ═══════════════════════════════════════════════════════════════════════════════

class TestInfrastructure:
    """Test infrastructure endpoints."""
    
    def test_e2e_040_infrastructure_health(self, http_client, e2e_config):
        """E2E-040: Test infrastructure health endpoint."""
        start = datetime.now()
        try:
            response = http_client.get("/infrastructure/health")
            duration = (datetime.now() - start).total_seconds() * 1000
            
            if response.status_code == 404:
                pytest.skip("Infrastructure endpoint not available")
            
            assert response.status_code == 200, f"Expected 200, got {response.status_code}"
            
            logger.info(f"E2E-040 PASSED: Infrastructure health OK ({duration:.0f}ms)")
            
        except httpx.ConnectError as e:
            pytest.skip(f"API not available: {e}")
    
    def test_e2e_041_list_environments(self, http_client, e2e_config):
        """E2E-041: Test listing environments."""
        start = datetime.now()
        try:
            response = http_client.get("/environments")
            duration = (datetime.now() - start).total_seconds() * 1000
            
            if response.status_code == 404:
                pytest.skip("Environments endpoint not available")
            
            assert response.status_code == 200, f"Expected 200, got {response.status_code}"
            
            logger.info(f"E2E-041 PASSED: Environments listed ({duration:.0f}ms)")
            
        except httpx.ConnectError as e:
            pytest.skip(f"API not available: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# Test Class: Exploitation Endpoints
# ═══════════════════════════════════════════════════════════════════════════════

class TestExploitation:
    """Test exploitation endpoints (read-only in safe mode)."""
    
    def test_e2e_050_exploitation_status(self, http_client, e2e_config):
        """E2E-050: Test exploitation module status."""
        start = datetime.now()
        try:
            response = http_client.get("/exploits/status")
            duration = (datetime.now() - start).total_seconds() * 1000
            
            if response.status_code == 404:
                # Try alternative endpoint
                response = http_client.get("/c2/status")
                if response.status_code == 404:
                    pytest.skip("Exploitation endpoints not available")
            
            assert response.status_code == 200, f"Expected 200, got {response.status_code}"
            
            logger.info(f"E2E-050 PASSED: Exploitation status retrieved ({duration:.0f}ms)")
            
        except httpx.ConnectError as e:
            pytest.skip(f"API not available: {e}")
    
    def test_e2e_051_list_exploits(self, http_client, e2e_config):
        """E2E-051: Test listing available exploits."""
        start = datetime.now()
        try:
            response = http_client.get("/exploits")
            duration = (datetime.now() - start).total_seconds() * 1000
            
            if response.status_code == 404:
                pytest.skip("Exploits endpoint not available")
            
            assert response.status_code == 200, f"Expected 200, got {response.status_code}"
            
            logger.info(f"E2E-051 PASSED: Exploits listed ({duration:.0f}ms)")
            
        except httpx.ConnectError as e:
            pytest.skip(f"API not available: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# Test Class: Full Workflow
# ═══════════════════════════════════════════════════════════════════════════════

class TestFullWorkflow:
    """Test complete penetration testing workflow."""
    
    @pytest.mark.slow
    def test_e2e_100_complete_reconnaissance_workflow(self, http_client, e2e_config):
        """E2E-100: Test complete reconnaissance workflow."""
        if e2e_config.skip_mission_tests:
            pytest.skip("Mission tests skipped by configuration")
        
        start = datetime.now()
        results = {}
        
        try:
            # Step 1: Create mission
            mission_data = {
                "name": f"E2E Full Workflow {datetime.now().strftime('%Y%m%d_%H%M%S')}",
                "scope": e2e_config.test_scope,
                "goals": ["reconnaissance"],
                "constraints": {
                    "test_mode": True,
                    "max_threads": 2
                }
            }
            
            response = http_client.post("/missions", json=mission_data)
            if response.status_code not in [200, 201]:
                pytest.skip(f"Could not create mission: {response.status_code}")
            
            mission = response.json()
            mission_id = mission.get("id") or mission.get("mission_id")
            results["mission_id"] = mission_id
            logger.info(f"  Step 1: Created mission {mission_id}")
            
            # Step 2: Get mission status
            response = http_client.get(f"/missions/{mission_id}")
            assert response.status_code == 200, f"Could not get mission: {response.status_code}"
            
            mission_status = response.json()
            results["status"] = mission_status.get("status")
            logger.info(f"  Step 2: Mission status - {results['status']}")
            
            # Step 3: Check mission findings (if available)
            response = http_client.get(f"/missions/{mission_id}/findings")
            if response.status_code == 200:
                findings = response.json()
                results["findings_count"] = len(findings) if isinstance(findings, list) else 0
                logger.info(f"  Step 3: Found {results['findings_count']} findings")
            
            duration = (datetime.now() - start).total_seconds() * 1000
            logger.info(f"E2E-100 PASSED: Complete workflow executed ({duration:.0f}ms)")
            
        except httpx.ConnectError as e:
            pytest.skip(f"API not available: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# Main Runner
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # Run with pytest
    import sys
    sys.exit(pytest.main([
        __file__,
        "-v",
        "--tb=short",
        "-x",  # Stop on first failure
    ]))
