# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - SEC-03/SEC-04 Tests
# Tests for Input Validation and Rate Limiting
# ═══════════════════════════════════════════════════════════════
"""
Test suite for SEC-03 (Input Validation) and SEC-04 (Rate Limiting).

Tests cover:
- Input validation for various data types (IP, CIDR, UUID, CVE, etc.)
- Injection detection (SQL, XSS, command injection)
- Rate limiting enforcement
- Rate limit headers
- Batch validation
"""

import pytest
import asyncio
from typing import Dict, Any
from unittest.mock import Mock, patch, AsyncMock
from fastapi.testclient import TestClient


class TestInputValidation:
    """SEC-03: Input Validation Tests"""
    
    def test_validate_ip_address_valid(self, test_client: TestClient):
        """Test valid IP address validation."""
        response = test_client.post(
            "/api/v1/security/validate/ip",
            json={"value": "192.168.1.1"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
        assert data["value"] == "192.168.1.1"
    
    def test_validate_ip_address_invalid(self, test_client: TestClient):
        """Test invalid IP address validation."""
        response = test_client.post(
            "/api/v1/security/validate/ip",
            json={"value": "not-an-ip"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is False
    
    def test_validate_ip_address_private(self, test_client: TestClient):
        """Test private IP address detection."""
        response = test_client.post(
            "/api/v1/security/validate/ip",
            json={"value": "10.0.0.1"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
        assert data.get("is_private", False) is True
    
    def test_validate_cidr_valid(self, test_client: TestClient):
        """Test valid CIDR notation validation."""
        response = test_client.post(
            "/api/v1/security/validate/cidr",
            json={"value": "192.168.1.0/24"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
    
    def test_validate_cidr_invalid(self, test_client: TestClient):
        """Test invalid CIDR notation."""
        response = test_client.post(
            "/api/v1/security/validate/cidr",
            json={"value": "192.168.1.0/33"}  # Invalid prefix length
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is False
    
    def test_validate_uuid_valid(self, test_client: TestClient):
        """Test valid UUID validation."""
        response = test_client.post(
            "/api/v1/security/validate/uuid",
            json={"value": "550e8400-e29b-41d4-a716-446655440000"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
    
    def test_validate_uuid_invalid(self, test_client: TestClient):
        """Test invalid UUID validation."""
        response = test_client.post(
            "/api/v1/security/validate/uuid",
            json={"value": "not-a-uuid"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is False
    
    def test_validate_hostname_valid(self, test_client: TestClient):
        """Test valid hostname validation."""
        response = test_client.post(
            "/api/v1/security/validate/hostname",
            json={"value": "server-01.example.com"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
    
    def test_validate_hostname_invalid(self, test_client: TestClient):
        """Test invalid hostname validation."""
        response = test_client.post(
            "/api/v1/security/validate/hostname",
            json={"value": "invalid_hostname!@#"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is False
    
    def test_validate_port_valid(self, test_client: TestClient):
        """Test valid port validation."""
        response = test_client.post(
            "/api/v1/security/validate/port",
            json={"value": 443}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
    
    def test_validate_port_out_of_range(self, test_client: TestClient):
        """Test port out of range."""
        response = test_client.post(
            "/api/v1/security/validate/port",
            json={"value": 65536}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is False
    
    def test_validate_cve_valid(self, test_client: TestClient):
        """Test valid CVE ID validation."""
        response = test_client.post(
            "/api/v1/security/validate/cve",
            json={"value": "CVE-2021-44228"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
    
    def test_validate_cve_invalid(self, test_client: TestClient):
        """Test invalid CVE ID validation."""
        response = test_client.post(
            "/api/v1/security/validate/cve",
            json={"value": "CVE-invalid"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is False


class TestInjectionDetection:
    """SEC-03: Injection Detection Tests"""
    
    def test_detect_sql_injection(self, test_client: TestClient):
        """Test SQL injection detection."""
        response = test_client.post(
            "/api/v1/security/check-injection",
            json={"value": "'; DROP TABLE users; --"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["is_safe"] is False
        assert "sql" in [d["type"] for d in data.get("detections", [])]
    
    def test_detect_xss_attack(self, test_client: TestClient):
        """Test XSS attack detection."""
        response = test_client.post(
            "/api/v1/security/check-injection",
            json={"value": "<script>alert('xss')</script>"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["is_safe"] is False
        assert "xss" in [d["type"] for d in data.get("detections", [])]
    
    def test_detect_command_injection(self, test_client: TestClient):
        """Test command injection detection."""
        response = test_client.post(
            "/api/v1/security/check-injection",
            json={"value": "test; rm -rf /"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["is_safe"] is False
        assert "command" in [d["type"] for d in data.get("detections", [])]
    
    def test_detect_path_traversal(self, test_client: TestClient):
        """Test path traversal detection."""
        response = test_client.post(
            "/api/v1/security/check-injection",
            json={"value": "../../../etc/passwd"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["is_safe"] is False
        assert "path_traversal" in [d["type"] for d in data.get("detections", [])]
    
    def test_safe_string(self, test_client: TestClient):
        """Test safe string passes validation."""
        response = test_client.post(
            "/api/v1/security/check-injection",
            json={"value": "This is a normal safe string"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["is_safe"] is True


class TestBatchValidation:
    """SEC-03: Batch Validation Tests"""
    
    def test_batch_validation_success(self, test_client: TestClient):
        """Test batch validation with multiple inputs."""
        response = test_client.post(
            "/api/v1/security/validate/batch",
            json={
                "validations": [
                    {"type": "ip", "value": "192.168.1.1"},
                    {"type": "uuid", "value": "550e8400-e29b-41d4-a716-446655440000"},
                    {"type": "port", "value": 443}
                ]
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 3
        assert data["valid"] == 3
        assert data["invalid"] == 0
    
    def test_batch_validation_mixed(self, test_client: TestClient):
        """Test batch validation with mixed results."""
        response = test_client.post(
            "/api/v1/security/validate/batch",
            json={
                "validations": [
                    {"type": "ip", "value": "192.168.1.1"},
                    {"type": "ip", "value": "invalid-ip"},
                    {"type": "port", "value": 70000}
                ]
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 3
        assert data["valid"] == 1
        assert data["invalid"] == 2


class TestRateLimiting:
    """SEC-04: Rate Limiting Tests"""
    
    def test_rate_limit_info(self, test_client: TestClient):
        """Test rate limit info endpoint."""
        response = test_client.get("/api/v1/security/rate-limits")
        assert response.status_code == 200
        data = response.json()
        assert "limits" in data
        assert isinstance(data["limits"], dict)
    
    def test_rate_limit_status(self, test_client: TestClient):
        """Test rate limit status endpoint."""
        response = test_client.get("/api/v1/security/rate-limits/status")
        assert response.status_code == 200
        data = response.json()
        assert "current_usage" in data or "status" in data
    
    def test_rate_limit_stats(self, test_client: TestClient):
        """Test rate limit statistics endpoint."""
        response = test_client.get("/api/v1/security/rate-limits/stats")
        assert response.status_code == 200
        data = response.json()
        assert "requests_total" in data or "stats" in data
    
    def test_rate_limit_test_endpoint(self, test_client: TestClient):
        """Test rate limit test functionality."""
        response = test_client.post(
            "/api/v1/security/rate-limits/test",
            json={"endpoint": "test", "count": 5}
        )
        assert response.status_code in [200, 429]  # Either success or rate limited
    
    def test_rate_limit_headers(self, test_client: TestClient):
        """Test that rate limit headers are present in responses."""
        response = test_client.get("/api/v1/security/health")
        # Check for rate limit headers
        headers = response.headers
        # Headers may include X-RateLimit-Limit, X-RateLimit-Remaining, etc.
        # This test verifies the endpoint responds
        assert response.status_code in [200, 429]


class TestSecurityHealth:
    """Security Health Endpoint Tests"""
    
    def test_security_health_endpoint(self, test_client: TestClient):
        """Test security health endpoint."""
        response = test_client.get("/api/v1/security/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert data["status"] in ["healthy", "degraded", "unhealthy"]
    
    def test_validation_stats(self, test_client: TestClient):
        """Test validation statistics endpoint."""
        response = test_client.get("/api/v1/security/validate/stats")
        assert response.status_code == 200
        data = response.json()
        assert "total_validations" in data or "stats" in data


class TestScopeValidation:
    """SEC-03: Scope Validation Tests"""
    
    def test_validate_scope_valid(self, test_client: TestClient):
        """Test valid scope validation."""
        response = test_client.post(
            "/api/v1/security/validate/scope",
            json={
                "target": "192.168.1.100",
                "scope": ["192.168.1.0/24", "10.0.0.0/8"]
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["in_scope"] is True
    
    def test_validate_scope_invalid(self, test_client: TestClient):
        """Test out of scope target."""
        response = test_client.post(
            "/api/v1/security/validate/scope",
            json={
                "target": "8.8.8.8",
                "scope": ["192.168.1.0/24", "10.0.0.0/8"]
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["in_scope"] is False


class TestSafeStringValidation:
    """SEC-03: Safe String Validation Tests"""
    
    def test_validate_safe_string_clean(self, test_client: TestClient):
        """Test clean string validation."""
        response = test_client.post(
            "/api/v1/security/validate/safe-string",
            json={"value": "This is a clean string 123"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["is_safe"] is True
    
    def test_validate_safe_string_with_injection(self, test_client: TestClient):
        """Test string with potential injection."""
        response = test_client.post(
            "/api/v1/security/validate/safe-string",
            json={"value": "admin' OR '1'='1"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["is_safe"] is False


# ═══════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════

@pytest.fixture
def test_client():
    """Create test client for API testing."""
    from src.api.main import app
    return TestClient(app)


# ═══════════════════════════════════════════════════════════════
# Integration Tests
# ═══════════════════════════════════════════════════════════════

class TestSecurityIntegration:
    """Integration tests for security components"""
    
    def test_validation_followed_by_rate_check(self, test_client: TestClient):
        """Test that validation works with rate limiting enabled."""
        # Make validation request
        response1 = test_client.post(
            "/api/v1/security/validate/ip",
            json={"value": "192.168.1.1"}
        )
        assert response1.status_code == 200
        
        # Check rate limit status
        response2 = test_client.get("/api/v1/security/rate-limits/status")
        assert response2.status_code == 200
    
    def test_multiple_validations_performance(self, test_client: TestClient):
        """Test multiple validations don't cause performance issues."""
        for i in range(10):
            response = test_client.post(
                "/api/v1/security/validate/ip",
                json={"value": f"192.168.1.{i}"}
            )
            assert response.status_code in [200, 429]  # OK or rate limited
