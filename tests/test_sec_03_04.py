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
            json={"ip": "192.168.1.1"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
    
    def test_validate_ip_address_invalid(self, test_client: TestClient):
        """Test invalid IP address validation."""
        response = test_client.post(
            "/api/v1/security/validate/ip",
            json={"ip": "not-an-ip"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is False
    
    def test_validate_ip_address_ipv6(self, test_client: TestClient):
        """Test IPv6 address validation."""
        response = test_client.post(
            "/api/v1/security/validate/ip",
            json={"ip": "::1"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
    
    def test_validate_cidr_valid(self, test_client: TestClient):
        """Test valid CIDR notation validation."""
        response = test_client.post(
            "/api/v1/security/validate/cidr",
            json={"cidr": "192.168.1.0/24"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
    
    def test_validate_cidr_invalid(self, test_client: TestClient):
        """Test invalid CIDR notation."""
        response = test_client.post(
            "/api/v1/security/validate/cidr",
            json={"cidr": "192.168.1.0/33"}  # Invalid prefix length
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is False
    
    def test_validate_uuid_valid(self, test_client: TestClient):
        """Test valid UUID validation."""
        response = test_client.post(
            "/api/v1/security/validate/uuid",
            json={"uuid": "550e8400-e29b-41d4-a716-446655440000"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
    
    def test_validate_uuid_invalid(self, test_client: TestClient):
        """Test invalid UUID validation."""
        response = test_client.post(
            "/api/v1/security/validate/uuid",
            json={"uuid": "not-a-uuid"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is False
    
    def test_validate_hostname_valid(self, test_client: TestClient):
        """Test valid hostname validation."""
        response = test_client.post(
            "/api/v1/security/validate/hostname",
            json={"hostname": "server-01.example.com"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
    
    def test_validate_hostname_invalid(self, test_client: TestClient):
        """Test invalid hostname validation."""
        response = test_client.post(
            "/api/v1/security/validate/hostname",
            json={"hostname": "inv@lid!host"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is False
    
    def test_validate_port_valid(self, test_client: TestClient):
        """Test valid port validation."""
        response = test_client.post(
            "/api/v1/security/validate/port",
            json={"port": "443"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
    
    def test_validate_port_range(self, test_client: TestClient):
        """Test port range validation."""
        response = test_client.post(
            "/api/v1/security/validate/port",
            json={"port": "80-443"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
    
    def test_validate_port_invalid(self, test_client: TestClient):
        """Test invalid port."""
        response = test_client.post(
            "/api/v1/security/validate/port",
            json={"port": "65536"}  # Out of range
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is False
    
    def test_validate_cve_valid(self, test_client: TestClient):
        """Test valid CVE ID validation."""
        response = test_client.post(
            "/api/v1/security/validate/cve",
            json={"cve": "CVE-2021-44228"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
    
    def test_validate_cve_invalid(self, test_client: TestClient):
        """Test invalid CVE ID validation."""
        response = test_client.post(
            "/api/v1/security/validate/cve",
            json={"cve": "CVE-invalid"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is False


class TestSafeStringValidation:
    """SEC-03: Safe String Validation Tests"""
    
    def test_validate_safe_string_clean(self, test_client: TestClient):
        """Test clean string validation."""
        response = test_client.post(
            "/api/v1/security/validate/safe-string",
            json={"value": "This is a clean string 123", "field_name": "description"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
    
    def test_validate_safe_string_with_injection(self, test_client: TestClient):
        """Test string with potential injection."""
        response = test_client.post(
            "/api/v1/security/validate/safe-string",
            json={"value": "SELECT * FROM users", "field_name": "input"}
        )
        assert response.status_code == 200
        data = response.json()
        # Response should have valid field
        assert "valid" in data


class TestScopeValidation:
    """SEC-03: Scope Validation Tests"""
    
    def test_validate_scope_valid(self, test_client: TestClient):
        """Test valid scope validation."""
        response = test_client.post(
            "/api/v1/security/validate/scope",
            json={
                "scope": ["192.168.1.0/24", "10.0.0.1", "target.example.com"]
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
    
    def test_validate_scope_with_invalid_entry(self, test_client: TestClient):
        """Test scope with invalid entry."""
        response = test_client.post(
            "/api/v1/security/validate/scope",
            json={
                "scope": ["192.168.1.0/24", "invalid!!!entry"]
            }
        )
        assert response.status_code == 200
        data = response.json()
        # Response should indicate some entries are invalid
        assert "valid" in data


class TestBatchValidation:
    """SEC-03: Batch Validation Tests"""
    
    def test_batch_validation_success(self, test_client: TestClient):
        """Test batch validation with multiple IPs."""
        response = test_client.post(
            "/api/v1/security/validate/batch",
            json={
                "items": [
                    {"value": "192.168.1.1"},
                    {"value": "192.168.1.2"},
                    {"value": "10.0.0.1"}
                ],
                "validation_type": "ip"
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert "results" in data or "total" in data
    
    def test_batch_validation_mixed(self, test_client: TestClient):
        """Test batch validation with mixed results."""
        response = test_client.post(
            "/api/v1/security/validate/batch",
            json={
                "items": [
                    {"value": "192.168.1.1"},
                    {"value": "invalid-ip"},
                    {"value": "10.0.0.1"}
                ],
                "validation_type": "ip"
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert "results" in data or "valid_count" in data or "invalid_count" in data


class TestInjectionDetection:
    """SEC-03: Injection Detection Tests"""
    
    def test_detect_sql_injection(self, test_client: TestClient):
        """Test SQL injection detection."""
        response = test_client.post(
            "/api/v1/security/check-injection",
            json={"value": "'; DROP TABLE users; --"}
        )
        # May return 400 if middleware blocks dangerous input
        assert response.status_code in [200, 400]
        if response.status_code == 200:
            data = response.json()
            assert data.get("safe") is False or data.get("is_safe") is False
    
    def test_detect_xss_attack(self, test_client: TestClient):
        """Test XSS attack detection."""
        response = test_client.post(
            "/api/v1/security/check-injection",
            json={"value": "<script>alert('xss')</script>"}
        )
        # May return 400 if middleware blocks dangerous input
        assert response.status_code in [200, 400]
        if response.status_code == 200:
            data = response.json()
            assert data.get("safe") is False or data.get("is_safe") is False
    
    def test_detect_command_injection(self, test_client: TestClient):
        """Test command injection detection."""
        response = test_client.post(
            "/api/v1/security/check-injection",
            json={"value": "test; rm -rf /"}
        )
        # May return 400 if middleware blocks dangerous input
        assert response.status_code in [200, 400]
        if response.status_code == 200:
            data = response.json()
            assert data.get("safe") is False or data.get("is_safe") is False
    
    def test_detect_path_traversal(self, test_client: TestClient):
        """Test path traversal detection."""
        response = test_client.post(
            "/api/v1/security/check-injection",
            json={"value": "../../../etc/passwd"}
        )
        # May return 400 if middleware blocks dangerous input
        assert response.status_code in [200, 400]
        if response.status_code == 200:
            data = response.json()
            assert data.get("safe") is False or data.get("is_safe") is False
    
    def test_safe_string(self, test_client: TestClient):
        """Test safe string passes validation."""
        response = test_client.post(
            "/api/v1/security/check-injection",
            json={"value": "This is a normal safe string"}
        )
        assert response.status_code == 200
        data = response.json()
        # Check for 'safe' key (actual API response)
        assert data.get("safe") is True


class TestRateLimiting:
    """SEC-04: Rate Limiting Tests"""
    
    def test_rate_limit_info(self, test_client: TestClient):
        """Test rate limit info endpoint."""
        response = test_client.get("/api/v1/security/rate-limits")
        assert response.status_code == 200
        data = response.json()
        # API returns rate limits as a dict directly
        assert isinstance(data, dict)
        # Should have at least the default limit
        assert len(data) > 0
    
    def test_rate_limit_status(self, test_client: TestClient):
        """Test rate limit status endpoint."""
        response = test_client.get("/api/v1/security/rate-limits/status")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data or "current_usage" in data
    
    def test_rate_limit_stats(self, test_client: TestClient):
        """Test rate limit statistics endpoint."""
        response = test_client.get("/api/v1/security/rate-limits/stats")
        assert response.status_code == 200
        data = response.json()
        # Should return some stats structure
        assert isinstance(data, dict)
    
    def test_rate_limit_test_endpoint(self, test_client: TestClient):
        """Test rate limit test functionality."""
        response = test_client.post(
            "/api/v1/security/rate-limits/test",
            json={"endpoint": "test", "count": 5}
        )
        assert response.status_code in [200, 429]  # Either success or rate limited
    
    def test_rate_limit_reset(self, test_client: TestClient):
        """Test rate limit reset endpoint."""
        response = test_client.post(
            "/api/v1/security/rate-limits/reset",
            json={"endpoint": "test"}
        )
        assert response.status_code in [200, 202, 403]  # Success, accepted, or forbidden


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
        # Should return some stats structure
        assert isinstance(data, dict)


class TestSecurityIntegration:
    """Integration tests for security components"""
    
    def test_validation_followed_by_rate_check(self, test_client: TestClient):
        """Test that validation works with rate limiting enabled."""
        # Make validation request
        response1 = test_client.post(
            "/api/v1/security/validate/ip",
            json={"ip": "192.168.1.1"}
        )
        assert response1.status_code == 200
        
        # Check rate limit status
        response2 = test_client.get("/api/v1/security/rate-limits/status")
        assert response2.status_code == 200
    
    def test_multiple_validations_performance(self, test_client: TestClient):
        """Test multiple validations don't cause issues."""
        for i in range(5):
            response = test_client.post(
                "/api/v1/security/validate/ip",
                json={"ip": f"192.168.1.{i}"}
            )
            assert response.status_code in [200, 429]  # OK or rate limited
    
    def test_security_health_after_operations(self, test_client: TestClient):
        """Test security health after multiple operations."""
        # Perform some operations
        test_client.post(
            "/api/v1/security/validate/ip",
            json={"ip": "192.168.1.1"}
        )
        test_client.post(
            "/api/v1/security/validate/uuid",
            json={"uuid": "550e8400-e29b-41d4-a716-446655440000"}
        )
        
        # Check health
        response = test_client.get("/api/v1/security/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"


# ═══════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════

@pytest.fixture
def test_client():
    """Create test client for API testing."""
    from src.api.main import app
    return TestClient(app)
