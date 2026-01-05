"""
Tests for general endpoints: root and health check.
"""

import pytest
import httpx
from typing import Dict, Any


class TestRootEndpoint:
    """Test cases for the root endpoint."""

    def test_root_get_success(self, client: httpx.Client) -> None:
        """Test that GET / returns 200 OK."""
        response = client.get("/")
        assert response.status_code == 200
        # Response should be JSON (could be empty object)
        assert response.headers["content-type"] == "application/json"


class TestHealthEndpoint:
    """Test cases for the health check endpoint."""

    def test_health_check_success(self, client: httpx.Client) -> None:
        """Test that GET /health returns 200 OK."""
        response = client.get("/health")
        assert response.status_code == 200
        # Response should be JSON (could be empty object)
        assert response.headers["content-type"] == "application/json"
        
        # Optional: Check if health check returns any status information
        data = response.json()
        # Health check might include status, timestamp, etc.
        # This is flexible based on implementation
        assert isinstance(data, dict)