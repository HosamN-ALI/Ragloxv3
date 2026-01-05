"""
Tests for Nuclei templates endpoints.
"""

import pytest
import httpx
from typing import Dict, Any


class TestNucleiTemplates:
    """Test cases for Nuclei templates endpoints."""

    def test_list_nuclei_templates_success(self, client: httpx.Client) -> None:
        """Test that GET /api/v1/knowledge/nuclei/templates returns 200 OK."""
        response = client.get("/api/v1/knowledge/nuclei/templates")
        assert response.status_code == 200
        data = response.json()
        
        # Verify paginated response structure
        assert "items" in data
        assert "total" in data
        assert "limit" in data
        assert "offset" in data
        
        # Verify types
        assert isinstance(data["items"], list)
        assert isinstance(data["total"], int)
        assert isinstance(data["limit"], int)
        assert isinstance(data["offset"], int)
        
        # If there are items, verify structure
        if data["items"]:
            template = data["items"][0]
            assert "template_id" in template
            assert "name" in template

    def test_list_nuclei_templates_with_filters(self, client: httpx.Client) -> None:
        """Test listing Nuclei templates with filters."""
        response = client.get("/api/v1/knowledge/nuclei/templates?severity=high&limit=10")
        assert response.status_code == 200
        data = response.json()
        
        assert "items" in data
        assert isinstance(data["items"], list)
        assert len(data["items"]) <= 10

    def test_list_nuclei_templates_validation_error(self, client: httpx.Client) -> None:
        """Test that listing Nuclei templates with invalid parameters returns 422."""
        # Limit too high
        response = client.get("/api/v1/knowledge/nuclei/templates?limit=501")
        assert response.status_code == 422
        
        # Negative limit
        response = client.get("/api/v1/knowledge/nuclei/templates?limit=-1")
        assert response.status_code == 422
        
        # Negative offset
        response = client.get("/api/v1/knowledge/nuclei/templates?offset=-1")
        assert response.status_code == 422

    def test_get_nuclei_template_success(self, client: httpx.Client, template_id: str) -> None:
        """Test that GET /api/v1/knowledge/nuclei/templates/{template_id} returns 200 OK."""
        response = client.get(f"/api/v1/knowledge/nuclei/templates/{template_id}")
        # Could be 200 if template exists or 404 if not
        assert response.status_code in [200, 404]
        
        if response.status_code == 200:
            data = response.json()
            assert "template_id" in data
            assert "name" in data
            assert data["template_id"] == template_id

    def test_get_nuclei_template_not_found(self, client: httpx.Client) -> None:
        """Test that getting a non-existent Nuclei template returns 404."""
        response = client.get("/api/v1/knowledge/nuclei/templates/INVALID-TEMPLATE-ID")
        assert response.status_code == 404

    def test_search_nuclei_templates_success(self, client: httpx.Client) -> None:
        """Test that GET /api/v1/knowledge/nuclei/search returns 200 OK."""
        response = client.get("/api/v1/knowledge/nuclei/search?q=cve")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        
        # If there are results, verify structure
        if data:
            template = data[0]
            assert "template_id" in template
            assert "name" in template

    def test_search_nuclei_templates_with_filters(self, client: httpx.Client) -> None:
        """Test searching Nuclei templates with filters."""
        response = client.get("/api/v1/knowledge/nuclei/search?q=cve&severity=high&limit=5")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) <= 5

    def test_search_nuclei_templates_validation_error(self, client: httpx.Client) -> None:
        """Test that searching Nuclei templates with invalid parameters returns 422."""
        # Missing query
        response = client.get("/api/v1/knowledge/nuclei/search")
        assert response.status_code == 422
        
        # Empty query
        response = client.get("/api/v1/knowledge/nuclei/search?q=")
        assert response.status_code == 422
        
        # Query too long
        long_query = "a" * 201
        response = client.get(f"/api/v1/knowledge/nuclei/search?q={long_query}")
        assert response.status_code == 422
        
        # Limit too high
        response = client.get("/api/v1/knowledge/nuclei/search?q=test&limit=201")
        assert response.status_code == 422

    def test_get_nuclei_template_by_cve_success(self, client: httpx.Client, cve_id: str) -> None:
        """Test that GET /api/v1/knowledge/nuclei/cve/{cve_id} returns 200 OK."""
        response = client.get(f"/api/v1/knowledge/nuclei/cve/{cve_id}")
        # Could be 200 if template exists or 404 if not
        assert response.status_code in [200, 404]
        
        if response.status_code == 200:
            data = response.json()
            assert "template_id" in data
            assert "name" in data
            # Should be related to the CVE
            assert cve_id in str(data.get("cve_id", ""))

    def test_get_nuclei_template_by_cve_not_found(self, client: httpx.Client) -> None:
        """Test that getting a template for non-existent CVE returns 404."""
        response = client.get("/api/v1/knowledge/nuclei/cve/CVE-9999-9999")
        assert response.status_code == 404

    def test_get_nuclei_templates_by_severity_success(self, client: httpx.Client) -> None:
        """Test that GET /api/v1/knowledge/nuclei/severity/{severity} returns 200 OK."""
        response = client.get("/api/v1/knowledge/nuclei/severity/high")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        
        # If there are results, verify structure
        if data:
            template = data[0]
            assert "template_id" in template
            assert "name" in template
            assert "severity" in template
            assert template["severity"] == "high"

    def test_get_nuclei_templates_by_severity_with_limit(self, client: httpx.Client) -> None:
        """Test getting Nuclei templates by severity with limit."""
        response = client.get("/api/v1/knowledge/nuclei/severity/critical?limit=5")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) <= 5

    def test_get_nuclei_templates_by_severity_validation_error(self, client: httpx.Client) -> None:
        """Test that getting templates by severity with invalid limit returns 422."""
        # Limit too high
        response = client.get("/api/v1/knowledge/nuclei/severity/high?limit=501")
        assert response.status_code == 422
        
        # Negative limit
        response = client.get("/api/v1/knowledge/nuclei/severity/high?limit=-1")
        assert response.status_code == 422

    def test_get_critical_nuclei_templates_success(self, client: httpx.Client) -> None:
        """Test that GET /api/v1/knowledge/nuclei/critical returns 200 OK."""
        response = client.get("/api/v1/knowledge/nuclei/critical")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        
        # If there are results, verify structure
        if data:
            template = data[0]
            assert "template_id" in template
            assert "name" in template
            assert "severity" in template
            assert template["severity"] == "critical"

    def test_get_critical_nuclei_templates_with_limit(self, client: httpx.Client) -> None:
        """Test getting critical Nuclei templates with limit."""
        response = client.get("/api/v1/knowledge/nuclei/critical?limit=5")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) <= 5

    def test_get_critical_nuclei_templates_validation_error(self, client: httpx.Client) -> None:
        """Test that getting critical templates with invalid limit returns 422."""
        # Limit too high
        response = client.get("/api/v1/knowledge/nuclei/critical?limit=201")
        assert response.status_code == 422
        
        # Negative limit
        response = client.get("/api/v1/knowledge/nuclei/critical?limit=-1")
        assert response.status_code == 422

    def test_get_rce_nuclei_templates_success(self, client: httpx.Client) -> None:
        """Test that GET /api/v1/knowledge/nuclei/rce returns 200 OK."""
        response = client.get("/api/v1/knowledge/nuclei/rce")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        
        # If there are results, verify structure
        if data:
            template = data[0]
            assert "template_id" in template
            assert "name" in template
            assert "tags" in template
            # Should have 'rce' tag
            assert "rce" in template["tags"]

    def test_get_rce_nuclei_templates_with_limit(self, client: httpx.Client) -> None:
        """Test getting RCE Nuclei templates with limit."""
        response = client.get("/api/v1/knowledge/nuclei/rce?limit=5")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) <= 5

    def test_get_rce_nuclei_templates_validation_error(self, client: httpx.Client) -> None:
        """Test that getting RCE templates with invalid limit returns 422."""
        # Limit too high
        response = client.get("/api/v1/knowledge/nuclei/rce?limit=201")
        assert response.status_code == 422
        
        # Negative limit
        response = client.get("/api/v1/knowledge/nuclei/rce?limit=-1")
        assert response.status_code == 422

    def test_get_sqli_nuclei_templates_success(self, client: httpx.Client) -> None:
        """Test that GET /api/v1/knowledge/nuclei/sqli returns 200 OK."""
        response = client.get("/api/v1/knowledge/nuclei/sqli")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        
        # If there are results, verify structure
        if data:
            template = data[0]
            assert "template_id" in template
            assert "name" in template
            assert "tags" in template
            # Should have 'sqli' tag
            assert "sqli" in template["tags"]

    def test_get_sqli_nuclei_templates_with_limit(self, client: httpx.Client) -> None:
        """Test getting SQLi Nuclei templates with limit."""
        response = client.get("/api/v1/knowledge/nuclei/sqli?limit=5")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) <= 5

    def test_get_sqli_nuclei_templates_validation_error(self, client: httpx.Client) -> None:
        """Test that getting SQLi templates with invalid limit returns 422."""
        # Limit too high
        response = client.get("/api/v1/knowledge/nuclei/sqli?limit=201")
        assert response.status_code == 422
        
        # Negative limit
        response = client.get("/api/v1/knowledge/nuclei/sqli?limit=-1")
        assert response.status_code == 422

    def test_get_xss_nuclei_templates_success(self, client: httpx.Client) -> None:
        """Test that GET /api/v1/knowledge/nuclei/xss returns 200 OK."""
        response = client.get("/api/v1/knowledge/nuclei/xss")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        
        # If there are results, verify structure
        if data:
            template = data[0]
            assert "template_id" in template
            assert "name" in template
            assert "tags" in template
            # Should have 'xss' tag
            assert "xss" in template["tags"]

    def test_get_xss_nuclei_templates_with_limit(self, client: httpx.Client) -> None:
        """Test getting XSS Nuclei templates with limit."""
        response = client.get("/api/v1/knowledge/nuclei/xss?limit=5")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) <= 5

    def test_get_xss_nuclei_templates_validation_error(self, client: httpx.Client) -> None:
        """Test that getting XSS templates with invalid limit returns 422."""
        # Limit too high
        response = client.get("/api/v1/knowledge/nuclei/xss?limit=201")
        assert response.status_code == 422
        
        # Negative limit
        response = client.get("/api/v1/knowledge/nuclei/xss?limit=-1")
        assert response.status_code == 422