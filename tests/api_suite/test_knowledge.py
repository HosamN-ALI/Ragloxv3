"""
Tests for knowledge base endpoints.
"""

import pytest
import httpx
from typing import Dict, Any


class TestKnowledgeStats:
    """Test cases for knowledge stats endpoint."""

    def test_get_knowledge_stats_success(self, client: httpx.Client) -> None:
        """Test that GET /api/v1/knowledge/stats returns 200 OK."""
        response = client.get("/api/v1/knowledge/stats")
        assert response.status_code == 200
        data = response.json()
        
        # Verify response structure
        assert "total_techniques" in data
        assert "total_tactics" in data
        assert "total_rx_modules" in data
        assert "platforms" in data
        assert "modules_per_platform" in data
        assert "modules_per_executor" in data
        assert "memory_size_mb" in data
        assert "loaded" in data
        
        # Verify types
        assert isinstance(data["total_techniques"], int)
        assert isinstance(data["total_tactics"], int)
        assert isinstance(data["total_rx_modules"], int)
        assert isinstance(data["platforms"], list)
        assert isinstance(data["modules_per_platform"], dict)
        assert isinstance(data["modules_per_executor"], dict)
        assert isinstance(data["memory_size_mb"], (int, float))
        assert isinstance(data["loaded"], bool)


class TestKnowledgeTechniques:
    """Test cases for knowledge techniques endpoints."""

    def test_list_techniques_success(self, client: httpx.Client) -> None:
        """Test that GET /api/v1/knowledge/techniques returns 200 OK."""
        response = client.get("/api/v1/knowledge/techniques")
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
            technique = data["items"][0]
            assert "id" in technique
            assert "name" in technique

    def test_list_techniques_with_filters(self, client: httpx.Client) -> None:
        """Test listing techniques with platform filter."""
        response = client.get("/api/v1/knowledge/techniques?platform=windows&limit=10")
        assert response.status_code == 200
        data = response.json()
        
        assert "items" in data
        assert isinstance(data["items"], list)
        assert len(data["items"]) <= 10

    def test_list_techniques_validation_error(self, client: httpx.Client) -> None:
        """Test that listing techniques with invalid parameters returns 422."""
        # Limit too high
        response = client.get("/api/v1/knowledge/techniques?limit=501")
        assert response.status_code == 422
        
        # Negative limit
        response = client.get("/api/v1/knowledge/techniques?limit=-1")
        assert response.status_code == 422
        
        # Negative offset
        response = client.get("/api/v1/knowledge/techniques?offset=-1")
        assert response.status_code == 422

    def test_get_technique_success(self, client: httpx.Client, technique_id: str) -> None:
        """Test that GET /api/v1/knowledge/techniques/{technique_id} returns 200 OK."""
        response = client.get(f"/api/v1/knowledge/techniques/{technique_id}")
        # Could be 200 if technique exists or 404 if not
        assert response.status_code in [200, 404]
        
        if response.status_code == 200:
            data = response.json()
            assert "id" in data
            assert "name" in data
            assert data["id"] == technique_id

    def test_get_technique_not_found(self, client: httpx.Client) -> None:
        """Test that getting a non-existent technique returns 404."""
        response = client.get("/api/v1/knowledge/techniques/INVALID-TECHNIQUE-ID")
        assert response.status_code == 404

    def test_get_technique_modules_success(self, client: httpx.Client, technique_id: str) -> None:
        """Test that GET /api/v1/knowledge/techniques/{technique_id}/modules returns 200 OK."""
        response = client.get(f"/api/v1/knowledge/techniques/{technique_id}/modules")
        # Could be 200 if technique exists or 404 if not
        assert response.status_code in [200, 404]
        
        if response.status_code == 200:
            data = response.json()
            assert isinstance(data, list)
            
            # If there are modules, verify structure
            if data:
                module = data[0]
                assert "rx_module_id" in module
                assert "technique_id" in module
                assert "technique_name" in module

    def test_get_technique_modules_with_platform_filter(self, client: httpx.Client, technique_id: str) -> None:
        """Test getting technique modules with platform filter."""
        response = client.get(f"/api/v1/knowledge/techniques/{technique_id}/modules?platform=windows")
        # Could be 200 if technique exists or 404 if not
        assert response.status_code in [200, 404]


class TestKnowledgeModules:
    """Test cases for knowledge modules endpoints."""

    def test_list_modules_success(self, client: httpx.Client) -> None:
        """Test that GET /api/v1/knowledge/modules returns 200 OK."""
        response = client.get("/api/v1/knowledge/modules")
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
            module = data["items"][0]
            assert "rx_module_id" in module
            assert "technique_id" in module
            assert "technique_name" in module

    def test_list_modules_with_filters(self, client: httpx.Client) -> None:
        """Test listing modules with filters."""
        response = client.get("/api/v1/knowledge/modules?platform=windows&limit=10")
        assert response.status_code == 200
        data = response.json()
        
        assert "items" in data
        assert isinstance(data["items"], list)
        assert len(data["items"]) <= 10

    def test_list_modules_validation_error(self, client: httpx.Client) -> None:
        """Test that listing modules with invalid parameters returns 422."""
        # Limit too high
        response = client.get("/api/v1/knowledge/modules?limit=501")
        assert response.status_code == 422
        
        # Negative limit
        response = client.get("/api/v1/knowledge/modules?limit=-1")
        assert response.status_code == 422

    def test_get_module_success(self, client: httpx.Client, module_id: str) -> None:
        """Test that GET /api/v1/knowledge/modules/{module_id} returns 200 OK."""
        response = client.get(f"/api/v1/knowledge/modules/{module_id}")
        # Could be 200 if module exists or 404 if not
        assert response.status_code in [200, 404]
        
        if response.status_code == 200:
            data = response.json()
            assert "rx_module_id" in data
            assert "technique_id" in data
            assert "technique_name" in data
            assert data["rx_module_id"] == module_id

    def test_get_module_not_found(self, client: httpx.Client) -> None:
        """Test that getting a non-existent module returns 404."""
        response = client.get("/api/v1/knowledge/modules/INVALID-MODULE-ID")
        assert response.status_code == 404


class TestKnowledgeTactics:
    """Test cases for knowledge tactics endpoints."""

    def test_list_tactics_success(self, client: httpx.Client) -> None:
        """Test that GET /api/v1/knowledge/tactics returns 200 OK."""
        response = client.get("/api/v1/knowledge/tactics")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        
        # If there are tactics, verify structure
        if data:
            tactic = data[0]
            assert "id" in tactic
            assert "name" in tactic
            assert "technique_count" in tactic

    def test_get_tactic_techniques_success(self, client: httpx.Client, tactic_id: str) -> None:
        """Test that GET /api/v1/knowledge/tactics/{tactic_id}/techniques returns 200 OK."""
        response = client.get(f"/api/v1/knowledge/tactics/{tactic_id}/techniques")
        # Could be 200 if tactic exists or 404 if not
        assert response.status_code in [200, 404]
        
        if response.status_code == 200:
            data = response.json()
            assert isinstance(data, list)
            
            # If there are techniques, verify structure
            if data:
                technique = data[0]
                assert "id" in technique
                assert "name" in technique

    def test_get_tactic_techniques_not_found(self, client: httpx.Client) -> None:
        """Test that getting techniques for non-existent tactic returns 404."""
        response = client.get("/api/v1/knowledge/tactics/INVALID-TACTIC-ID/techniques")
        assert response.status_code == 404


class TestKnowledgePlatforms:
    """Test cases for knowledge platforms endpoints."""

    def test_list_platforms_success(self, client: httpx.Client) -> None:
        """Test that GET /api/v1/knowledge/platforms returns 200 OK."""
        response = client.get("/api/v1/knowledge/platforms")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        
        # Each item should be a string (platform name)
        for platform in data:
            assert isinstance(platform, str)

    def test_get_platform_modules_success(self, client: httpx.Client) -> None:
        """Test that GET /api/v1/knowledge/platforms/{platform}/modules returns 200 OK."""
        response = client.get("/api/v1/knowledge/platforms/windows/modules")
        # Could be 200 if platform exists or 404 if not
        assert response.status_code in [200, 404]
        
        if response.status_code == 200:
            data = response.json()
            assert isinstance(data, list)
            
            # If there are modules, verify structure
            if data:
                module = data[0]
                assert "rx_module_id" in module
                assert "technique_id" in module
                assert "technique_name" in module

    def test_get_platform_modules_with_limit(self, client: httpx.Client) -> None:
        """Test getting platform modules with limit."""
        response = client.get("/api/v1/knowledge/platforms/windows/modules?limit=5")
        # Could be 200 if platform exists or 404 if not
        assert response.status_code in [200, 404]
        
        if response.status_code == 200:
            data = response.json()
            assert isinstance(data, list)
            assert len(data) <= 5

    def test_get_platform_modules_validation_error(self, client: httpx.Client) -> None:
        """Test that getting platform modules with invalid limit returns 422."""
        # Limit too high
        response = client.get("/api/v1/knowledge/platforms/windows/modules?limit=201")
        assert response.status_code in [404, 422]  # 404 if platform doesn't exist, 422 for validation
        
        # Negative limit
        response = client.get("/api/v1/knowledge/platforms/windows/modules?limit=-1")
        assert response.status_code in [404, 422]  # 404 if platform doesn't exist, 422 for validation


class TestKnowledgeSearch:
    """Test cases for knowledge search endpoints."""

    def test_search_modules_get_success(self, client: httpx.Client) -> None:
        """Test that GET /api/v1/knowledge/search returns 200 OK."""
        response = client.get("/api/v1/knowledge/search?q=credential")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        
        # If there are results, verify structure
        if data:
            module = data[0]
            assert "rx_module_id" in module
            assert "technique_id" in module
            assert "technique_name" in module

    def test_search_modules_get_with_filters(self, client: httpx.Client) -> None:
        """Test searching modules with filters."""
        response = client.get("/api/v1/knowledge/search?q=credential&platform=windows&limit=5")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) <= 5

    def test_search_modules_get_validation_error(self, client: httpx.Client) -> None:
        """Test that searching modules with invalid parameters returns 422."""
        # Missing query
        response = client.get("/api/v1/knowledge/search")
        assert response.status_code == 422
        
        # Empty query
        response = client.get("/api/v1/knowledge/search?q=")
        assert response.status_code == 422
        
        # Query too long
        long_query = "a" * 201
        response = client.get(f"/api/v1/knowledge/search?q={long_query}")
        assert response.status_code == 422
        
        # Limit too high
        response = client.get("/api/v1/knowledge/search?q=test&limit=101")
        assert response.status_code == 422

    def test_search_modules_post_success(self, client: httpx.Client, sample_search_request: Dict[str, Any]) -> None:
        """Test that POST /api/v1/knowledge/search returns 200 OK."""
        response = client.post("/api/v1/knowledge/search", json=sample_search_request)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        
        # If there are results, verify structure
        if data:
            module = data[0]
            assert "rx_module_id" in module
            assert "technique_id" in module
            assert "technique_name" in module

    def test_search_modules_post_validation_error(self, client: httpx.Client) -> None:
        """Test that POST search with invalid data returns 422."""
        # Missing query
        response = client.post("/api/v1/knowledge/search", json={})
        assert response.status_code == 422
        
        # Empty query
        response = client.post("/api/v1/knowledge/search", json={"query": ""})
        assert response.status_code == 422
        
        # Query too long
        response = client.post("/api/v1/knowledge/search", json={"query": "a" * 201})
        assert response.status_code == 422

    def test_get_best_module_for_task_success(self, client: httpx.Client, sample_task_module_request: Dict[str, Any]) -> None:
        """Test that POST /api/v1/knowledge/best-module returns 200 OK."""
        response = client.post("/api/v1/knowledge/best-module", json=sample_task_module_request)
        assert response.status_code == 200
        data = response.json()
        
        # Response can be a module object or null
        if data is not None:
            assert "rx_module_id" in data
            assert "technique_id" in data
            assert "technique_name" in data


class TestSpecializedModules:
    """Test cases for specialized module endpoints."""

    def test_get_exploit_modules_success(self, client: httpx.Client) -> None:
        """Test that GET /api/v1/knowledge/exploit-modules returns 200 OK."""
        response = client.get("/api/v1/knowledge/exploit-modules")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        
        # If there are results, verify structure
        if data:
            module = data[0]
            assert "rx_module_id" in module
            assert "technique_id" in module
            assert "technique_name" in module

    def test_get_exploit_modules_with_filters(self, client: httpx.Client) -> None:
        """Test getting exploit modules with filters."""
        response = client.get("/api/v1/knowledge/exploit-modules?platform=windows&limit=5")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) <= 5

    def test_get_recon_modules_success(self, client: httpx.Client) -> None:
        """Test that GET /api/v1/knowledge/recon-modules returns 200 OK."""
        response = client.get("/api/v1/knowledge/recon-modules")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        
        # If there are results, verify structure
        if data:
            module = data[0]
            assert "rx_module_id" in module
            assert "technique_id" in module
            assert "technique_name" in module

    def test_get_credential_modules_success(self, client: httpx.Client) -> None:
        """Test that GET /api/v1/knowledge/credential-modules returns 200 OK."""
        response = client.get("/api/v1/knowledge/credential-modules")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        
        # If there are results, verify structure
        if data:
            module = data[0]
            assert "rx_module_id" in module
            assert "technique_id" in module
            assert "technique_name" in module

    def test_get_privesc_modules_success(self, client: httpx.Client) -> None:
        """Test that GET /api/v1/knowledge/privesc-modules returns 200 OK."""
        response = client.get("/api/v1/knowledge/privesc-modules")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        
        # If there are results, verify structure
        if data:
            module = data[0]
            assert "rx_module_id" in module
            assert "technique_id" in module
            assert "technique_name" in module