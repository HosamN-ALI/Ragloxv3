# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Knowledge API Tests
# Tests for Knowledge REST API endpoints
# ═══════════════════════════════════════════════════════════════

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from src.core.knowledge import EmbeddedKnowledge, init_knowledge, get_knowledge


# ═══════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def knowledge_instance():
    """Create knowledge instance for tests."""
    EmbeddedKnowledge.reset()
    get_knowledge.cache_clear()
    
    data_path = Path(__file__).parent.parent / "data"
    knowledge = init_knowledge(data_path=str(data_path))
    
    yield knowledge
    
    EmbeddedKnowledge.reset()
    get_knowledge.cache_clear()


@pytest.fixture(scope="module")
def test_client(knowledge_instance):
    """Create test client with knowledge."""
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    from src.api.routes import router
    from src.api.knowledge_routes import router as knowledge_router
    
    # Create app manually to avoid lifespan issues
    app = FastAPI(
        title="RAGLOX Test",
        version="3.0.0",
    )
    
    # Include routers
    app.include_router(router, prefix="/api/v1")
    app.include_router(knowledge_router, prefix="/api/v1")
    
    # Set knowledge in state
    app.state.knowledge = knowledge_instance
    app.state.controller = None  # Not needed for knowledge tests
    app.state.blackboard = None
    
    with TestClient(app) as client:
        yield client


# ═══════════════════════════════════════════════════════════════
# Stats Endpoint Tests
# ═══════════════════════════════════════════════════════════════

class TestStatsEndpoint:
    """Test /knowledge/stats endpoint."""
    
    def test_get_stats(self, test_client):
        """GET /api/v1/knowledge/stats should return statistics."""
        response = test_client.get("/api/v1/knowledge/stats")
        
        assert response.status_code == 200
        data = response.json()
        
        assert 'total_techniques' in data
        assert 'total_tactics' in data
        assert 'total_rx_modules' in data
        assert 'platforms' in data
        assert 'loaded' in data
        
        assert data['total_rx_modules'] == 1761
        assert data['total_techniques'] == 327
        assert data['loaded'] is True


# ═══════════════════════════════════════════════════════════════
# Techniques Endpoint Tests
# ═══════════════════════════════════════════════════════════════

class TestTechniquesEndpoints:
    """Test /knowledge/techniques endpoints."""
    
    def test_list_techniques(self, test_client):
        """GET /api/v1/knowledge/techniques should return list."""
        response = test_client.get("/api/v1/knowledge/techniques?limit=10")
        
        assert response.status_code == 200
        data = response.json()
        
        assert 'items' in data
        assert 'total' in data
        assert 'limit' in data
        assert 'offset' in data
        
        assert len(data['items']) <= 10
        assert data['total'] > 0
    
    def test_list_techniques_with_platform(self, test_client):
        """GET techniques filtered by platform."""
        response = test_client.get("/api/v1/knowledge/techniques?platform=windows&limit=20")
        
        assert response.status_code == 200
        data = response.json()
        
        for tech in data['items']:
            assert 'windows' in [p.lower() for p in tech['platforms']]
    
    def test_get_technique_by_id(self, test_client):
        """GET /api/v1/knowledge/techniques/{id} should return technique."""
        response = test_client.get("/api/v1/knowledge/techniques/T1003")
        
        assert response.status_code == 200
        data = response.json()
        
        assert data['id'] == 'T1003'
        assert data['name'] == 'OS Credential Dumping'
    
    def test_get_technique_not_found(self, test_client):
        """GET non-existent technique should return 404."""
        response = test_client.get("/api/v1/knowledge/techniques/T9999")
        
        assert response.status_code == 404
    
    def test_get_technique_modules(self, test_client):
        """GET /api/v1/knowledge/techniques/{id}/modules should return modules."""
        response = test_client.get("/api/v1/knowledge/techniques/T1003/modules")
        
        assert response.status_code == 200
        data = response.json()
        
        assert isinstance(data, list)
        assert len(data) > 0
        
        for module in data:
            assert module['technique_id'] == 'T1003'
    
    def test_get_technique_modules_filtered(self, test_client):
        """GET technique modules filtered by platform."""
        response = test_client.get("/api/v1/knowledge/techniques/T1003/modules?platform=windows")
        
        assert response.status_code == 200
        data = response.json()
        
        for module in data:
            assert 'windows' in [p.lower() for p in module['execution']['platforms']]


# ═══════════════════════════════════════════════════════════════
# Modules Endpoint Tests
# ═══════════════════════════════════════════════════════════════

class TestModulesEndpoints:
    """Test /knowledge/modules endpoints."""
    
    def test_list_modules(self, test_client):
        """GET /api/v1/knowledge/modules should return list."""
        response = test_client.get("/api/v1/knowledge/modules?limit=10")
        
        assert response.status_code == 200
        data = response.json()
        
        assert 'items' in data
        assert 'total' in data
        assert len(data['items']) <= 10
    
    def test_list_modules_filtered(self, test_client):
        """GET modules with filters."""
        response = test_client.get(
            "/api/v1/knowledge/modules?platform=linux&executor_type=sh&limit=20"
        )
        
        assert response.status_code == 200
        data = response.json()
        
        for module in data['items']:
            assert 'linux' in [p.lower() for p in module['execution']['platforms']]
            assert module['execution']['executor_type'] == 'sh'
    
    def test_get_module_by_id(self, test_client):
        """GET /api/v1/knowledge/modules/{id} should return module."""
        # First get a valid module ID
        list_response = test_client.get("/api/v1/knowledge/modules?limit=1")
        modules = list_response.json()['items']
        
        if modules:
            module_id = modules[0]['rx_module_id']
            
            response = test_client.get(f"/api/v1/knowledge/modules/{module_id}")
            
            assert response.status_code == 200
            data = response.json()
            
            assert data['rx_module_id'] == module_id
    
    def test_get_module_not_found(self, test_client):
        """GET non-existent module should return 404."""
        response = test_client.get("/api/v1/knowledge/modules/rx-invalid-999")
        
        assert response.status_code == 404


# ═══════════════════════════════════════════════════════════════
# Tactics Endpoint Tests
# ═══════════════════════════════════════════════════════════════

class TestTacticsEndpoints:
    """Test /knowledge/tactics endpoints."""
    
    def test_list_tactics(self, test_client):
        """GET /api/v1/knowledge/tactics should return list."""
        response = test_client.get("/api/v1/knowledge/tactics")
        
        assert response.status_code == 200
        data = response.json()
        
        assert isinstance(data, list)
        assert len(data) == 14  # 14 ATT&CK tactics
        
        for tactic in data:
            assert 'id' in tactic
            assert 'name' in tactic
            assert 'technique_count' in tactic
    
    def test_get_tactic_techniques(self, test_client):
        """GET /api/v1/knowledge/tactics/{id}/techniques should return list."""
        # First get a valid tactic
        tactics_response = test_client.get("/api/v1/knowledge/tactics")
        tactics = tactics_response.json()
        
        # Find a tactic with techniques
        for tactic in tactics:
            if tactic['technique_count'] > 0:
                response = test_client.get(f"/api/v1/knowledge/tactics/{tactic['id']}/techniques")
                
                if response.status_code == 200:
                    data = response.json()
                    assert isinstance(data, list)
                    break


# ═══════════════════════════════════════════════════════════════
# Platform Endpoint Tests
# ═══════════════════════════════════════════════════════════════

class TestPlatformEndpoints:
    """Test /knowledge/platforms endpoints."""
    
    def test_list_platforms(self, test_client):
        """GET /api/v1/knowledge/platforms should return list."""
        response = test_client.get("/api/v1/knowledge/platforms")
        
        assert response.status_code == 200
        data = response.json()
        
        assert isinstance(data, list)
        assert 'windows' in data
        assert 'linux' in data
    
    def test_get_platform_modules(self, test_client):
        """GET /api/v1/knowledge/platforms/{platform}/modules should return list."""
        response = test_client.get("/api/v1/knowledge/platforms/windows/modules?limit=10")
        
        assert response.status_code == 200
        data = response.json()
        
        assert isinstance(data, list)
        assert len(data) <= 10
        
        for module in data:
            assert 'windows' in [p.lower() for p in module['execution']['platforms']]


# ═══════════════════════════════════════════════════════════════
# Search Endpoint Tests
# ═══════════════════════════════════════════════════════════════

class TestSearchEndpoints:
    """Test /knowledge/search endpoints."""
    
    def test_search_get(self, test_client):
        """GET /api/v1/knowledge/search should return results."""
        response = test_client.get("/api/v1/knowledge/search?q=credential&limit=10")
        
        assert response.status_code == 200
        data = response.json()
        
        assert isinstance(data, list)
        assert len(data) <= 10
    
    def test_search_with_platform(self, test_client):
        """GET search with platform filter."""
        response = test_client.get("/api/v1/knowledge/search?q=dump&platform=windows&limit=10")
        
        assert response.status_code == 200
        data = response.json()
        
        for module in data:
            assert 'windows' in [p.lower() for p in module['execution']['platforms']]
    
    def test_search_post(self, test_client):
        """POST /api/v1/knowledge/search should work."""
        response = test_client.post(
            "/api/v1/knowledge/search",
            json={
                "query": "credential",
                "platform": "windows",
                "limit": 5
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert isinstance(data, list)
        assert len(data) <= 5
    
    def test_search_no_results(self, test_client):
        """Search with no matches should return empty list."""
        response = test_client.get("/api/v1/knowledge/search?q=xyznonexistent123")
        
        assert response.status_code == 200
        data = response.json()
        
        assert data == []
    
    def test_search_short_query(self, test_client):
        """Search with very short query should work."""
        response = test_client.get("/api/v1/knowledge/search?q=a&limit=5")
        
        assert response.status_code == 200


# ═══════════════════════════════════════════════════════════════
# Task-Oriented Endpoint Tests
# ═══════════════════════════════════════════════════════════════

class TestTaskOrientedEndpoints:
    """Test task-oriented endpoints for specialists."""
    
    def test_best_module(self, test_client):
        """POST /api/v1/knowledge/best-module should return best match."""
        response = test_client.post(
            "/api/v1/knowledge/best-module",
            json={
                "technique": "T1003",
                "platform": "windows"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        
        if data:  # May be None if no match
            assert data['technique_id'] == 'T1003'
    
    def test_best_module_no_match(self, test_client):
        """Best module with no match should return null."""
        response = test_client.post(
            "/api/v1/knowledge/best-module",
            json={
                "technique": "T9999",
                "platform": "invalid"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data is None
    
    def test_exploit_modules(self, test_client):
        """GET /api/v1/knowledge/exploit-modules should return list."""
        response = test_client.get("/api/v1/knowledge/exploit-modules?platform=windows&limit=10")
        
        assert response.status_code == 200
        data = response.json()
        
        assert isinstance(data, list)
    
    def test_recon_modules(self, test_client):
        """GET /api/v1/knowledge/recon-modules should return list."""
        response = test_client.get("/api/v1/knowledge/recon-modules?platform=windows&limit=10")
        
        assert response.status_code == 200
        data = response.json()
        
        assert isinstance(data, list)
    
    def test_credential_modules(self, test_client):
        """GET /api/v1/knowledge/credential-modules should return list."""
        response = test_client.get("/api/v1/knowledge/credential-modules?platform=windows&limit=10")
        
        assert response.status_code == 200
        data = response.json()
        
        assert isinstance(data, list)
        assert len(data) > 0
    
    def test_privesc_modules(self, test_client):
        """GET /api/v1/knowledge/privesc-modules should return list."""
        response = test_client.get("/api/v1/knowledge/privesc-modules?platform=windows&limit=10")
        
        assert response.status_code == 200
        data = response.json()
        
        assert isinstance(data, list)


# ═══════════════════════════════════════════════════════════════
# Error Handling Tests
# ═══════════════════════════════════════════════════════════════

class TestErrorHandling:
    """Test error handling in API."""
    
    def test_invalid_limit(self, test_client):
        """Invalid limit should return validation error."""
        response = test_client.get("/api/v1/knowledge/modules?limit=9999")
        
        # Should return 422 for validation error
        assert response.status_code == 422
    
    def test_invalid_offset(self, test_client):
        """Negative offset should return validation error."""
        response = test_client.get("/api/v1/knowledge/modules?offset=-1")
        
        assert response.status_code == 422
    
    def test_missing_required_param(self, test_client):
        """Missing required param should return error."""
        response = test_client.get("/api/v1/knowledge/search")  # Missing 'q'
        
        assert response.status_code == 422
