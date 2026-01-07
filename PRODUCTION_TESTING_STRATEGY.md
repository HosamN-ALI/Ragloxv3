# 🎯 RAGLOX V3 - Production Testing Strategy
## Real-World End-to-End Testing Without Mocks

**Date**: 2026-01-07  
**Purpose**: Prepare comprehensive production-ready testing strategy  
**Goal**: Test real system behavior with actual infrastructure  

---

## 📊 Current State Analysis

### What We Have Now (Unit/Integration Tests with Mocks)
```python
# Current approach: 67+ test files use mocks
@pytest.fixture
def mock_blackboard():
    return MagicMock()

@pytest.fixture
def mock_redis():
    return AsyncMock()

@pytest.fixture
def mock_llm():
    return MagicMock(spec=LLM)
```

**Problems with Mock-Heavy Testing:**
1. ❌ Mocks don't catch integration issues
2. ❌ Don't test real Redis behavior
3. ❌ Don't test real database transactions
4. ❌ Don't test real network conditions
5. ❌ Don't test real LLM responses
6. ❌ Miss real-world edge cases

---

## 🏗️ Production Testing Strategy

### Testing Pyramid for RAGLOX

```
                    ┌─────────────────┐
                    │   E2E Tests     │  ← Manual/Automated (Real infrastructure)
                    │   (Real Data)   │
                    └─────────────────┘
                   /                   \
                  /                     \
         ┌──────────────────┐   ┌──────────────────┐
         │ Integration Tests│   │  System Tests    │  ← Real components
         │  (Real Services) │   │  (Real APIs)     │
         └──────────────────┘   └──────────────────┘
        /                                            \
       /                                              \
┌─────────────────────────────────────────────────────┐
│           Unit Tests (with mocks)                   │  ← Fast feedback
│              Keep existing tests                    │
└─────────────────────────────────────────────────────┘
```

---

## 🎯 Three-Tier Testing Approach

### Tier 1: Unit Tests (Current - Keep as is)
**Purpose**: Fast feedback for developers  
**Scope**: Individual functions/classes  
**Infrastructure**: Mocked  
**Runtime**: < 5 minutes  

### Tier 2: Integration Tests (New - Real Services)
**Purpose**: Test component interactions  
**Scope**: Service-to-service communication  
**Infrastructure**: Real (Redis, PostgreSQL, etc.)  
**Runtime**: 10-20 minutes  

### Tier 3: End-to-End Tests (New - Full System)
**Purpose**: Test complete user workflows  
**Scope**: Full system behavior  
**Infrastructure**: Production-like environment  
**Runtime**: 30-60 minutes  

---

## 🔧 Implementation Plan

### Phase 1: Setup Real Test Infrastructure

#### 1.1 Test Environment Configuration
```python
# tests/production/config.py
from dataclasses import dataclass
from typing import Optional

@dataclass
class ProductionTestConfig:
    """Configuration for production-like testing"""
    
    # Database
    db_host: str = "localhost"
    db_port: int = 5432
    db_name: str = "raglox_test_production"
    db_user: str = "raglox_test"
    db_password: str = "test_password"
    
    # Redis
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 15  # Separate DB for testing
    
    # API
    api_base_url: str = "http://localhost:8000"
    api_timeout: int = 60
    
    # LLM (Use cheaper models for testing)
    llm_provider: str = "openai"
    llm_model: str = "gpt-3.5-turbo"  # Cheaper than gpt-4
    llm_api_key: Optional[str] = None
    
    # Target Environment (Controlled test network)
    test_target_network: str = "192.168.100.0/24"
    test_target_hosts: list = None
    
    # Security
    max_concurrent_scans: int = 5
    scan_timeout: int = 300
    exploit_disabled: bool = True  # Safety first!
    
    def __post_init__(self):
        if self.test_target_hosts is None:
            self.test_target_hosts = [
                "192.168.100.10",  # Test web server
                "192.168.100.11",  # Test database
                "192.168.100.12",  # Test vulnerable app
            ]
```

#### 1.2 Docker Compose for Test Infrastructure
```yaml
# docker-compose.test-production.yml
version: '3.8'

services:
  # PostgreSQL for testing
  postgres-test:
    image: postgres:15
    environment:
      POSTGRES_DB: raglox_test_production
      POSTGRES_USER: raglox_test
      POSTGRES_PASSWORD: test_password
    ports:
      - "5433:5432"
    volumes:
      - postgres-test-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U raglox_test"]
      interval: 5s
      timeout: 5s
      retries: 5

  # Redis for testing
  redis-test:
    image: redis:7-alpine
    ports:
      - "6380:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 5

  # RAGLOX API
  raglox-api:
    build:
      context: .
      dockerfile: Dockerfile
    environment:
      DATABASE_URL: postgresql://raglox_test:test_password@postgres-test:5432/raglox_test_production
      REDIS_URL: redis://redis-test:6379/0
      LLM_PROVIDER: openai
      LLM_MODEL: gpt-3.5-turbo
      LLM_API_KEY: ${OPENAI_API_KEY}
      EXPLOIT_DISABLED: "true"
    ports:
      - "8001:8000"
    depends_on:
      postgres-test:
        condition: service_healthy
      redis-test:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 10s
      timeout: 5s
      retries: 5

  # Test target: Vulnerable web app (DVWA)
  test-target-web:
    image: vulnerables/web-dvwa
    ports:
      - "8080:80"
    networks:
      test-network:
        ipv4_address: 192.168.100.10

  # Test target: Metasploitable (careful!)
  test-target-vuln:
    image: tleemcjr/metasploitable2
    ports:
      - "2222:22"
    networks:
      test-network:
        ipv4_address: 192.168.100.11

networks:
  test-network:
    driver: bridge
    ipam:
      config:
        - subnet: 192.168.100.0/24

volumes:
  postgres-test-data:
```

---

### Phase 2: Create Production Test Suite

#### 2.1 Base Classes for Production Tests
```python
# tests/production/base.py
import pytest
import asyncio
import httpx
from typing import Dict, Any, Optional
from datetime import datetime, timedelta

from src.core.database.postgres_manager import PostgresManager
from src.blackboard.blackboard import RedisBlackboard
from .config import ProductionTestConfig


class ProductionTestBase:
    """Base class for production-like testing"""
    
    @pytest.fixture(scope="class")
    def config(self) -> ProductionTestConfig:
        """Production test configuration"""
        return ProductionTestConfig()
    
    @pytest.fixture(scope="class")
    async def real_database(self, config: ProductionTestConfig):
        """Real PostgreSQL database connection"""
        db = PostgresManager(
            host=config.db_host,
            port=config.db_port,
            database=config.db_name,
            user=config.db_user,
            password=config.db_password
        )
        await db.connect()
        
        # Run migrations
        await db.run_migrations()
        
        yield db
        
        # Cleanup: Drop all test data
        await db.execute("TRUNCATE TABLE missions, users, organizations CASCADE")
        await db.close()
    
    @pytest.fixture(scope="class")
    async def real_blackboard(self, config: ProductionTestConfig):
        """Real Redis blackboard connection"""
        blackboard = RedisBlackboard(
            host=config.redis_host,
            port=config.redis_port,
            db=config.redis_db
        )
        await blackboard.connect()
        
        yield blackboard
        
        # Cleanup: Clear all test data
        await blackboard._redis.flushdb()
        await blackboard.disconnect()
    
    @pytest.fixture(scope="class")
    def real_api_client(self, config: ProductionTestConfig) -> httpx.AsyncClient:
        """Real HTTP client for API testing"""
        return httpx.AsyncClient(
            base_url=config.api_base_url,
            timeout=config.api_timeout,
            follow_redirects=True
        )
    
    @pytest.fixture
    async def authenticated_user(self, real_api_client: httpx.AsyncClient) -> Dict[str, Any]:
        """Create real user and authenticate"""
        # Register user
        user_data = {
            "email": f"test-{datetime.utcnow().timestamp()}@raglox-test.com",
            "password": "TestPassword123!",
            "full_name": "Production Test User",
            "organization_name": f"Test Org {datetime.utcnow().timestamp()}"
        }
        
        response = await real_api_client.post("/api/v1/auth/register", json=user_data)
        assert response.status_code == 201, f"Failed to register: {response.text}"
        
        # Login
        login_data = {
            "email": user_data["email"],
            "password": user_data["password"]
        }
        response = await real_api_client.post("/api/v1/auth/login", json=login_data)
        assert response.status_code == 200, f"Failed to login: {response.text}"
        
        token_data = response.json()
        return {
            **user_data,
            "access_token": token_data["access_token"],
            "user_id": token_data["user_id"],
            "organization_id": token_data["organization_id"]
        }
    
    @pytest.fixture
    def auth_headers(self, authenticated_user: Dict[str, Any]) -> Dict[str, str]:
        """Authentication headers for API requests"""
        return {
            "Authorization": f"Bearer {authenticated_user['access_token']}",
            "Content-Type": "application/json"
        }


class ProductionE2ETestBase(ProductionTestBase):
    """Base class for end-to-end testing with full system"""
    
    async def wait_for_mission_status(
        self,
        client: httpx.AsyncClient,
        headers: Dict[str, str],
        mission_id: str,
        expected_status: str,
        timeout: int = 300,
        poll_interval: int = 5
    ) -> Dict[str, Any]:
        """Wait for mission to reach expected status"""
        start_time = datetime.utcnow()
        
        while (datetime.utcnow() - start_time).total_seconds() < timeout:
            response = await client.get(
                f"/api/v1/missions/{mission_id}",
                headers=headers
            )
            
            if response.status_code == 200:
                mission = response.json()
                if mission["status"] == expected_status:
                    return mission
            
            await asyncio.sleep(poll_interval)
        
        raise TimeoutError(
            f"Mission {mission_id} did not reach status {expected_status} "
            f"within {timeout} seconds"
        )
    
    async def collect_mission_metrics(
        self,
        client: httpx.AsyncClient,
        headers: Dict[str, str],
        mission_id: str
    ) -> Dict[str, Any]:
        """Collect all mission metrics"""
        # Get mission details
        mission_response = await client.get(
            f"/api/v1/missions/{mission_id}",
            headers=headers
        )
        mission = mission_response.json()
        
        # Get targets
        targets_response = await client.get(
            f"/api/v1/missions/{mission_id}/targets",
            headers=headers
        )
        targets = targets_response.json()
        
        # Get vulnerabilities
        vulns_response = await client.get(
            f"/api/v1/missions/{mission_id}/vulnerabilities",
            headers=headers
        )
        vulnerabilities = vulns_response.json()
        
        # Get statistics
        stats_response = await client.get(
            f"/api/v1/missions/{mission_id}/statistics",
            headers=headers
        )
        statistics = stats_response.json()
        
        return {
            "mission": mission,
            "targets": targets,
            "vulnerabilities": vulnerabilities,
            "statistics": statistics
        }
```

#### 2.2 Production Integration Tests
```python
# tests/production/test_integration_real.py
import pytest
from typing import Dict, Any
import httpx

from .base import ProductionTestBase


@pytest.mark.production
@pytest.mark.integration
class TestProductionIntegration(ProductionTestBase):
    """Integration tests with real infrastructure"""
    
    @pytest.mark.asyncio
    async def test_user_registration_real_database(
        self,
        real_api_client: httpx.AsyncClient,
        real_database
    ):
        """Test user registration with real database"""
        # Register user
        user_data = {
            "email": "integration-test@raglox.com",
            "password": "SecurePass123!",
            "full_name": "Integration Test",
            "organization_name": "Test Org"
        }
        
        response = await real_api_client.post("/api/v1/auth/register", json=user_data)
        assert response.status_code == 201
        
        result = response.json()
        assert "access_token" in result
        assert result["user"]["email"] == user_data["email"]
        
        # Verify in database
        user_in_db = await real_database.fetchrow(
            "SELECT * FROM users WHERE email = $1",
            user_data["email"]
        )
        assert user_in_db is not None
        assert user_in_db["email"] == user_data["email"]
    
    @pytest.mark.asyncio
    async def test_mission_lifecycle_real_redis(
        self,
        real_api_client: httpx.AsyncClient,
        real_blackboard,
        auth_headers: Dict[str, str]
    ):
        """Test mission lifecycle with real Redis blackboard"""
        # Create mission
        mission_data = {
            "name": "Redis Integration Test",
            "scope": ["192.168.100.10"],
            "goals": ["enumerate_services"]
        }
        
        response = await real_api_client.post(
            "/api/v1/missions",
            headers=auth_headers,
            json=mission_data
        )
        assert response.status_code == 201
        
        mission = response.json()
        mission_id = mission["mission_id"]
        
        # Verify mission in Redis
        mission_in_redis = await real_blackboard.get_mission(mission_id)
        assert mission_in_redis is not None
        assert mission_in_redis["name"] == mission_data["name"]
        
        # Start mission
        response = await real_api_client.post(
            f"/api/v1/missions/{mission_id}/start",
            headers=auth_headers,
            json={}
        )
        assert response.status_code == 200
        
        # Verify status in Redis
        mission_in_redis = await real_blackboard.get_mission(mission_id)
        assert mission_in_redis["status"] == "running"
```

#### 2.3 Production End-to-End Tests
```python
# tests/production/test_e2e_real.py
import pytest
from typing import Dict, Any
import httpx
import asyncio

from .base import ProductionE2ETestBase
from .config import ProductionTestConfig


@pytest.mark.production
@pytest.mark.e2e
@pytest.mark.slow
class TestProductionE2E(ProductionE2ETestBase):
    """End-to-end tests with real system and targets"""
    
    @pytest.mark.asyncio
    async def test_complete_reconnaissance_mission(
        self,
        real_api_client: httpx.AsyncClient,
        auth_headers: Dict[str, str],
        config: ProductionTestConfig
    ):
        """Test complete reconnaissance mission flow"""
        # Step 1: Create mission
        mission_data = {
            "name": "E2E Reconnaissance Test",
            "description": "Full reconnaissance of test target",
            "scope": [config.test_target_hosts[0]],  # 192.168.100.10
            "goals": [
                "enumerate_services",
                "identify_vulnerabilities",
                "map_attack_surface"
            ],
            "constraints": {
                "stealth": True,
                "no_exploits": True
            }
        }
        
        response = await real_api_client.post(
            "/api/v1/missions",
            headers=auth_headers,
            json=mission_data
        )
        assert response.status_code == 201
        
        mission = response.json()
        mission_id = mission["mission_id"]
        print(f"✅ Created mission: {mission_id}")
        
        # Step 2: Start mission
        response = await real_api_client.post(
            f"/api/v1/missions/{mission_id}/start",
            headers=auth_headers,
            json={}
        )
        assert response.status_code == 200
        print(f"✅ Started mission: {mission_id}")
        
        # Step 3: Wait for targets to be discovered
        await asyncio.sleep(30)  # Give it time to scan
        
        targets_response = await real_api_client.get(
            f"/api/v1/missions/{mission_id}/targets",
            headers=auth_headers
        )
        assert targets_response.status_code == 200
        targets = targets_response.json()
        
        assert len(targets) > 0, "No targets discovered"
        print(f"✅ Discovered {len(targets)} targets")
        
        # Step 4: Verify services were enumerated
        target = targets[0]
        assert "services" in target
        assert len(target["services"]) > 0, "No services enumerated"
        print(f"✅ Enumerated {len(target['services'])} services")
        
        # Step 5: Wait for vulnerabilities
        await asyncio.sleep(60)  # Give it time to scan
        
        vulns_response = await real_api_client.get(
            f"/api/v1/missions/{mission_id}/vulnerabilities",
            headers=auth_headers
        )
        assert vulns_response.status_code == 200
        vulnerabilities = vulns_response.json()
        
        print(f"✅ Found {len(vulnerabilities)} vulnerabilities")
        
        # Step 6: Stop mission
        response = await real_api_client.post(
            f"/api/v1/missions/{mission_id}/stop",
            headers=auth_headers,
            json={}
        )
        assert response.status_code == 200
        print(f"✅ Stopped mission: {mission_id}")
        
        # Step 7: Collect final metrics
        metrics = await self.collect_mission_metrics(
            real_api_client,
            auth_headers,
            mission_id
        )
        
        # Assertions
        assert metrics["mission"]["status"] == "stopped"
        assert metrics["statistics"]["targets_discovered"] > 0
        assert metrics["statistics"]["services_enumerated"] > 0
        
        print(f"\n✅ Mission Complete!")
        print(f"  Targets: {metrics['statistics']['targets_discovered']}")
        print(f"  Services: {metrics['statistics']['services_enumerated']}")
        print(f"  Vulnerabilities: {metrics['statistics']['vulnerabilities_found']}")
    
    @pytest.mark.asyncio
    async def test_chat_interaction_with_real_llm(
        self,
        real_api_client: httpx.AsyncClient,
        auth_headers: Dict[str, str],
        authenticated_user: Dict[str, Any]
    ):
        """Test chat interaction with real LLM"""
        # Create mission first
        mission_data = {
            "name": "LLM Chat Test",
            "scope": ["192.168.100.10"],
            "goals": ["enumerate_services"]
        }
        
        response = await real_api_client.post(
            "/api/v1/missions",
            headers=auth_headers,
            json=mission_data
        )
        mission = response.json()
        mission_id = mission["mission_id"]
        
        # Send chat message
        chat_data = {
            "content": "What is the current status of this mission?"
        }
        
        response = await real_api_client.post(
            f"/api/v1/missions/{mission_id}/chat",
            headers=auth_headers,
            json=chat_data
        )
        
        assert response.status_code == 200
        chat_response = response.json()
        
        # Verify LLM responded
        assert "content" in chat_response
        assert len(chat_response["content"]) > 0
        assert chat_response["role"] in ["assistant", "system"]
        
        print(f"✅ LLM Response: {chat_response['content'][:100]}...")
    
    @pytest.mark.asyncio
    async def test_human_in_the_loop_approval_flow(
        self,
        real_api_client: httpx.AsyncClient,
        auth_headers: Dict[str, str]
    ):
        """Test HITL approval workflow with real system"""
        # Create and start mission
        mission_data = {
            "name": "HITL Test Mission",
            "scope": ["192.168.100.10"],
            "goals": ["gain_access"],
            "constraints": {"require_approval": True}
        }
        
        response = await real_api_client.post(
            "/api/v1/missions",
            headers=auth_headers,
            json=mission_data
        )
        mission = response.json()
        mission_id = mission["mission_id"]
        
        # Start mission
        await real_api_client.post(
            f"/api/v1/missions/{mission_id}/start",
            headers=auth_headers,
            json={}
        )
        
        # Wait for approval request
        await asyncio.sleep(60)
        
        # Check for pending approvals
        response = await real_api_client.get(
            f"/api/v1/missions/{mission_id}/approvals",
            headers=auth_headers
        )
        
        approvals = response.json()
        assert len(approvals) > 0, "No approval requests generated"
        
        approval = approvals[0]
        action_id = approval["action_id"]
        
        print(f"✅ Approval request: {approval['action_description']}")
        
        # Approve the action
        approval_data = {
            "approved": True,
            "comment": "Automated test approval"
        }
        
        response = await real_api_client.post(
            f"/api/v1/missions/{mission_id}/approve/{action_id}",
            headers=auth_headers,
            json=approval_data
        )
        
        assert response.status_code == 200
        print(f"✅ Action approved")
        
        # Verify mission continued
        await asyncio.sleep(30)
        
        response = await real_api_client.get(
            f"/api/v1/missions/{mission_id}",
            headers=auth_headers
        )
        mission = response.json()
        
        assert mission["status"] == "running"
        print(f"✅ Mission continued after approval")
```

#### 2.4 Performance and Load Tests
```python
# tests/production/test_performance_real.py
import pytest
import asyncio
from typing import List
import httpx
import time
from statistics import mean, median, stdev

from .base import ProductionTestBase


@pytest.mark.production
@pytest.mark.performance
class TestProductionPerformance(ProductionTestBase):
    """Performance tests with real system"""
    
    @pytest.mark.asyncio
    async def test_concurrent_mission_creation(
        self,
        real_api_client: httpx.AsyncClient,
        auth_headers: Dict[str, str]
    ):
        """Test creating multiple missions concurrently"""
        num_missions = 10
        mission_data = {
            "name": "Performance Test",
            "scope": ["192.168.100.10"],
            "goals": ["enumerate_services"]
        }
        
        async def create_mission(index: int):
            start = time.time()
            response = await real_api_client.post(
                "/api/v1/missions",
                headers=auth_headers,
                json={**mission_data, "name": f"Performance Test {index}"}
            )
            duration = time.time() - start
            return {
                "index": index,
                "status_code": response.status_code,
                "duration": duration,
                "success": response.status_code == 201
            }
        
        # Create missions concurrently
        start_time = time.time()
        results = await asyncio.gather(
            *[create_mission(i) for i in range(num_missions)]
        )
        total_time = time.time() - start_time
        
        # Analyze results
        successful = [r for r in results if r["success"]]
        durations = [r["duration"] for r in successful]
        
        print(f"\n📊 Performance Results:")
        print(f"  Total missions: {num_missions}")
        print(f"  Successful: {len(successful)}")
        print(f"  Total time: {total_time:.2f}s")
        print(f"  Avg duration: {mean(durations):.2f}s")
        print(f"  Median duration: {median(durations):.2f}s")
        print(f"  Std dev: {stdev(durations):.2f}s")
        
        # Assertions
        assert len(successful) == num_missions, f"Only {len(successful)}/{num_missions} succeeded"
        assert mean(durations) < 2.0, f"Average duration too high: {mean(durations):.2f}s"
    
    @pytest.mark.asyncio
    async def test_api_response_times(
        self,
        real_api_client: httpx.AsyncClient,
        auth_headers: Dict[str, str]
    ):
        """Test API endpoint response times"""
        endpoints = [
            ("GET", "/api/v1/knowledge/tactics", {}),
            ("GET", "/api/v1/knowledge/techniques", {}),
            ("GET", "/api/v1/nuclei/templates", {"severity": "critical"}),
        ]
        
        results = []
        
        for method, path, params in endpoints:
            start = time.time()
            
            if method == "GET":
                response = await real_api_client.get(path, params=params, headers=auth_headers)
            else:
                response = await real_api_client.post(path, json=params, headers=auth_headers)
            
            duration = time.time() - start
            
            results.append({
                "endpoint": f"{method} {path}",
                "status_code": response.status_code,
                "duration": duration,
                "success": 200 <= response.status_code < 300
            })
        
        # Print results
        print(f"\n📊 API Response Times:")
        for result in results:
            status = "✅" if result["success"] else "❌"
            print(f"  {status} {result['endpoint']}: {result['duration']:.3f}s")
        
        # Assertions
        for result in results:
            assert result["success"], f"{result['endpoint']} failed"
            assert result["duration"] < 1.0, f"{result['endpoint']} too slow: {result['duration']:.3f}s"
```

---

### Phase 3: Security and Chaos Testing

#### 3.1 Security Tests
```python
# tests/production/test_security_real.py
import pytest
import httpx
from typing import Dict

from .base import ProductionTestBase


@pytest.mark.production
@pytest.mark.security
class TestProductionSecurity(ProductionTestBase):
    """Security tests with real system"""
    
    @pytest.mark.asyncio
    async def test_sql_injection_protection(
        self,
        real_api_client: httpx.AsyncClient,
        auth_headers: Dict[str, str]
    ):
        """Test SQL injection protection"""
        # Attempt SQL injection in mission name
        malicious_data = {
            "name": "Test'; DROP TABLE missions; --",
            "scope": ["192.168.100.10"],
            "goals": ["test"]
        }
        
        response = await real_api_client.post(
            "/api/v1/missions",
            headers=auth_headers,
            json=malicious_data
        )
        
        # Should either reject or sanitize
        assert response.status_code in [201, 400, 422]
        
        # Verify missions table still exists
        missions_response = await real_api_client.get(
            "/api/v1/missions",
            headers=auth_headers
        )
        assert missions_response.status_code == 200
        print("✅ SQL injection protection working")
    
    @pytest.mark.asyncio
    async def test_unauthorized_access_protection(
        self,
        real_api_client: httpx.AsyncClient
    ):
        """Test unauthorized access is blocked"""
        # Try to access without auth
        response = await real_api_client.get("/api/v1/missions")
        assert response.status_code == 401
        
        # Try with invalid token
        response = await real_api_client.get(
            "/api/v1/missions",
            headers={"Authorization": "Bearer invalid_token"}
        )
        assert response.status_code == 401
        print("✅ Unauthorized access protection working")
    
    @pytest.mark.asyncio
    async def test_rate_limiting(
        self,
        real_api_client: httpx.AsyncClient,
        auth_headers: Dict[str, str]
    ):
        """Test rate limiting is enforced"""
        # Make many requests quickly
        responses = []
        for i in range(100):
            response = await real_api_client.get(
                "/api/v1/knowledge/tactics",
                headers=auth_headers
            )
            responses.append(response.status_code)
        
        # Should see some 429 (Too Many Requests)
        rate_limited = [r for r in responses if r == 429]
        
        print(f"📊 Rate limiting: {len(rate_limited)}/100 requests rate-limited")
        assert len(rate_limited) > 0, "Rate limiting not working"
```

#### 3.2 Chaos Testing
```python
# tests/production/test_chaos_real.py
import pytest
import asyncio
import httpx
from typing import Dict

from .base import ProductionE2ETestBase


@pytest.mark.production
@pytest.mark.chaos
@pytest.mark.slow
class TestProductionChaos(ProductionE2ETestBase):
    """Chaos testing - test system under failure conditions"""
    
    @pytest.mark.asyncio
    async def test_redis_connection_loss_recovery(
        self,
        real_api_client: httpx.AsyncClient,
        auth_headers: Dict[str, str],
        real_blackboard
    ):
        """Test system recovers from Redis connection loss"""
        # Create mission
        mission_data = {
            "name": "Chaos Test - Redis",
            "scope": ["192.168.100.10"],
            "goals": ["enumerate_services"]
        }
        
        response = await real_api_client.post(
            "/api/v1/missions",
            headers=auth_headers,
            json=mission_data
        )
        mission = response.json()
        mission_id = mission["mission_id"]
        
        # Start mission
        await real_api_client.post(
            f"/api/v1/missions/{mission_id}/start",
            headers=auth_headers,
            json={}
        )
        
        print("✅ Mission started")
        
        # Simulate Redis connection loss
        await real_blackboard.disconnect()
        print("⚠️  Redis disconnected")
        
        # Wait a bit
        await asyncio.sleep(10)
        
        # Reconnect
        await real_blackboard.connect()
        print("✅ Redis reconnected")
        
        # Verify mission still accessible
        response = await real_api_client.get(
            f"/api/v1/missions/{mission_id}",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        print("✅ Mission recovered after Redis reconnection")
    
    @pytest.mark.asyncio
    async def test_high_load_stability(
        self,
        real_api_client: httpx.AsyncClient,
        auth_headers: Dict[str, str]
    ):
        """Test system stability under high load"""
        # Create multiple missions and start them all
        num_missions = 20
        mission_ids = []
        
        for i in range(num_missions):
            mission_data = {
                "name": f"High Load Test {i}",
                "scope": ["192.168.100.10"],
                "goals": ["enumerate_services"]
            }
            
            response = await real_api_client.post(
                "/api/v1/missions",
                headers=auth_headers,
                json=mission_data
            )
            
            if response.status_code == 201:
                mission = response.json()
                mission_ids.append(mission["mission_id"])
        
        print(f"✅ Created {len(mission_ids)} missions")
        
        # Start all missions concurrently
        async def start_mission(mid):
            try:
                response = await real_api_client.post(
                    f"/api/v1/missions/{mid}/start",
                    headers=auth_headers,
                    json={}
                )
                return response.status_code == 200
            except Exception as e:
                print(f"❌ Failed to start {mid}: {e}")
                return False
        
        results = await asyncio.gather(
            *[start_mission(mid) for mid in mission_ids]
        )
        
        successful_starts = sum(results)
        print(f"✅ Started {successful_starts}/{len(mission_ids)} missions")
        
        # System should handle at least 80% successfully
        assert successful_starts >= len(mission_ids) * 0.8
        
        # Wait and verify all are still running
        await asyncio.sleep(30)
        
        running_count = 0
        for mid in mission_ids:
            response = await real_api_client.get(
                f"/api/v1/missions/{mid}",
                headers=auth_headers
            )
            if response.status_code == 200:
                mission = response.json()
                if mission["status"] == "running":
                    running_count += 1
        
        print(f"✅ {running_count} missions still running")
        assert running_count >= successful_starts * 0.9
```

---

### Phase 4: Test Execution Strategy

#### 4.1 Test Markers and Organization
```python
# pytest.ini (add to existing)
[pytest]
markers =
    production: Production tests with real infrastructure
    integration: Integration tests with real services
    e2e: End-to-end tests with full system
    performance: Performance and load tests
    security: Security tests
    chaos: Chaos engineering tests
    slow: Tests that take >1 minute
    requires_targets: Tests that need test targets running
```

#### 4.2 Test Execution Commands
```bash
# Run only production integration tests
pytest tests/production/ -m "production and integration" -v

# Run E2E tests (slow)
pytest tests/production/ -m "production and e2e" -v --timeout=600

# Run performance tests
pytest tests/production/ -m "production and performance" -v

# Run security tests
pytest tests/production/ -m "production and security" -v

# Run all production tests (comprehensive)
pytest tests/production/ -m "production" -v --timeout=3600

# Run with coverage
pytest tests/production/ -m "production" --cov=src --cov-report=html

# Run specific test file
pytest tests/production/test_e2e_real.py -v
```

#### 4.3 CI/CD Integration
```yaml
# .github/workflows/production-tests.yml
name: Production Tests

on:
  schedule:
    - cron: '0 2 * * *'  # Run daily at 2 AM
  workflow_dispatch:  # Manual trigger

jobs:
  production-tests:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_DB: raglox_test_production
          POSTGRES_USER: raglox_test
          POSTGRES_PASSWORD: test_password
        ports:
          - 5433:5432
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
      
      redis:
        image: redis:7-alpine
        ports:
          - 6380:6379
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.12'
      
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install -r requirements-test.txt
      
      - name: Start RAGLOX API
        run: |
          python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000 &
          sleep 10
        env:
          DATABASE_URL: postgresql://raglox_test:test_password@localhost:5433/raglox_test_production
          REDIS_URL: redis://localhost:6380/0
          LLM_PROVIDER: openai
          LLM_MODEL: gpt-3.5-turbo
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
      
      - name: Run Production Integration Tests
        run: |
          pytest tests/production/ -m "production and integration" -v
      
      - name: Run Production E2E Tests
        run: |
          pytest tests/production/ -m "production and e2e" -v --timeout=1800
      
      - name: Run Security Tests
        run: |
          pytest tests/production/ -m "production and security" -v
      
      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: production-test-results
          path: |
            htmlcov/
            .pytest_cache/
```

---

### Phase 5: Monitoring and Reporting

#### 5.1 Test Monitoring Dashboard
```python
# tests/production/monitoring.py
from dataclasses import dataclass
from typing import List, Dict
from datetime import datetime
import json


@dataclass
class TestMetrics:
    """Metrics collected during production testing"""
    test_name: str
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    status: str  # passed, failed, skipped
    error_message: str = None
    
    # Performance metrics
    api_calls_made: int = 0
    avg_response_time: float = 0.0
    
    # Mission metrics
    targets_discovered: int = 0
    services_enumerated: int = 0
    vulnerabilities_found: int = 0
    
    def to_dict(self) -> Dict:
        return {
            "test_name": self.test_name,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "duration_seconds": self.duration_seconds,
            "status": self.status,
            "error_message": self.error_message,
            "api_calls_made": self.api_calls_made,
            "avg_response_time": self.avg_response_time,
            "targets_discovered": self.targets_discovered,
            "services_enumerated": self.services_enumerated,
            "vulnerabilities_found": self.vulnerabilities_found,
        }


class ProductionTestMonitor:
    """Monitor and report production test execution"""
    
    def __init__(self):
        self.metrics: List[TestMetrics] = []
    
    def record_test(self, metrics: TestMetrics):
        """Record test metrics"""
        self.metrics.append(metrics)
    
    def generate_report(self) -> Dict:
        """Generate comprehensive test report"""
        total_tests = len(self.metrics)
        passed = len([m for m in self.metrics if m.status == "passed"])
        failed = len([m for m in self.metrics if m.status == "failed"])
        skipped = len([m for m in self.metrics if m.status == "skipped"])
        
        total_duration = sum(m.duration_seconds for m in self.metrics)
        avg_duration = total_duration / total_tests if total_tests > 0 else 0
        
        return {
            "summary": {
                "total_tests": total_tests,
                "passed": passed,
                "failed": failed,
                "skipped": skipped,
                "pass_rate": f"{(passed/total_tests*100):.1f}%" if total_tests > 0 else "0%",
                "total_duration": f"{total_duration:.2f}s",
                "avg_duration": f"{avg_duration:.2f}s",
            },
            "tests": [m.to_dict() for m in self.metrics],
            "failures": [
                {
                    "test": m.test_name,
                    "error": m.error_message
                }
                for m in self.metrics if m.status == "failed"
            ]
        }
    
    def save_report(self, filepath: str = "production-test-report.json"):
        """Save report to file"""
        report = self.generate_report()
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"✅ Report saved to {filepath}")
```

---

## 📋 Summary Checklist

### Setup Checklist
- [ ] Create `tests/production/` directory
- [ ] Create `ProductionTestConfig` configuration class
- [ ] Set up Docker Compose for test infrastructure
- [ ] Create test targets (DVWA, Metasploitable, etc.)
- [ ] Configure test database and Redis
- [ ] Set up LLM API keys (cheaper models)
- [ ] Configure CI/CD pipeline

### Test Development Checklist
- [ ] Create base test classes (`ProductionTestBase`, `ProductionE2ETestBase`)
- [ ] Write integration tests (database, Redis, API)
- [ ] Write E2E tests (full mission lifecycle)
- [ ] Write performance tests (load, concurrency)
- [ ] Write security tests (injection, auth, rate limiting)
- [ ] Write chaos tests (failure recovery)

### Execution Checklist
- [ ] Run integration tests locally
- [ ] Run E2E tests with test targets
- [ ] Run performance tests
- [ ] Run security tests
- [ ] Run full production test suite
- [ ] Generate and review reports
- [ ] Fix identified issues
- [ ] Set up automated daily runs

### Documentation Checklist
- [ ] Document test infrastructure setup
- [ ] Document how to run tests
- [ ] Document test markers and categories
- [ ] Create troubleshooting guide
- [ ] Document expected results
- [ ] Create runbook for test failures

---

## 🎯 Expected Outcomes

### Metrics to Track
1. **Test Coverage**: % of production code paths tested
2. **Pass Rate**: % of tests passing consistently
3. **Performance**: API response times, mission completion times
4. **Reliability**: Test flakiness rate
5. **Security**: Number of vulnerabilities caught

### Success Criteria
- ✅ 95%+ pass rate on production tests
- ✅ <5% test flakiness
- ✅ All critical paths covered
- ✅ Performance benchmarks met
- ✅ Security tests all passing
- ✅ Tests run successfully in CI/CD

---

## 🚀 Next Steps

1. **Week 1**: Set up infrastructure (Docker, databases, test targets)
2. **Week 2**: Create base classes and integration tests
3. **Week 3**: Write E2E tests for main workflows
4. **Week 4**: Add performance and security tests
5. **Week 5**: Set up monitoring and CI/CD
6. **Week 6**: Run full test suite and fix issues

---

**Status**: 📋 **PLAN READY FOR IMPLEMENTATION**  
**Estimated Effort**: 6 weeks  
**Resources Needed**: Test infrastructure, LLM API budget, dedicated test targets  
**ROI**: High - Catch production issues before deployment

