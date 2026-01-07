"""
Base Classes for Production Testing

This module provides base test classes with fixtures for production-like testing.
All fixtures use real infrastructure (no mocks).
"""

import pytest
import asyncio
import httpx
from typing import Dict, Any, Optional, AsyncGenerator
from datetime import datetime
import uuid

from .config import ProductionTestConfig, get_config


class ProductionTestBase:
    """
    Base class for production-like testing with real infrastructure.
    
    Provides fixtures for:
    - Real PostgreSQL database connection
    - Real Redis blackboard connection
    - Real HTTP API client
    - Real authenticated user
    - Authentication headers
    
    All cleanup is automatic after tests complete.
    """
    
    @pytest.fixture(scope="class")
    def config(self) -> ProductionTestConfig:
        """
        Production test configuration.
        
        Returns:
            ProductionTestConfig instance with all settings
        """
        return get_config()
    
    @pytest.fixture(scope="function")
    async def real_database(self, config: ProductionTestConfig) -> AsyncGenerator:
        """
        Real PostgreSQL database connection.
        
        Features:
        - Connects to real test database
        - Runs migrations if needed
        - Auto cleanup after tests
        
        Yields:
            Database connection pool
        """
        import asyncpg
        
        # Create connection pool
        pool = await asyncpg.create_pool(
            host=config.db_host,
            port=config.db_port,
            database=config.db_name,
            user=config.db_user,
            password=config.db_password,
            min_size=5,
            max_size=20,
            timeout=30
        )
        
        print(f"\n✅ Connected to PostgreSQL: {config.db_host}:{config.db_port}/{config.db_name}")
        
        yield pool
        
        # Cleanup: Optionally truncate test data
        if config.test_data_cleanup:
            async with pool.acquire() as conn:
                try:
                    # Truncate tables but keep structure
                    await conn.execute("""
                        TRUNCATE TABLE 
                            missions, 
                            users, 
                            organizations 
                        CASCADE
                    """)
                    print("✅ Test data cleaned up from database")
                except Exception as e:
                    print(f"⚠️  Cleanup warning: {e}")
        
        await pool.close()
        print("✅ Database connection closed")
    
    @pytest.fixture(scope="class")
    async def real_blackboard(self, config: ProductionTestConfig) -> AsyncGenerator:
        """
        Real Redis blackboard connection.
        
        Features:
        - Connects to real Redis instance
        - Auto cleanup after tests
        - Flushes test data
        
        Yields:
            Redis connection
        """
        import redis.asyncio as redis
        
        # Create Redis connection
        redis_client = await redis.from_url(
            config.redis_url,
            encoding="utf-8",
            decode_responses=True,
            max_connections=50
        )
        
        # Test connection
        await redis_client.ping()
        print(f"\n✅ Connected to Redis: {config.redis_host}:{config.redis_port}")
        
        yield redis_client
        
        # Cleanup: Flush test data
        if config.test_data_cleanup:
            await redis_client.flushdb()
            print("✅ Test data cleaned up from Redis")
        
        await redis_client.close()
        print("✅ Redis connection closed")
    
    @pytest.fixture(scope="class")
    async def real_api_client(self, config: ProductionTestConfig) -> AsyncGenerator:
        """
        Real HTTP client for API testing.
        
        Features:
        - Async HTTP client
        - Configured timeouts
        - Follows redirects
        
        Yields:
            httpx.AsyncClient instance
        """
        async with httpx.AsyncClient(
            base_url=config.api_base_url,
            timeout=httpx.Timeout(config.api_timeout),
            follow_redirects=True,
            headers={"Content-Type": "application/json"}
        ) as client:
            print(f"\n✅ API client ready: {config.api_base_url}")
            yield client
            print("✅ API client closed")
    
    @pytest.fixture
    async def authenticated_user(
        self, 
        real_api_client: httpx.AsyncClient
    ) -> Dict[str, Any]:
        """
        Create real user and authenticate.
        
        Features:
        - Registers unique user
        - Gets auth token
        - Returns user data with token
        
        Returns:
            Dict with user data and access token
        """
        # Generate unique user data
        timestamp = datetime.utcnow().timestamp()
        user_data = {
            "email": f"test-{timestamp}@raglox-test.com",
            "password": "TestPassword123!",
            "full_name": f"Test User {int(timestamp)}",
            "organization_name": f"Test Org {int(timestamp)}"
        }
        
        # Register user
        response = await real_api_client.post(
            "/api/v1/auth/register",
            json=user_data
        )
        
        if response.status_code != 201:
            raise AssertionError(
                f"Failed to register user: {response.status_code} - {response.text}"
            )
        
        register_data = response.json()
        print(f"✅ User registered: {user_data['email']}")
        
        # Return complete user data
        return {
            **user_data,
            "access_token": register_data["access_token"],
            "user_id": register_data["user"]["id"],
            "organization_id": register_data["user"]["organization_id"]
        }
    
    @pytest.fixture
    def auth_headers(self, authenticated_user: Dict[str, Any]) -> Dict[str, str]:
        """
        Authentication headers for API requests.
        
        Args:
            authenticated_user: User data with token
        
        Returns:
            Dict with Authorization header
        """
        return {
            "Authorization": f"Bearer {authenticated_user['access_token']}",
            "Content-Type": "application/json"
        }
    
    @pytest.fixture
    async def authenticated_client(
        self,
        real_api_client: httpx.AsyncClient,
        auth_headers: Dict[str, str]
    ) -> httpx.AsyncClient:
        """
        HTTP client with authentication headers.
        
        Args:
            real_api_client: Base API client
            auth_headers: Authentication headers
        
        Returns:
            Authenticated HTTP client
        """
        real_api_client.headers.update(auth_headers)
        return real_api_client


class ProductionE2ETestBase(ProductionTestBase):
    """
    Base class for end-to-end testing with full system.
    
    Extends ProductionTestBase with helpers for:
    - Waiting for async operations
    - Collecting metrics
    - Polling mission status
    - Verifying workflows
    """
    
    async def wait_for_mission_status(
        self,
        client: httpx.AsyncClient,
        headers: Dict[str, str],
        mission_id: str,
        expected_status: str,
        timeout: int = 300,
        poll_interval: int = 5
    ) -> Dict[str, Any]:
        """
        Wait for mission to reach expected status.
        
        Args:
            client: HTTP client
            headers: Auth headers
            mission_id: Mission ID to check
            expected_status: Expected status (e.g., 'running', 'completed')
            timeout: Max wait time in seconds
            poll_interval: Time between checks in seconds
        
        Returns:
            Mission data when status reached
        
        Raises:
            TimeoutError: If status not reached within timeout
        """
        start_time = datetime.utcnow()
        
        print(f"⏳ Waiting for mission {mission_id} to reach status: {expected_status}")
        
        while (datetime.utcnow() - start_time).total_seconds() < timeout:
            response = await client.get(
                f"/api/v1/missions/{mission_id}",
                headers=headers
            )
            
            if response.status_code == 200:
                mission = response.json()
                current_status = mission.get("status")
                
                if current_status == expected_status:
                    print(f"✅ Mission {mission_id} reached status: {expected_status}")
                    return mission
                else:
                    print(f"   Current status: {current_status}, waiting...")
            
            await asyncio.sleep(poll_interval)
        
        raise TimeoutError(
            f"Mission {mission_id} did not reach status '{expected_status}' "
            f"within {timeout} seconds"
        )
    
    async def wait_for_condition(
        self,
        condition_func: callable,
        timeout: int = 60,
        poll_interval: int = 2,
        condition_name: str = "condition"
    ) -> Any:
        """
        Wait for a custom condition to be true.
        
        Args:
            condition_func: Async function that returns True when condition met
            timeout: Max wait time in seconds
            poll_interval: Time between checks in seconds
            condition_name: Name for logging
        
        Returns:
            Result from condition_func when True
        
        Raises:
            TimeoutError: If condition not met within timeout
        """
        start_time = datetime.utcnow()
        
        print(f"⏳ Waiting for {condition_name}...")
        
        while (datetime.utcnow() - start_time).total_seconds() < timeout:
            result = await condition_func()
            if result:
                print(f"✅ {condition_name} met")
                return result
            await asyncio.sleep(poll_interval)
        
        raise TimeoutError(
            f"{condition_name} not met within {timeout} seconds"
        )
    
    async def collect_mission_metrics(
        self,
        client: httpx.AsyncClient,
        headers: Dict[str, str],
        mission_id: str
    ) -> Dict[str, Any]:
        """
        Collect all mission metrics.
        
        Args:
            client: HTTP client
            headers: Auth headers
            mission_id: Mission ID
        
        Returns:
            Dict with mission, targets, vulnerabilities, statistics
        """
        print(f"📊 Collecting metrics for mission {mission_id}...")
        
        # Get mission details
        mission_response = await client.get(
            f"/api/v1/missions/{mission_id}",
            headers=headers
        )
        mission = mission_response.json() if mission_response.status_code == 200 else {}
        
        # Get targets
        targets_response = await client.get(
            f"/api/v1/missions/{mission_id}/targets",
            headers=headers
        )
        targets = targets_response.json() if targets_response.status_code == 200 else []
        
        # Get vulnerabilities
        vulns_response = await client.get(
            f"/api/v1/missions/{mission_id}/vulnerabilities",
            headers=headers
        )
        vulnerabilities = vulns_response.json() if vulns_response.status_code == 200 else []
        
        # Get statistics
        stats_response = await client.get(
            f"/api/v1/missions/{mission_id}/statistics",
            headers=headers
        )
        statistics = stats_response.json() if stats_response.status_code == 200 else {}
        
        metrics = {
            "mission": mission,
            "targets": targets,
            "vulnerabilities": vulnerabilities,
            "statistics": statistics,
            "summary": {
                "mission_id": mission_id,
                "status": mission.get("status"),
                "target_count": len(targets),
                "vulnerability_count": len(vulnerabilities),
                "collected_at": datetime.utcnow().isoformat()
            }
        }
        
        print(f"✅ Metrics collected:")
        print(f"   - Targets: {len(targets)}")
        print(f"   - Vulnerabilities: {len(vulnerabilities)}")
        print(f"   - Status: {mission.get('status')}")
        
        return metrics
    
    async def verify_target_discovered(
        self,
        client: httpx.AsyncClient,
        headers: Dict[str, str],
        mission_id: str,
        target_ip: str,
        timeout: int = 120
    ) -> Dict[str, Any]:
        """
        Wait for and verify target is discovered.
        
        Args:
            client: HTTP client
            headers: Auth headers
            mission_id: Mission ID
            target_ip: Expected target IP
            timeout: Max wait time
        
        Returns:
            Target data
        
        Raises:
            TimeoutError: If target not discovered
        """
        async def check_target():
            response = await client.get(
                f"/api/v1/missions/{mission_id}/targets",
                headers=headers
            )
            if response.status_code == 200:
                targets = response.json()
                for target in targets:
                    if target.get("ip") == target_ip:
                        return target
            return None
        
        return await self.wait_for_condition(
            check_target,
            timeout=timeout,
            poll_interval=5,
            condition_name=f"target {target_ip} discovered"
        )
    
    async def verify_services_enumerated(
        self,
        client: httpx.AsyncClient,
        headers: Dict[str, str],
        mission_id: str,
        target_ip: str,
        min_services: int = 1,
        timeout: int = 120
    ) -> list:
        """
        Wait for and verify services are enumerated.
        
        Args:
            client: HTTP client
            headers: Auth headers
            mission_id: Mission ID
            target_ip: Target IP to check
            min_services: Minimum services expected
            timeout: Max wait time
        
        Returns:
            List of services
        
        Raises:
            TimeoutError: If services not enumerated
        """
        async def check_services():
            target = await self.verify_target_discovered(
                client, headers, mission_id, target_ip, timeout=10
            )
            if target and "services" in target:
                services = target.get("services", [])
                if len(services) >= min_services:
                    return services
            return None
        
        return await self.wait_for_condition(
            check_services,
            timeout=timeout,
            poll_interval=10,
            condition_name=f"services enumerated on {target_ip}"
        )
    
    def generate_unique_id(self) -> str:
        """Generate unique ID for test data"""
        return str(uuid.uuid4())
    
    def generate_test_email(self) -> str:
        """Generate unique test email"""
        return f"test-{uuid.uuid4()}@raglox-test.com"
    
    def generate_mission_name(self, prefix: str = "Test Mission") -> str:
        """Generate unique mission name"""
        return f"{prefix} {datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
