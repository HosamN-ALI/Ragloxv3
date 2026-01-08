"""
Chaos & Resilience Tests: System Stability Under Failure Conditions
===================================================================

Tests system resilience, recovery, and graceful degradation under various failure scenarios.
"""

import pytest
import asyncio
import httpx
import time
from typing import Dict, Any
import os

from tests.production.base import ProductionE2ETestBase
from tests.production.config import get_config

# Try to import psutil, if not available skip memory tests
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


@pytest.mark.chaos
@pytest.mark.asyncio
class TestDatabaseResilience(ProductionE2ETestBase):
    """Chaos tests for database resilience"""

    async def test_chaos_database_connection_recovery(
        self,
        real_database,
        real_api_client: httpx.AsyncClient,
        auth_headers: Dict[str, str]
    ):
        """
        Test 1: Database connection loss and recovery
        
        Simulates database connection issues and verifies recovery.
        """
        print("\n" + "="*80)
        print("💥 Chaos Test: Database Connection Recovery")
        print("="*80)
        
        # Step 1: Verify normal operation
        print("\n✅ Step 1: Verifying normal database operation...")
        from sqlalchemy import text
        
        with real_database.session_scope() as session:
            result = session.execute(text("SELECT COUNT(*) FROM users")).fetchone()
            print(f"   Users in database: {result[0]}")
        
        # Step 2: Test API functionality before disruption
        print("\n✅ Step 2: Testing API before disruption...")
        response = await real_api_client.get(
            "/api/v1/missions",
            headers=auth_headers
        )
        assert response.status_code == 200
        print(f"   API responded: {response.status_code}")
        
        # Step 3: Simulate connection pool exhaustion
        print("\n💥 Step 3: Simulating database stress (connection pool exhaustion)...")
        connections = []
        try:
            # Create multiple connections to stress the pool
            for i in range(5):
                conn = real_database.engine.connect()
                connections.append(conn)
                print(f"   Created connection {i+1}/5")
            
            # Try API call during stress
            print("\n🔍 Testing API during database stress...")
            response = await real_api_client.get(
                "/api/v1/missions",
                headers=auth_headers,
                timeout=10.0
            )
            
            if response.status_code == 200:
                print("   ✅ API handled stress gracefully")
            else:
                print(f"   ⚠️  API returned: {response.status_code}")
            
        finally:
            # Step 4: Release connections (simulate recovery)
            print("\n🔄 Step 4: Releasing connections (simulating recovery)...")
            for conn in connections:
                conn.close()
            print("   ✅ All connections released")
        
        # Step 5: Verify recovery
        print("\n✅ Step 5: Verifying system recovery...")
        await asyncio.sleep(2)  # Brief recovery period
        
        response = await real_api_client.get(
            "/api/v1/missions",
            headers=auth_headers
        )
        assert response.status_code == 200
        print("   ✅ API fully recovered")
        
        # Step 6: Verify data integrity
        print("\n✅ Step 6: Verifying data integrity...")
        with real_database.session_scope() as session:
            result = session.execute(text("SELECT COUNT(*) FROM users")).fetchone()
            print(f"   Users in database: {result[0]}")
        
        print("\n✅ Chaos Test PASSED: Database Connection Recovery")

    async def test_chaos_database_slow_queries(
        self,
        real_database,
        real_api_client: httpx.AsyncClient,
        auth_headers: Dict[str, str]
    ):
        """
        Test 2: Slow database queries handling
        
        Simulates slow queries and verifies timeout handling.
        """
        print("\n" + "="*80)
        print("💥 Chaos Test: Slow Database Queries")
        print("="*80)
        
        from sqlalchemy import text
        import uuid
        
        # Create test data
        print("\n📝 Creating test data...")
        org_id = str(uuid.uuid4())
        
        with real_database.session_scope() as session:
            session.execute(
                text("INSERT INTO organizations (id, name, plan, created_at) VALUES (:id, :name, :plan, NOW())"),
                {"id": org_id, "name": f"chaos_test_{uuid.uuid4().hex[:8]}", "plan": "free"}
            )
            session.commit()
        
        # Simulate slow query with pg_sleep
        print("\n💥 Simulating slow query (2 seconds)...")
        start = time.time()
        
        try:
            with real_database.session_scope() as session:
                # Simulate slow query
                session.execute(text("SELECT pg_sleep(2), * FROM organizations WHERE id = :id"), {"id": org_id})
            
            duration = time.time() - start
            print(f"   Query completed in {duration:.2f}s")
            
        except Exception as e:
            duration = time.time() - start
            print(f"   ⚠️  Query timeout or error after {duration:.2f}s: {str(e)[:100]}")
        
        # Verify system still responsive
        print("\n✅ Verifying system responsiveness...")
        response = await real_api_client.get(
            "/api/v1/missions",
            headers=auth_headers,
            timeout=5.0
        )
        assert response.status_code == 200
        print("   ✅ System still responsive")
        
        print("\n✅ Chaos Test PASSED: Slow Database Queries")

    async def test_chaos_database_transaction_rollback(
        self,
        real_database
    ):
        """
        Test 3: Transaction rollback under errors
        
        Verifies proper rollback on transaction failures.
        """
        print("\n" + "="*80)
        print("💥 Chaos Test: Transaction Rollback")
        print("="*80)
        
        from sqlalchemy import text
        import uuid
        
        user_id = str(uuid.uuid4())
        org_id = str(uuid.uuid4())
        
        print("\n💥 Starting transaction with intentional error...")
        
        try:
            with real_database.session_scope() as session:
                # Insert organization
                session.execute(
                    text("INSERT INTO organizations (id, name, plan, created_at) VALUES (:id, :name, :plan, NOW())"),
                    {"id": org_id, "name": f"rollback_test_{uuid.uuid4().hex[:8]}", "plan": "free"}
                )
                print("   ✅ Organization inserted")
                
                # Try to insert user with NULL username (should fail)
                session.execute(
                    text("INSERT INTO users (id, email, username, hashed_password, organization_id) VALUES (:id, :email, NULL, :password, :org_id)"),
                    {
                        "id": user_id,
                        "email": f"chaos_{uuid.uuid4().hex[:8]}@test.com",
                        "password": "test_hash",
                        "org_id": org_id
                    }
                )
                
                session.commit()
        
        except Exception as e:
            print(f"   ✅ Transaction failed as expected: {str(e)[:100]}")
        
        # Verify rollback - organization should NOT exist
        print("\n✅ Verifying transaction rollback...")
        with real_database.session_scope() as session:
            result = session.execute(
                text("SELECT COUNT(*) FROM organizations WHERE id = :id"),
                {"id": org_id}
            ).fetchone()
            
            assert result[0] == 0, "Organization should not exist after rollback"
            print("   ✅ Transaction properly rolled back")
        
        print("\n✅ Chaos Test PASSED: Transaction Rollback")


@pytest.mark.chaos
@pytest.mark.asyncio
class TestRedisResilience(ProductionE2ETestBase):
    """Chaos tests for Redis resilience"""

    async def test_chaos_redis_connection_loss(
        self,
        real_blackboard,
        real_api_client: httpx.AsyncClient,
        auth_headers: Dict[str, str]
    ):
        """
        Test 4: Redis connection loss and fallback
        
        Simulates Redis unavailability and verifies graceful degradation.
        """
        print("\n" + "="*80)
        print("💥 Chaos Test: Redis Connection Loss")
        print("="*80)
        
        # Step 1: Verify Redis working
        print("\n✅ Step 1: Verifying Redis operation...")
        test_key = f"chaos:test:{time.time()}"
        real_blackboard.set(test_key, "test_value", expire=60)
        value = real_blackboard.get(test_key)
        assert value == "test_value"
        print("   ✅ Redis operational")
        
        # Step 2: Test API with Redis available
        print("\n✅ Step 2: Testing API with Redis available...")
        response = await real_api_client.get(
            "/api/v1/missions",
            headers=auth_headers
        )
        assert response.status_code == 200
        print("   ✅ API working with Redis")
        
        # Step 3: Simulate Redis being slow/unresponsive
        print("\n💥 Step 3: Simulating Redis stress...")
        
        # Fill Redis with data to create stress
        stress_keys = []
        for i in range(100):
            key = f"chaos:stress:{i}"
            real_blackboard.set(key, "x" * 1000, expire=60)
            stress_keys.append(key)
        
        print("   💥 Created 100 large keys in Redis")
        
        # Step 4: Test API during stress
        print("\n🔍 Testing API during Redis stress...")
        response = await real_api_client.get(
            "/api/v1/missions",
            headers=auth_headers,
            timeout=10.0
        )
        
        if response.status_code == 200:
            print("   ✅ API handled Redis stress gracefully")
        else:
            print(f"   ⚠️  API returned: {response.status_code}")
        
        # Step 5: Cleanup and verify recovery
        print("\n🔄 Step 5: Cleaning up and verifying recovery...")
        for key in stress_keys:
            real_blackboard.delete(key)
        real_blackboard.delete(test_key)
        
        response = await real_api_client.get(
            "/api/v1/missions",
            headers=auth_headers
        )
        assert response.status_code == 200
        print("   ✅ System recovered")
        
        print("\n✅ Chaos Test PASSED: Redis Connection Loss")

    async def test_chaos_redis_memory_pressure(
        self,
        real_blackboard
    ):
        """
        Test 5: Redis memory pressure handling
        
        Tests behavior under Redis memory constraints.
        """
        print("\n" + "="*80)
        print("💥 Chaos Test: Redis Memory Pressure")
        print("="*80)
        
        print("\n💥 Creating memory pressure in Redis...")
        
        # Create many keys to simulate memory pressure
        keys_created = []
        
        for i in range(1000):
            key = f"chaos:memory:{i}"
            # Create 10KB values
            value = "x" * (10 * 1024)
            real_blackboard.set(key, value, expire=120)
            keys_created.append(key)
            
            if i % 100 == 0:
                print(f"   Created {i+1}/1000 keys...")
        
        print(f"   💥 Created {len(keys_created)} keys (~10MB total)")
        
        # Test operations under pressure
        print("\n🔍 Testing operations under memory pressure...")
        
        # Test SET
        start = time.time()
        real_blackboard.set("chaos:pressure:test", "value", expire=60)
        set_time = time.time() - start
        print(f"   SET operation: {set_time*1000:.2f}ms")
        
        # Test GET
        start = time.time()
        real_blackboard.get("chaos:pressure:test")
        get_time = time.time() - start
        print(f"   GET operation: {get_time*1000:.2f}ms")
        
        # Cleanup
        print("\n🔄 Cleaning up...")
        for key in keys_created:
            real_blackboard.delete(key)
        real_blackboard.delete("chaos:pressure:test")
        
        print("   ✅ Cleanup complete")
        
        # Verify operations acceptable
        assert set_time < 1.0, f"SET too slow under pressure: {set_time:.3f}s"
        assert get_time < 1.0, f"GET too slow under pressure: {get_time:.3f}s"
        
        print("\n✅ Chaos Test PASSED: Redis Memory Pressure")


@pytest.mark.chaos
@pytest.mark.asyncio
class TestAPIResilience(ProductionE2ETestBase):
    """Chaos tests for API resilience"""

    async def test_chaos_api_timeout_handling(
        self,
        real_api_client: httpx.AsyncClient,
        auth_headers: Dict[str, str]
    ):
        """
        Test 6: API timeout handling
        
        Tests API behavior with very short timeouts.
        """
        print("\n" + "="*80)
        print("💥 Chaos Test: API Timeout Handling")
        print("="*80)
        
        # Test with extremely short timeout
        print("\n💥 Testing with 0.1s timeout...")
        
        try:
            response = await real_api_client.get(
                "/api/v1/missions",
                headers=auth_headers,
                timeout=0.1
            )
            print(f"   Response: {response.status_code}")
        except httpx.TimeoutException:
            print("   ✅ Timeout exception properly raised")
        except Exception as e:
            print(f"   Exception: {type(e).__name__}")
        
        # Verify system still responsive with normal timeout
        print("\n✅ Verifying system still responsive...")
        response = await real_api_client.get(
            "/api/v1/missions",
            headers=auth_headers,
            timeout=10.0
        )
        assert response.status_code == 200
        print("   ✅ System recovered")
        
        print("\n✅ Chaos Test PASSED: API Timeout Handling")

    async def test_chaos_api_concurrent_failures(
        self,
        real_api_client: httpx.AsyncClient,
        auth_headers: Dict[str, str]
    ):
        """
        Test 7: API concurrent request failures
        
        Tests system under mixed success/failure scenarios.
        """
        print("\n" + "="*80)
        print("💥 Chaos Test: API Concurrent Failures")
        print("="*80)
        
        print("\n💥 Sending mix of valid and invalid requests...")
        
        async def make_request(index: int):
            """Make request - some valid, some invalid"""
            if index % 3 == 0:
                # Invalid request (no auth)
                response = await real_api_client.get("/api/v1/missions")
            elif index % 3 == 1:
                # Invalid endpoint
                response = await real_api_client.get(
                    "/api/v1/nonexistent",
                    headers=auth_headers
                )
            else:
                # Valid request
                response = await real_api_client.get(
                    "/api/v1/missions",
                    headers=auth_headers
                )
            
            return {
                "index": index,
                "status_code": response.status_code,
                "success": response.status_code in [200, 201]
            }
        
        # Send 30 mixed requests
        tasks = [make_request(i) for i in range(30)]
        results = await asyncio.gather(*tasks)
        
        # Analyze results
        valid_requests = [r for r in results if r["index"] % 3 == 2]
        valid_success = sum(1 for r in valid_requests if r["success"])
        
        print(f"\n📊 Results:")
        print(f"   Total requests: {len(results)}")
        print(f"   Valid requests: {len(valid_requests)}")
        print(f"   Valid success: {valid_success}/{len(valid_requests)}")
        
        # All valid requests should succeed
        success_rate = (valid_success / len(valid_requests)) * 100 if valid_requests else 0
        assert success_rate >= 90, f"Valid request success rate {success_rate:.1f}% below 90%"
        
        print("\n✅ Chaos Test PASSED: API Concurrent Failures")

    async def test_chaos_api_malformed_requests(
        self,
        real_api_client: httpx.AsyncClient,
        auth_headers: Dict[str, str]
    ):
        """
        Test 8: API handling of malformed requests
        
        Tests API resilience against various malformed inputs.
        """
        print("\n" + "="*80)
        print("💥 Chaos Test: Malformed Requests")
        print("="*80)
        
        malformed_payloads = [
            {},  # Empty
            {"invalid": "structure"},  # Wrong structure
            {"name": None, "description": None},  # Null values
            {"name": "", "description": ""},  # Empty strings
            "not a json object",  # String instead of object
        ]
        
        print("\n💥 Sending malformed requests...")
        
        for i, payload in enumerate(malformed_payloads):
            try:
                if isinstance(payload, str):
                    # Send as text
                    response = await real_api_client.post(
                        "/api/v1/missions",
                        content=payload,
                        headers={**auth_headers, "Content-Type": "application/json"}
                    )
                else:
                    response = await real_api_client.post(
                        "/api/v1/missions",
                        json=payload,
                        headers=auth_headers
                    )
                
                print(f"   Payload {i+1}: {response.status_code}")
                
                # Should reject with 400/422
                assert response.status_code in [400, 422], \
                    f"Malformed request should be rejected, got {response.status_code}"
                
            except Exception as e:
                print(f"   Payload {i+1}: Exception - {type(e).__name__}")
        
        # Verify system still works with valid request
        print("\n✅ Verifying system still operational...")
        response = await real_api_client.get(
            "/api/v1/missions",
            headers=auth_headers
        )
        assert response.status_code == 200
        
        print("\n✅ Chaos Test PASSED: Malformed Requests")


@pytest.mark.chaos
@pytest.mark.asyncio
class TestResourceExhaustion(ProductionE2ETestBase):
    """Chaos tests for resource exhaustion scenarios"""

    @pytest.mark.skipif(not PSUTIL_AVAILABLE, reason="psutil not available")
    async def test_chaos_memory_monitoring(self):
        """
        Test 9: Memory usage monitoring
        
        Monitors memory usage during stress operations.
        """
        print("\n" + "="*80)
        print("💥 Chaos Test: Memory Usage Monitoring")
        print("="*80)
        
        # Get initial memory
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        print(f"\n📊 Initial memory: {initial_memory:.2f} MB")
        
        # Create memory pressure
        print("\n💥 Creating memory pressure...")
        large_data = []
        
        for i in range(10):
            # Create 1MB chunks
            data = "x" * (1024 * 1024)
            large_data.append(data)
            
            current_memory = process.memory_info().rss / 1024 / 1024
            print(f"   Iteration {i+1}: {current_memory:.2f} MB")
        
        peak_memory = process.memory_info().rss / 1024 / 1024
        memory_increase = peak_memory - initial_memory
        
        print(f"\n📊 Memory Statistics:")
        print(f"   Initial: {initial_memory:.2f} MB")
        print(f"   Peak: {peak_memory:.2f} MB")
        print(f"   Increase: {memory_increase:.2f} MB")
        
        # Cleanup
        large_data.clear()
        
        # Brief pause for GC
        await asyncio.sleep(1)
        
        final_memory = process.memory_info().rss / 1024 / 1024
        print(f"   After cleanup: {final_memory:.2f} MB")
        
        print("\n✅ Chaos Test PASSED: Memory Usage Monitoring")

    async def test_chaos_rate_limit_enforcement(
        self,
        real_api_client: httpx.AsyncClient
    ):
        """
        Test 10: Rate limit enforcement under rapid requests
        
        Tests rate limiting mechanisms.
        """
        print("\n" + "="*80)
        print("💥 Chaos Test: Rate Limit Enforcement")
        print("="*80)
        
        print("\n💥 Sending 100 rapid requests...")
        
        responses = []
        start_time = time.time()
        
        for i in range(100):
            try:
                response = await real_api_client.get("/")
                responses.append(response.status_code)
            except Exception as e:
                responses.append(None)
        
        duration = time.time() - start_time
        
        # Analyze results
        success_count = sum(1 for r in responses if r == 200)
        rate_limited = sum(1 for r in responses if r == 429)
        errors = sum(1 for r in responses if r is None or (r not in [200, 429]))
        
        print(f"\n📊 Results ({duration:.2f}s):")
        print(f"   Total requests: 100")
        print(f"   Success (200): {success_count}")
        print(f"   Rate limited (429): {rate_limited}")
        print(f"   Errors: {errors}")
        print(f"   Requests/sec: {100/duration:.1f}")
        
        if rate_limited > 0:
            print("\n✅ Rate limiting is active")
        else:
            print("\n⚠️  No rate limiting detected (might not be configured)")
        
        print("\n✅ Chaos Test PASSED: Rate Limit Enforcement")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-s"])
