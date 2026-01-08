"""
Performance Tests: Concurrent Operations and Load Testing
=========================================================

Tests system performance under various load conditions.
"""

import pytest
import asyncio
import httpx
import time
from typing import Dict, Any, List
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import statistics

from tests.production.base import ProductionE2ETestBase
from tests.production.config import get_config


@pytest.mark.performance
@pytest.mark.asyncio
class TestConcurrentOperations(ProductionE2ETestBase):
    """Performance tests for concurrent operations"""

    async def test_perf_concurrent_mission_creation(
        self,
        real_api_client: httpx.AsyncClient,
        auth_headers: Dict[str, str]
    ):
        """
        Test 1: Concurrent mission creation
        
        Creates 20 missions concurrently and measures:
        - Success rate
        - Average response time
        - Maximum response time
        - Throughput (missions/second)
        """
        print("\n" + "="*80)
        print("🚀 Performance Test: Concurrent Mission Creation (20 missions)")
        print("="*80)
        
        num_missions = 20
        mission_data_template = {
            "description": "Performance test mission",
            "scope": {
                "ip_ranges": ["192.168.100.0/24"]
            },
            "goals": ["reconnaissance"]
        }
        
        results = []
        start_time = time.time()
        
        async def create_mission(index: int):
            """Create single mission and measure time"""
            mission_data = mission_data_template.copy()
            mission_data["name"] = self.generate_mission_name(f"Perf Test {index}")
            
            request_start = time.time()
            try:
                response = await real_api_client.post(
                    "/api/v1/missions",
                    json=mission_data,
                    headers=auth_headers
                )
                request_time = time.time() - request_start
                
                return {
                    "index": index,
                    "success": response.status_code in [200, 201],
                    "status_code": response.status_code,
                    "response_time": request_time,
                    "mission_id": response.json().get("id") if response.status_code in [200, 201] else None
                }
            except Exception as e:
                request_time = time.time() - request_start
                return {
                    "index": index,
                    "success": False,
                    "status_code": None,
                    "response_time": request_time,
                    "error": str(e)
                }
        
        # Create missions concurrently
        print(f"\n⏳ Creating {num_missions} missions concurrently...")
        tasks = [create_mission(i) for i in range(num_missions)]
        results = await asyncio.gather(*tasks)
        
        total_time = time.time() - start_time
        
        # Calculate metrics
        successful = [r for r in results if r["success"]]
        failed = [r for r in results if not r["success"]]
        response_times = [r["response_time"] for r in results]
        
        success_rate = (len(successful) / num_missions) * 100
        avg_response_time = statistics.mean(response_times)
        median_response_time = statistics.median(response_times)
        max_response_time = max(response_times)
        min_response_time = min(response_times)
        std_dev = statistics.stdev(response_times) if len(response_times) > 1 else 0
        throughput = num_missions / total_time
        
        # Display results
        print("\n" + "="*80)
        print("📊 PERFORMANCE METRICS")
        print("="*80)
        print(f"Total Missions:        {num_missions}")
        print(f"Successful:            {len(successful)} ({success_rate:.1f}%)")
        print(f"Failed:                {len(failed)} ({100-success_rate:.1f}%)")
        print(f"\nTotal Time:            {total_time:.2f}s")
        print(f"Throughput:            {throughput:.2f} missions/second")
        print(f"\nResponse Times:")
        print(f"  Average:             {avg_response_time:.3f}s")
        print(f"  Median:              {median_response_time:.3f}s")
        print(f"  Min:                 {min_response_time:.3f}s")
        print(f"  Max:                 {max_response_time:.3f}s")
        print(f"  Std Dev:             {std_dev:.3f}s")
        print("="*80)
        
        # Assertions
        assert success_rate >= 90, \
            f"Success rate {success_rate:.1f}% below threshold of 90%"
        
        assert avg_response_time < 2.0, \
            f"Average response time {avg_response_time:.3f}s exceeds 2s threshold"
        
        assert max_response_time < 5.0, \
            f"Max response time {max_response_time:.3f}s exceeds 5s threshold"
        
        print("\n✅ Performance Test PASSED: Concurrent Mission Creation")

    async def test_perf_concurrent_api_requests(
        self,
        real_api_client: httpx.AsyncClient,
        auth_headers: Dict[str, str]
    ):
        """
        Test 2: Concurrent API requests to various endpoints
        
        Tests 50 concurrent requests to different endpoints:
        - GET /api/v1/missions (list)
        - GET / (health check)
        - GET /api/v1/auth/me (user info)
        """
        print("\n" + "="*80)
        print("🚀 Performance Test: Concurrent API Requests (50 requests)")
        print("="*80)
        
        num_requests = 50
        endpoints = [
            {"method": "GET", "path": "/api/v1/missions", "name": "List Missions"},
            {"method": "GET", "path": "/", "name": "Health Check"},
            {"method": "GET", "path": "/api/v1/auth/me", "name": "User Info"},
        ]
        
        async def make_request(index: int):
            """Make single API request"""
            endpoint = endpoints[index % len(endpoints)]
            
            request_start = time.time()
            try:
                if endpoint["method"] == "GET":
                    response = await real_api_client.get(
                        endpoint["path"],
                        headers=auth_headers if "auth" in endpoint["path"] or "missions" in endpoint["path"] else {}
                    )
                
                request_time = time.time() - request_start
                
                return {
                    "index": index,
                    "endpoint": endpoint["name"],
                    "success": response.status_code in [200, 201],
                    "status_code": response.status_code,
                    "response_time": request_time
                }
            except Exception as e:
                request_time = time.time() - request_start
                return {
                    "index": index,
                    "endpoint": endpoint["name"],
                    "success": False,
                    "status_code": None,
                    "response_time": request_time,
                    "error": str(e)
                }
        
        start_time = time.time()
        tasks = [make_request(i) for i in range(num_requests)]
        results = await asyncio.gather(*tasks)
        total_time = time.time() - start_time
        
        # Calculate metrics
        successful = [r for r in results if r["success"]]
        response_times = [r["response_time"] for r in results]
        
        success_rate = (len(successful) / num_requests) * 100
        avg_response_time = statistics.mean(response_times)
        throughput = num_requests / total_time
        
        # Group by endpoint
        by_endpoint = {}
        for r in results:
            endpoint = r["endpoint"]
            if endpoint not in by_endpoint:
                by_endpoint[endpoint] = []
            by_endpoint[endpoint].append(r)
        
        print("\n" + "="*80)
        print("📊 PERFORMANCE METRICS")
        print("="*80)
        print(f"Total Requests:        {num_requests}")
        print(f"Successful:            {len(successful)} ({success_rate:.1f}%)")
        print(f"Total Time:            {total_time:.2f}s")
        print(f"Throughput:            {throughput:.2f} requests/second")
        print(f"Average Response:      {avg_response_time:.3f}s")
        
        print("\n" + "-"*80)
        print("BY ENDPOINT:")
        print("-"*80)
        for endpoint_name, endpoint_results in by_endpoint.items():
            endpoint_times = [r["response_time"] for r in endpoint_results]
            endpoint_success = len([r for r in endpoint_results if r["success"]])
            print(f"\n{endpoint_name}:")
            print(f"  Requests:   {len(endpoint_results)}")
            print(f"  Success:    {endpoint_success}/{len(endpoint_results)}")
            print(f"  Avg Time:   {statistics.mean(endpoint_times):.3f}s")
            print(f"  Max Time:   {max(endpoint_times):.3f}s")
        print("="*80)
        
        assert success_rate >= 95, \
            f"Success rate {success_rate:.1f}% below threshold of 95%"
        
        assert avg_response_time < 1.0, \
            f"Average response time {avg_response_time:.3f}s exceeds 1s threshold"
        
        print("\n✅ Performance Test PASSED: Concurrent API Requests")

    async def test_perf_database_query_performance(
        self,
        real_database
    ):
        """
        Test 3: Database query performance
        
        Tests various database operations:
        - Simple SELECT queries
        - Complex JOINs
        - Aggregation queries
        - Bulk inserts
        """
        print("\n" + "="*80)
        print("🚀 Performance Test: Database Query Performance")
        print("="*80)
        
        from sqlalchemy import text
        import uuid
        
        test_results = {}
        
        # Test 1: Simple SELECT
        print("\n1️⃣  Testing simple SELECT queries (100 iterations)...")
        start = time.time()
        for _ in range(100):
            with real_database.session_scope() as session:
                session.execute(text("SELECT COUNT(*) FROM users")).fetchone()
        simple_select_time = (time.time() - start) / 100
        test_results["Simple SELECT"] = simple_select_time
        print(f"   Average time: {simple_select_time*1000:.2f}ms")
        
        # Test 2: Complex JOIN
        print("\n2️⃣  Testing complex JOIN queries (50 iterations)...")
        start = time.time()
        for _ in range(50):
            with real_database.session_scope() as session:
                session.execute(text("""
                    SELECT u.username, o.name, COUNT(m.id) as mission_count
                    FROM users u
                    JOIN organizations o ON u.organization_id = o.id
                    LEFT JOIN missions m ON m.organization_id = o.id
                    GROUP BY u.id, o.id
                    LIMIT 10
                """)).fetchall()
        complex_join_time = (time.time() - start) / 50
        test_results["Complex JOIN"] = complex_join_time
        print(f"   Average time: {complex_join_time*1000:.2f}ms")
        
        # Test 3: Bulk Insert
        print("\n3️⃣  Testing bulk insert (100 rows)...")
        org_id = str(uuid.uuid4())
        
        # Create org first
        with real_database.session_scope() as session:
            session.execute(
                text("INSERT INTO organizations (id, name, plan, created_at) VALUES (:id, :name, :plan, NOW())"),
                {"id": org_id, "name": f"perf_test_{uuid.uuid4().hex[:8]}", "plan": "free"}
            )
            session.commit()
        
        start = time.time()
        with real_database.session_scope() as session:
            for i in range(100):
                session.execute(
                    text("""
                        INSERT INTO users (id, email, username, hashed_password, organization_id, created_at)
                        VALUES (:id, :email, :username, :password, :org_id, NOW())
                    """),
                    {
                        "id": str(uuid.uuid4()),
                        "email": f"perf_{i}_{uuid.uuid4().hex[:8]}@test.com",
                        "username": f"perfuser_{i}_{uuid.uuid4().hex[:8]}",
                        "password": "test_hash",
                        "org_id": org_id
                    }
                )
            session.commit()
        bulk_insert_time = time.time() - start
        test_results["Bulk Insert (100 rows)"] = bulk_insert_time
        print(f"   Total time: {bulk_insert_time:.2f}s")
        print(f"   Per row: {bulk_insert_time*10:.2f}ms")
        
        # Display summary
        print("\n" + "="*80)
        print("📊 DATABASE PERFORMANCE SUMMARY")
        print("="*80)
        for operation, duration in test_results.items():
            if "Bulk" in operation:
                print(f"{operation:30s} {duration:.3f}s")
            else:
                print(f"{operation:30s} {duration*1000:.2f}ms")
        print("="*80)
        
        # Assertions
        assert simple_select_time < 0.050, \
            f"Simple SELECT too slow: {simple_select_time*1000:.2f}ms"
        
        assert complex_join_time < 0.200, \
            f"Complex JOIN too slow: {complex_join_time*1000:.2f}ms"
        
        assert bulk_insert_time < 5.0, \
            f"Bulk insert too slow: {bulk_insert_time:.2f}s"
        
        print("\n✅ Performance Test PASSED: Database Query Performance")

    async def test_perf_redis_cache_performance(
        self,
        real_blackboard
    ):
        """
        Test 4: Redis cache performance
        
        Tests various Redis operations:
        - SET/GET operations
        - Hash operations
        - List operations
        - Pipeline performance
        """
        print("\n" + "="*80)
        print("🚀 Performance Test: Redis Cache Performance")
        print("="*80)
        
        test_results = {}
        
        # Test 1: SET/GET operations (1000 iterations)
        print("\n1️⃣  Testing SET operations (1000 iterations)...")
        start = time.time()
        for i in range(1000):
            real_blackboard.set(f"perf:test:{i}", f"value_{i}", expire=60)
        set_time = time.time() - start
        test_results["SET (1000 ops)"] = set_time
        print(f"   Total time: {set_time:.3f}s")
        print(f"   Per operation: {set_time*1:.2f}ms")
        
        print("\n2️⃣  Testing GET operations (1000 iterations)...")
        start = time.time()
        for i in range(1000):
            real_blackboard.get(f"perf:test:{i}")
        get_time = time.time() - start
        test_results["GET (1000 ops)"] = get_time
        print(f"   Total time: {get_time:.3f}s")
        print(f"   Per operation: {get_time*1:.2f}ms")
        
        # Test 2: Hash operations
        print("\n3️⃣  Testing HASH operations (1000 iterations)...")
        hash_key = "perf:test:hash"
        start = time.time()
        for i in range(1000):
            real_blackboard.redis_client.hset(hash_key, f"field_{i}", f"value_{i}")
        hset_time = time.time() - start
        test_results["HSET (1000 ops)"] = hset_time
        print(f"   Total time: {hset_time:.3f}s")
        print(f"   Per operation: {hset_time*1:.2f}ms")
        
        # Test 3: Pipeline operations
        print("\n4️⃣  Testing PIPELINE operations (1000 ops)...")
        start = time.time()
        pipeline = real_blackboard.redis_client.pipeline()
        for i in range(1000):
            pipeline.set(f"perf:pipe:{i}", f"value_{i}")
        pipeline.execute()
        pipeline_time = time.time() - start
        test_results["PIPELINE (1000 ops)"] = pipeline_time
        print(f"   Total time: {pipeline_time:.3f}s")
        print(f"   Per operation: {pipeline_time*1:.2f}ms")
        print(f"   Speedup vs SET: {set_time/pipeline_time:.1f}x")
        
        # Display summary
        print("\n" + "="*80)
        print("📊 REDIS PERFORMANCE SUMMARY")
        print("="*80)
        for operation, duration in test_results.items():
            ops_per_sec = 1000 / duration
            print(f"{operation:30s} {duration:.3f}s  ({ops_per_sec:.0f} ops/sec)")
        print("="*80)
        
        # Cleanup
        for i in range(1000):
            real_blackboard.delete(f"perf:test:{i}")
            real_blackboard.delete(f"perf:pipe:{i}")
        real_blackboard.delete(hash_key)
        
        # Assertions
        assert set_time < 2.0, f"SET operations too slow: {set_time:.3f}s"
        assert get_time < 2.0, f"GET operations too slow: {get_time:.3f}s"
        assert pipeline_time < 0.5, f"Pipeline operations too slow: {pipeline_time:.3f}s"
        
        print("\n✅ Performance Test PASSED: Redis Cache Performance")


@pytest.mark.performance
@pytest.mark.asyncio
class TestLoadAndStress(ProductionE2ETestBase):
    """Load and stress testing"""

    async def test_perf_api_load_test(
        self,
        real_api_client: httpx.AsyncClient,
        auth_headers: Dict[str, str]
    ):
        """
        Test 5: API load test
        
        Simulates sustained load:
        - 100 requests over 10 seconds
        - 10 requests/second sustained
        - Measures latency distribution
        """
        print("\n" + "="*80)
        print("🚀 Performance Test: API Load Test (100 requests, 10 req/sec)")
        print("="*80)
        
        num_requests = 100
        duration_seconds = 10
        requests_per_second = num_requests / duration_seconds
        
        results = []
        start_time = time.time()
        
        async def make_request(index: int):
            request_start = time.time()
            try:
                response = await real_api_client.get(
                    "/api/v1/missions",
                    headers=auth_headers
                )
                request_time = time.time() - request_start
                
                return {
                    "index": index,
                    "success": response.status_code == 200,
                    "status_code": response.status_code,
                    "response_time": request_time,
                    "timestamp": time.time() - start_time
                }
            except Exception as e:
                request_time = time.time() - request_start
                return {
                    "index": index,
                    "success": False,
                    "status_code": None,
                    "response_time": request_time,
                    "timestamp": time.time() - start_time,
                    "error": str(e)
                }
        
        print(f"\n⏳ Executing load test: {requests_per_second:.1f} req/sec...")
        
        # Stagger requests over time
        delay_between_requests = 1.0 / requests_per_second
        tasks = []
        
        for i in range(num_requests):
            await asyncio.sleep(delay_between_requests)
            tasks.append(asyncio.create_task(make_request(i)))
        
        results = await asyncio.gather(*tasks)
        total_time = time.time() - start_time
        
        # Calculate metrics
        successful = [r for r in results if r["success"]]
        response_times = [r["response_time"] for r in results]
        
        success_rate = (len(successful) / num_requests) * 100
        avg_response_time = statistics.mean(response_times)
        p50 = statistics.median(response_times)
        p95 = sorted(response_times)[int(len(response_times) * 0.95)]
        p99 = sorted(response_times)[int(len(response_times) * 0.99)]
        max_response_time = max(response_times)
        actual_throughput = num_requests / total_time
        
        print("\n" + "="*80)
        print("📊 LOAD TEST RESULTS")
        print("="*80)
        print(f"Total Requests:        {num_requests}")
        print(f"Duration:              {total_time:.2f}s")
        print(f"Target Throughput:     {requests_per_second:.1f} req/sec")
        print(f"Actual Throughput:     {actual_throughput:.1f} req/sec")
        print(f"Success Rate:          {success_rate:.1f}%")
        print(f"\nLatency Distribution:")
        print(f"  Average:             {avg_response_time:.3f}s")
        print(f"  P50 (Median):        {p50:.3f}s")
        print(f"  P95:                 {p95:.3f}s")
        print(f"  P99:                 {p99:.3f}s")
        print(f"  Max:                 {max_response_time:.3f}s")
        print("="*80)
        
        # Assertions
        assert success_rate >= 98, \
            f"Success rate {success_rate:.1f}% below 98% threshold"
        
        assert p95 < 2.0, \
            f"P95 latency {p95:.3f}s exceeds 2s threshold"
        
        assert p99 < 3.0, \
            f"P99 latency {p99:.3f}s exceeds 3s threshold"
        
        print("\n✅ Performance Test PASSED: API Load Test")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-s"])
