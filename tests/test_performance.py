# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Performance Tests
# Load testing and performance benchmarks
# ═══════════════════════════════════════════════════════════════

import pytest
import asyncio
import time
from datetime import datetime
from uuid import uuid4
from typing import List
from unittest.mock import AsyncMock, MagicMock, patch

from src.core.models import (
    Mission, MissionCreate, MissionStatus,
    Target, TargetStatus, Priority,
    Vulnerability, Severity,
    Task, TaskType, TaskStatus, SpecialistType,
)
from src.core.blackboard import Blackboard
from src.controller.mission import MissionController


# ═══════════════════════════════════════════════════════════════
# Mock Redis for Performance Testing
# ═══════════════════════════════════════════════════════════════

class MockRedis:
    """Mock Redis for performance testing without actual Redis connection."""
    
    def __init__(self):
        self.data = {}
        self.sets = {}
        self.sorted_sets = {}
        self.lists = {}
        self.streams = {}
        self.pubsub = None
    
    async def ping(self):
        return True
    
    async def hset(self, key, mapping=None, **kwargs):
        if mapping:
            if key not in self.data:
                self.data[key] = {}
            self.data[key].update(mapping)
        return len(mapping) if mapping else 0
    
    async def hgetall(self, key):
        return self.data.get(key, {})
    
    async def hget(self, key, field):
        return self.data.get(key, {}).get(field)
    
    async def hincrby(self, key, field, amount):
        if key not in self.data:
            self.data[key] = {}
        current = int(self.data[key].get(field, 0))
        self.data[key][field] = str(current + amount)
        return current + amount
    
    async def sadd(self, key, *values):
        if key not in self.sets:
            self.sets[key] = set()
        self.sets[key].update(values)
        return len(values)
    
    async def smembers(self, key):
        return self.sets.get(key, set())
    
    async def srem(self, key, *values):
        if key in self.sets:
            for v in values:
                self.sets[key].discard(v)
        return len(values)
    
    async def zadd(self, key, mapping):
        if key not in self.sorted_sets:
            self.sorted_sets[key] = {}
        self.sorted_sets[key].update(mapping)
        return len(mapping)
    
    async def zrevrange(self, key, start, end, withscores=False):
        if key not in self.sorted_sets:
            return []
        items = sorted(
            self.sorted_sets[key].items(),
            key=lambda x: x[1],
            reverse=True
        )
        if end == -1:
            items = items[start:]
        else:
            items = items[start:end+1]
        if withscores:
            return items
        return [item[0] for item in items]
    
    async def zrem(self, key, *members):
        if key in self.sorted_sets:
            for m in members:
                self.sorted_sets[key].pop(m, None)
        return len(members)
    
    async def lpush(self, key, *values):
        if key not in self.lists:
            self.lists[key] = []
        for v in values:
            self.lists[key].insert(0, v)
        return len(self.lists[key])
    
    async def lrange(self, key, start, end):
        if key not in self.lists:
            return []
        if end == -1:
            return self.lists[key][start:]
        return self.lists[key][start:end+1]
    
    async def xadd(self, key, fields):
        if key not in self.streams:
            self.streams[key] = []
        stream_id = f"{int(time.time()*1000)}-{len(self.streams[key])}"
        self.streams[key].append((stream_id, fields))
        return stream_id
    
    async def xrange(self, key, min="-", max="+", count=None):
        if key not in self.streams:
            return []
        return self.streams[key][:count] if count else self.streams[key]
    
    async def delete(self, *keys):
        for key in keys:
            self.data.pop(key, None)
            self.sets.pop(key, None)
            self.sorted_sets.pop(key, None)
        return len(keys)
    
    async def publish(self, channel, message):
        return 1
    
    def pubsub(self):
        self.pubsub = MockPubSub()
        return self.pubsub
    
    async def close(self):
        pass
    
    async def eval(self, script, num_keys, *args):
        """
        Mock Redis eval for Lua scripts.
        Simulates the claim_task Lua script behavior.
        """
        if num_keys >= 2:
            pending_key = args[0]
            running_key = args[1]
            specialist = args[2] if len(args) > 2 else None
            worker_id = args[3] if len(args) > 3 else None
            started_at = args[4] if len(args) > 4 else None
            running_status = args[5] if len(args) > 5 else None
            
            # Get tasks from pending sorted set (simulating ZREVRANGE)
            if pending_key in self.sorted_sets:
                tasks = sorted(self.sorted_sets[pending_key].items(), key=lambda x: x[1], reverse=True)
                
                for task_key, _ in tasks:
                    # Get task specialist from storage
                    task_data = self.data.get(task_key, {})
                    task_specialist = task_data.get('specialist')
                    
                    if task_specialist == specialist:
                        # Remove from pending (ZREM)
                        self.sorted_sets[pending_key].pop(task_key, None)
                        
                        # Add to running set (SADD)
                        if running_key not in self.sets:
                            self.sets[running_key] = set()
                        self.sets[running_key].add(task_key)
                        
                        # Update task fields (HSET)
                        if task_key in self.data:
                            self.data[task_key]['status'] = running_status
                            self.data[task_key]['assigned_to'] = worker_id
                            self.data[task_key]['started_at'] = started_at
                            self.data[task_key]['updated_at'] = started_at
                        
                        return task_key
        
        return None


class MockPubSub:
    """Mock Pub/Sub for testing."""
    
    async def subscribe(self, *channels):
        pass
    
    async def get_message(self, ignore_subscribe_messages=True, timeout=1.0):
        return None
    
    async def close(self):
        pass


# ═══════════════════════════════════════════════════════════════
# Performance Test Fixtures
# ═══════════════════════════════════════════════════════════════

@pytest.fixture
def mock_redis():
    """Create mock Redis for testing."""
    return MockRedis()


@pytest.fixture
def performance_blackboard(mock_redis):
    """Create Blackboard with mock Redis."""
    blackboard = Blackboard()
    blackboard._redis = mock_redis
    blackboard._connected = True
    return blackboard


# ═══════════════════════════════════════════════════════════════
# Blackboard Performance Tests
# ═══════════════════════════════════════════════════════════════

class TestBlackboardPerformance:
    """Performance tests for Blackboard operations."""
    
    @pytest.mark.asyncio
    async def test_bulk_target_creation(self, performance_blackboard):
        """Test creating many targets quickly."""
        blackboard = performance_blackboard
        mission_id = str(uuid4())
        
        # Create mission first
        mission = Mission(
            id=uuid4(),
            name="Performance Test Mission",
            scope=["192.168.0.0/16"],
            goals={"test": "pending"}
        )
        await blackboard.create_mission(mission)
        
        start_time = time.time()
        num_targets = 100
        
        for i in range(num_targets):
            target = Target(
                mission_id=mission.id,
                ip=f"192.168.{i//256}.{i%256}",
                status=TargetStatus.DISCOVERED
            )
            await blackboard.add_target(target)
        
        elapsed = time.time() - start_time
        
        # Should complete within reasonable time
        assert elapsed < 5.0, f"Creating {num_targets} targets took {elapsed:.2f}s"
        
        # Verify all targets were created
        targets = await blackboard.get_mission_targets(str(mission.id))
        assert len(targets) == num_targets
    
    @pytest.mark.asyncio
    async def test_bulk_vulnerability_creation(self, performance_blackboard):
        """Test creating many vulnerabilities quickly."""
        blackboard = performance_blackboard
        mission_id = str(uuid4())
        target_id = str(uuid4())
        
        start_time = time.time()
        num_vulns = 50
        
        for i in range(num_vulns):
            vuln = Vulnerability(
                mission_id=uuid4(),
                target_id=uuid4(),
                type=f"CVE-2025-{1000+i}",
                severity=Severity.HIGH,
                cvss=7.5 + (i % 30) / 10
            )
            await blackboard.add_vulnerability(vuln)
        
        elapsed = time.time() - start_time
        
        assert elapsed < 3.0, f"Creating {num_vulns} vulns took {elapsed:.2f}s"
    
    @pytest.mark.asyncio
    async def test_bulk_task_creation_and_claiming(self, performance_blackboard):
        """Test creating and claiming many tasks."""
        blackboard = performance_blackboard
        mission = Mission(
            name="Task Test",
            scope=["10.0.0.0/8"],
            goals={"test": "pending"}
        )
        mission_id = await blackboard.create_mission(mission)
        
        # Create tasks
        start_time = time.time()
        num_tasks = 50
        
        for i in range(num_tasks):
            task = Task(
                mission_id=mission.id,
                type=TaskType.PORT_SCAN,
                specialist=SpecialistType.RECON,
                priority=10 - (i % 10)
            )
            await blackboard.add_task(task)
        
        create_time = time.time() - start_time
        
        # Claim tasks
        start_time = time.time()
        claimed = 0
        
        for _ in range(num_tasks):
            task_id = await blackboard.claim_task(
                mission_id,
                "worker-1",
                SpecialistType.RECON.value
            )
            if task_id:
                claimed += 1
        
        claim_time = time.time() - start_time
        
        assert create_time < 3.0, f"Creating {num_tasks} tasks took {create_time:.2f}s"
        assert claim_time < 5.0, f"Claiming {num_tasks} tasks took {claim_time:.2f}s"
        assert claimed == num_tasks
    
    @pytest.mark.asyncio
    async def test_concurrent_operations(self, performance_blackboard):
        """Test concurrent Blackboard operations."""
        blackboard = performance_blackboard
        mission = Mission(
            name="Concurrent Test",
            scope=["10.0.0.0/8"],
            goals={"test": "pending"}
        )
        mission_id = await blackboard.create_mission(mission)
        
        async def add_targets(count: int):
            for i in range(count):
                target = Target(
                    mission_id=mission.id,
                    ip=f"10.0.{i//256}.{i%256}"
                )
                await blackboard.add_target(target)
        
        async def add_vulns(count: int):
            for i in range(count):
                vuln = Vulnerability(
                    mission_id=mission.id,
                    target_id=uuid4(),
                    type=f"VULN-{i}",
                    severity=Severity.MEDIUM
                )
                await blackboard.add_vulnerability(vuln)
        
        start_time = time.time()
        
        # Run operations concurrently
        await asyncio.gather(
            add_targets(30),
            add_vulns(30),
            add_targets(30),
            add_vulns(30),
        )
        
        elapsed = time.time() - start_time
        
        assert elapsed < 5.0, f"Concurrent operations took {elapsed:.2f}s"


# ═══════════════════════════════════════════════════════════════
# Controller Performance Tests
# ═══════════════════════════════════════════════════════════════

class TestControllerPerformance:
    """Performance tests for Mission Controller."""
    
    @pytest.mark.asyncio
    async def test_mission_creation_performance(self, performance_blackboard):
        """Test mission creation performance."""
        controller = MissionController(blackboard=performance_blackboard)
        
        start_time = time.time()
        num_missions = 20
        mission_ids = []
        
        for i in range(num_missions):
            mission_data = MissionCreate(
                name=f"Performance Test {i}",
                scope=[f"10.{i}.0.0/24"],
                goals=["goal1", "goal2"]
            )
            mission_id = await controller.create_mission(mission_data)
            mission_ids.append(mission_id)
        
        elapsed = time.time() - start_time
        
        assert elapsed < 3.0, f"Creating {num_missions} missions took {elapsed:.2f}s"
        assert len(mission_ids) == num_missions
    
    @pytest.mark.asyncio
    async def test_status_retrieval_performance(self, performance_blackboard):
        """Test mission status retrieval performance."""
        controller = MissionController(blackboard=performance_blackboard)
        
        # Create a mission
        mission_data = MissionCreate(
            name="Status Test",
            scope=["192.168.1.0/24"],
            goals=["goal1"]
        )
        mission_id = await controller.create_mission(mission_data)
        
        # Add some data
        for i in range(10):
            target = Target(
                mission_id=uuid4(),
                ip=f"192.168.1.{i+1}"
            )
            await performance_blackboard.add_target(target)
        
        start_time = time.time()
        num_requests = 100
        
        for _ in range(num_requests):
            status = await controller.get_mission_status(mission_id)
        
        elapsed = time.time() - start_time
        
        assert elapsed < 2.0, f"{num_requests} status requests took {elapsed:.2f}s"


# ═══════════════════════════════════════════════════════════════
# Memory and Resource Tests
# ═══════════════════════════════════════════════════════════════

class TestResourceUsage:
    """Tests for resource usage and memory leaks."""
    
    @pytest.mark.asyncio
    async def test_no_memory_leak_on_repeated_operations(self, performance_blackboard):
        """Test that repeated operations don't cause memory leaks."""
        import gc
        
        blackboard = performance_blackboard
        mission = Mission(
            name="Memory Test",
            scope=["10.0.0.0/8"],
            goals={"test": "pending"}
        )
        mission_id = await blackboard.create_mission(mission)
        
        # Perform many operations
        for _ in range(100):
            target = Target(
                mission_id=mission.id,
                ip="10.0.0.1"
            )
            await blackboard.add_target(target)
            
            # Force garbage collection
            gc.collect()
        
        # If we get here without running out of memory, test passes
    
    @pytest.mark.asyncio
    async def test_large_data_handling(self, performance_blackboard):
        """Test handling of large data structures."""
        blackboard = performance_blackboard
        
        # Create mission with large scope
        mission = Mission(
            name="Large Data Test",
            scope=[f"10.{i}.0.0/24" for i in range(100)],  # 100 CIDRs
            goals={f"goal_{i}": "pending" for i in range(50)}  # 50 goals
        )
        
        mission_id = await blackboard.create_mission(mission)
        
        # Should handle large data without issues
        retrieved = await blackboard.get_mission(mission_id)
        assert retrieved is not None


# ═══════════════════════════════════════════════════════════════
# Stress Tests
# ═══════════════════════════════════════════════════════════════

class TestStressConditions:
    """Stress tests for edge conditions."""
    
    @pytest.mark.asyncio
    async def test_rapid_task_creation_and_completion(self, performance_blackboard):
        """Test rapid task lifecycle."""
        blackboard = performance_blackboard
        mission = Mission(
            name="Stress Test",
            scope=["10.0.0.0/8"],
            goals={"test": "pending"}
        )
        mission_id = await blackboard.create_mission(mission)
        
        num_tasks = 50
        
        for _ in range(num_tasks):
            # Create task
            task = Task(
                mission_id=mission.id,
                type=TaskType.PORT_SCAN,
                specialist=SpecialistType.RECON,
                priority=5
            )
            task_id = await blackboard.add_task(task)
            
            # Claim task
            claimed_id = await blackboard.claim_task(
                mission_id,
                "worker-1",
                SpecialistType.RECON.value
            )
            
            # Complete task
            if claimed_id:
                await blackboard.complete_task(
                    mission_id,
                    claimed_id,
                    "success"
                )
        
        # Should complete without errors
    
    @pytest.mark.asyncio
    async def test_many_concurrent_workers(self, performance_blackboard):
        """Test many workers claiming tasks concurrently."""
        blackboard = performance_blackboard
        mission = Mission(
            name="Worker Test",
            scope=["10.0.0.0/8"],
            goals={"test": "pending"}
        )
        mission_id = await blackboard.create_mission(mission)
        
        # Create tasks
        num_tasks = 30
        for i in range(num_tasks):
            task = Task(
                mission_id=mission.id,
                type=TaskType.PORT_SCAN,
                specialist=SpecialistType.RECON,
                priority=(i % 10) + 1  # Priority must be >= 1
            )
            await blackboard.add_task(task)
        
        # Simulate multiple workers claiming
        async def worker_claim(worker_id: str):
            claimed = 0
            for _ in range(num_tasks):
                task_id = await blackboard.claim_task(
                    mission_id,
                    worker_id,
                    SpecialistType.RECON.value
                )
                if task_id:
                    claimed += 1
            return claimed
        
        # Run workers concurrently
        results = await asyncio.gather(
            worker_claim("worker-1"),
            worker_claim("worker-2"),
            worker_claim("worker-3"),
        )
        
        # Total claimed should equal total tasks
        total_claimed = sum(results)
        assert total_claimed == num_tasks


# ═══════════════════════════════════════════════════════════════
# Benchmark Tests
# ═══════════════════════════════════════════════════════════════

class TestBenchmarks:
    """Benchmark tests for key operations."""
    
    @pytest.mark.asyncio
    async def test_hash_operations_benchmark(self, performance_blackboard):
        """Benchmark hash operations."""
        blackboard = performance_blackboard
        
        iterations = 100
        
        # Benchmark write
        start = time.time()
        for i in range(iterations):
            await blackboard._set_hash(f"test:{i}", {"key": "value", "num": i})
        write_time = (time.time() - start) / iterations * 1000
        
        # Benchmark read
        start = time.time()
        for i in range(iterations):
            await blackboard._get_hash(f"test:{i}")
        read_time = (time.time() - start) / iterations * 1000
        
        print(f"\nHash Operations Benchmark:")
        print(f"  Write: {write_time:.3f}ms per operation")
        print(f"  Read: {read_time:.3f}ms per operation")
        
        # Should be reasonably fast
        assert write_time < 10  # Less than 10ms per write
        assert read_time < 10   # Less than 10ms per read
    
    @pytest.mark.asyncio
    async def test_sorted_set_benchmark(self, performance_blackboard):
        """Benchmark sorted set operations."""
        blackboard = performance_blackboard
        redis = blackboard.redis
        
        iterations = 100
        
        # Benchmark add
        start = time.time()
        for i in range(iterations):
            await redis.zadd(f"benchmark:zset", {f"item:{i}": i})
        add_time = (time.time() - start) / iterations * 1000
        
        # Benchmark range query
        start = time.time()
        for _ in range(iterations):
            await redis.zrevrange("benchmark:zset", 0, 9)
        range_time = (time.time() - start) / iterations * 1000
        
        print(f"\nSorted Set Benchmark:")
        print(f"  Add: {add_time:.3f}ms per operation")
        print(f"  Range: {range_time:.3f}ms per operation")
        
        assert add_time < 10
        assert range_time < 10
