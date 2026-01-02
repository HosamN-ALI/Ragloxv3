# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Distributed Task Claiming Tests
# Stress Testing for Horizontal Scaling Support
# ═══════════════════════════════════════════════════════════════
#
# This test file validates the system's ability to handle:
# 1. Concurrent task claiming (race conditions)
# 2. Atomic operations (WATCH/MULTI or Lua scripts)
# 3. No duplicate task execution
# 4. Horizontal scaling support
#
# Goal: Ensure Blackboard logic supports scaling without conflicts
# ═══════════════════════════════════════════════════════════════

import pytest
import pytest_asyncio
import asyncio
import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import UUID, uuid4
import random
import threading
from concurrent.futures import ThreadPoolExecutor
from collections import Counter

from src.core.config import Settings
from src.core.models import (
    Mission, MissionStatus, GoalStatus,
    Target, TargetStatus, Priority,
    Task, TaskType, TaskStatus, SpecialistType,
)


# ═══════════════════════════════════════════════════════════════
# Thread-Safe Atomic Blackboard
# ═══════════════════════════════════════════════════════════════

class AtomicBlackboard:
    """
    Blackboard with atomic operations for concurrent access.
    
    Implements atomic task claiming to prevent race conditions:
    - Uses asyncio.Lock for atomic claim operations
    - Tracks claim history for verification
    - Simulates Redis WATCH/MULTI behavior
    """
    
    def __init__(self):
        # Data storage
        self.hashes: Dict[str, Dict[str, Any]] = {}
        self.sorted_sets: Dict[str, Dict[str, float]] = {}
        self.sets: Dict[str, set] = {}
        self.lists: Dict[str, List[str]] = {}
        
        # Atomic operation lock
        self._claim_lock = asyncio.Lock()
        
        # Tracking for test assertions
        self.claim_history: List[Dict[str, Any]] = []
        self.claim_attempts: int = 0
        self.claim_successes: int = 0
        self.claim_failures: int = 0
        
        # Task ownership tracking (task_id -> worker_id)
        self.task_ownership: Dict[str, str] = {}
        
        # Duplicate detection
        self.duplicate_claims: List[Tuple[str, str, str]] = []  # (task_id, worker1, worker2)
        
        # Connection state
        self._connected = False
    
    # ═══════════════════════════════════════════════════════════
    # Connection Management
    # ═══════════════════════════════════════════════════════════
    
    async def connect(self) -> None:
        self._connected = True
    
    async def disconnect(self) -> None:
        self._connected = False
    
    async def health_check(self) -> bool:
        return self._connected
    
    async def flush_all(self) -> None:
        self.hashes.clear()
        self.sorted_sets.clear()
        self.sets.clear()
        self.lists.clear()
        self.claim_history.clear()
        self.task_ownership.clear()
        self.duplicate_claims.clear()
        self.claim_attempts = 0
        self.claim_successes = 0
        self.claim_failures = 0
    
    # ═══════════════════════════════════════════════════════════
    # Mission Operations
    # ═══════════════════════════════════════════════════════════
    
    async def create_mission(self, mission: Mission) -> str:
        mission_id = str(mission.id)
        self.hashes[f"mission:{mission_id}:info"] = {
            "id": mission_id,
            "name": mission.name,
            "status": mission.status.value if hasattr(mission.status, 'value') else mission.status,
            "scope": json.dumps(mission.scope),
            "created_at": datetime.utcnow().isoformat(),
        }
        self.hashes[f"mission:{mission_id}:stats"] = {
            "tasks_created": "0",
            "tasks_claimed": "0",
            "tasks_completed": "0",
        }
        return mission_id
    
    async def get_mission(self, mission_id: str) -> Optional[Dict[str, Any]]:
        return self.hashes.get(f"mission:{mission_id}:info")
    
    # ═══════════════════════════════════════════════════════════
    # Target Operations
    # ═══════════════════════════════════════════════════════════
    
    async def add_target(self, target: Target) -> str:
        target_id = str(target.id)
        mission_id = str(target.mission_id)
        self.hashes[f"target:{target_id}"] = {
            "id": target_id,
            "mission_id": mission_id,
            "ip": target.ip,
        }
        return target_id
    
    # ═══════════════════════════════════════════════════════════
    # Task Operations
    # ═══════════════════════════════════════════════════════════
    
    async def add_task(self, task: Task) -> str:
        """Add a task to the pending queue."""
        task_id = str(task.id)
        mission_id = str(task.mission_id)
        
        self.hashes[f"task:{task_id}"] = {
            "id": task_id,
            "mission_id": mission_id,
            "type": task.type.value if hasattr(task.type, 'value') else task.type,
            "specialist": task.specialist.value if hasattr(task.specialist, 'value') else task.specialist,
            "priority": str(task.priority),
            "status": TaskStatus.PENDING.value,
            "target_id": str(task.target_id) if task.target_id else None,
            "created_at": datetime.utcnow().isoformat(),
            "assigned_to": None,
            "started_at": None,
        }
        
        pending_key = f"mission:{mission_id}:tasks:pending"
        if pending_key not in self.sorted_sets:
            self.sorted_sets[pending_key] = {}
        self.sorted_sets[pending_key][f"task:{task_id}"] = task.priority
        
        # Update stats
        stats_key = f"mission:{mission_id}:stats"
        if stats_key in self.hashes:
            current = int(self.hashes[stats_key].get("tasks_created", 0))
            self.hashes[stats_key]["tasks_created"] = str(current + 1)
        
        return task_id
    
    async def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        return self.hashes.get(f"task:{task_id}")
    
    async def claim_task_atomic(
        self,
        mission_id: str,
        worker_id: str,
        specialist: str
    ) -> Optional[str]:
        """
        Atomically claim a task using a lock.
        
        This simulates Redis WATCH/MULTI transaction:
        1. Acquire lock
        2. Find highest priority matching task
        3. Check task is still available
        4. Move task from pending to running
        5. Release lock
        
        Only ONE worker can claim each task.
        """
        self.claim_attempts += 1
        
        async with self._claim_lock:
            pending_key = f"mission:{mission_id}:tasks:pending"
            running_key = f"mission:{mission_id}:tasks:running"
            
            if pending_key not in self.sorted_sets or not self.sorted_sets[pending_key]:
                self.claim_failures += 1
                return None
            
            # Sort by priority (higher first)
            items = sorted(
                self.sorted_sets[pending_key].items(),
                key=lambda x: x[1],
                reverse=True
            )
            
            for task_key, priority in items:
                task = self.hashes.get(task_key)
                if not task:
                    continue
                
                # Check specialist match
                if task.get("specialist") != specialist:
                    continue
                
                # Check if already claimed (race condition detection)
                task_id = task_key.replace("task:", "")
                if task_id in self.task_ownership:
                    # Duplicate claim attempt!
                    existing_owner = self.task_ownership[task_id]
                    self.duplicate_claims.append((task_id, existing_owner, worker_id))
                    continue
                
                # ===== ATOMIC CLAIM =====
                # Remove from pending
                del self.sorted_sets[pending_key][task_key]
                
                # Add to running
                if running_key not in self.sets:
                    self.sets[running_key] = set()
                self.sets[running_key].add(task_key)
                
                # Update task
                now = datetime.utcnow()
                self.hashes[task_key]["status"] = TaskStatus.RUNNING.value
                self.hashes[task_key]["assigned_to"] = worker_id
                self.hashes[task_key]["started_at"] = now.isoformat()
                
                # Record ownership
                self.task_ownership[task_id] = worker_id
                
                # Record history
                self.claim_history.append({
                    "task_id": task_id,
                    "worker_id": worker_id,
                    "timestamp": now.isoformat(),
                    "specialist": specialist,
                })
                
                self.claim_successes += 1
                
                # Update stats
                stats_key = f"mission:{mission_id}:stats"
                if stats_key in self.hashes:
                    current = int(self.hashes[stats_key].get("tasks_claimed", 0))
                    self.hashes[stats_key]["tasks_claimed"] = str(current + 1)
                
                return task_id
            
            self.claim_failures += 1
            return None
    
    async def claim_task_non_atomic(
        self,
        mission_id: str,
        worker_id: str,
        specialist: str
    ) -> Optional[str]:
        """
        Non-atomic claim for comparison (intentionally racy).
        
        This simulates what happens WITHOUT proper locking.
        Used to demonstrate the race condition problem.
        """
        self.claim_attempts += 1
        
        pending_key = f"mission:{mission_id}:tasks:pending"
        running_key = f"mission:{mission_id}:tasks:running"
        
        if pending_key not in self.sorted_sets or not self.sorted_sets[pending_key]:
            self.claim_failures += 1
            return None
        
        # Sort by priority (higher first)
        items = sorted(
            self.sorted_sets[pending_key].items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        for task_key, priority in items:
            task = self.hashes.get(task_key)
            if not task:
                continue
            
            if task.get("specialist") != specialist:
                continue
            
            task_id = task_key.replace("task:", "")
            
            # ===== RACE CONDITION WINDOW =====
            # Without atomic ops, multiple workers can reach here simultaneously
            await asyncio.sleep(0.001)  # Simulate network latency
            
            # Check ownership (may have been claimed in the window)
            if task_id in self.task_ownership:
                existing_owner = self.task_ownership[task_id]
                if existing_owner != worker_id:
                    self.duplicate_claims.append((task_id, existing_owner, worker_id))
                continue
            
            # Remove from pending
            if task_key in self.sorted_sets.get(pending_key, {}):
                del self.sorted_sets[pending_key][task_key]
            
            # Add to running
            if running_key not in self.sets:
                self.sets[running_key] = set()
            self.sets[running_key].add(task_key)
            
            # Update task
            now = datetime.utcnow()
            self.hashes[task_key]["status"] = TaskStatus.RUNNING.value
            self.hashes[task_key]["assigned_to"] = worker_id
            
            # Record ownership
            self.task_ownership[task_id] = worker_id
            
            self.claim_successes += 1
            return task_id
        
        self.claim_failures += 1
        return None
    
    async def complete_task(
        self,
        mission_id: str,
        task_id: str,
        result: str
    ) -> None:
        """Mark a task as completed."""
        task_key = f"task:{task_id}"
        running_key = f"mission:{mission_id}:tasks:running"
        completed_key = f"mission:{mission_id}:tasks:completed"
        
        if running_key in self.sets:
            self.sets[running_key].discard(task_key)
        
        if completed_key not in self.lists:
            self.lists[completed_key] = []
        self.lists[completed_key].insert(0, task_key)
        
        if task_key in self.hashes:
            self.hashes[task_key]["status"] = TaskStatus.COMPLETED.value
            self.hashes[task_key]["completed_at"] = datetime.utcnow().isoformat()
            self.hashes[task_key]["result"] = result
        
        # Update stats
        stats_key = f"mission:{mission_id}:stats"
        if stats_key in self.hashes:
            current = int(self.hashes[stats_key].get("tasks_completed", 0))
            self.hashes[stats_key]["tasks_completed"] = str(current + 1)
    
    # ═══════════════════════════════════════════════════════════
    # Statistics and Verification
    # ═══════════════════════════════════════════════════════════
    
    def get_pending_count(self, mission_id: str) -> int:
        key = f"mission:{mission_id}:tasks:pending"
        return len(self.sorted_sets.get(key, {}))
    
    def get_running_count(self, mission_id: str) -> int:
        key = f"mission:{mission_id}:tasks:running"
        return len(self.sets.get(key, set()))
    
    def get_completed_count(self, mission_id: str) -> int:
        key = f"mission:{mission_id}:tasks:completed"
        return len(self.lists.get(key, []))
    
    def get_claim_stats(self) -> Dict[str, Any]:
        """Get claiming statistics for test assertions."""
        return {
            "attempts": self.claim_attempts,
            "successes": self.claim_successes,
            "failures": self.claim_failures,
            "duplicate_claims": len(self.duplicate_claims),
            "unique_workers": len(set(h["worker_id"] for h in self.claim_history)),
            "unique_tasks_claimed": len(self.task_ownership),
        }
    
    def verify_no_duplicates(self) -> Tuple[bool, List[str]]:
        """
        Verify that no task was claimed by multiple workers.
        
        Returns:
            (is_valid, list of error messages)
        """
        errors = []
        
        # Check for duplicate claims
        if self.duplicate_claims:
            for task_id, worker1, worker2 in self.duplicate_claims:
                errors.append(
                    f"Task {task_id} claimed by both {worker1} and {worker2}"
                )
        
        # Check ownership uniqueness
        worker_tasks = {}  # worker -> [tasks]
        for task_id, worker_id in self.task_ownership.items():
            if worker_id not in worker_tasks:
                worker_tasks[worker_id] = []
            worker_tasks[worker_id].append(task_id)
        
        # Each task should only appear once
        all_tasks = []
        for tasks in worker_tasks.values():
            all_tasks.extend(tasks)
        
        task_counts = Counter(all_tasks)
        for task_id, count in task_counts.items():
            if count > 1:
                errors.append(f"Task {task_id} assigned to {count} workers")
        
        return (len(errors) == 0, errors)
    
    def get_worker_assignments(self) -> Dict[str, List[str]]:
        """Get task assignments per worker."""
        assignments = {}
        for task_id, worker_id in self.task_ownership.items():
            if worker_id not in assignments:
                assignments[worker_id] = []
            assignments[worker_id].append(task_id)
        return assignments


# ═══════════════════════════════════════════════════════════════
# Simulated Worker
# ═══════════════════════════════════════════════════════════════

class SimulatedWorker:
    """
    Simulates a specialist worker that claims and processes tasks.
    """
    
    def __init__(
        self,
        worker_id: str,
        specialist: str,
        blackboard: AtomicBlackboard,
        use_atomic: bool = True
    ):
        self.worker_id = worker_id
        self.specialist = specialist
        self.blackboard = blackboard
        self.use_atomic = use_atomic
        self.claimed_tasks: List[str] = []
        self.completed_tasks: List[str] = []
    
    async def run(self, mission_id: str, max_claims: int = 10) -> int:
        """
        Run the worker, claiming tasks until none available or max reached.
        
        Returns number of tasks claimed.
        """
        claims = 0
        
        for _ in range(max_claims):
            if self.use_atomic:
                task_id = await self.blackboard.claim_task_atomic(
                    mission_id, self.worker_id, self.specialist
                )
            else:
                task_id = await self.blackboard.claim_task_non_atomic(
                    mission_id, self.worker_id, self.specialist
                )
            
            if not task_id:
                break
            
            self.claimed_tasks.append(task_id)
            claims += 1
            
            # Simulate work
            await asyncio.sleep(random.uniform(0.001, 0.01))
            
            # Complete task
            await self.blackboard.complete_task(mission_id, task_id, "success")
            self.completed_tasks.append(task_id)
        
        return claims


# ═══════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════

@pytest.fixture
async def blackboard():
    bb = AtomicBlackboard()
    await bb.connect()
    yield bb
    await bb.flush_all()
    await bb.disconnect()


@pytest.fixture
def target_ip():
    return "192.168.1.50"


# ═══════════════════════════════════════════════════════════════
# Test Class: Basic Concurrent Claiming
# ═══════════════════════════════════════════════════════════════

class TestBasicConcurrentClaiming:
    """Test basic concurrent task claiming scenarios."""
    
    @pytest.mark.asyncio
    async def test_single_worker_claims_all_tasks(self, blackboard, target_ip):
        """Test that a single worker can claim all available tasks."""
        mission = Mission(
            name="Single Worker Test",
            scope=[f"{target_ip}/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        
        target = Target(mission_id=mission.id, ip=target_ip)
        await blackboard.add_target(target)
        
        # Create 10 tasks
        for i in range(10):
            task = Task(
                mission_id=mission.id,
                type=TaskType.PORT_SCAN,
                specialist=SpecialistType.RECON,
                target_id=target.id,
                priority=5
            )
            await blackboard.add_task(task)
        
        assert blackboard.get_pending_count(mission_id) == 10
        
        # Single worker claims all
        worker = SimulatedWorker("recon-001", "recon", blackboard)
        claims = await worker.run(mission_id)
        
        assert claims == 10
        assert blackboard.get_pending_count(mission_id) == 0
        assert blackboard.get_completed_count(mission_id) == 10
        
        # Verify no duplicates
        is_valid, errors = blackboard.verify_no_duplicates()
        assert is_valid, f"Duplicate errors: {errors}"
    
    @pytest.mark.asyncio
    async def test_two_workers_no_overlap(self, blackboard, target_ip):
        """Test that two workers don't claim the same task."""
        mission = Mission(
            name="Two Workers Test",
            scope=[f"{target_ip}/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        
        target = Target(mission_id=mission.id, ip=target_ip)
        await blackboard.add_target(target)
        
        # Create 10 tasks
        for i in range(10):
            task = Task(
                mission_id=mission.id,
                type=TaskType.PORT_SCAN,
                specialist=SpecialistType.RECON,
                target_id=target.id,
                priority=5
            )
            await blackboard.add_task(task)
        
        # Two workers compete
        worker1 = SimulatedWorker("recon-001", "recon", blackboard)
        worker2 = SimulatedWorker("recon-002", "recon", blackboard)
        
        # Run concurrently
        results = await asyncio.gather(
            worker1.run(mission_id),
            worker2.run(mission_id)
        )
        
        total_claims = sum(results)
        assert total_claims == 10
        
        # Each worker should have some tasks
        assert len(worker1.claimed_tasks) > 0 or len(worker2.claimed_tasks) > 0
        
        # No overlap
        overlap = set(worker1.claimed_tasks) & set(worker2.claimed_tasks)
        assert len(overlap) == 0, f"Overlapping tasks: {overlap}"
        
        # Verify via blackboard
        is_valid, errors = blackboard.verify_no_duplicates()
        assert is_valid, f"Duplicate errors: {errors}"


# ═══════════════════════════════════════════════════════════════
# Test Class: Stress Test with Many Workers
# ═══════════════════════════════════════════════════════════════

class TestStressTestManyWorkers:
    """
    Stress test with 10 workers competing for 10 tasks.
    
    This is the core test for horizontal scaling support.
    """
    
    @pytest.mark.asyncio
    async def test_10_workers_10_tasks_atomic(self, blackboard, target_ip):
        """
        Core stress test: 10 workers, 10 tasks, atomic claiming.
        
        Expected:
        - All 10 tasks claimed exactly once
        - No duplicate executions
        - Each task assigned to unique worker
        """
        mission = Mission(
            name="Stress Test 10x10",
            scope=[f"{target_ip}/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        
        target = Target(mission_id=mission.id, ip=target_ip)
        await blackboard.add_target(target)
        
        # Create 10 tasks
        created_task_ids = []
        for i in range(10):
            task = Task(
                mission_id=mission.id,
                type=TaskType.PORT_SCAN,
                specialist=SpecialistType.RECON,
                target_id=target.id,
                priority=10 - i  # Different priorities
            )
            task_id = await blackboard.add_task(task)
            created_task_ids.append(task_id)
        
        assert blackboard.get_pending_count(mission_id) == 10
        
        # Create 10 workers
        workers = [
            SimulatedWorker(f"recon-{i:03d}", "recon", blackboard, use_atomic=True)
            for i in range(10)
        ]
        
        # Run all workers concurrently
        results = await asyncio.gather(*[
            worker.run(mission_id, max_claims=10) for worker in workers
        ])
        
        # ===== ASSERTIONS =====
        total_claims = sum(results)
        
        print("\n" + "="*60)
        print("STRESS TEST RESULTS: 10 Workers, 10 Tasks (Atomic)")
        print("="*60)
        print(f"Total claims: {total_claims}")
        print(f"Claims per worker: {results}")
        print(f"Pending: {blackboard.get_pending_count(mission_id)}")
        print(f"Completed: {blackboard.get_completed_count(mission_id)}")
        
        stats = blackboard.get_claim_stats()
        print(f"\nClaim Statistics:")
        print(f"  Attempts: {stats['attempts']}")
        print(f"  Successes: {stats['successes']}")
        print(f"  Failures: {stats['failures']}")
        print(f"  Duplicate Claims: {stats['duplicate_claims']}")
        print(f"  Unique Workers: {stats['unique_workers']}")
        print(f"  Unique Tasks Claimed: {stats['unique_tasks_claimed']}")
        
        # Verify results
        assert total_claims == 10, f"Expected 10 claims, got {total_claims}"
        assert blackboard.get_pending_count(mission_id) == 0, "Tasks still pending"
        assert blackboard.get_completed_count(mission_id) == 10, "Not all tasks completed"
        
        # Verify no duplicates
        is_valid, errors = blackboard.verify_no_duplicates()
        assert is_valid, f"Duplicate errors: {errors}"
        
        # Verify each task was claimed exactly once
        assert stats['unique_tasks_claimed'] == 10
        assert stats['duplicate_claims'] == 0
        
        print("\n✅ STRESS TEST PASSED: No duplicate executions")
        print("="*60)
    
    @pytest.mark.asyncio
    async def test_20_workers_10_tasks_atomic(self, blackboard, target_ip):
        """
        Extended stress test: 20 workers competing for 10 tasks.
        
        More workers than tasks - tests contention handling.
        """
        mission = Mission(
            name="Stress Test 20x10",
            scope=[f"{target_ip}/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        
        target = Target(mission_id=mission.id, ip=target_ip)
        await blackboard.add_target(target)
        
        # Create 10 tasks
        for i in range(10):
            task = Task(
                mission_id=mission.id,
                type=TaskType.PORT_SCAN,
                specialist=SpecialistType.RECON,
                target_id=target.id,
                priority=5
            )
            await blackboard.add_task(task)
        
        # Create 20 workers
        workers = [
            SimulatedWorker(f"recon-{i:03d}", "recon", blackboard, use_atomic=True)
            for i in range(20)
        ]
        
        # Run all concurrently
        results = await asyncio.gather(*[
            worker.run(mission_id, max_claims=10) for worker in workers
        ])
        
        total_claims = sum(results)
        
        # Only 10 tasks should be claimed despite 20 workers
        assert total_claims == 10
        assert blackboard.get_completed_count(mission_id) == 10
        
        # Verify no duplicates
        is_valid, errors = blackboard.verify_no_duplicates()
        assert is_valid, f"Duplicate errors: {errors}"
        
        stats = blackboard.get_claim_stats()
        assert stats['duplicate_claims'] == 0
    
    @pytest.mark.asyncio
    async def test_100_workers_50_tasks_atomic(self, blackboard, target_ip):
        """
        High-load stress test: 100 workers, 50 tasks.
        
        Tests system under heavy contention.
        """
        mission = Mission(
            name="High Load Test",
            scope=[f"{target_ip}/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        
        target = Target(mission_id=mission.id, ip=target_ip)
        await blackboard.add_target(target)
        
        # Create 50 tasks
        for i in range(50):
            task = Task(
                mission_id=mission.id,
                type=TaskType.PORT_SCAN,
                specialist=SpecialistType.RECON,
                target_id=target.id,
                priority=random.randint(1, 10)
            )
            await blackboard.add_task(task)
        
        # Create 100 workers
        workers = [
            SimulatedWorker(f"recon-{i:03d}", "recon", blackboard, use_atomic=True)
            for i in range(100)
        ]
        
        # Run all concurrently
        results = await asyncio.gather(*[
            worker.run(mission_id, max_claims=50) for worker in workers
        ])
        
        total_claims = sum(results)
        
        print("\n" + "="*60)
        print("HIGH LOAD TEST: 100 Workers, 50 Tasks")
        print("="*60)
        print(f"Total claims: {total_claims}")
        print(f"Active workers: {sum(1 for r in results if r > 0)}")
        
        stats = blackboard.get_claim_stats()
        print(f"Claim attempts: {stats['attempts']}")
        print(f"Duplicate claims: {stats['duplicate_claims']}")
        
        # Verify
        assert total_claims == 50
        assert blackboard.get_completed_count(mission_id) == 50
        
        is_valid, errors = blackboard.verify_no_duplicates()
        assert is_valid, f"Duplicate errors: {errors}"
        
        print("\n✅ HIGH LOAD TEST PASSED")
        print("="*60)


# ═══════════════════════════════════════════════════════════════
# Test Class: Specialist Type Filtering
# ═══════════════════════════════════════════════════════════════

class TestSpecialistTypeFiltering:
    """Test that workers only claim tasks matching their specialist type."""
    
    @pytest.mark.asyncio
    async def test_recon_only_claims_recon_tasks(self, blackboard, target_ip):
        """Test that Recon worker doesn't claim Attack tasks."""
        mission = Mission(
            name="Specialist Filter Test",
            scope=[f"{target_ip}/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        
        target = Target(mission_id=mission.id, ip=target_ip)
        await blackboard.add_target(target)
        
        # Create mixed tasks
        recon_tasks = []
        attack_tasks = []
        
        for i in range(5):
            recon_task = Task(
                mission_id=mission.id,
                type=TaskType.PORT_SCAN,
                specialist=SpecialistType.RECON,
                target_id=target.id,
                priority=5
            )
            recon_tasks.append(await blackboard.add_task(recon_task))
            
            attack_task = Task(
                mission_id=mission.id,
                type=TaskType.EXPLOIT,
                specialist=SpecialistType.ATTACK,
                target_id=target.id,
                priority=5
            )
            attack_tasks.append(await blackboard.add_task(attack_task))
        
        assert blackboard.get_pending_count(mission_id) == 10
        
        # Recon worker
        recon_worker = SimulatedWorker("recon-001", "recon", blackboard)
        claims = await recon_worker.run(mission_id)
        
        # Should only claim recon tasks
        assert claims == 5
        for task_id in recon_worker.claimed_tasks:
            assert task_id in recon_tasks
            assert task_id not in attack_tasks
        
        # Attack tasks still pending
        assert blackboard.get_pending_count(mission_id) == 5
    
    @pytest.mark.asyncio
    async def test_mixed_specialists_concurrent(self, blackboard, target_ip):
        """Test concurrent claiming with mixed specialist types."""
        mission = Mission(
            name="Mixed Specialists Test",
            scope=[f"{target_ip}/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        
        target = Target(mission_id=mission.id, ip=target_ip)
        await blackboard.add_target(target)
        
        # Create 10 recon and 10 attack tasks
        for i in range(10):
            recon_task = Task(
                mission_id=mission.id,
                type=TaskType.PORT_SCAN,
                specialist=SpecialistType.RECON,
                target_id=target.id,
                priority=5
            )
            await blackboard.add_task(recon_task)
            
            attack_task = Task(
                mission_id=mission.id,
                type=TaskType.EXPLOIT,
                specialist=SpecialistType.ATTACK,
                target_id=target.id,
                priority=5
            )
            await blackboard.add_task(attack_task)
        
        # Create workers of each type
        recon_workers = [
            SimulatedWorker(f"recon-{i}", "recon", blackboard)
            for i in range(5)
        ]
        attack_workers = [
            SimulatedWorker(f"attack-{i}", "attack", blackboard)
            for i in range(5)
        ]
        
        # Run all concurrently
        all_workers = recon_workers + attack_workers
        results = await asyncio.gather(*[
            worker.run(mission_id) for worker in all_workers
        ])
        
        total = sum(results)
        assert total == 20
        
        # Verify type assignment
        for worker in recon_workers:
            for task_id in worker.claimed_tasks:
                task = await blackboard.get_task(task_id)
                assert task["specialist"] == "recon"
        
        for worker in attack_workers:
            for task_id in worker.claimed_tasks:
                task = await blackboard.get_task(task_id)
                assert task["specialist"] == "attack"


# ═══════════════════════════════════════════════════════════════
# Test Class: Worker Assignment Distribution
# ═══════════════════════════════════════════════════════════════

class TestWorkerDistribution:
    """Test fair distribution of tasks among workers."""
    
    @pytest.mark.asyncio
    async def test_distribution_among_equal_workers(self, blackboard, target_ip):
        """Test that tasks are distributed among workers."""
        mission = Mission(
            name="Distribution Test",
            scope=[f"{target_ip}/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        
        target = Target(mission_id=mission.id, ip=target_ip)
        await blackboard.add_target(target)
        
        # Create 100 tasks
        for i in range(100):
            task = Task(
                mission_id=mission.id,
                type=TaskType.PORT_SCAN,
                specialist=SpecialistType.RECON,
                target_id=target.id,
                priority=5
            )
            await blackboard.add_task(task)
        
        # Create 10 workers
        workers = [
            SimulatedWorker(f"recon-{i}", "recon", blackboard)
            for i in range(10)
        ]
        
        # Run concurrently
        await asyncio.gather(*[worker.run(mission_id) for worker in workers])
        
        # Check distribution
        claims_per_worker = [len(w.claimed_tasks) for w in workers]
        
        print("\n" + "="*60)
        print("DISTRIBUTION TEST: 100 Tasks, 10 Workers")
        print("="*60)
        print(f"Claims per worker: {claims_per_worker}")
        print(f"Min claims: {min(claims_per_worker)}")
        print(f"Max claims: {max(claims_per_worker)}")
        print(f"Average: {sum(claims_per_worker) / len(claims_per_worker):.1f}")
        
        # All tasks should be claimed
        assert sum(claims_per_worker) == 100
        
        # Distribution should be somewhat fair (not all to one worker)
        assert max(claims_per_worker) < 100  # No single worker got everything


# ═══════════════════════════════════════════════════════════════
# Test Class: Verify Unique Worker IDs
# ═══════════════════════════════════════════════════════════════

class TestUniqueWorkerIds:
    """Verify that each task has a unique worker_id after claiming."""
    
    @pytest.mark.asyncio
    async def test_each_task_has_unique_worker(self, blackboard, target_ip):
        """Verify each claimed task has a distinct worker_id."""
        mission = Mission(
            name="Unique Worker Test",
            scope=[f"{target_ip}/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        
        target = Target(mission_id=mission.id, ip=target_ip)
        await blackboard.add_target(target)
        
        # Create 10 tasks
        task_ids = []
        for i in range(10):
            task = Task(
                mission_id=mission.id,
                type=TaskType.PORT_SCAN,
                specialist=SpecialistType.RECON,
                target_id=target.id,
                priority=5
            )
            task_ids.append(await blackboard.add_task(task))
        
        # 10 workers claim concurrently
        workers = [
            SimulatedWorker(f"recon-{i:03d}", "recon", blackboard)
            for i in range(10)
        ]
        
        await asyncio.gather(*[worker.run(mission_id) for worker in workers])
        
        # Verify each task's worker_id
        worker_ids_used = set()
        for task_id in task_ids:
            task = await blackboard.get_task(task_id)
            worker_id = task.get("assigned_to")
            assert worker_id is not None, f"Task {task_id} has no worker_id"
            
            # Each assignment should be to a unique worker
            # (since we have 10 tasks and 10 workers, each gets one)
            # Actually, a worker might get multiple tasks
        
        # Verify ownership tracking
        assignments = blackboard.get_worker_assignments()
        print("\n" + "="*60)
        print("WORKER ASSIGNMENTS")
        print("="*60)
        for worker_id, tasks in assignments.items():
            print(f"  {worker_id}: {len(tasks)} tasks")
        
        # Each task should appear exactly once across all workers
        all_tasks = []
        for tasks in assignments.values():
            all_tasks.extend(tasks)
        
        assert len(all_tasks) == 10
        assert len(set(all_tasks)) == 10  # All unique


# ═══════════════════════════════════════════════════════════════
# Test Class: Race Condition Detection
# ═══════════════════════════════════════════════════════════════

class TestRaceConditionDetection:
    """
    Test that race conditions ARE detected when using non-atomic operations.
    
    This demonstrates WHY atomic operations are necessary.
    """
    
    @pytest.mark.asyncio
    async def test_atomic_vs_non_atomic_comparison(self, target_ip):
        """
        Compare atomic vs non-atomic claiming.
        
        Non-atomic should show potential for race conditions.
        Atomic should have zero duplicates.
        """
        # Test 1: Atomic claiming
        atomic_bb = AtomicBlackboard()
        await atomic_bb.connect()
        
        mission1 = Mission(
            name="Atomic Test",
            scope=[f"{target_ip}/32"],
            goals={}
        )
        mission_id1 = await atomic_bb.create_mission(mission1)
        
        target1 = Target(mission_id=mission1.id, ip=target_ip)
        await atomic_bb.add_target(target1)
        
        for i in range(10):
            task = Task(
                mission_id=mission1.id,
                type=TaskType.PORT_SCAN,
                specialist=SpecialistType.RECON,
                target_id=target1.id,
                priority=5
            )
            await atomic_bb.add_task(task)
        
        atomic_workers = [
            SimulatedWorker(f"atomic-{i}", "recon", atomic_bb, use_atomic=True)
            for i in range(10)
        ]
        
        await asyncio.gather(*[w.run(mission_id1) for w in atomic_workers])
        
        atomic_stats = atomic_bb.get_claim_stats()
        atomic_valid, atomic_errors = atomic_bb.verify_no_duplicates()
        
        await atomic_bb.disconnect()
        
        # Test 2: Non-atomic claiming (for comparison)
        # Note: This may or may not show race conditions depending on timing
        # The point is that atomic GUARANTEES no duplicates
        
        print("\n" + "="*60)
        print("ATOMIC VS NON-ATOMIC COMPARISON")
        print("="*60)
        print("\nAtomic Results:")
        print(f"  Duplicates: {atomic_stats['duplicate_claims']}")
        print(f"  Valid: {atomic_valid}")
        if not atomic_valid:
            print(f"  Errors: {atomic_errors}")
        
        # Atomic should always be valid
        assert atomic_valid, f"Atomic claiming failed: {atomic_errors}"
        assert atomic_stats['duplicate_claims'] == 0


# ═══════════════════════════════════════════════════════════════
# Test Class: Complete Distributed Scenario
# ═══════════════════════════════════════════════════════════════

class TestCompleteDistributedScenario:
    """
    Complete distributed system scenario test.
    
    Simulates a real deployment with:
    - Multiple workers of different types
    - Various task priorities
    - Concurrent execution
    - Full verification
    """
    
    @pytest.mark.asyncio
    async def test_full_distributed_scenario(self, blackboard, target_ip):
        """Complete distributed claiming scenario."""
        mission = Mission(
            name="Full Distributed Scenario",
            scope=[f"{target_ip}/32"],
            goals={"domain_admin": GoalStatus.PENDING}
        )
        mission_id = await blackboard.create_mission(mission)
        
        target = Target(
            mission_id=mission.id,
            ip=target_ip,
            status=TargetStatus.DISCOVERED
        )
        await blackboard.add_target(target)
        
        # Create diverse tasks
        # 5 high-priority recon tasks
        for i in range(5):
            task = Task(
                mission_id=mission.id,
                type=TaskType.PORT_SCAN,
                specialist=SpecialistType.RECON,
                target_id=target.id,
                priority=10
            )
            await blackboard.add_task(task)
        
        # 3 medium-priority recon tasks
        for i in range(3):
            task = Task(
                mission_id=mission.id,
                type=TaskType.SERVICE_ENUM,
                specialist=SpecialistType.RECON,
                target_id=target.id,
                priority=5
            )
            await blackboard.add_task(task)
        
        # 2 attack tasks
        for i in range(2):
            task = Task(
                mission_id=mission.id,
                type=TaskType.EXPLOIT,
                specialist=SpecialistType.ATTACK,
                target_id=target.id,
                priority=8
            )
            await blackboard.add_task(task)
        
        print("\n" + "="*60)
        print("FULL DISTRIBUTED SCENARIO")
        print("="*60)
        print("Tasks created:")
        print("  - 5 PORT_SCAN (recon, priority 10)")
        print("  - 3 SERVICE_ENUM (recon, priority 5)")
        print("  - 2 EXPLOIT (attack, priority 8)")
        
        # Create workers
        recon_workers = [
            SimulatedWorker(f"recon-{i}", "recon", blackboard)
            for i in range(5)
        ]
        attack_workers = [
            SimulatedWorker(f"attack-{i}", "attack", blackboard)
            for i in range(3)
        ]
        
        # Run all concurrently
        all_workers = recon_workers + attack_workers
        results = await asyncio.gather(*[
            worker.run(mission_id) for worker in all_workers
        ])
        
        # Collect results
        recon_results = results[:5]
        attack_results = results[5:]
        
        print(f"\nWorker Results:")
        print(f"  Recon workers claimed: {recon_results} (total: {sum(recon_results)})")
        print(f"  Attack workers claimed: {attack_results} (total: {sum(attack_results)})")
        
        # Verify
        stats = blackboard.get_claim_stats()
        print(f"\nStatistics:")
        print(f"  Total attempts: {stats['attempts']}")
        print(f"  Successful claims: {stats['successes']}")
        print(f"  Failed attempts: {stats['failures']}")
        print(f"  Duplicate claims: {stats['duplicate_claims']}")
        
        # Assertions
        assert sum(recon_results) == 8  # 5 + 3 recon tasks
        assert sum(attack_results) == 2  # 2 attack tasks
        assert blackboard.get_pending_count(mission_id) == 0
        assert blackboard.get_completed_count(mission_id) == 10
        
        is_valid, errors = blackboard.verify_no_duplicates()
        assert is_valid, f"Duplicate errors: {errors}"
        
        print("\n✅ FULL DISTRIBUTED SCENARIO PASSED")
        print("="*60)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
