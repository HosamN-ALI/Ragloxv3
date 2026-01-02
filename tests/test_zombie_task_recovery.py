# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Zombie Task Recovery Tests
# SRE Stability Tests for Stale Task Detection and Recovery
# ═══════════════════════════════════════════════════════════════
#
# This test file validates the system's resilience against:
# 1. Agent Crash scenarios (worker disappears mid-task)
# 2. Stale task detection (tasks stuck in RUNNING beyond timeout)
# 3. Automatic re-queueing of orphaned tasks
# 4. Heartbeat monitoring and dead worker detection
#
# Goal: Ensure the platform has "self-awareness" of stuck tasks
# ═══════════════════════════════════════════════════════════════

import pytest
import pytest_asyncio
import asyncio
import json
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4

from src.core.config import Settings
from src.core.models import (
    Mission, MissionStatus, GoalStatus,
    Target, TargetStatus, Priority,
    Task, TaskType, TaskStatus, SpecialistType,
)


# ═══════════════════════════════════════════════════════════════
# Enhanced Blackboard with Zombie Detection
# ═══════════════════════════════════════════════════════════════

class ZombieAwareBlackboard:
    """
    Enhanced Blackboard with zombie task detection and recovery capabilities.
    
    Features:
    - Heartbeat tracking per worker
    - Stale task detection based on timeout
    - Automatic re-queueing of orphaned tasks
    - Dead worker detection
    """
    
    # Configuration
    TASK_TIMEOUT_SECONDS = 300  # 5 minutes default
    HEARTBEAT_TIMEOUT_SECONDS = 60  # 1 minute
    HEARTBEAT_INTERVAL_SECONDS = 30  # 30 seconds
    
    def __init__(self):
        # Data storage
        self.hashes: Dict[str, Dict[str, Any]] = {}
        self.sorted_sets: Dict[str, Dict[str, float]] = {}
        self.sets: Dict[str, set] = {}
        self.lists: Dict[str, List[str]] = {}
        
        # Heartbeat tracking
        self.heartbeats: Dict[str, datetime] = {}  # worker_id -> last_heartbeat
        
        # Task timing
        self.task_started_at: Dict[str, datetime] = {}  # task_id -> started_at
        
        # Recovery tracking
        self.recovered_tasks: List[str] = []
        self.dead_workers: Set[str] = set()
        
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
        self.heartbeats.clear()
        self.task_started_at.clear()
        self.recovered_tasks.clear()
        self.dead_workers.clear()
    
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
            "targets_discovered": "0",
            "vulns_found": "0",
            "tasks_completed": "0",
            "tasks_failed": "0",
            "tasks_recovered": "0",
        }
        return mission_id
    
    async def get_mission(self, mission_id: str) -> Optional[Dict[str, Any]]:
        return self.hashes.get(f"mission:{mission_id}:info")
    
    async def update_mission_status(self, mission_id: str, status: MissionStatus) -> None:
        key = f"mission:{mission_id}:info"
        if key in self.hashes:
            self.hashes[key]["status"] = status.value
    
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
            "status": target.status.value if hasattr(target.status, 'value') else target.status,
        }
        if f"mission:{mission_id}:targets" not in self.sets:
            self.sets[f"mission:{mission_id}:targets"] = set()
        self.sets[f"mission:{mission_id}:targets"].add(f"target:{target_id}")
        return target_id
    
    async def get_target(self, target_id: str) -> Optional[Dict[str, Any]]:
        return self.hashes.get(f"target:{target_id}")
    
    # ═══════════════════════════════════════════════════════════
    # Task Operations with Zombie Detection
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
            "recovery_count": "0",
        }
        
        pending_key = f"mission:{mission_id}:tasks:pending"
        if pending_key not in self.sorted_sets:
            self.sorted_sets[pending_key] = {}
        self.sorted_sets[pending_key][f"task:{task_id}"] = task.priority
        
        return task_id
    
    async def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        return self.hashes.get(f"task:{task_id}")
    
    async def claim_task(
        self,
        mission_id: str,
        worker_id: str,
        specialist: str
    ) -> Optional[str]:
        """
        Claim a task from the pending queue.
        Records started_at for timeout tracking.
        """
        pending_key = f"mission:{mission_id}:tasks:pending"
        running_key = f"mission:{mission_id}:tasks:running"
        
        if pending_key not in self.sorted_sets:
            return None
        
        # Sort by priority (higher first)
        items = sorted(
            self.sorted_sets[pending_key].items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        for task_key, priority in items:
            task = self.hashes.get(task_key)
            if task and task.get("specialist") == specialist:
                # Move from pending to running
                del self.sorted_sets[pending_key][task_key]
                
                if running_key not in self.sets:
                    self.sets[running_key] = set()
                self.sets[running_key].add(task_key)
                
                # Update task
                task_id = task_key.replace("task:", "")
                now = datetime.utcnow()
                self.hashes[task_key]["status"] = TaskStatus.RUNNING.value
                self.hashes[task_key]["assigned_to"] = worker_id
                self.hashes[task_key]["started_at"] = now.isoformat()
                
                # Track for timeout detection
                self.task_started_at[task_id] = now
                
                # Record heartbeat for worker
                self.heartbeats[worker_id] = now
                
                return task_id
        
        return None
    
    async def complete_task(
        self,
        mission_id: str,
        task_id: str,
        result: str,
        result_data: Optional[Dict[str, Any]] = None
    ) -> None:
        """Mark a task as completed."""
        task_key = f"task:{task_id}"
        running_key = f"mission:{mission_id}:tasks:running"
        completed_key = f"mission:{mission_id}:tasks:completed"
        
        # Move from running to completed
        if running_key in self.sets:
            self.sets[running_key].discard(task_key)
        
        if completed_key not in self.lists:
            self.lists[completed_key] = []
        self.lists[completed_key].insert(0, task_key)
        
        # Update task
        if task_key in self.hashes:
            self.hashes[task_key]["status"] = TaskStatus.COMPLETED.value
            self.hashes[task_key]["completed_at"] = datetime.utcnow().isoformat()
            self.hashes[task_key]["result"] = result
            if result_data:
                self.hashes[task_key]["result_data"] = json.dumps(result_data)
        
        # Clean up tracking
        if task_id in self.task_started_at:
            del self.task_started_at[task_id]
        
        # Update stats
        stats_key = f"mission:{mission_id}:stats"
        if stats_key in self.hashes:
            current = int(self.hashes[stats_key].get("tasks_completed", 0))
            self.hashes[stats_key]["tasks_completed"] = str(current + 1)
    
    async def fail_task(
        self,
        mission_id: str,
        task_id: str,
        error_message: str
    ) -> None:
        """Mark a task as failed."""
        task_key = f"task:{task_id}"
        running_key = f"mission:{mission_id}:tasks:running"
        completed_key = f"mission:{mission_id}:tasks:completed"
        
        if running_key in self.sets:
            self.sets[running_key].discard(task_key)
        
        if completed_key not in self.lists:
            self.lists[completed_key] = []
        self.lists[completed_key].insert(0, task_key)
        
        if task_key in self.hashes:
            self.hashes[task_key]["status"] = TaskStatus.FAILED.value
            self.hashes[task_key]["completed_at"] = datetime.utcnow().isoformat()
            self.hashes[task_key]["error_message"] = error_message
        
        # Clean up tracking
        if task_id in self.task_started_at:
            del self.task_started_at[task_id]
        
        # Update stats
        stats_key = f"mission:{mission_id}:stats"
        if stats_key in self.hashes:
            current = int(self.hashes[stats_key].get("tasks_failed", 0))
            self.hashes[stats_key]["tasks_failed"] = str(current + 1)
    
    # ═══════════════════════════════════════════════════════════
    # Heartbeat Operations
    # ═══════════════════════════════════════════════════════════
    
    async def send_heartbeat(self, worker_id: str) -> None:
        """Record a heartbeat from a worker."""
        self.heartbeats[worker_id] = datetime.utcnow()
    
    async def get_worker_last_heartbeat(self, worker_id: str) -> Optional[datetime]:
        """Get the last heartbeat time for a worker."""
        return self.heartbeats.get(worker_id)
    
    async def remove_worker_heartbeat(self, worker_id: str) -> None:
        """Remove heartbeat record (simulate worker crash)."""
        if worker_id in self.heartbeats:
            del self.heartbeats[worker_id]
    
    async def is_worker_alive(self, worker_id: str) -> bool:
        """Check if a worker is alive based on heartbeat."""
        last_heartbeat = self.heartbeats.get(worker_id)
        if not last_heartbeat:
            return False
        
        elapsed = (datetime.utcnow() - last_heartbeat).total_seconds()
        return elapsed < self.HEARTBEAT_TIMEOUT_SECONDS
    
    # ═══════════════════════════════════════════════════════════
    # Zombie Detection and Recovery
    # ═══════════════════════════════════════════════════════════
    
    async def get_running_tasks(self, mission_id: str) -> List[str]:
        """Get all running task IDs for a mission."""
        running_key = f"mission:{mission_id}:tasks:running"
        if running_key not in self.sets:
            return []
        return [t.replace("task:", "") for t in self.sets[running_key]]
    
    async def get_stale_tasks(
        self,
        mission_id: str,
        timeout_seconds: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Find tasks that have been RUNNING longer than the timeout.
        
        Returns list of stale task info including:
        - task_id
        - worker_id
        - started_at
        - elapsed_seconds
        """
        timeout = timeout_seconds or self.TASK_TIMEOUT_SECONDS
        stale_tasks = []
        now = datetime.utcnow()
        
        running_key = f"mission:{mission_id}:tasks:running"
        if running_key not in self.sets:
            return []
        
        for task_key in self.sets[running_key]:
            task = self.hashes.get(task_key)
            if not task:
                continue
            
            task_id = task_key.replace("task:", "")
            started_at = self.task_started_at.get(task_id)
            
            if started_at:
                elapsed = (now - started_at).total_seconds()
                if elapsed > timeout:
                    stale_tasks.append({
                        "task_id": task_id,
                        "task_key": task_key,
                        "worker_id": task.get("assigned_to"),
                        "started_at": started_at.isoformat(),
                        "elapsed_seconds": elapsed,
                        "task_type": task.get("type"),
                    })
        
        return stale_tasks
    
    async def get_dead_workers(self) -> List[str]:
        """Find workers that haven't sent a heartbeat recently."""
        dead = []
        now = datetime.utcnow()
        
        for worker_id, last_heartbeat in list(self.heartbeats.items()):
            elapsed = (now - last_heartbeat).total_seconds()
            if elapsed > self.HEARTBEAT_TIMEOUT_SECONDS:
                dead.append(worker_id)
                self.dead_workers.add(worker_id)
        
        return dead
    
    async def get_tasks_by_worker(
        self,
        mission_id: str,
        worker_id: str
    ) -> List[str]:
        """Get all running tasks assigned to a specific worker."""
        running_key = f"mission:{mission_id}:tasks:running"
        if running_key not in self.sets:
            return []
        
        tasks = []
        for task_key in self.sets[running_key]:
            task = self.hashes.get(task_key)
            if task and task.get("assigned_to") == worker_id:
                tasks.append(task_key.replace("task:", ""))
        
        return tasks
    
    async def requeue_task(
        self,
        mission_id: str,
        task_id: str,
        reason: str = "worker_dead"
    ) -> bool:
        """
        Re-queue a running task back to pending.
        
        This is the key recovery mechanism:
        1. Move task from running to pending
        2. Reset task state
        3. Increment recovery count
        4. Record the recovery event
        """
        task_key = f"task:{task_id}"
        running_key = f"mission:{mission_id}:tasks:running"
        pending_key = f"mission:{mission_id}:tasks:pending"
        
        task = self.hashes.get(task_key)
        if not task:
            return False
        
        # Remove from running
        if running_key in self.sets:
            self.sets[running_key].discard(task_key)
        
        # Get original priority
        priority = int(task.get("priority", 5))
        
        # Reset task state
        self.hashes[task_key]["status"] = TaskStatus.PENDING.value
        self.hashes[task_key]["assigned_to"] = None
        self.hashes[task_key]["started_at"] = None
        
        # Increment recovery count
        recovery_count = int(task.get("recovery_count", 0)) + 1
        self.hashes[task_key]["recovery_count"] = str(recovery_count)
        self.hashes[task_key]["last_recovery_reason"] = reason
        self.hashes[task_key]["last_recovery_at"] = datetime.utcnow().isoformat()
        
        # Add back to pending queue
        if pending_key not in self.sorted_sets:
            self.sorted_sets[pending_key] = {}
        self.sorted_sets[pending_key][task_key] = priority
        
        # Clean up tracking
        if task_id in self.task_started_at:
            del self.task_started_at[task_id]
        
        # Record recovery
        self.recovered_tasks.append(task_id)
        
        # Update stats
        stats_key = f"mission:{mission_id}:stats"
        if stats_key in self.hashes:
            current = int(self.hashes[stats_key].get("tasks_recovered", 0))
            self.hashes[stats_key]["tasks_recovered"] = str(current + 1)
        
        return True
    
    async def recover_zombie_tasks(
        self,
        mission_id: str,
        timeout_seconds: Optional[int] = None
    ) -> List[str]:
        """
        Main recovery routine: find and requeue all zombie tasks.
        
        This should be called periodically by the MissionController monitor.
        """
        recovered = []
        
        # Find stale tasks
        stale_tasks = await self.get_stale_tasks(mission_id, timeout_seconds)
        
        for stale in stale_tasks:
            task_id = stale["task_id"]
            worker_id = stale["worker_id"]
            
            # Check if the worker is dead
            is_alive = await self.is_worker_alive(worker_id) if worker_id else False
            
            # Requeue the task
            reason = "timeout" if is_alive else "worker_dead"
            success = await self.requeue_task(mission_id, task_id, reason)
            
            if success:
                recovered.append(task_id)
        
        return recovered
    
    async def recover_tasks_from_dead_worker(
        self,
        mission_id: str,
        worker_id: str
    ) -> List[str]:
        """Recover all tasks from a specific dead worker."""
        recovered = []
        
        tasks = await self.get_tasks_by_worker(mission_id, worker_id)
        for task_id in tasks:
            success = await self.requeue_task(mission_id, task_id, "worker_dead")
            if success:
                recovered.append(task_id)
        
        return recovered
    
    # ═══════════════════════════════════════════════════════════
    # Utility Methods
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
    
    def get_channel(self, mission_id: str, entity: str) -> str:
        return f"channel:mission:{mission_id}:{entity}"


# ═══════════════════════════════════════════════════════════════
# Mission Controller with Zombie Detection
# ═══════════════════════════════════════════════════════════════

class ZombieAwareMissionController:
    """
    Enhanced MissionController with zombie task detection.
    
    Features:
    - Periodic monitoring of running tasks
    - Dead worker detection
    - Automatic task recovery
    """
    
    def __init__(self, blackboard: ZombieAwareBlackboard):
        self.blackboard = blackboard
        self._monitor_interval = 5  # seconds
        self._task_timeout = 300  # 5 minutes
        self._running = False
        self._recovery_events: List[Dict[str, Any]] = []
    
    async def monitor_mission(self, mission_id: str) -> Dict[str, Any]:
        """
        Monitor a mission for zombie tasks and dead workers.
        
        Returns a report of what was found and recovered.
        """
        report = {
            "mission_id": mission_id,
            "timestamp": datetime.utcnow().isoformat(),
            "stale_tasks_found": [],
            "dead_workers_found": [],
            "tasks_recovered": [],
            "errors": [],
        }
        
        try:
            # Check for stale tasks
            stale = await self.blackboard.get_stale_tasks(
                mission_id, 
                self._task_timeout
            )
            report["stale_tasks_found"] = stale
            
            # Check for dead workers
            dead_workers = await self.blackboard.get_dead_workers()
            report["dead_workers_found"] = dead_workers
            
            # Recover zombie tasks
            recovered = await self.blackboard.recover_zombie_tasks(
                mission_id,
                self._task_timeout
            )
            report["tasks_recovered"] = recovered
            
            # Record recovery event
            if recovered:
                self._recovery_events.append({
                    "mission_id": mission_id,
                    "timestamp": report["timestamp"],
                    "tasks_recovered": recovered,
                    "reason": "zombie_detection",
                })
        
        except Exception as e:
            report["errors"].append(str(e))
        
        return report
    
    async def handle_worker_crash(
        self,
        mission_id: str,
        worker_id: str
    ) -> List[str]:
        """Handle a specific worker crash by recovering its tasks."""
        recovered = await self.blackboard.recover_tasks_from_dead_worker(
            mission_id,
            worker_id
        )
        
        if recovered:
            self._recovery_events.append({
                "mission_id": mission_id,
                "timestamp": datetime.utcnow().isoformat(),
                "worker_id": worker_id,
                "tasks_recovered": recovered,
                "reason": "worker_crash",
            })
        
        return recovered
    
    def get_recovery_events(self) -> List[Dict[str, Any]]:
        return self._recovery_events


# ═══════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════

@pytest.fixture
async def blackboard():
    bb = ZombieAwareBlackboard()
    await bb.connect()
    yield bb
    await bb.flush_all()
    await bb.disconnect()


@pytest.fixture
def controller(blackboard):
    return ZombieAwareMissionController(blackboard)


@pytest.fixture
def target_ip():
    return "192.168.1.50"


# ═══════════════════════════════════════════════════════════════
# Test Class: Agent Crash Simulation
# ═══════════════════════════════════════════════════════════════

class TestAgentCrashSimulation:
    """
    Test Scenario: Agent crashes while processing a task.
    
    Steps:
    1. Create mission and PORT_SCAN task
    2. Worker claims task (status -> RUNNING)
    3. Simulate crash by removing worker heartbeat
    4. Verify task can be detected as orphaned
    5. Verify task can be recovered
    """
    
    @pytest.mark.asyncio
    async def test_worker_claims_task_and_starts_heartbeat(
        self, blackboard, target_ip
    ):
        """Test normal task claiming with heartbeat registration."""
        # Setup
        mission = Mission(
            name="Agent Crash Test",
            scope=[f"{target_ip}/32"],
            goals={"domain_admin": GoalStatus.PENDING}
        )
        mission_id = await blackboard.create_mission(mission)
        
        target = Target(
            mission_id=mission.id,
            ip=target_ip,
            status=TargetStatus.DISCOVERED
        )
        target_id = await blackboard.add_target(target)
        
        # Create PORT_SCAN task
        task = Task(
            mission_id=mission.id,
            type=TaskType.PORT_SCAN,
            specialist=SpecialistType.RECON,
            target_id=target.id,
            priority=8
        )
        task_id = await blackboard.add_task(task)
        
        # Worker claims task
        worker_id = "recon-worker-001"
        claimed_id = await blackboard.claim_task(mission_id, worker_id, "recon")
        
        # Assertions
        assert claimed_id == str(task.id)
        assert blackboard.get_running_count(mission_id) == 1
        assert blackboard.get_pending_count(mission_id) == 0
        
        # Verify heartbeat was recorded
        last_heartbeat = await blackboard.get_worker_last_heartbeat(worker_id)
        assert last_heartbeat is not None
        assert await blackboard.is_worker_alive(worker_id) == True
        
        # Verify task state
        task_data = await blackboard.get_task(claimed_id)
        assert task_data["status"] == TaskStatus.RUNNING.value
        assert task_data["assigned_to"] == worker_id
        assert task_data["started_at"] is not None
    
    @pytest.mark.asyncio
    async def test_simulate_agent_crash_by_removing_heartbeat(
        self, blackboard, target_ip
    ):
        """Test simulating agent crash by stopping heartbeat."""
        # Setup
        mission = Mission(
            name="Heartbeat Crash Test",
            scope=[f"{target_ip}/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        
        target = Target(mission_id=mission.id, ip=target_ip)
        await blackboard.add_target(target)
        
        task = Task(
            mission_id=mission.id,
            type=TaskType.PORT_SCAN,
            specialist=SpecialistType.RECON,
            target_id=target.id,
            priority=8
        )
        task_id = await blackboard.add_task(task)
        
        # Worker claims task
        worker_id = "recon-worker-crash"
        await blackboard.claim_task(mission_id, worker_id, "recon")
        
        # Verify worker is alive
        assert await blackboard.is_worker_alive(worker_id) == True
        
        # ===== SIMULATE CRASH =====
        # Remove heartbeat (worker stopped sending)
        await blackboard.remove_worker_heartbeat(worker_id)
        
        # Verify worker is now considered dead
        assert await blackboard.is_worker_alive(worker_id) == False
        
        # Task is still in running state (orphaned)
        assert blackboard.get_running_count(mission_id) == 1
        task_data = await blackboard.get_task(str(task.id))
        assert task_data["status"] == TaskStatus.RUNNING.value
    
    @pytest.mark.asyncio
    async def test_agent_crash_with_expired_heartbeat(
        self, blackboard, target_ip
    ):
        """Test detecting dead worker via expired heartbeat."""
        mission = Mission(
            name="Expired Heartbeat Test",
            scope=[f"{target_ip}/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        
        target = Target(mission_id=mission.id, ip=target_ip)
        await blackboard.add_target(target)
        
        task = Task(
            mission_id=mission.id,
            type=TaskType.PORT_SCAN,
            specialist=SpecialistType.RECON,
            target_id=target.id,
            priority=8
        )
        await blackboard.add_task(task)
        
        worker_id = "recon-worker-timeout"
        await blackboard.claim_task(mission_id, worker_id, "recon")
        
        # Manually set old heartbeat (simulate time passing)
        old_time = datetime.utcnow() - timedelta(seconds=120)  # 2 minutes ago
        blackboard.heartbeats[worker_id] = old_time
        
        # Worker should be detected as dead
        assert await blackboard.is_worker_alive(worker_id) == False
        
        # Find dead workers
        dead_workers = await blackboard.get_dead_workers()
        assert worker_id in dead_workers


# ═══════════════════════════════════════════════════════════════
# Test Class: Stale Task Detection
# ═══════════════════════════════════════════════════════════════

class TestStaleTaskDetection:
    """
    Test the detection of tasks stuck in RUNNING state.
    
    Verifies:
    - Tasks beyond timeout are detected
    - Multiple stale tasks are found
    - Task timing information is accurate
    """
    
    @pytest.mark.asyncio
    async def test_detect_stale_task_beyond_timeout(
        self, blackboard, target_ip
    ):
        """Test detection of a task that has exceeded timeout."""
        mission = Mission(
            name="Stale Detection Test",
            scope=[f"{target_ip}/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        
        target = Target(mission_id=mission.id, ip=target_ip)
        await blackboard.add_target(target)
        
        task = Task(
            mission_id=mission.id,
            type=TaskType.PORT_SCAN,
            specialist=SpecialistType.RECON,
            target_id=target.id,
            priority=8
        )
        task_id = await blackboard.add_task(task)
        
        worker_id = "recon-stale-worker"
        claimed = await blackboard.claim_task(mission_id, worker_id, "recon")
        
        # Manually backdate the started_at to simulate timeout
        old_start = datetime.utcnow() - timedelta(seconds=600)  # 10 minutes ago
        blackboard.task_started_at[claimed] = old_start
        
        # Detect stale tasks (5 minute timeout)
        stale_tasks = await blackboard.get_stale_tasks(mission_id, timeout_seconds=300)
        
        # Assertions
        assert len(stale_tasks) == 1
        assert stale_tasks[0]["task_id"] == claimed
        assert stale_tasks[0]["worker_id"] == worker_id
        assert stale_tasks[0]["elapsed_seconds"] > 300
    
    @pytest.mark.asyncio
    async def test_detect_multiple_stale_tasks(self, blackboard, target_ip):
        """Test detection of multiple stale tasks."""
        mission = Mission(
            name="Multi Stale Test",
            scope=[f"{target_ip}/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        
        target = Target(mission_id=mission.id, ip=target_ip)
        await blackboard.add_target(target)
        
        # Create multiple tasks
        task_ids = []
        for i in range(3):
            task = Task(
                mission_id=mission.id,
                type=TaskType.PORT_SCAN,
                specialist=SpecialistType.RECON,
                target_id=target.id,
                priority=8 - i
            )
            await blackboard.add_task(task)
            task_ids.append(str(task.id))
        
        # Different workers claim tasks
        for i, task_id in enumerate(task_ids):
            worker_id = f"recon-worker-{i}"
            claimed = await blackboard.claim_task(mission_id, worker_id, "recon")
            # Backdate to make stale
            blackboard.task_started_at[claimed] = datetime.utcnow() - timedelta(seconds=400)
        
        # Detect stale tasks
        stale_tasks = await blackboard.get_stale_tasks(mission_id, timeout_seconds=300)
        
        # All 3 should be stale
        assert len(stale_tasks) == 3
    
    @pytest.mark.asyncio
    async def test_fresh_task_not_detected_as_stale(self, blackboard, target_ip):
        """Test that fresh tasks are not detected as stale."""
        mission = Mission(
            name="Fresh Task Test",
            scope=[f"{target_ip}/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        
        target = Target(mission_id=mission.id, ip=target_ip)
        await blackboard.add_target(target)
        
        task = Task(
            mission_id=mission.id,
            type=TaskType.PORT_SCAN,
            specialist=SpecialistType.RECON,
            target_id=target.id,
            priority=8
        )
        await blackboard.add_task(task)
        
        worker_id = "recon-fresh-worker"
        await blackboard.claim_task(mission_id, worker_id, "recon")
        
        # Task just started - should NOT be stale
        stale_tasks = await blackboard.get_stale_tasks(mission_id, timeout_seconds=300)
        
        assert len(stale_tasks) == 0


# ═══════════════════════════════════════════════════════════════
# Test Class: Task Recovery (Re-queuing)
# ═══════════════════════════════════════════════════════════════

class TestTaskRecovery:
    """
    Test the re-queuing mechanism for orphaned tasks.
    
    Verifies:
    - Task moves from RUNNING back to PENDING
    - Recovery count is incremented
    - Task can be claimed by another worker
    - Multiple recoveries are tracked
    """
    
    @pytest.mark.asyncio
    async def test_requeue_task_to_pending(self, blackboard, target_ip):
        """Test re-queuing a stale task back to pending."""
        mission = Mission(
            name="Requeue Test",
            scope=[f"{target_ip}/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        
        target = Target(mission_id=mission.id, ip=target_ip)
        await blackboard.add_target(target)
        
        task = Task(
            mission_id=mission.id,
            type=TaskType.PORT_SCAN,
            specialist=SpecialistType.RECON,
            target_id=target.id,
            priority=8
        )
        task_id = await blackboard.add_task(task)
        
        # Worker claims and task becomes stale
        worker_id = "recon-dead-worker"
        claimed = await blackboard.claim_task(mission_id, worker_id, "recon")
        
        assert blackboard.get_running_count(mission_id) == 1
        assert blackboard.get_pending_count(mission_id) == 0
        
        # ===== REQUEUE THE TASK =====
        success = await blackboard.requeue_task(
            mission_id, 
            claimed, 
            reason="worker_dead"
        )
        
        # Assertions
        assert success == True
        assert blackboard.get_running_count(mission_id) == 0
        assert blackboard.get_pending_count(mission_id) == 1
        
        # Verify task state reset
        task_data = await blackboard.get_task(claimed)
        assert task_data["status"] == TaskStatus.PENDING.value
        assert task_data["assigned_to"] is None
        assert task_data["started_at"] is None
        assert int(task_data["recovery_count"]) == 1
        assert task_data["last_recovery_reason"] == "worker_dead"
    
    @pytest.mark.asyncio
    async def test_recovered_task_can_be_claimed_by_new_worker(
        self, blackboard, target_ip
    ):
        """Test that a recovered task can be claimed by another worker."""
        mission = Mission(
            name="Re-claim Test",
            scope=[f"{target_ip}/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        
        target = Target(mission_id=mission.id, ip=target_ip)
        await blackboard.add_target(target)
        
        task = Task(
            mission_id=mission.id,
            type=TaskType.PORT_SCAN,
            specialist=SpecialistType.RECON,
            target_id=target.id,
            priority=8
        )
        await blackboard.add_task(task)
        
        # First worker claims and crashes
        worker1 = "recon-worker-crash"
        claimed1 = await blackboard.claim_task(mission_id, worker1, "recon")
        
        # Requeue the task
        await blackboard.requeue_task(mission_id, claimed1, "worker_dead")
        
        # Second worker claims the recovered task
        worker2 = "recon-worker-new"
        claimed2 = await blackboard.claim_task(mission_id, worker2, "recon")
        
        # Same task, new worker
        assert claimed2 == claimed1
        
        task_data = await blackboard.get_task(claimed2)
        assert task_data["assigned_to"] == worker2
        assert task_data["status"] == TaskStatus.RUNNING.value
        assert int(task_data["recovery_count"]) == 1
    
    @pytest.mark.asyncio
    async def test_multiple_recovery_cycles(self, blackboard, target_ip):
        """Test a task going through multiple recovery cycles."""
        mission = Mission(
            name="Multi Recovery Test",
            scope=[f"{target_ip}/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        
        target = Target(mission_id=mission.id, ip=target_ip)
        await blackboard.add_target(target)
        
        task = Task(
            mission_id=mission.id,
            type=TaskType.PORT_SCAN,
            specialist=SpecialistType.RECON,
            target_id=target.id,
            priority=8
        )
        await blackboard.add_task(task)
        
        task_id = str(task.id)
        
        # Simulate 3 crash-recovery cycles
        for i in range(3):
            worker = f"recon-worker-{i}"
            claimed = await blackboard.claim_task(mission_id, worker, "recon")
            assert claimed == task_id
            
            # Simulate crash and recovery
            await blackboard.requeue_task(mission_id, task_id, f"crash_{i}")
        
        # Verify recovery count
        task_data = await blackboard.get_task(task_id)
        assert int(task_data["recovery_count"]) == 3
        
        # Task should still be pending and claimable
        assert blackboard.get_pending_count(mission_id) == 1
    
    @pytest.mark.asyncio
    async def test_automatic_zombie_recovery(self, blackboard, controller, target_ip):
        """Test the automatic zombie task recovery routine."""
        mission = Mission(
            name="Auto Recovery Test",
            scope=[f"{target_ip}/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        
        target = Target(mission_id=mission.id, ip=target_ip)
        await blackboard.add_target(target)
        
        # Create and claim task
        task = Task(
            mission_id=mission.id,
            type=TaskType.PORT_SCAN,
            specialist=SpecialistType.RECON,
            target_id=target.id,
            priority=8
        )
        await blackboard.add_task(task)
        
        worker_id = "recon-zombie"
        claimed = await blackboard.claim_task(mission_id, worker_id, "recon")
        
        # Make task stale
        blackboard.task_started_at[claimed] = datetime.utcnow() - timedelta(seconds=600)
        
        # Remove heartbeat (worker dead)
        await blackboard.remove_worker_heartbeat(worker_id)
        
        # Run recovery via controller
        report = await controller.monitor_mission(mission_id)
        
        # Assertions
        assert len(report["stale_tasks_found"]) == 1
        assert len(report["tasks_recovered"]) == 1
        assert claimed in report["tasks_recovered"]
        
        # Task should be back in pending
        assert blackboard.get_pending_count(mission_id) == 1
        assert blackboard.get_running_count(mission_id) == 0
    
    @pytest.mark.asyncio
    async def test_recovery_stats_updated(self, blackboard, target_ip):
        """Test that recovery statistics are tracked."""
        mission = Mission(
            name="Stats Test",
            scope=[f"{target_ip}/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        
        target = Target(mission_id=mission.id, ip=target_ip)
        await blackboard.add_target(target)
        
        task = Task(
            mission_id=mission.id,
            type=TaskType.PORT_SCAN,
            specialist=SpecialistType.RECON,
            target_id=target.id,
            priority=8
        )
        await blackboard.add_task(task)
        
        worker_id = "recon-stats"
        claimed = await blackboard.claim_task(mission_id, worker_id, "recon")
        
        # Requeue
        await blackboard.requeue_task(mission_id, claimed, "test")
        
        # Check stats
        stats = blackboard.hashes.get(f"mission:{mission_id}:stats", {})
        assert int(stats.get("tasks_recovered", 0)) == 1
        
        # Check recovered tasks list
        assert claimed in blackboard.recovered_tasks


# ═══════════════════════════════════════════════════════════════
# Test Class: Controller Monitor Integration
# ═══════════════════════════════════════════════════════════════

class TestControllerMonitorIntegration:
    """
    Test the MissionController's monitoring and recovery capabilities.
    
    Verifies:
    - Controller detects zombie tasks
    - Controller handles worker crashes
    - Recovery events are logged
    """
    
    @pytest.mark.asyncio
    async def test_controller_detects_zombie_tasks(
        self, blackboard, controller, target_ip
    ):
        """Test that controller's monitor detects zombie tasks."""
        mission = Mission(
            name="Controller Monitor Test",
            scope=[f"{target_ip}/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        
        target = Target(mission_id=mission.id, ip=target_ip)
        await blackboard.add_target(target)
        
        # Create multiple tasks
        for i in range(3):
            task = Task(
                mission_id=mission.id,
                type=TaskType.PORT_SCAN,
                specialist=SpecialistType.RECON,
                target_id=target.id,
                priority=8 - i
            )
            await blackboard.add_task(task)
            
            worker = f"recon-monitor-{i}"
            claimed = await blackboard.claim_task(mission_id, worker, "recon")
            
            # Make stale
            blackboard.task_started_at[claimed] = datetime.utcnow() - timedelta(seconds=400)
            await blackboard.remove_worker_heartbeat(worker)
        
        # Run monitor
        report = await controller.monitor_mission(mission_id)
        
        # All 3 tasks should be detected and recovered
        assert len(report["stale_tasks_found"]) == 3
        assert len(report["tasks_recovered"]) == 3
        assert len(report["errors"]) == 0
    
    @pytest.mark.asyncio
    async def test_controller_handles_specific_worker_crash(
        self, blackboard, controller, target_ip
    ):
        """Test controller handling a specific worker crash."""
        mission = Mission(
            name="Worker Crash Handler Test",
            scope=[f"{target_ip}/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        
        target = Target(mission_id=mission.id, ip=target_ip)
        await blackboard.add_target(target)
        
        # Create tasks for one worker
        crash_worker = "recon-crash-handler"
        for i in range(2):
            task = Task(
                mission_id=mission.id,
                type=TaskType.PORT_SCAN,
                specialist=SpecialistType.RECON,
                target_id=target.id,
                priority=8
            )
            await blackboard.add_task(task)
            await blackboard.claim_task(mission_id, crash_worker, "recon")
        
        # Worker crashes
        await blackboard.remove_worker_heartbeat(crash_worker)
        
        # Handle crash
        recovered = await controller.handle_worker_crash(mission_id, crash_worker)
        
        # Both tasks should be recovered
        assert len(recovered) == 2
        
        # Check recovery events
        events = controller.get_recovery_events()
        assert len(events) == 1
        assert events[0]["worker_id"] == crash_worker
        assert events[0]["reason"] == "worker_crash"
    
    @pytest.mark.asyncio
    async def test_controller_recovery_event_logging(
        self, blackboard, controller, target_ip
    ):
        """Test that recovery events are properly logged."""
        mission = Mission(
            name="Event Logging Test",
            scope=[f"{target_ip}/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        
        target = Target(mission_id=mission.id, ip=target_ip)
        await blackboard.add_target(target)
        
        task = Task(
            mission_id=mission.id,
            type=TaskType.PORT_SCAN,
            specialist=SpecialistType.RECON,
            target_id=target.id,
            priority=8
        )
        await blackboard.add_task(task)
        
        worker_id = "recon-event-log"
        claimed = await blackboard.claim_task(mission_id, worker_id, "recon")
        
        # Make stale and remove heartbeat
        blackboard.task_started_at[claimed] = datetime.utcnow() - timedelta(seconds=400)
        await blackboard.remove_worker_heartbeat(worker_id)
        
        # Run monitor
        await controller.monitor_mission(mission_id)
        
        # Check events
        events = controller.get_recovery_events()
        assert len(events) == 1
        assert events[0]["mission_id"] == mission_id
        assert events[0]["reason"] == "zombie_detection"
        assert claimed in events[0]["tasks_recovered"]


# ═══════════════════════════════════════════════════════════════
# Test Class: Complete Recovery Scenario
# ═══════════════════════════════════════════════════════════════

class TestCompleteRecoveryScenario:
    """
    End-to-end test of the zombie task recovery system.
    
    Simulates a real-world scenario:
    1. Mission starts with multiple tasks
    2. Workers claim and process tasks
    3. One worker crashes mid-task
    4. Monitor detects and recovers the orphaned task
    5. New worker picks up the recovered task
    6. Task completes successfully
    """
    
    @pytest.mark.asyncio
    async def test_full_crash_recovery_scenario(
        self, blackboard, controller, target_ip
    ):
        """Test complete crash recovery workflow."""
        # ===== PHASE 1: Setup =====
        mission = Mission(
            name="Full Recovery Scenario",
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
        
        # Create PORT_SCAN task
        task = Task(
            mission_id=mission.id,
            type=TaskType.PORT_SCAN,
            specialist=SpecialistType.RECON,
            target_id=target.id,
            priority=8
        )
        task_id = await blackboard.add_task(task)
        
        print("\n" + "="*60)
        print("PHASE 1: Mission Created")
        print(f"  Mission ID: {mission_id}")
        print(f"  Task ID: {task_id}")
        print(f"  Pending: {blackboard.get_pending_count(mission_id)}")
        print("="*60)
        
        # ===== PHASE 2: Worker Claims Task =====
        worker1 = "recon-worker-unstable"
        claimed = await blackboard.claim_task(mission_id, worker1, "recon")
        
        assert claimed == str(task.id)
        assert blackboard.get_running_count(mission_id) == 1
        
        print("\nPHASE 2: Worker Claims Task")
        print(f"  Worker: {worker1}")
        print(f"  Claimed Task: {claimed}")
        print(f"  Running: {blackboard.get_running_count(mission_id)}")
        
        # ===== PHASE 3: Worker Crashes =====
        # Simulate crash: stop heartbeat and make task stale
        await blackboard.remove_worker_heartbeat(worker1)
        blackboard.task_started_at[claimed] = datetime.utcnow() - timedelta(seconds=400)
        
        print("\nPHASE 3: Worker Crashes!")
        print(f"  Worker {worker1} stopped sending heartbeats")
        print(f"  Task {claimed} is now orphaned")
        
        # ===== PHASE 4: Monitor Detects and Recovers =====
        report = await controller.monitor_mission(mission_id)
        
        assert len(report["stale_tasks_found"]) == 1
        assert len(report["tasks_recovered"]) == 1
        
        print("\nPHASE 4: Monitor Detects Zombie")
        print(f"  Stale tasks found: {len(report['stale_tasks_found'])}")
        print(f"  Tasks recovered: {report['tasks_recovered']}")
        print(f"  Pending: {blackboard.get_pending_count(mission_id)}")
        print(f"  Running: {blackboard.get_running_count(mission_id)}")
        
        # ===== PHASE 5: New Worker Claims Recovered Task =====
        worker2 = "recon-worker-stable"
        claimed2 = await blackboard.claim_task(mission_id, worker2, "recon")
        
        assert claimed2 == claimed  # Same task
        
        task_data = await blackboard.get_task(claimed2)
        assert task_data["assigned_to"] == worker2
        assert int(task_data["recovery_count"]) == 1
        
        print("\nPHASE 5: New Worker Claims Recovered Task")
        print(f"  Worker: {worker2}")
        print(f"  Same task: {claimed2 == claimed}")
        print(f"  Recovery count: {task_data['recovery_count']}")
        
        # ===== PHASE 6: Task Completes Successfully =====
        await blackboard.complete_task(
            mission_id,
            claimed2,
            "success",
            {"ports_found": [22, 80, 443]}
        )
        
        final_task = await blackboard.get_task(claimed2)
        assert final_task["status"] == TaskStatus.COMPLETED.value
        
        stats = blackboard.hashes.get(f"mission:{mission_id}:stats", {})
        
        print("\nPHASE 6: Task Completed!")
        print(f"  Status: {final_task['status']}")
        print(f"  Completed: {blackboard.get_completed_count(mission_id)}")
        print(f"  Tasks Recovered (stats): {stats.get('tasks_recovered', 0)}")
        print("="*60)
        print("✅ FULL RECOVERY SCENARIO PASSED")
        print("="*60)


# ═══════════════════════════════════════════════════════════════
# Test Class: Edge Cases
# ═══════════════════════════════════════════════════════════════

class TestEdgeCases:
    """Test edge cases in zombie detection and recovery."""
    
    @pytest.mark.asyncio
    async def test_requeue_nonexistent_task(self, blackboard, target_ip):
        """Test requeuing a task that doesn't exist."""
        mission = Mission(
            name="Nonexistent Test",
            scope=[f"{target_ip}/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        
        result = await blackboard.requeue_task(mission_id, "fake-task-id", "test")
        
        assert result == False
    
    @pytest.mark.asyncio
    async def test_no_stale_tasks_in_empty_mission(self, blackboard, target_ip):
        """Test stale detection on empty mission."""
        mission = Mission(
            name="Empty Mission",
            scope=[f"{target_ip}/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        
        stale = await blackboard.get_stale_tasks(mission_id)
        
        assert len(stale) == 0
    
    @pytest.mark.asyncio
    async def test_worker_alive_with_recent_heartbeat(self, blackboard):
        """Test worker is considered alive with recent heartbeat."""
        worker_id = "active-worker"
        await blackboard.send_heartbeat(worker_id)
        
        assert await blackboard.is_worker_alive(worker_id) == True
    
    @pytest.mark.asyncio
    async def test_worker_dead_with_no_heartbeat(self, blackboard):
        """Test worker is considered dead with no heartbeat."""
        worker_id = "unknown-worker"
        
        assert await blackboard.is_worker_alive(worker_id) == False


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
