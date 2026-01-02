# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Analysis Reflexion Tests
# Tests for AnalysisSpecialist and Reflexion Logic Flow
# ═══════════════════════════════════════════════════════════════
#
# This test file validates the Reflexion Logic pattern:
# 1. Failed task events trigger AnalysisSpecialist
# 2. Error context is properly captured and propagated
# 3. Decisions (retry, skip, modify, escalate) are made correctly
# 4. MissionController passes context to AnalysisSpecialist
# 5. The data path is ready for LLM integration
#
# Goal: Ensure the platform can learn from failures and adapt
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
    ErrorContext, ExecutionLog,
    TaskFailedEvent, TaskAnalysisRequestEvent, TaskAnalysisResultEvent,
    Vulnerability, Severity,
)


# ═══════════════════════════════════════════════════════════════
# Analysis-Aware Blackboard Mock
# ═══════════════════════════════════════════════════════════════

class AnalysisAwareBlackboard:
    """
    In-memory Blackboard implementation for testing Reflexion Logic.
    
    Features:
    - Task storage with error_context and execution_logs
    - Event publishing and tracking
    - Analysis result storage
    - Full lifecycle tracking
    """
    
    def __init__(self):
        # Data storage
        self.hashes: Dict[str, Dict[str, Any]] = {}
        self.sorted_sets: Dict[str, Dict[str, float]] = {}
        self.sets: Dict[str, set] = {}
        self.lists: Dict[str, List[str]] = {}
        
        # Event tracking for tests
        self.published_events: List[Dict[str, Any]] = []
        self.analysis_requests: List[Dict[str, Any]] = []
        self.analysis_results: List[Dict[str, Any]] = []
        
        # Connection state
        self._connected = False
        self._subscribed_channels: Set[str] = set()
    
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
        self.published_events.clear()
        self.analysis_requests.clear()
        self.analysis_results.clear()
    
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
            "tasks_analyzed": "0",
            "retries_triggered": "0",
        }
        # Initialize goals
        goals = mission.goals if isinstance(mission.goals, dict) else {g: GoalStatus.PENDING for g in mission.goals}
        self.hashes[f"mission:{mission_id}:goals"] = {
            k: v.value if hasattr(v, 'value') else v for k, v in goals.items()
        }
        return mission_id
    
    async def get_mission(self, mission_id: str) -> Optional[Dict[str, Any]]:
        return self.hashes.get(f"mission:{mission_id}:info")
    
    async def get_mission_goals(self, mission_id: str) -> Dict[str, str]:
        return self.hashes.get(f"mission:{mission_id}:goals", {})
    
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
            "hostname": target.hostname,
            "os": target.os,
            "status": target.status.value if hasattr(target.status, 'value') else target.status,
        }
        if f"mission:{mission_id}:targets" not in self.sets:
            self.sets[f"mission:{mission_id}:targets"] = set()
        self.sets[f"mission:{mission_id}:targets"].add(f"target:{target_id}")
        return target_id
    
    async def get_target(self, target_id: str) -> Optional[Dict[str, Any]]:
        if target_id.startswith("target:"):
            target_id = target_id.replace("target:", "")
        return self.hashes.get(f"target:{target_id}")
    
    # ═══════════════════════════════════════════════════════════
    # Vulnerability Operations
    # ═══════════════════════════════════════════════════════════
    
    async def add_vulnerability(self, vuln: Vulnerability) -> str:
        vuln_id = str(vuln.id)
        mission_id = str(vuln.mission_id)
        self.hashes[f"vuln:{vuln_id}"] = {
            "id": vuln_id,
            "mission_id": mission_id,
            "target_id": str(vuln.target_id),
            "type": vuln.type,
            "name": vuln.name,
            "severity": vuln.severity.value if hasattr(vuln.severity, 'value') else vuln.severity,
            "exploit_available": vuln.exploit_available,
            "rx_modules": json.dumps(vuln.rx_modules),
        }
        if f"mission:{mission_id}:vulns" not in self.sets:
            self.sets[f"mission:{mission_id}:vulns"] = set()
        self.sets[f"mission:{mission_id}:vulns"].add(f"vuln:{vuln_id}")
        return vuln_id
    
    async def get_vulnerability(self, vuln_id: str) -> Optional[Dict[str, Any]]:
        if vuln_id.startswith("vuln:"):
            vuln_id = vuln_id.replace("vuln:", "")
        return self.hashes.get(f"vuln:{vuln_id}")
    
    # ═══════════════════════════════════════════════════════════
    # Task Operations with Error Context
    # ═══════════════════════════════════════════════════════════
    
    async def add_task(self, task: Task) -> str:
        """Add a task with full error context support."""
        task_id = str(task.id)
        mission_id = str(task.mission_id)
        
        task_data = {
            "id": task_id,
            "mission_id": mission_id,
            "type": task.type.value if hasattr(task.type, 'value') else task.type,
            "specialist": task.specialist.value if hasattr(task.specialist, 'value') else task.specialist,
            "priority": str(task.priority),
            "status": TaskStatus.PENDING.value,
            "target_id": str(task.target_id) if task.target_id else None,
            "vuln_id": str(task.vuln_id) if task.vuln_id else None,
            "rx_module": task.rx_module,
            "created_at": datetime.utcnow().isoformat(),
            "assigned_to": None,
            "started_at": None,
            "completed_at": None,
            "result": None,
            "result_data": json.dumps(task.result_data or {}),
            "error_message": None,
            # Reflexion Logic fields
            "error_context": json.dumps(task.error_context.model_dump() if task.error_context else None),
            "execution_logs": json.dumps([log.model_dump() for log in task.execution_logs] if task.execution_logs else []),
            "retry_count": str(task.retry_count),
            "max_retries": str(task.max_retries),
            "parent_task_id": str(task.parent_task_id) if task.parent_task_id else None,
            "needs_analysis": str(task.needs_analysis).lower(),
            "analysis_result": task.analysis_result,
        }
        
        self.hashes[f"task:{task_id}"] = task_data
        
        # Add to pending queue
        pending_key = f"mission:{mission_id}:tasks:pending"
        if pending_key not in self.sorted_sets:
            self.sorted_sets[pending_key] = {}
        self.sorted_sets[pending_key][f"task:{task_id}"] = task.priority
        
        return task_id
    
    async def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        if task_id.startswith("task:"):
            task_id = task_id.replace("task:", "")
        return self.hashes.get(f"task:{task_id}")
    
    async def claim_task(
        self,
        mission_id: str,
        worker_id: str,
        specialist: str
    ) -> Optional[str]:
        """Claim a task from the pending queue."""
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
        
        if running_key in self.sets:
            self.sets[running_key].discard(task_key)
        
        if completed_key not in self.lists:
            self.lists[completed_key] = []
        self.lists[completed_key].insert(0, task_key)
        
        if task_key in self.hashes:
            self.hashes[task_key]["status"] = TaskStatus.COMPLETED.value
            self.hashes[task_key]["completed_at"] = datetime.utcnow().isoformat()
            self.hashes[task_key]["result"] = result
            if result_data:
                self.hashes[task_key]["result_data"] = json.dumps(result_data)
        
        # Update stats
        self._increment_stat(mission_id, "tasks_completed")
    
    async def fail_task(
        self,
        mission_id: str,
        task_id: str,
        error_message: str,
        error_context: Optional[Dict[str, Any]] = None,
        execution_logs: Optional[List[Dict[str, Any]]] = None
    ) -> None:
        """
        Mark a task as failed with error context.
        
        This is the key entry point for Reflexion Logic.
        """
        task_key = f"task:{task_id}"
        running_key = f"mission:{mission_id}:tasks:running"
        failed_key = f"mission:{mission_id}:tasks:failed"
        
        if running_key in self.sets:
            self.sets[running_key].discard(task_key)
        
        if failed_key not in self.lists:
            self.lists[failed_key] = []
        self.lists[failed_key].insert(0, task_key)
        
        if task_key in self.hashes:
            self.hashes[task_key]["status"] = TaskStatus.FAILED.value
            self.hashes[task_key]["completed_at"] = datetime.utcnow().isoformat()
            self.hashes[task_key]["error_message"] = error_message
            self.hashes[task_key]["needs_analysis"] = "true"
            
            if error_context:
                self.hashes[task_key]["error_context"] = json.dumps(error_context)
            
            if execution_logs:
                self.hashes[task_key]["execution_logs"] = json.dumps(execution_logs)
        
        # Update stats
        self._increment_stat(mission_id, "tasks_failed")
    
    async def update_task_with_analysis(
        self,
        task_id: str,
        analysis_result: str,
        decision: str
    ) -> None:
        """Update a task with analysis result."""
        task_key = f"task:{task_id}"
        if task_key in self.hashes:
            self.hashes[task_key]["analysis_result"] = analysis_result
            self.hashes[task_key]["needs_analysis"] = "false"
    
    def _increment_stat(self, mission_id: str, stat_name: str) -> None:
        stats_key = f"mission:{mission_id}:stats"
        if stats_key in self.hashes:
            current = int(self.hashes[stats_key].get(stat_name, 0))
            self.hashes[stats_key][stat_name] = str(current + 1)
    
    # ═══════════════════════════════════════════════════════════
    # Pub/Sub Operations
    # ═══════════════════════════════════════════════════════════
    
    async def subscribe(self, *channels) -> None:
        self._subscribed_channels.update(channels)
    
    async def publish(self, channel: str, event: Any) -> None:
        """Publish an event and track it."""
        event_data = event.model_dump() if hasattr(event, 'model_dump') else event
        self.published_events.append({
            "channel": channel,
            "event": event_data,
            "timestamp": datetime.utcnow().isoformat(),
        })
        
        # Track analysis-specific events
        event_type = event_data.get("event")
        if event_type == "task_failed":
            self.analysis_requests.append(event_data)
        elif event_type == "analysis_result":
            self.analysis_results.append(event_data)
    
    async def get_message(self, timeout: float = 1.0) -> Optional[Dict[str, Any]]:
        """Get next event (for simulation)."""
        return None
    
    def get_channel(self, mission_id: str, entity: str) -> str:
        return f"channel:mission:{mission_id}:{entity}"
    
    async def send_heartbeat(self, mission_id: str, worker_id: str) -> None:
        pass
    
    async def log_result(
        self,
        mission_id: str,
        event_type: str,
        data: Dict[str, Any]
    ) -> None:
        """Log a result event."""
        log_key = f"mission:{mission_id}:results"
        if log_key not in self.lists:
            self.lists[log_key] = []
        self.lists[log_key].insert(0, json.dumps({
            "event": event_type,
            "data": data,
            "timestamp": datetime.utcnow().isoformat(),
        }))
    
    # ═══════════════════════════════════════════════════════════
    # Utility Methods
    # ═══════════════════════════════════════════════════════════
    
    def get_pending_count(self, mission_id: str) -> int:
        key = f"mission:{mission_id}:tasks:pending"
        return len(self.sorted_sets.get(key, {}))
    
    def get_running_count(self, mission_id: str) -> int:
        key = f"mission:{mission_id}:tasks:running"
        return len(self.sets.get(key, set()))
    
    def get_failed_count(self, mission_id: str) -> int:
        key = f"mission:{mission_id}:tasks:failed"
        return len(self.lists.get(key, []))
    
    def get_events_by_type(self, event_type: str) -> List[Dict[str, Any]]:
        return [e for e in self.published_events if e["event"].get("event") == event_type]


# ═══════════════════════════════════════════════════════════════
# Mock Analysis Specialist (Simplified for Testing)
# ═══════════════════════════════════════════════════════════════

class MockAnalysisSpecialist:
    """
    Simplified AnalysisSpecialist for testing Reflexion Logic.
    
    This mock captures the essential decision-making logic without
    the full Blackboard integration complexity.
    """
    
    # Error categories
    ERROR_CATEGORIES = {
        "connection_refused": "network",
        "av_detected": "defense",
        "edr_blocked": "defense",
        "auth_failed": "authentication",
        "target_patched": "vulnerability",
        "timeout": "technical",
        "unknown": "unknown"
    }
    
    def __init__(self, blackboard: AnalysisAwareBlackboard):
        self.blackboard = blackboard
        self.worker_id = f"analysis-{uuid4().hex[:8]}"
        self._current_mission_id: Optional[str] = None
        
        # Analysis tracking
        self.analyses_performed: List[Dict[str, Any]] = []
        self.decisions_made: Dict[str, int] = {
            "retry": 0,
            "skip": 0,
            "modify_approach": 0,
            "escalate": 0,
        }
    
    async def start(self, mission_id: str) -> None:
        self._current_mission_id = mission_id
    
    async def stop(self) -> None:
        self._current_mission_id = None
    
    async def analyze_failure(
        self,
        task_id: str,
        error_context: Dict[str, Any],
        execution_logs: List[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Analyze a failed task and determine next steps.
        
        Core Reflexion Logic implementation.
        """
        # Get original task
        task = await self.blackboard.get_task(task_id)
        if not task:
            return {
                "decision": "skip",
                "reasoning": "Task not found",
                "task_id": task_id
            }
        
        # Categorize error
        error_type = error_context.get("error_type", "unknown")
        category = self.ERROR_CATEGORIES.get(error_type, "unknown")
        
        # Get retry count
        retry_count = int(task.get("retry_count", 0))
        max_retries = int(task.get("max_retries", 3))
        
        # Make decision based on category
        decision = self._make_decision(
            task=task,
            error_context=error_context,
            category=category,
            retry_count=retry_count,
            max_retries=max_retries
        )
        
        # Track analysis
        self.analyses_performed.append({
            "task_id": task_id,
            "error_type": error_type,
            "category": category,
            "decision": decision["decision"],
            "timestamp": datetime.utcnow().isoformat(),
        })
        
        self.decisions_made[decision["decision"]] += 1
        
        return decision
    
    def _make_decision(
        self,
        task: Dict[str, Any],
        error_context: Dict[str, Any],
        category: str,
        retry_count: int,
        max_retries: int
    ) -> Dict[str, Any]:
        """Make a decision based on error category and context."""
        detected_defenses = error_context.get("detected_defenses", [])
        
        # Defense detected - modify or skip
        if category == "defense":
            if detected_defenses:
                return {
                    "decision": "modify_approach",
                    "reasoning": f"Defense detected ({detected_defenses}). Trying alternative approach.",
                    "detected_defenses": detected_defenses,
                    "modified_parameters": {
                        "use_evasion": True,
                        "encode_payload": True,
                    }
                }
            return {
                "decision": "skip",
                "reasoning": "Defense detected with no alternatives."
            }
        
        # Vulnerability patched - skip
        if category == "vulnerability":
            return {
                "decision": "skip",
                "reasoning": "Target appears to be patched or not vulnerable."
            }
        
        # Network/technical issues - retry if within limits
        if category in ("network", "technical"):
            if retry_count < max_retries:
                return {
                    "decision": "retry",
                    "reasoning": f"Transient error - retry attempt {retry_count + 1}/{max_retries}",
                    "delay_seconds": 30,
                }
            return {
                "decision": "escalate",
                "reasoning": "Max retries exceeded for transient error.",
                "escalation_reason": error_context.get("error_message", "Unknown"),
            }
        
        # Authentication failed
        if category == "authentication":
            if retry_count < max_retries:
                return {
                    "decision": "retry",
                    "reasoning": "Authentication failed - may be transient.",
                    "delay_seconds": 30,
                }
            return {
                "decision": "modify_approach",
                "reasoning": "Authentication persistently failing - need different credentials.",
                "modified_parameters": {
                    "harvest_more_creds": True,
                }
            }
        
        # Unknown - escalate
        return {
            "decision": "escalate",
            "reasoning": "Unknown error type - needs investigation.",
            "escalation_reason": error_context.get("error_message", "Unknown error"),
        }
    
    async def handle_task_failed_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Handle a TaskFailedEvent from Pub/Sub."""
        task_id = str(event.get("task_id", ""))
        
        error_context = {
            "error_type": event.get("error_type", "unknown"),
            "error_message": event.get("error_message", ""),
            "technique_id": event.get("technique_id"),
            "module_used": event.get("module_used"),
            "detected_defenses": event.get("detected_defenses", []),
        }
        
        return await self.analyze_failure(task_id, error_context)
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            "analyses_performed": len(self.analyses_performed),
            "decisions": self.decisions_made.copy(),
        }


# ═══════════════════════════════════════════════════════════════
# Mock Mission Controller (with Analysis Integration)
# ═══════════════════════════════════════════════════════════════

class MockMissionController:
    """
    Mission Controller with Analysis integration for testing.
    
    Demonstrates how the controller passes failed task context
    to the AnalysisSpecialist.
    """
    
    def __init__(
        self,
        blackboard: AnalysisAwareBlackboard,
        analysis_specialist: MockAnalysisSpecialist
    ):
        self.blackboard = blackboard
        self.analysis_specialist = analysis_specialist
        self._active_missions: Set[str] = set()
    
    async def start_mission(self, mission_id: str) -> None:
        self._active_missions.add(mission_id)
        await self.analysis_specialist.start(mission_id)
    
    async def handle_task_failure(
        self,
        mission_id: str,
        task_id: str,
        error_message: str,
        error_context: Dict[str, Any],
        execution_logs: List[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Handle a task failure by:
        1. Recording the failure in Blackboard
        2. Publishing TaskFailedEvent
        3. Passing to AnalysisSpecialist
        4. Acting on the analysis decision
        """
        # Record failure
        await self.blackboard.fail_task(
            mission_id,
            task_id,
            error_message,
            error_context,
            execution_logs
        )
        
        # Create and publish TaskFailedEvent
        task = await self.blackboard.get_task(task_id)
        event = TaskFailedEvent(
            mission_id=UUID(mission_id),
            task_id=UUID(task_id),
            task_type=TaskType(task["type"]),
            target_id=UUID(task["target_id"]) if task.get("target_id") else None,
            error_type=error_context.get("error_type", "unknown"),
            error_message=error_message,
            technique_id=error_context.get("technique_id"),
            module_used=error_context.get("module_used"),
            detected_defenses=error_context.get("detected_defenses", []),
            retry_count=int(task.get("retry_count", 0)),
        )
        
        channel = self.blackboard.get_channel(mission_id, "failures")
        await self.blackboard.publish(channel, event)
        
        # Analyze the failure
        analysis_result = await self.analysis_specialist.analyze_failure(
            task_id,
            error_context,
            execution_logs
        )
        
        # Update task with analysis result
        await self.blackboard.update_task_with_analysis(
            task_id,
            json.dumps(analysis_result),
            analysis_result["decision"]
        )
        
        # Act on decision
        await self._act_on_analysis_decision(mission_id, task_id, task, analysis_result)
        
        return analysis_result
    
    async def _act_on_analysis_decision(
        self,
        mission_id: str,
        original_task_id: str,
        original_task: Dict[str, Any],
        decision: Dict[str, Any]
    ) -> None:
        """Act on the analysis decision."""
        decision_type = decision["decision"]
        
        if decision_type == "retry":
            # Create retry task
            retry_task = Task(
                mission_id=UUID(mission_id),
                type=TaskType(original_task["type"]),
                specialist=SpecialistType(original_task["specialist"]),
                priority=int(original_task.get("priority", 5)),
                target_id=UUID(original_task["target_id"]) if original_task.get("target_id") else None,
                vuln_id=UUID(original_task["vuln_id"]) if original_task.get("vuln_id") else None,
                rx_module=original_task.get("rx_module"),
                retry_count=int(original_task.get("retry_count", 0)) + 1,
                parent_task_id=UUID(original_task_id),
            )
            await self.blackboard.add_task(retry_task)
            self.blackboard._increment_stat(mission_id, "retries_triggered")
        
        elif decision_type == "modify_approach":
            # Create modified task
            modified_params = decision.get("modified_parameters", {})
            # Priority boost capped at 10
            new_priority = min(int(original_task.get("priority", 5)) + 1, 10)
            modified_task = Task(
                mission_id=UUID(mission_id),
                type=TaskType(original_task["type"]),
                specialist=SpecialistType(original_task["specialist"]),
                priority=new_priority,  # Slight boost, capped at 10
                target_id=UUID(original_task["target_id"]) if original_task.get("target_id") else None,
                vuln_id=UUID(original_task["vuln_id"]) if original_task.get("vuln_id") else None,
                rx_module=modified_params.get("new_module") or original_task.get("rx_module"),
                parent_task_id=UUID(original_task_id),
                result_data=modified_params,
            )
            await self.blackboard.add_task(modified_task)
        
        elif decision_type == "escalate":
            # Log escalation
            await self.blackboard.log_result(
                mission_id,
                "task_escalated",
                {
                    "task_id": original_task_id,
                    "reason": decision.get("escalation_reason"),
                    "reasoning": decision.get("reasoning"),
                }
            )


# ═══════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════

@pytest.fixture
async def blackboard():
    bb = AnalysisAwareBlackboard()
    await bb.connect()
    yield bb
    await bb.flush_all()
    await bb.disconnect()


@pytest.fixture
def analysis_specialist(blackboard):
    return MockAnalysisSpecialist(blackboard)


@pytest.fixture
def controller(blackboard, analysis_specialist):
    return MockMissionController(blackboard, analysis_specialist)


@pytest.fixture
def target_ip():
    return "192.168.1.50"


# ═══════════════════════════════════════════════════════════════
# Test Class: Error Context Capture
# ═══════════════════════════════════════════════════════════════

class TestErrorContextCapture:
    """
    Test proper capture and storage of error context in failed tasks.
    """
    
    @pytest.mark.asyncio
    async def test_task_failure_captures_error_context(
        self, blackboard, target_ip
    ):
        """Test that error context is properly captured on failure."""
        # Setup
        mission = Mission(
            name="Error Context Test",
            scope=[f"{target_ip}/32"],
            goals={"domain_admin": GoalStatus.PENDING}
        )
        mission_id = await blackboard.create_mission(mission)
        
        target = Target(mission_id=mission.id, ip=target_ip, os="Windows Server 2016")
        await blackboard.add_target(target)
        
        task = Task(
            mission_id=mission.id,
            type=TaskType.EXPLOIT,
            specialist=SpecialistType.ATTACK,
            target_id=target.id,
            priority=9,
            rx_module="exploit/windows/smb/ms17_010_eternalblue",
        )
        task_id = await blackboard.add_task(task)
        
        # Claim task
        worker_id = "attack-worker-001"
        await blackboard.claim_task(mission_id, worker_id, "attack")
        
        # Simulate failure with error context
        error_context = {
            "error_type": "av_detected",
            "error_code": "ERR_AV_001",
            "error_message": "Exploit blocked by Windows Defender",
            "target_ip": target_ip,
            "target_port": 445,
            "target_service": "SMB",
            "technique_id": "T1210",  # MITRE: Exploitation of Remote Services
            "module_used": "exploit/windows/smb/ms17_010_eternalblue",
            "command_executed": "use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS 192.168.1.50; exploit",
            "detected_defenses": ["Windows Defender", "Real-time Protection"],
            "network_conditions": "normal",
            "retry_recommended": True,
            "alternative_techniques": ["T1059.001", "T1059.003"],  # PowerShell, Windows Command Shell
            "alternative_modules": ["exploit/windows/smb/ms17_010_psexec", "auxiliary/scanner/smb/smb_ms17_010"],
        }
        
        execution_logs = [
            {"timestamp": datetime.utcnow().isoformat(), "level": "info", "message": "Starting exploit", "data": {}},
            {"timestamp": datetime.utcnow().isoformat(), "level": "info", "message": "Connected to target", "data": {"port": 445}},
            {"timestamp": datetime.utcnow().isoformat(), "level": "error", "message": "AV detection triggered", "data": {"av": "Windows Defender"}},
        ]
        
        await blackboard.fail_task(
            mission_id,
            str(task.id),
            "Exploit blocked by Windows Defender",
            error_context,
            execution_logs
        )
        
        # Verify error context is stored
        failed_task = await blackboard.get_task(str(task.id))
        assert failed_task["status"] == TaskStatus.FAILED.value
        assert failed_task["needs_analysis"] == "true"
        
        stored_context = json.loads(failed_task["error_context"])
        assert stored_context["error_type"] == "av_detected"
        assert "Windows Defender" in stored_context["detected_defenses"]
        assert stored_context["technique_id"] == "T1210"
        
        stored_logs = json.loads(failed_task["execution_logs"])
        assert len(stored_logs) == 3
        assert stored_logs[2]["level"] == "error"
    
    @pytest.mark.asyncio
    async def test_task_failure_publishes_event(
        self, blackboard, controller, target_ip
    ):
        """Test that TaskFailedEvent is published on failure."""
        # Setup
        mission = Mission(
            name="Event Publishing Test",
            scope=[f"{target_ip}/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        
        target = Target(mission_id=mission.id, ip=target_ip)
        await blackboard.add_target(target)
        
        task = Task(
            mission_id=mission.id,
            type=TaskType.EXPLOIT,
            specialist=SpecialistType.ATTACK,
            target_id=target.id,
            priority=9,
        )
        task_id = await blackboard.add_task(task)
        
        # Claim and fail via controller
        await blackboard.claim_task(mission_id, "attack-worker", "attack")
        
        error_context = {
            "error_type": "connection_refused",
            "error_message": "Connection refused by target",
            "detected_defenses": [],
        }
        
        await controller.handle_task_failure(
            mission_id,
            str(task.id),
            "Connection refused",
            error_context
        )
        
        # Verify event was published
        failure_events = blackboard.get_events_by_type("task_failed")
        assert len(failure_events) == 1
        
        event_data = failure_events[0]["event"]
        assert event_data["error_type"] == "connection_refused"


# ═══════════════════════════════════════════════════════════════
# Test Class: Analysis Decision Making
# ═══════════════════════════════════════════════════════════════

class TestAnalysisDecisionMaking:
    """
    Test the AnalysisSpecialist's decision-making logic.
    """
    
    @pytest.mark.asyncio
    async def test_av_detection_triggers_modify_approach(
        self, blackboard, analysis_specialist, target_ip
    ):
        """Test that AV detection leads to modify_approach decision."""
        # Setup
        mission = Mission(
            name="AV Detection Test",
            scope=[f"{target_ip}/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        await analysis_specialist.start(mission_id)
        
        target = Target(mission_id=mission.id, ip=target_ip)
        await blackboard.add_target(target)
        
        task = Task(
            mission_id=mission.id,
            type=TaskType.EXPLOIT,
            specialist=SpecialistType.ATTACK,
            target_id=target.id,
            priority=9,
        )
        task_id = await blackboard.add_task(task)
        await blackboard.claim_task(mission_id, "attack-worker", "attack")
        
        # Analyze with AV detection
        error_context = {
            "error_type": "av_detected",
            "error_message": "Blocked by AV",
            "detected_defenses": ["Windows Defender"],
        }
        
        result = await analysis_specialist.analyze_failure(str(task.id), error_context)
        
        # Should recommend modify_approach
        assert result["decision"] == "modify_approach"
        assert "Defense detected" in result["reasoning"]
        assert "use_evasion" in result.get("modified_parameters", {})
    
    @pytest.mark.asyncio
    async def test_connection_refused_triggers_retry(
        self, blackboard, analysis_specialist, target_ip
    ):
        """Test that network errors trigger retry decision."""
        # Setup
        mission = Mission(
            name="Network Error Test",
            scope=[f"{target_ip}/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        await analysis_specialist.start(mission_id)
        
        target = Target(mission_id=mission.id, ip=target_ip)
        await blackboard.add_target(target)
        
        task = Task(
            mission_id=mission.id,
            type=TaskType.EXPLOIT,
            specialist=SpecialistType.ATTACK,
            target_id=target.id,
            priority=9,
            retry_count=0,
            max_retries=3,
        )
        task_id = await blackboard.add_task(task)
        await blackboard.claim_task(mission_id, "attack-worker", "attack")
        
        error_context = {
            "error_type": "connection_refused",
            "error_message": "Connection refused",
        }
        
        result = await analysis_specialist.analyze_failure(str(task.id), error_context)
        
        # Should recommend retry
        assert result["decision"] == "retry"
        assert "retry attempt" in result["reasoning"].lower()
    
    @pytest.mark.asyncio
    async def test_patched_target_triggers_skip(
        self, blackboard, analysis_specialist, target_ip
    ):
        """Test that patched targets trigger skip decision."""
        # Setup
        mission = Mission(
            name="Patched Target Test",
            scope=[f"{target_ip}/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        await analysis_specialist.start(mission_id)
        
        target = Target(mission_id=mission.id, ip=target_ip)
        await blackboard.add_target(target)
        
        task = Task(
            mission_id=mission.id,
            type=TaskType.EXPLOIT,
            specialist=SpecialistType.ATTACK,
            target_id=target.id,
            priority=9,
        )
        task_id = await blackboard.add_task(task)
        await blackboard.claim_task(mission_id, "attack-worker", "attack")
        
        error_context = {
            "error_type": "target_patched",
            "error_message": "Vulnerability has been patched",
        }
        
        result = await analysis_specialist.analyze_failure(str(task.id), error_context)
        
        # Should recommend skip
        assert result["decision"] == "skip"
        assert "patched" in result["reasoning"].lower()
    
    @pytest.mark.asyncio
    async def test_max_retries_exceeded_triggers_escalate(
        self, blackboard, analysis_specialist, target_ip
    ):
        """Test that exceeding max retries triggers escalation."""
        # Setup
        mission = Mission(
            name="Max Retries Test",
            scope=[f"{target_ip}/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        await analysis_specialist.start(mission_id)
        
        target = Target(mission_id=mission.id, ip=target_ip)
        await blackboard.add_target(target)
        
        # Task already at max retries
        task = Task(
            mission_id=mission.id,
            type=TaskType.EXPLOIT,
            specialist=SpecialistType.ATTACK,
            target_id=target.id,
            priority=9,
            retry_count=3,  # Already at max
            max_retries=3,
        )
        task_id = await blackboard.add_task(task)
        await blackboard.claim_task(mission_id, "attack-worker", "attack")
        
        error_context = {
            "error_type": "connection_refused",
            "error_message": "Still failing",
        }
        
        result = await analysis_specialist.analyze_failure(str(task.id), error_context)
        
        # Should recommend escalate
        assert result["decision"] == "escalate"


# ═══════════════════════════════════════════════════════════════
# Test Class: Controller Integration
# ═══════════════════════════════════════════════════════════════

class TestControllerIntegration:
    """
    Test the MissionController's integration with AnalysisSpecialist.
    """
    
    @pytest.mark.asyncio
    async def test_controller_creates_retry_task(
        self, blackboard, controller, analysis_specialist, target_ip
    ):
        """Test that controller creates retry task on retry decision."""
        # Setup
        mission = Mission(
            name="Retry Task Test",
            scope=[f"{target_ip}/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        await controller.start_mission(mission_id)
        
        target = Target(mission_id=mission.id, ip=target_ip)
        await blackboard.add_target(target)
        
        task = Task(
            mission_id=mission.id,
            type=TaskType.EXPLOIT,
            specialist=SpecialistType.ATTACK,
            target_id=target.id,
            priority=9,
            retry_count=0,
            max_retries=3,
        )
        task_id = await blackboard.add_task(task)
        await blackboard.claim_task(mission_id, "attack-worker", "attack")
        
        initial_pending = blackboard.get_pending_count(mission_id)
        
        # Fail with network error
        error_context = {
            "error_type": "connection_refused",
            "error_message": "Connection refused",
        }
        
        result = await controller.handle_task_failure(
            mission_id,
            str(task.id),
            "Connection refused",
            error_context
        )
        
        # Should have created a retry task
        assert result["decision"] == "retry"
        assert blackboard.get_pending_count(mission_id) == initial_pending + 1
        
        # Check stats
        stats = blackboard.hashes.get(f"mission:{mission_id}:stats", {})
        assert int(stats.get("retries_triggered", 0)) == 1
    
    @pytest.mark.asyncio
    async def test_controller_creates_modified_task(
        self, blackboard, controller, analysis_specialist, target_ip
    ):
        """Test that controller creates modified task on modify_approach decision."""
        # Setup
        mission = Mission(
            name="Modified Task Test",
            scope=[f"{target_ip}/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        await controller.start_mission(mission_id)
        
        target = Target(mission_id=mission.id, ip=target_ip)
        await blackboard.add_target(target)
        
        task = Task(
            mission_id=mission.id,
            type=TaskType.EXPLOIT,
            specialist=SpecialistType.ATTACK,
            target_id=target.id,
            priority=9,
        )
        task_id = await blackboard.add_task(task)
        await blackboard.claim_task(mission_id, "attack-worker", "attack")
        
        initial_pending = blackboard.get_pending_count(mission_id)
        
        # Fail with AV detection
        error_context = {
            "error_type": "av_detected",
            "error_message": "Blocked by AV",
            "detected_defenses": ["Windows Defender"],
        }
        
        result = await controller.handle_task_failure(
            mission_id,
            str(task.id),
            "Blocked by AV",
            error_context
        )
        
        # Should have created a modified task
        assert result["decision"] == "modify_approach"
        assert blackboard.get_pending_count(mission_id) == initial_pending + 1
    
    @pytest.mark.asyncio
    async def test_controller_logs_escalation(
        self, blackboard, controller, analysis_specialist, target_ip
    ):
        """Test that controller logs escalation on escalate decision."""
        # Setup
        mission = Mission(
            name="Escalation Test",
            scope=[f"{target_ip}/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        await controller.start_mission(mission_id)
        
        target = Target(mission_id=mission.id, ip=target_ip)
        await blackboard.add_target(target)
        
        # Task at max retries
        task = Task(
            mission_id=mission.id,
            type=TaskType.EXPLOIT,
            specialist=SpecialistType.ATTACK,
            target_id=target.id,
            priority=9,
            retry_count=3,
            max_retries=3,
        )
        task_id = await blackboard.add_task(task)
        await blackboard.claim_task(mission_id, "attack-worker", "attack")
        
        error_context = {
            "error_type": "timeout",
            "error_message": "Operation timed out",
        }
        
        result = await controller.handle_task_failure(
            mission_id,
            str(task.id),
            "Operation timed out",
            error_context
        )
        
        # Should have escalated
        assert result["decision"] == "escalate"
        
        # Check result log
        results_key = f"mission:{mission_id}:results"
        assert results_key in blackboard.lists
        assert len(blackboard.lists[results_key]) > 0
        
        log_entry = json.loads(blackboard.lists[results_key][0])
        assert log_entry["event"] == "task_escalated"


# ═══════════════════════════════════════════════════════════════
# Test Class: Complete Reflexion Flow
# ═══════════════════════════════════════════════════════════════

class TestCompleteReflexionFlow:
    """
    End-to-end test of the Reflexion Logic flow.
    """
    
    @pytest.mark.asyncio
    async def test_complete_reflexion_flow_av_detection(
        self, blackboard, controller, analysis_specialist, target_ip
    ):
        """
        Test complete flow:
        1. Exploit task fails due to AV detection
        2. TaskFailedEvent published with full context
        3. AnalysisSpecialist analyzes and decides modify_approach
        4. Controller creates modified task with evasion parameters
        """
        print("\n" + "="*60)
        print("REFLEXION FLOW TEST: AV Detection Scenario")
        print("="*60)
        
        # ===== PHASE 1: Setup =====
        mission = Mission(
            name="Reflexion Flow Test",
            scope=[f"{target_ip}/32"],
            goals={"domain_admin": GoalStatus.PENDING}
        )
        mission_id = await blackboard.create_mission(mission)
        await controller.start_mission(mission_id)
        
        target = Target(
            mission_id=mission.id,
            ip=target_ip,
            os="Windows Server 2016"
        )
        await blackboard.add_target(target)
        
        vuln = Vulnerability(
            mission_id=mission.id,
            target_id=target.id,
            type="MS17-010",
            name="EternalBlue",
            severity=Severity.CRITICAL,
            exploit_available=True,
            rx_modules=["exploit/windows/smb/ms17_010_eternalblue"]
        )
        await blackboard.add_vulnerability(vuln)
        
        # Create EXPLOIT task
        exploit_task = Task(
            mission_id=mission.id,
            type=TaskType.EXPLOIT,
            specialist=SpecialistType.ATTACK,
            target_id=target.id,
            vuln_id=vuln.id,
            rx_module="exploit/windows/smb/ms17_010_eternalblue",
            priority=10,
        )
        task_id = await blackboard.add_task(exploit_task)
        
        print(f"\nPHASE 1: Setup Complete")
        print(f"  Mission ID: {mission_id}")
        print(f"  Target: {target_ip}")
        print(f"  Vulnerability: MS17-010 (EternalBlue)")
        print(f"  Task ID: {task_id}")
        
        # ===== PHASE 2: Attack Specialist Claims Task =====
        worker_id = "attack-specialist-001"
        claimed = await blackboard.claim_task(mission_id, worker_id, "attack")
        
        assert claimed == str(exploit_task.id)
        assert blackboard.get_running_count(mission_id) == 1
        
        print(f"\nPHASE 2: Task Claimed")
        print(f"  Worker: {worker_id}")
        print(f"  Status: RUNNING")
        
        # ===== PHASE 3: Exploit Fails - AV Detection =====
        error_context = {
            "error_type": "av_detected",
            "error_code": "AV_BLOCK_001",
            "error_message": "Exploit payload blocked by Windows Defender",
            "target_ip": target_ip,
            "target_port": 445,
            "target_service": "SMB",
            "technique_id": "T1210",
            "module_used": "exploit/windows/smb/ms17_010_eternalblue",
            "detected_defenses": ["Windows Defender", "Real-time Protection"],
            "network_conditions": "normal",
            "retry_recommended": True,
            "alternative_techniques": ["T1059.001"],
            "alternative_modules": ["exploit/windows/smb/ms17_010_psexec"],
        }
        
        execution_logs = [
            {"timestamp": datetime.utcnow().isoformat(), "level": "info", "message": "Initiating exploit", "data": {}},
            {"timestamp": datetime.utcnow().isoformat(), "level": "info", "message": "Connected to SMB", "data": {"port": 445}},
            {"timestamp": datetime.utcnow().isoformat(), "level": "warning", "message": "Payload delivery attempted", "data": {}},
            {"timestamp": datetime.utcnow().isoformat(), "level": "error", "message": "AV DETECTED - Payload blocked", "data": {"av": "Windows Defender", "action": "quarantine"}},
        ]
        
        print(f"\nPHASE 3: Exploit Failed!")
        print(f"  Error Type: av_detected")
        print(f"  Detected Defenses: {error_context['detected_defenses']}")
        
        # ===== PHASE 4: Handle Failure (Triggers Reflexion) =====
        result = await controller.handle_task_failure(
            mission_id,
            str(exploit_task.id),
            "Exploit blocked by Windows Defender",
            error_context,
            execution_logs
        )
        
        print(f"\nPHASE 4: Analysis Complete")
        print(f"  Decision: {result['decision']}")
        print(f"  Reasoning: {result['reasoning']}")
        
        # Verify decision
        assert result["decision"] == "modify_approach"
        assert "Defense detected" in result["reasoning"]
        
        # ===== PHASE 5: Verify Modified Task Created =====
        # Should have created a new task with evasion parameters
        assert blackboard.get_pending_count(mission_id) == 1
        
        # Check the original task was analyzed
        original_task = await blackboard.get_task(str(exploit_task.id))
        assert original_task["status"] == TaskStatus.FAILED.value
        assert original_task["needs_analysis"] == "false"
        assert original_task["analysis_result"] is not None
        
        print(f"\nPHASE 5: Modified Task Created")
        print(f"  New Pending Tasks: {blackboard.get_pending_count(mission_id)}")
        print(f"  Original Task Analyzed: Yes")
        
        # ===== PHASE 6: Verify Event Trail =====
        failure_events = blackboard.get_events_by_type("task_failed")
        assert len(failure_events) == 1
        
        event_data = failure_events[0]["event"]
        assert event_data["error_type"] == "av_detected"
        assert "Windows Defender" in event_data["detected_defenses"]
        
        print(f"\nPHASE 6: Event Trail Verified")
        print(f"  TaskFailedEvent Published: Yes")
        print(f"  Error Context Preserved: Yes")
        
        # ===== PHASE 7: Verify Analysis Statistics =====
        stats = analysis_specialist.get_stats()
        assert stats["analyses_performed"] == 1
        assert stats["decisions"]["modify_approach"] == 1
        
        print(f"\n" + "="*60)
        print("REFLEXION FLOW TEST COMPLETE")
        print(f"  Total Analyses: {stats['analyses_performed']}")
        print(f"  Decisions Made: {stats['decisions']}")
        print("="*60 + "\n")
    
    @pytest.mark.asyncio
    async def test_multiple_failures_with_different_decisions(
        self, blackboard, controller, analysis_specialist, target_ip
    ):
        """Test handling multiple failures with different outcomes."""
        mission = Mission(
            name="Multi-Failure Test",
            scope=[f"{target_ip}/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        await controller.start_mission(mission_id)
        
        target = Target(mission_id=mission.id, ip=target_ip)
        await blackboard.add_target(target)
        
        # Test scenarios
        scenarios = [
            {"error_type": "connection_refused", "expected": "retry"},
            {"error_type": "av_detected", "detected_defenses": ["AV"], "expected": "modify_approach"},
            {"error_type": "target_patched", "expected": "skip"},
        ]
        
        for i, scenario in enumerate(scenarios):
            task = Task(
                mission_id=mission.id,
                type=TaskType.EXPLOIT,
                specialist=SpecialistType.ATTACK,
                target_id=target.id,
                priority=9 - i,
                retry_count=0,
                max_retries=3,
            )
            task_id = await blackboard.add_task(task)
            await blackboard.claim_task(mission_id, f"worker-{i}", "attack")
            
            error_context = {
                "error_type": scenario["error_type"],
                "error_message": f"Test error {i}",
                "detected_defenses": scenario.get("detected_defenses", []),
            }
            
            result = await controller.handle_task_failure(
                mission_id,
                str(task.id),
                error_context["error_message"],
                error_context
            )
            
            assert result["decision"] == scenario["expected"], \
                f"Expected {scenario['expected']} for {scenario['error_type']}, got {result['decision']}"
        
        # Verify statistics
        stats = analysis_specialist.get_stats()
        assert stats["analyses_performed"] == 3
        assert stats["decisions"]["retry"] == 1
        assert stats["decisions"]["modify_approach"] == 1
        assert stats["decisions"]["skip"] == 1


# ═══════════════════════════════════════════════════════════════
# Test Class: LLM Readiness
# ═══════════════════════════════════════════════════════════════

class TestLLMReadiness:
    """
    Test that the data path is ready for LLM integration.
    
    Verifies that all necessary context is captured and available
    for an LLM to make intelligent decisions.
    """
    
    @pytest.mark.asyncio
    async def test_error_context_has_complete_information(
        self, blackboard, target_ip
    ):
        """Test that error context contains all info needed for LLM analysis."""
        mission = Mission(
            name="LLM Context Test",
            scope=[f"{target_ip}/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        
        target = Target(
            mission_id=mission.id,
            ip=target_ip,
            os="Windows Server 2016"
        )
        await blackboard.add_target(target)
        
        task = Task(
            mission_id=mission.id,
            type=TaskType.EXPLOIT,
            specialist=SpecialistType.ATTACK,
            target_id=target.id,
            priority=9,
        )
        task_id = await blackboard.add_task(task)
        await blackboard.claim_task(mission_id, "worker", "attack")
        
        # Comprehensive error context for LLM
        error_context = {
            # Error identification
            "error_type": "edr_blocked",
            "error_code": "EDR_001",
            "error_message": "Behavioral detection triggered by CrowdStrike Falcon",
            
            # Target context
            "target_ip": target_ip,
            "target_port": 445,
            "target_service": "SMB",
            
            # Technique/module info
            "technique_id": "T1210",
            "module_used": "exploit/windows/smb/ms17_010_eternalblue",
            "command_executed": "exploit -j",
            
            # Defense context
            "detected_defenses": ["CrowdStrike Falcon", "EDR Agent"],
            "defense_action": "process_terminated",
            "detection_time_ms": 250,
            
            # Network context
            "network_conditions": "filtered",
            "latency_ms": 45,
            
            # Suggestions (could be from knowledge base)
            "retry_recommended": False,
            "alternative_techniques": ["T1059.001", "T1059.003", "T1047"],
            "alternative_modules": [
                "exploit/windows/smb/ms17_010_psexec",
                "auxiliary/admin/smb/psexec_command",
            ],
            
            # Stack trace for debugging
            "stack_trace": "Traceback...(simulated)",
        }
        
        await blackboard.fail_task(
            mission_id,
            str(task.id),
            error_context["error_message"],
            error_context
        )
        
        # Retrieve and verify completeness
        failed_task = await blackboard.get_task(str(task.id))
        stored_context = json.loads(failed_task["error_context"])
        
        # Verify all LLM-relevant fields are present
        required_fields = [
            "error_type", "error_message", "target_ip",
            "technique_id", "module_used", "detected_defenses",
            "alternative_techniques", "alternative_modules"
        ]
        
        for field in required_fields:
            assert field in stored_context, f"Missing LLM-required field: {field}"
        
        # Verify target info is accessible
        target_data = await blackboard.get_target(str(target.id))
        assert target_data["os"] == "Windows Server 2016"
    
    @pytest.mark.asyncio
    async def test_execution_logs_are_preserved(
        self, blackboard, target_ip
    ):
        """Test that execution logs are preserved for LLM analysis."""
        mission = Mission(
            name="Logs Test",
            scope=[f"{target_ip}/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        
        target = Target(mission_id=mission.id, ip=target_ip)
        await blackboard.add_target(target)
        
        task = Task(
            mission_id=mission.id,
            type=TaskType.EXPLOIT,
            specialist=SpecialistType.ATTACK,
            target_id=target.id,
            priority=9,
        )
        task_id = await blackboard.add_task(task)
        await blackboard.claim_task(mission_id, "worker", "attack")
        
        # Detailed execution logs
        execution_logs = [
            {"timestamp": "2024-01-01T10:00:00", "level": "info", "message": "Task started", "data": {"module": "ms17_010"}},
            {"timestamp": "2024-01-01T10:00:01", "level": "debug", "message": "Connecting to target", "data": {"ip": target_ip, "port": 445}},
            {"timestamp": "2024-01-01T10:00:02", "level": "info", "message": "Connection established", "data": {"protocol": "SMBv2"}},
            {"timestamp": "2024-01-01T10:00:03", "level": "debug", "message": "Sending exploit payload", "data": {"payload_size": 2048}},
            {"timestamp": "2024-01-01T10:00:04", "level": "warning", "message": "Unusual delay in response", "data": {"expected_ms": 100, "actual_ms": 500}},
            {"timestamp": "2024-01-01T10:00:05", "level": "error", "message": "EDR intervention detected", "data": {"edr": "CrowdStrike", "action": "blocked"}},
        ]
        
        await blackboard.fail_task(
            mission_id,
            str(task.id),
            "EDR blocked",
            {"error_type": "edr_blocked"},
            execution_logs
        )
        
        # Retrieve and verify logs
        failed_task = await blackboard.get_task(str(task.id))
        stored_logs = json.loads(failed_task["execution_logs"])
        
        assert len(stored_logs) == 6
        
        # Verify log progression is preserved
        levels = [log["level"] for log in stored_logs]
        assert levels == ["info", "debug", "info", "debug", "warning", "error"]
        
        # Verify timing info is preserved
        assert stored_logs[4]["data"]["expected_ms"] == 100
        assert stored_logs[4]["data"]["actual_ms"] == 500


# ═══════════════════════════════════════════════════════════════
# Test Class: Edge Cases
# ═══════════════════════════════════════════════════════════════

class TestEdgeCases:
    """Test edge cases in Reflexion Logic."""
    
    @pytest.mark.asyncio
    async def test_analysis_with_missing_task(
        self, blackboard, analysis_specialist, target_ip
    ):
        """Test analysis when task doesn't exist."""
        mission = Mission(
            name="Missing Task Test",
            scope=[f"{target_ip}/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        await analysis_specialist.start(mission_id)
        
        result = await analysis_specialist.analyze_failure(
            "nonexistent-task-id",
            {"error_type": "unknown"}
        )
        
        assert result["decision"] == "skip"
        assert "not found" in result["reasoning"].lower()
    
    @pytest.mark.asyncio
    async def test_analysis_with_empty_error_context(
        self, blackboard, analysis_specialist, target_ip
    ):
        """Test analysis with minimal error context."""
        mission = Mission(
            name="Empty Context Test",
            scope=[f"{target_ip}/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        await analysis_specialist.start(mission_id)
        
        target = Target(mission_id=mission.id, ip=target_ip)
        await blackboard.add_target(target)
        
        task = Task(
            mission_id=mission.id,
            type=TaskType.EXPLOIT,
            specialist=SpecialistType.ATTACK,
            target_id=target.id,
            priority=9,
        )
        task_id = await blackboard.add_task(task)
        await blackboard.claim_task(mission_id, "worker", "attack")
        
        # Empty error context
        result = await analysis_specialist.analyze_failure(
            str(task.id),
            {}  # No context
        )
        
        # Should handle gracefully (escalate unknown)
        assert result["decision"] == "escalate"
    
    @pytest.mark.asyncio
    async def test_analysis_tracks_statistics(
        self, blackboard, analysis_specialist, target_ip
    ):
        """Test that analysis statistics are properly tracked."""
        mission = Mission(
            name="Stats Test",
            scope=[f"{target_ip}/32"],
            goals={}
        )
        mission_id = await blackboard.create_mission(mission)
        await analysis_specialist.start(mission_id)
        
        target = Target(mission_id=mission.id, ip=target_ip)
        await blackboard.add_target(target)
        
        # Perform multiple analyses
        for i in range(5):
            task = Task(
                mission_id=mission.id,
                type=TaskType.EXPLOIT,
                specialist=SpecialistType.ATTACK,
                target_id=target.id,
                priority=9,
            )
            await blackboard.add_task(task)
            await blackboard.claim_task(mission_id, f"worker-{i}", "attack")
            
            await analysis_specialist.analyze_failure(
                str(task.id),
                {"error_type": "connection_refused"}
            )
        
        stats = analysis_specialist.get_stats()
        assert stats["analyses_performed"] == 5
        assert stats["decisions"]["retry"] == 5


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
