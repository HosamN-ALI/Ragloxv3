# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Blackboard Implementation
# Central shared state using Redis
# ═══════════════════════════════════════════════════════════════

from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Type, TypeVar
from uuid import UUID
import json
import asyncio

import redis.asyncio as aioredis
from pydantic import BaseModel

from .config import Settings, get_settings
from .models import (
    Mission, MissionStatus, MissionStats,
    Target, TargetStatus,
    Vulnerability, Severity,
    Credential,
    Session, SessionStatus,
    Task, TaskStatus,
    AttackPath,
    BlackboardEvent,
)

T = TypeVar('T', bound=BaseModel)


class Blackboard:
    """
    Blackboard - The central shared state for RAGLOX.
    
    Implements the Blackboard pattern using Redis as the backing store.
    All specialists read from and write to this shared state.
    
    Features:
    - Key-value storage for entities
    - Pub/Sub for real-time notifications
    - Sorted sets for priority queues
    - Streams for event logs
    """
    
    def __init__(
        self,
        redis_url: Optional[str] = None,
        settings: Optional[Settings] = None
    ):
        """
        Initialize the Blackboard.
        
        Args:
            redis_url: Redis connection URL (overrides settings)
            settings: Application settings
        """
        self.settings = settings or get_settings()
        self.redis_url = redis_url or self.settings.redis_url
        self._redis: Optional[aioredis.Redis] = None
        self._pubsub: Optional[aioredis.client.PubSub] = None
        self._connected = False
    
    # ═══════════════════════════════════════════════════════════
    # Connection Management
    # ═══════════════════════════════════════════════════════════
    
    async def connect(self) -> None:
        """Connect to Redis."""
        if self._connected:
            return
            
        self._redis = await aioredis.from_url(
            self.redis_url,
            encoding="utf-8",
            decode_responses=True,
            max_connections=self.settings.redis_max_connections,
        )
        self._connected = True
    
    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        if self._pubsub:
            await self._pubsub.close()
            self._pubsub = None
        if self._redis:
            await self._redis.close()
            self._redis = None
        self._connected = False
    
    async def health_check(self) -> bool:
        """Check if Redis connection is healthy."""
        if not self._redis:
            return False
        try:
            await self._redis.ping()
            return True
        except Exception:
            return False
    
    @property
    def redis(self) -> aioredis.Redis:
        """Get Redis client (raises if not connected)."""
        if not self._redis:
            raise RuntimeError("Blackboard not connected. Call connect() first.")
        return self._redis
    
    # ═══════════════════════════════════════════════════════════
    # Generic CRUD Operations
    # ═══════════════════════════════════════════════════════════
    
    async def _set_hash(self, key: str, data: Dict[str, Any]) -> None:
        """Set a hash in Redis."""
        # Convert complex types to JSON strings
        serialized = {}
        for k, v in data.items():
            if isinstance(v, (dict, list)):
                serialized[k] = json.dumps(v)
            elif isinstance(v, datetime):
                serialized[k] = v.isoformat()
            elif isinstance(v, UUID):
                serialized[k] = str(v)
            elif isinstance(v, bool):
                serialized[k] = "true" if v else "false"
            elif v is None:
                continue  # Skip None values
            else:
                serialized[k] = str(v)
        
        await self.redis.hset(key, mapping=serialized)
    
    async def _get_hash(self, key: str) -> Optional[Dict[str, Any]]:
        """Get a hash from Redis."""
        data = await self.redis.hgetall(key)
        if not data:
            return None
        return data
    
    async def _delete(self, key: str) -> None:
        """Delete a key from Redis."""
        await self.redis.delete(key)
    
    # ═══════════════════════════════════════════════════════════
    # Mission Operations
    # ═══════════════════════════════════════════════════════════
    
    async def create_mission(self, mission: Mission) -> str:
        """
        Create a new mission.
        
        Args:
            mission: Mission object to create
            
        Returns:
            Mission ID
        """
        mission_id = str(mission.id)
        
        # Store mission info
        await self._set_hash(f"mission:{mission_id}:info", mission.model_dump())
        
        # Initialize goals
        goals = {goal: "pending" for goal in mission.goals.keys()}
        if goals:
            await self.redis.hset(f"mission:{mission_id}:goals", mapping=goals)
        
        # Initialize stats
        await self.redis.hset(f"mission:{mission_id}:stats", mapping={
            "targets_discovered": 0,
            "vulns_found": 0,
            "creds_harvested": 0,
            "sessions_established": 0,
            "goals_achieved": 0,
        })
        
        return mission_id
    
    async def get_mission(self, mission_id: str) -> Optional[Dict[str, Any]]:
        """Get mission by ID."""
        return await self._get_hash(f"mission:{mission_id}:info")
    
    async def update_mission_status(
        self,
        mission_id: str,
        status: MissionStatus
    ) -> None:
        """Update mission status."""
        await self.redis.hset(f"mission:{mission_id}:info", "status", status.value)
        
        if status == MissionStatus.RUNNING:
            await self.redis.hset(
                f"mission:{mission_id}:info",
                "started_at",
                datetime.utcnow().isoformat()
            )
        elif status in (MissionStatus.COMPLETED, MissionStatus.FAILED):
            await self.redis.hset(
                f"mission:{mission_id}:info",
                "completed_at",
                datetime.utcnow().isoformat()
            )
    
    async def get_mission_goals(self, mission_id: str) -> Dict[str, str]:
        """Get mission goals and their status."""
        return await self.redis.hgetall(f"mission:{mission_id}:goals") or {}
    
    async def update_goal_status(
        self,
        mission_id: str,
        goal: str,
        status: str
    ) -> None:
        """Update a goal's status."""
        await self.redis.hset(f"mission:{mission_id}:goals", goal, status)
        
        if status == "achieved":
            await self.redis.hincrby(f"mission:{mission_id}:stats", "goals_achieved", 1)
    
    async def get_mission_stats(self, mission_id: str) -> MissionStats:
        """Get mission statistics."""
        stats = await self.redis.hgetall(f"mission:{mission_id}:stats")
        if not stats:
            return MissionStats()
        
        return MissionStats(
            targets_discovered=int(stats.get("targets_discovered", 0)),
            vulns_found=int(stats.get("vulns_found", 0)),
            creds_harvested=int(stats.get("creds_harvested", 0)),
            sessions_established=int(stats.get("sessions_established", 0)),
            goals_achieved=int(stats.get("goals_achieved", 0)),
        )
    
    # ═══════════════════════════════════════════════════════════
    # Target Operations
    # ═══════════════════════════════════════════════════════════
    
    async def add_target(self, target: Target) -> str:
        """Add a new target."""
        target_id = str(target.id)
        mission_id = str(target.mission_id)
        
        # Store target
        await self._set_hash(f"target:{target_id}", target.model_dump())
        
        # Add to mission's target set
        await self.redis.sadd(f"mission:{mission_id}:targets", f"target:{target_id}")
        
        # Update stats
        await self.redis.hincrby(f"mission:{mission_id}:stats", "targets_discovered", 1)
        
        return target_id
    
    async def get_target(self, target_id: str) -> Optional[Dict[str, Any]]:
        """Get target by ID."""
        return await self._get_hash(f"target:{target_id}")
    
    async def get_mission_targets(self, mission_id: str) -> List[str]:
        """Get all target IDs for a mission."""
        targets = await self.redis.smembers(f"mission:{mission_id}:targets")
        return list(targets) if targets else []
    
    async def update_target_status(
        self,
        target_id: str,
        status: TargetStatus
    ) -> None:
        """Update target status."""
        await self.redis.hset(f"target:{target_id}", "status", status.value)
    
    async def add_target_ports(
        self,
        target_id: str,
        ports: Dict[int, str]
    ) -> None:
        """Add ports to a target."""
        if ports:
            mapping = {str(port): info for port, info in ports.items()}
            await self.redis.hset(f"target:{target_id}:ports", mapping=mapping)
    
    async def get_target_ports(self, target_id: str) -> Dict[str, str]:
        """Get target ports."""
        return await self.redis.hgetall(f"target:{target_id}:ports") or {}
    
    # ═══════════════════════════════════════════════════════════
    # Vulnerability Operations
    # ═══════════════════════════════════════════════════════════
    
    async def add_vulnerability(self, vuln: Vulnerability) -> str:
        """Add a new vulnerability."""
        vuln_id = str(vuln.id)
        mission_id = str(vuln.mission_id)
        
        # Store vulnerability
        await self._set_hash(f"vuln:{vuln_id}", vuln.model_dump())
        
        # Add to sorted set by CVSS score
        score = vuln.cvss if vuln.cvss else self._severity_to_score(vuln.severity)
        await self.redis.zadd(f"mission:{mission_id}:vulns", {f"vuln:{vuln_id}": score})
        
        # Update stats
        await self.redis.hincrby(f"mission:{mission_id}:stats", "vulns_found", 1)
        
        return vuln_id
    
    def _severity_to_score(self, severity: Severity) -> float:
        """Convert severity to numeric score."""
        mapping = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 8.0,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 3.0,
            Severity.INFO: 1.0,
        }
        return mapping.get(severity, 5.0)
    
    async def get_vulnerability(self, vuln_id: str) -> Optional[Dict[str, Any]]:
        """Get vulnerability by ID."""
        return await self._get_hash(f"vuln:{vuln_id}")
    
    async def get_mission_vulns(
        self,
        mission_id: str,
        limit: int = 100
    ) -> List[str]:
        """Get vulnerability IDs for a mission, sorted by severity."""
        vulns = await self.redis.zrevrange(
            f"mission:{mission_id}:vulns",
            0,
            limit - 1
        )
        return list(vulns) if vulns else []
    
    async def update_vuln_status(self, vuln_id: str, status: str) -> None:
        """Update vulnerability status."""
        await self.redis.hset(f"vuln:{vuln_id}", "status", status)
    
    # ═══════════════════════════════════════════════════════════
    # Credential Operations
    # ═══════════════════════════════════════════════════════════
    
    async def add_credential(self, cred: Credential) -> str:
        """Add a new credential."""
        cred_id = str(cred.id)
        mission_id = str(cred.mission_id)
        
        # Store credential
        await self._set_hash(f"cred:{cred_id}", cred.model_dump())
        
        # Add to mission's credential set
        await self.redis.sadd(f"mission:{mission_id}:creds", f"cred:{cred_id}")
        
        # Update stats
        await self.redis.hincrby(f"mission:{mission_id}:stats", "creds_harvested", 1)
        
        return cred_id
    
    async def get_credential(self, cred_id: str) -> Optional[Dict[str, Any]]:
        """Get credential by ID."""
        return await self._get_hash(f"cred:{cred_id}")
    
    async def get_mission_creds(self, mission_id: str) -> List[str]:
        """Get all credential IDs for a mission."""
        creds = await self.redis.smembers(f"mission:{mission_id}:creds")
        return list(creds) if creds else []
    
    # ═══════════════════════════════════════════════════════════
    # Session Operations
    # ═══════════════════════════════════════════════════════════
    
    async def add_session(self, session: Session) -> str:
        """Add a new session."""
        session_id = str(session.id)
        mission_id = str(session.mission_id)
        
        # Store session
        await self._set_hash(f"session:{session_id}", session.model_dump())
        
        # Add to mission's session set
        await self.redis.sadd(f"mission:{mission_id}:sessions", f"session:{session_id}")
        
        # Update stats
        await self.redis.hincrby(f"mission:{mission_id}:stats", "sessions_established", 1)
        
        return session_id
    
    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session by ID."""
        return await self._get_hash(f"session:{session_id}")
    
    async def get_mission_sessions(self, mission_id: str) -> List[str]:
        """Get all session IDs for a mission."""
        sessions = await self.redis.smembers(f"mission:{mission_id}:sessions")
        return list(sessions) if sessions else []
    
    async def update_session_status(
        self,
        session_id: str,
        status: SessionStatus
    ) -> None:
        """Update session status."""
        await self.redis.hset(f"session:{session_id}", "status", status.value)
        await self.redis.hset(
            f"session:{session_id}",
            "last_activity",
            datetime.utcnow().isoformat()
        )
    
    # ═══════════════════════════════════════════════════════════
    # Task Operations
    # ═══════════════════════════════════════════════════════════
    
    async def add_task(self, task: Task) -> str:
        """Add a new task to the pending queue."""
        task_id = str(task.id)
        mission_id = str(task.mission_id)
        
        # Store task
        await self._set_hash(f"task:{task_id}", task.model_dump())
        
        # Add to pending queue (sorted by priority)
        await self.redis.zadd(
            f"mission:{mission_id}:tasks:pending",
            {f"task:{task_id}": task.priority}
        )
        
        return task_id
    
    async def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get task by ID."""
        return await self._get_hash(f"task:{task_id}")
    
    async def claim_task(
        self,
        mission_id: str,
        worker_id: str,
        specialist: str
    ) -> Optional[str]:
        """
        Claim a pending task for a worker.
        
        Args:
            mission_id: Mission ID
            worker_id: Worker ID claiming the task
            specialist: Specialist type
            
        Returns:
            Task ID if claimed, None if no tasks available
        """
        # Get highest priority task for this specialist
        pending_key = f"mission:{mission_id}:tasks:pending"
        running_key = f"mission:{mission_id}:tasks:running"
        
        # Get all pending tasks
        tasks = await self.redis.zrevrange(pending_key, 0, -1)
        
        for task_key in tasks:
            task = await self._get_hash(task_key)
            if task and task.get("specialist") == specialist:
                # Move to running
                await self.redis.zrem(pending_key, task_key)
                await self.redis.sadd(running_key, task_key)
                
                # Update task
                task_id = task_key.replace("task:", "")
                await self.redis.hset(f"task:{task_id}", mapping={
                    "status": TaskStatus.RUNNING.value,
                    "assigned_to": worker_id,
                    "started_at": datetime.utcnow().isoformat(),
                })
                
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
        await self.redis.srem(running_key, task_key)
        await self.redis.lpush(completed_key, task_key)
        
        # Update task
        update = {
            "status": TaskStatus.COMPLETED.value,
            "completed_at": datetime.utcnow().isoformat(),
            "result": result,
        }
        if result_data:
            update["result_data"] = json.dumps(result_data)
        
        await self.redis.hset(task_key, mapping=update)
    
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
        
        # Move from running to completed
        await self.redis.srem(running_key, task_key)
        await self.redis.lpush(completed_key, task_key)
        
        # Update task
        await self.redis.hset(task_key, mapping={
            "status": TaskStatus.FAILED.value,
            "completed_at": datetime.utcnow().isoformat(),
            "result": "failure",
            "error_message": error_message,
        })
    
    async def get_pending_tasks(
        self,
        mission_id: str,
        specialist: Optional[str] = None,
        limit: int = 100
    ) -> List[str]:
        """Get pending task IDs."""
        tasks = await self.redis.zrevrange(
            f"mission:{mission_id}:tasks:pending",
            0,
            limit - 1
        )
        
        if not specialist:
            return list(tasks) if tasks else []
        
        # Filter by specialist
        result = []
        for task_key in tasks:
            task = await self._get_hash(task_key)
            if task and task.get("specialist") == specialist:
                result.append(task_key.replace("task:", ""))
        
        return result
    
    # ═══════════════════════════════════════════════════════════
    # Pub/Sub Operations
    # ═══════════════════════════════════════════════════════════
    
    async def publish(self, channel: str, event: BlackboardEvent) -> None:
        """Publish an event to a channel."""
        await self.redis.publish(channel, event.model_dump_json())
    
    async def publish_dict(self, channel: str, data: Dict[str, Any]) -> None:
        """Publish a dictionary to a channel."""
        await self.redis.publish(channel, json.dumps(data))
    
    async def subscribe(self, *channels: str) -> aioredis.client.PubSub:
        """Subscribe to channels."""
        if not self._pubsub:
            self._pubsub = self.redis.pubsub()
        
        await self._pubsub.subscribe(*channels)
        return self._pubsub
    
    async def get_message(
        self,
        timeout: float = 1.0
    ) -> Optional[Dict[str, Any]]:
        """Get next message from subscribed channels."""
        if not self._pubsub:
            return None
        
        message = await self._pubsub.get_message(
            ignore_subscribe_messages=True,
            timeout=timeout
        )
        
        if message and message["type"] == "message":
            try:
                return json.loads(message["data"])
            except json.JSONDecodeError:
                return {"raw": message["data"]}
        
        return None
    
    def get_channel(self, mission_id: str, entity: str) -> str:
        """Get the channel name for a mission entity."""
        return f"channel:mission:{mission_id}:{entity}"
    
    # ═══════════════════════════════════════════════════════════
    # Heartbeat Operations
    # ═══════════════════════════════════════════════════════════
    
    async def send_heartbeat(
        self,
        mission_id: str,
        specialist_id: str
    ) -> None:
        """Send a heartbeat from a specialist."""
        await self.redis.hset(
            f"mission:{mission_id}:heartbeats",
            specialist_id,
            datetime.utcnow().isoformat()
        )
    
    async def get_heartbeats(self, mission_id: str) -> Dict[str, str]:
        """Get all heartbeats for a mission."""
        return await self.redis.hgetall(f"mission:{mission_id}:heartbeats") or {}
    
    # ═══════════════════════════════════════════════════════════
    # Results Stream
    # ═══════════════════════════════════════════════════════════
    
    async def log_result(
        self,
        mission_id: str,
        event_type: str,
        data: Dict[str, Any]
    ) -> None:
        """Log a result to the mission's result stream."""
        await self.redis.xadd(
            f"mission:{mission_id}:results",
            {
                "type": event_type,
                "data": json.dumps(data),
                "timestamp": datetime.utcnow().isoformat(),
            }
        )
    
    async def get_results(
        self,
        mission_id: str,
        count: int = 100,
        start: str = "-",
        end: str = "+"
    ) -> List[Dict[str, Any]]:
        """Get results from the mission's result stream."""
        results = await self.redis.xrange(
            f"mission:{mission_id}:results",
            min=start,
            max=end,
            count=count
        )
        
        parsed = []
        for entry_id, fields in results:
            parsed.append({
                "id": entry_id,
                "type": fields.get("type"),
                "data": json.loads(fields.get("data", "{}")),
                "timestamp": fields.get("timestamp"),
            })
        
        return parsed
