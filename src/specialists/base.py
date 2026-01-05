# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Base Specialist
# Abstract base class for all specialist agents
# ═══════════════════════════════════════════════════════════════

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, TYPE_CHECKING
from uuid import uuid4, UUID
import asyncio
import logging

from ..core.blackboard import Blackboard
from ..core.models import (
    Task, TaskStatus, TaskType, SpecialistType,
    Mission, MissionStatus,
    Target, TargetStatus,
    Vulnerability, Severity,
    Credential, CredentialType, PrivilegeLevel,
    Session, SessionStatus,
    BlackboardEvent, NewTargetEvent, NewVulnEvent,
    NewCredEvent, NewSessionEvent, NewTaskEvent,
    ExecutionLog, ErrorContext
)
from ..core.config import Settings, get_settings
from ..core.knowledge import EmbeddedKnowledge, get_knowledge
from ..core.retry_policy import get_retry_manager, RetryPolicy

# Type hints for executor imports (avoid circular imports)
if TYPE_CHECKING:
    from ..executors import RXModuleRunner, ExecutorFactory


class BaseSpecialist(ABC):
    """
    Base class for all RAGLOX specialists.
    
    Specialists are autonomous agents that:
    - Read from and write to the Blackboard (shared state)
    - Process tasks assigned to them
    - Communicate via Pub/Sub events
    - Never communicate directly with other specialists
    
    Design Principles:
    - Specialization: Each specialist focuses on specific task types
    - Autonomy: Operates independently based on Blackboard state
    - No Direct Communication: Only communicates through Blackboard
    - Scalability: Multiple instances can run in parallel
    """
    
    def __init__(
        self,
        specialist_type: SpecialistType,
        blackboard: Optional[Blackboard] = None,
        settings: Optional[Settings] = None,
        worker_id: Optional[str] = None,
        knowledge: Optional[EmbeddedKnowledge] = None,
        runner: Optional['RXModuleRunner'] = None,
        executor_factory: Optional['ExecutorFactory'] = None
    ):
        """
        Initialize the specialist.
        
        Args:
            specialist_type: Type of specialist (recon, attack, etc.)
            blackboard: Blackboard instance (will create if not provided)
            settings: Application settings
            worker_id: Unique worker identifier
            knowledge: Embedded knowledge base (will use singleton if not provided)
            runner: RXModuleRunner for executing RX modules (injected for testability)
            executor_factory: ExecutorFactory for managing connections (injected for testability)
        """
        self.specialist_type = specialist_type
        self.settings = settings or get_settings()
        self.blackboard = blackboard or Blackboard(settings=self.settings)
        self.worker_id = worker_id or f"{specialist_type.value}-{uuid4().hex[:8]}"
        
        # Knowledge base - use singleton if not provided
        self._knowledge = knowledge
        
        # Execution layer dependencies (lazy-loaded if not provided)
        self._runner = runner
        self._executor_factory = executor_factory
        
        # Logging
        self.logger = logging.getLogger(f"raglox.specialist.{specialist_type.value}")
        
        # State
        self._running = False
        self._current_mission_id: Optional[str] = None
        self._subscribed_channels: Set[str] = set()
        
        # Task types this specialist handles
        self._supported_task_types: Set[TaskType] = set()
        
        # ═══════════════════════════════════════════════════════════
        # GAP-C04 FIX: Concurrent Task Control
        # Implement semaphore-based concurrency control to prevent
        # resource exhaustion from unlimited parallel task execution
        # ═══════════════════════════════════════════════════════════
        
        # Max concurrent tasks per specialist (configurable from settings)
        self._max_concurrent_tasks = getattr(
            self.settings,
            f'{specialist_type.value}_max_concurrent_tasks',
            5  # Default: 5 concurrent tasks
        )
        
        # Semaphore to control concurrent task execution
        self._task_semaphore = asyncio.Semaphore(self._max_concurrent_tasks)
        
        # Active tasks tracking (for monitoring and graceful shutdown)
        self._active_tasks: Set[asyncio.Task] = set()
        self._active_task_ids: Set[str] = set()
        
        # Task execution statistics
        self._task_stats = {
            "total_tasks_processed": 0,
            "concurrent_tasks_current": 0,
            "concurrent_tasks_peak": 0,
            "tasks_queued_total": 0,
            "tasks_rejected_total": 0,
        }
        
        self.logger.info(
            f"{specialist_type.value} initialized with max_concurrent_tasks={self._max_concurrent_tasks}"
        )
        
        # Heartbeat interval (seconds)
        self._heartbeat_interval = 30
        
        # ═══════════════════════════════════════════════════════════
        # GAP-C01 FIX: Centralized Retry Policy
        # Integrate unified retry manager for consistent retry behavior
        # across all specialists and operation types
        # ═══════════════════════════════════════════════════════════
        
        self._retry_manager = get_retry_manager()
        
        # Execution mode: "real" uses Runner, "simulated" uses mock functions
        self._execution_mode = "real" if runner else "simulated"
        
    # ═══════════════════════════════════════════════════════════
    # Abstract Methods - Must be implemented by subclasses
    # ═══════════════════════════════════════════════════════════
    
    @abstractmethod
    async def execute_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a task.
        
        Args:
            task: Task data from Redis
            
        Returns:
            Result data dictionary
            
        This method must be implemented by each specialist type.
        """
        pass
    
    @abstractmethod
    async def on_event(self, event: Dict[str, Any]) -> None:
        """
        Handle an event from Pub/Sub.
        
        Args:
            event: Event data
            
        This method must be implemented by each specialist type.
        """
        pass
    
    # ═══════════════════════════════════════════════════════════
    # Lifecycle Methods
    # ═══════════════════════════════════════════════════════════
    
    async def start(self, mission_id: str) -> None:
        """
        Start the specialist for a mission.
        
        Args:
            mission_id: Mission to work on
        """
        self.logger.info(f"Starting {self.worker_id} for mission {mission_id}")
        
        # Connect to Blackboard
        await self.blackboard.connect()
        
        self._running = True
        self._current_mission_id = mission_id
        
        # Subscribe to relevant channels
        await self._subscribe_to_channels(mission_id)
        
        # Start main loops
        asyncio.create_task(self._task_loop())
        asyncio.create_task(self._event_loop())
        asyncio.create_task(self._heartbeat_loop())
        
        self.logger.info(f"{self.worker_id} started successfully")
    
    async def stop(self) -> None:
        """Stop the specialist."""
        self.logger.info(f"Stopping {self.worker_id}")
        
        self._running = False
        self._current_mission_id = None
        self._subscribed_channels.clear()
        
        # Cleanup executor connections
        await self.cleanup_connections()
        
        # Disconnect from Blackboard
        await self.blackboard.disconnect()
        
        self.logger.info(f"{self.worker_id} stopped")
    
    async def pause(self) -> None:
        """Pause task processing."""
        self._running = False
        self.logger.info(f"{self.worker_id} paused")
    
    async def resume(self) -> None:
        """Resume task processing."""
        self._running = True
        self.logger.info(f"{self.worker_id} resumed")
    
    # ═══════════════════════════════════════════════════════════
    # Main Loops
    # ═══════════════════════════════════════════════════════════
    
    async def _task_loop(self) -> None:
        """
        ═══════════════════════════════════════════════════════════════
        GAP-C04 FIX: Concurrency-Controlled Task Processing Loop
        ═══════════════════════════════════════════════════════════════
        
        Main task processing loop with semaphore-based concurrency control.
        
        Flow:
        1. Claim task from Blackboard
        2. Acquire semaphore slot (wait if at max concurrency)
        3. Spawn task in background with semaphore release
        4. Track active tasks for monitoring
        5. Update statistics
        
        This prevents resource exhaustion by limiting parallel task execution.
        """
        while self._current_mission_id:
            if not self._running:
                await asyncio.sleep(1)
                continue
            
            try:
                # Try to claim a task
                task_id = await self.blackboard.claim_task(
                    self._current_mission_id,
                    self.worker_id,
                    self.specialist_type.value
                )
                
                if task_id:
                    self._task_stats["tasks_queued_total"] += 1
                    
                    # ═══════════════════════════════════════════════════════════
                    # CRITICAL: Spawn task with semaphore control
                    # This ensures we never exceed max_concurrent_tasks
                    # ═══════════════════════════════════════════════════════════
                    
                    # Try to acquire semaphore (non-blocking check first)
                    if self._task_semaphore.locked() and len(self._active_tasks) >= self._max_concurrent_tasks:
                        # At max capacity - this shouldn't happen often due to backpressure
                        # but log it for monitoring
                        self.logger.warning(
                            f"At max concurrent tasks ({self._max_concurrent_tasks}), "
                            f"waiting for slot..."
                        )
                    
                    # Spawn task in background with concurrency control
                    task_coro = self._process_task_with_semaphore(task_id)
                    async_task = asyncio.create_task(task_coro)
                    
                    # Track active task
                    self._active_tasks.add(async_task)
                    self._active_task_ids.add(task_id)
                    
                    # Clean up when done
                    async_task.add_done_callback(
                        lambda t: self._on_task_complete(t, task_id)
                    )
                    
                else:
                    # No tasks available, wait briefly
                    await asyncio.sleep(0.5)
                    
            except asyncio.CancelledError:
                # SEC-01: Handle task cancellation gracefully
                self.logger.info("Task loop cancelled")
                break
            except (ConnectionError, OSError) as e:
                # SEC-01: Handle connection errors with retry
                self.logger.warning(f"Connection error in task loop: {e}")
                await asyncio.sleep(2)  # Longer wait for connection issues
            except (KeyError, ValueError, TypeError) as e:
                # SEC-01: Handle data errors
                self.logger.error(f"Data error in task loop: {e}")
                await asyncio.sleep(1)
    
    async def _process_task_with_semaphore(self, task_id: str) -> None:
        """
        Process a task with semaphore-based concurrency control.
        
        This wrapper ensures:
        1. Task acquires semaphore slot before execution
        2. Semaphore is released even if task fails
        3. Concurrent task count is tracked
        
        Args:
            task_id: ID of the task to process
        """
        # Acquire semaphore (blocks if at max concurrency)
        async with self._task_semaphore:
            # Update statistics
            concurrent = len(self._active_tasks)
            self._task_stats["concurrent_tasks_current"] = concurrent
            if concurrent > self._task_stats["concurrent_tasks_peak"]:
                self._task_stats["concurrent_tasks_peak"] = concurrent
            
            self.logger.debug(
                f"Task {task_id} acquired execution slot "
                f"({concurrent}/{self._max_concurrent_tasks} active)"
            )
            
            # Execute the actual task
            try:
                await self._process_task(task_id)
            except asyncio.CancelledError:
                # SEC-01: Handle task cancellation
                self.logger.info(f"Task {task_id} was cancelled")
                raise  # Re-raise to allow proper cleanup
            except (ConnectionError, OSError, asyncio.TimeoutError) as e:
                # SEC-01: Handle connection/timeout errors
                self.logger.error(f"Task {task_id} connection/timeout error: {e}")
            except (KeyError, ValueError, TypeError) as e:
                # SEC-01: Handle data/validation errors
                self.logger.error(f"Task {task_id} data error: {e}")
            finally:
                # Semaphore is automatically released by async with context manager
                self.logger.debug(f"Task {task_id} released execution slot")
    
    def _on_task_complete(self, task: asyncio.Task, task_id: str) -> None:
        """
        Callback when a task completes (success or failure).
        
        Clean up tracking data structures.
        
        Args:
            task: The asyncio.Task that completed
            task_id: The task ID
        """
        # Remove from active tracking
        self._active_tasks.discard(task)
        self._active_task_ids.discard(task_id)
        
        # Update statistics
        self._task_stats["total_tasks_processed"] += 1
        self._task_stats["concurrent_tasks_current"] = len(self._active_tasks)
        
        # Log any uncaught exception
        if task.exception():
            self.logger.error(
                f"Task {task_id} raised uncaught exception: {task.exception()}",
                exc_info=task.exception()
            )
    
    async def _event_loop(self) -> None:
        """Pub/Sub event processing loop."""
        while self._current_mission_id:
            try:
                message = await self.blackboard.get_message(timeout=1.0)
                
                if message and self._running:
                    await self.on_event(message)
                    
            except asyncio.CancelledError:
                # SEC-01: Handle event loop cancellation
                self.logger.info("Event loop cancelled")
                break
            except (ConnectionError, OSError) as e:
                # SEC-01: Handle connection errors
                self.logger.warning(f"Connection error in event loop: {e}")
                await asyncio.sleep(2)
            except (KeyError, ValueError, TypeError) as e:
                # SEC-01: Handle data errors
                self.logger.error(f"Data error in event loop: {e}")
                await asyncio.sleep(1)
    
    async def _heartbeat_loop(self) -> None:
        """Heartbeat loop to signal worker is alive."""
        while self._current_mission_id:
            try:
                if self._running:
                    await self.blackboard.send_heartbeat(
                        self._current_mission_id,
                        self.worker_id
                    )
                await asyncio.sleep(self._heartbeat_interval)
            except asyncio.CancelledError:
                # SEC-01: Handle heartbeat cancellation
                self.logger.info("Heartbeat loop cancelled")
                break
            except (ConnectionError, OSError) as e:
                # SEC-01: Handle connection errors with longer retry
                self.logger.warning(f"Connection error in heartbeat: {e}")
                await asyncio.sleep(10)  # Longer wait for connection issues
            except (KeyError, ValueError) as e:
                # SEC-01: Handle data errors
                self.logger.error(f"Data error in heartbeat: {e}")
                await asyncio.sleep(5)
    
    # ═══════════════════════════════════════════════════════════
    # Task Processing
    # ═══════════════════════════════════════════════════════════
    
    async def _process_task(self, task_id: str) -> None:
        """
        ═══════════════════════════════════════════════════════════════
        GAP-C01 FIX: Process task with centralized retry policy
        ═══════════════════════════════════════════════════════════════
        
        Process a claimed task with intelligent retry logic.
        
        Flow:
        1. Get task details from Blackboard
        2. Determine appropriate retry policy based on task type
        3. Execute task with retry wrapper
        4. Handle success/failure with proper retry coordination
        5. Log results and error contexts for Reflexion
        
        Args:
            task_id: ID of the task to process
        """
        self.logger.info(f"Processing task {task_id}")
        
        try:
            # Get task details
            task = await self.blackboard.get_task(task_id)
            
            if not task:
                self.logger.warning(f"Task {task_id} not found")
                return
            
            # Determine retry policy based on task type
            task_type = task.get("type", "")
            retry_policy_name = self._get_retry_policy_for_task(task_type, task)
            
            # Execute task with retry policy
            result_data = await self._retry_manager.execute_with_retry(
                func=self.execute_task,
                args=(task,),
                kwargs={},
                policy_name=retry_policy_name,
                context={
                    "task_id": task_id,
                    "task_type": task_type,
                    "mission_id": self._current_mission_id,
                    "worker_id": self.worker_id
                }
            )
            
            # Mark task as completed
            await self.blackboard.complete_task(
                self._current_mission_id,
                task_id,
                "success",
                result_data
            )
            
            # Log result
            await self.blackboard.log_result(
                self._current_mission_id,
                f"task_completed",
                {
                    "task_id": task_id,
                    "task_type": task.get("type"),
                    "worker_id": self.worker_id,
                    "result": result_data,
                    "retry_policy_used": retry_policy_name
                }
            )
            
            self.logger.info(f"Task {task_id} completed successfully with policy {retry_policy_name}")
            
        except asyncio.CancelledError:
            # SEC-01: Handle task cancellation
            self.logger.info(f"Task {task_id} was cancelled")
            raise
        except asyncio.TimeoutError as e:
            # SEC-01: Handle timeout specifically
            self.logger.error(f"Task {task_id} timed out: {e}")
            error_context = self._extract_error_context(e, task)
            error_context["category"] = "timeout"
            await self._handle_task_failure(task_id, task, "Task timed out", error_context)
        except (ConnectionError, OSError) as e:
            # SEC-01: Handle connection errors
            self.logger.error(f"Task {task_id} connection error: {e}")
            error_context = self._extract_error_context(e, task)
            error_context["category"] = "network"
            await self._handle_task_failure(task_id, task, f"Connection error: {type(e).__name__}", error_context)
        except (KeyError, ValueError, TypeError) as e:
            # SEC-01: Handle data/validation errors
            self.logger.error(f"Task {task_id} data error: {e}")
            error_context = self._extract_error_context(e, task)
            error_context["category"] = "validation"
            await self._handle_task_failure(task_id, task, f"Data error: {type(e).__name__}", error_context)
    
    def _get_retry_policy_for_task(self, task_type: str, task: Dict[str, Any]) -> str:
        """
        Determine appropriate retry policy based on task type and context.
        
        Args:
            task_type: Type of task
            task: Full task dictionary
            
        Returns:
            Retry policy name
        """
        # Map task types to retry policies
        task_type_lower = task_type.lower()
        
        if "network" in task_type_lower or "scan" in task_type_lower:
            return "network_operation"
        elif "exploit" in task_type_lower or "attack" in task_type_lower:
            return "vulnerability_operation"
        elif "auth" in task_type_lower or "cred" in task_type_lower:
            return "authentication_operation"
        elif "llm" in task_type_lower or "analysis" in task_type_lower:
            return "llm_api"
        else:
            return "default"
    
    def _extract_error_context(self, exception: Exception, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract error context for Reflexion analysis.
        
        Args:
            exception: Exception that occurred
            task: Task that failed
            
        Returns:
            Error context dictionary
        """
        error_str = str(exception).lower()
        
        # Categorize error
        if any(kw in error_str for kw in ["connection", "timeout", "network", "unreachable"]):
            category = "network"
        elif any(kw in error_str for kw in ["firewall", "waf", "blocked", "ids", "edr"]):
            category = "defense"
        elif any(kw in error_str for kw in ["auth", "permission", "denied", "forbidden"]):
            category = "authentication"
        elif any(kw in error_str for kw in ["patched", "not vulnerable", "failed to exploit"]):
            category = "vulnerability"
        else:
            category = "technical"
        
        return {
            "category": category,
            "error_message": str(exception),
            "task_type": task.get("type"),
            "task_params": task.get("params", {}),
            "timestamp": datetime.now().isoformat()
        }
    
    async def _handle_task_failure(
        self,
        task_id: str,
        task: Dict[str, Any],
        error_message: str,
        error_context: Dict[str, Any]
    ) -> None:
        """
        SEC-01: Centralized task failure handling.
        
        Handles logging and blackboard updates for failed tasks
        with sanitized error information.
        
        Args:
            task_id: ID of the failed task
            task: Task dictionary
            error_message: Sanitized error message
            error_context: Error context for Reflexion
        """
        # Mark task as failed
        try:
            await self.blackboard.fail_task(
                self._current_mission_id,
                task_id,
                error_message,  # Already sanitized
                error_context=error_context
            )
        except (ConnectionError, OSError) as e:
            self.logger.error(f"Failed to mark task {task_id} as failed: {e}")
        
        # Log error for analysis
        try:
            await self.blackboard.log_result(
                self._current_mission_id,
                "task_failed",
                {
                    "task_id": task_id,
                    "task_type": task.get("type"),
                    "worker_id": self.worker_id,
                    "error": error_message,
                    "error_context": error_context
                }
            )
        except (ConnectionError, OSError) as e:
            self.logger.error(f"Failed to log task failure for {task_id}: {e}")
    
    # ═══════════════════════════════════════════════════════════
    # Pub/Sub
    # ═══════════════════════════════════════════════════════════
    
    async def _subscribe_to_channels(self, mission_id: str) -> None:
        """Subscribe to relevant Pub/Sub channels."""
        channels = self._get_channels_to_subscribe(mission_id)
        
        if channels:
            await self.blackboard.subscribe(*channels)
            self._subscribed_channels = set(channels)
            self.logger.info(f"Subscribed to channels: {channels}")
    
    def _get_channels_to_subscribe(self, mission_id: str) -> List[str]:
        """
        Get channels this specialist should subscribe to.
        
        Override in subclasses to customize subscriptions.
        """
        return [
            self.blackboard.get_channel(mission_id, "tasks"),
            self.blackboard.get_channel(mission_id, "control"),
        ]
    
    async def publish_event(self, event: BlackboardEvent) -> None:
        """Publish an event to the Blackboard."""
        if not self._current_mission_id:
            return
            
        # Determine channel based on event type
        channel_type = self._get_channel_for_event(event)
        channel = self.blackboard.get_channel(self._current_mission_id, channel_type)
        
        await self.blackboard.publish(channel, event)
    
    def _get_channel_for_event(self, event: BlackboardEvent) -> str:
        """Get the channel type for an event."""
        event_channel_map = {
            "new_target": "targets",
            "new_vuln": "vulns",
            "new_cred": "creds",
            "new_session": "sessions",
            "new_task": "tasks",
            "goal_achieved": "goals",
        }
        return event_channel_map.get(event.event, "results")
    
    # ═══════════════════════════════════════════════════════════
    # Helper Methods for Subclasses
    # ═══════════════════════════════════════════════════════════
    
    async def create_task(
        self,
        task_type: TaskType,
        target_specialist: SpecialistType,
        priority: int = 5,
        target_id: Optional[str] = None,
        vuln_id: Optional[str] = None,
        cred_id: Optional[str] = None,
        rx_module: Optional[str] = None,
        **metadata
    ) -> str:
        """
        Create a new task for another specialist.
        
        Args:
            task_type: Type of task
            target_specialist: Specialist that should handle this
            priority: Task priority (1-10)
            target_id: Target ID if applicable
            vuln_id: Vulnerability ID if applicable
            cred_id: Credential ID if applicable
            rx_module: RX module to use
            **metadata: Additional metadata
            
        Returns:
            Task ID
        """
        task = Task(
            mission_id=self._safe_uuid(self._current_mission_id),
            type=task_type,
            specialist=target_specialist,
            priority=priority,
            target_id=self._safe_uuid(target_id) if target_id else None,
            vuln_id=self._safe_uuid(vuln_id) if vuln_id else None,
            cred_id=self._safe_uuid(cred_id) if cred_id else None,
            rx_module=rx_module,
            result_data=metadata
        )
        
        task_id = await self.blackboard.add_task(task)
        
        # Publish task event
        event = NewTaskEvent(
            mission_id=self._safe_uuid(self._current_mission_id),
            task_id=task.id,
            type=task_type,
            specialist=target_specialist,
            priority=priority
        )
        await self.publish_event(event)
        
        return task_id
    
    async def add_discovered_target(
        self,
        ip: str,
        hostname: Optional[str] = None,
        os: Optional[str] = None,
        priority: str = "medium",
        needs_deep_scan: bool = True
    ) -> str:
        """
        Add a newly discovered target to the Blackboard.
        
        Args:
            ip: Target IP address
            hostname: Hostname if known
            os: Operating system if detected
            priority: Priority level
            needs_deep_scan: Whether target needs deep scanning
            
        Returns:
            Target ID
        """
        from ..core.models import Priority
        
        target = Target(
            mission_id=self._safe_uuid(self._current_mission_id),
            ip=ip,
            hostname=hostname,
            os=os,
            priority=Priority(priority),
            discovered_by=self.worker_id
        )
        
        target_id = await self.blackboard.add_target(target)
        
        # Publish event
        event = NewTargetEvent(
            mission_id=self._safe_uuid(self._current_mission_id),
            target_id=target.id,
            ip=ip,
            priority=Priority(priority),
            needs_deep_scan=needs_deep_scan
        )
        await self.publish_event(event)
        
        self.logger.info(f"Added target: {ip} ({hostname or 'unknown'})")
        return target_id
    
    async def add_discovered_vulnerability(
        self,
        target_id: str,
        vuln_type: str,
        severity: Severity,
        cvss: Optional[float] = None,
        name: Optional[str] = None,
        description: Optional[str] = None,
        exploit_available: bool = False,
        rx_modules: Optional[List[str]] = None
    ) -> str:
        """
        Add a discovered vulnerability to the Blackboard.
        
        Args:
            target_id: Target this vuln was found on
            vuln_type: Vulnerability type (e.g., CVE-2021-44228)
            severity: Severity level
            cvss: CVSS score if known
            name: Human-readable name
            description: Description
            exploit_available: Whether exploit is available
            rx_modules: RX modules that can exploit this
            
        Returns:
            Vulnerability ID
        """
        vuln = Vulnerability(
            mission_id=self._safe_uuid(self._current_mission_id),
            target_id=self._safe_uuid(target_id),
            type=vuln_type,
            name=name,
            description=description,
            severity=severity,
            cvss=cvss,
            exploit_available=exploit_available,
            rx_modules=rx_modules or [],
            discovered_by=self.worker_id
        )
        
        vuln_id = await self.blackboard.add_vulnerability(vuln)
        
        # Publish event
        event = NewVulnEvent(
            mission_id=self._safe_uuid(self._current_mission_id),
            vuln_id=vuln.id,
            target_id=self._safe_uuid(target_id),
            severity=severity,
            exploit_available=exploit_available
        )
        await self.publish_event(event)
        
        self.logger.info(f"Added vulnerability: {vuln_type} on target {target_id}")
        return vuln_id
    
    async def add_discovered_credential(
        self,
        target_id: str,
        cred_type: CredentialType,
        username: Optional[str] = None,
        domain: Optional[str] = None,
        value_encrypted: Optional[bytes] = None,
        source: Optional[str] = None,
        verified: bool = False,
        privilege_level: PrivilegeLevel = PrivilegeLevel.UNKNOWN
    ) -> str:
        """
        Add a discovered credential to the Blackboard.
        
        Args:
            target_id: Target where cred was found
            cred_type: Type of credential
            username: Username
            domain: Domain if applicable
            value_encrypted: Encrypted credential value
            source: How it was obtained (mimikatz, etc.)
            verified: Whether credential has been verified
            privilege_level: Privilege level of the credential
            
        Returns:
            Credential ID
        """
        cred = Credential(
            mission_id=self._safe_uuid(self._current_mission_id),
            target_id=self._safe_uuid(target_id),
            type=cred_type,
            username=username,
            domain=domain,
            value_encrypted=value_encrypted,
            source=source,
            verified=verified,
            privilege_level=privilege_level,
            discovered_by=self.worker_id
        )
        
        cred_id = await self.blackboard.add_credential(cred)
        
        # Publish event
        event = NewCredEvent(
            mission_id=self._safe_uuid(self._current_mission_id),
            cred_id=cred.id,
            target_id=self._safe_uuid(target_id),
            type=cred_type,
            privilege_level=privilege_level
        )
        await self.publish_event(event)
        
        self.logger.info(f"Added credential: {username}@{domain or 'local'}")
        return cred_id
    
    def _safe_uuid(self, value: Any) -> UUID:
        """
        Safely convert value to UUID, generating new one if invalid.
        
        This method handles various input formats:
        - Already a UUID object
        - Valid UUID string
        - Prefixed string like "target:uuid-here"
        - Invalid input (returns new UUID)
        
        Args:
            value: Value to convert to UUID
            
        Returns:
            UUID object
        """
        if isinstance(value, UUID):
            return value
        if isinstance(value, str):
            try:
                # Remove prefixes like "target:", "vuln:", "cred:", "task:"
                clean_value = value.split(":")[-1] if ":" in value else value
                return UUID(clean_value)
            except (ValueError, TypeError):
                pass
        return uuid4()
    
    async def add_established_session(
        self,
        target_id: str,
        session_type: str,
        user: Optional[str] = None,
        privilege: PrivilegeLevel = PrivilegeLevel.USER,
        via_vuln_id: Optional[str] = None,
        via_cred_id: Optional[str] = None
    ) -> str:
        """
        Add an established session to the Blackboard.
        
        Args:
            target_id: Target the session is on
            session_type: Type of session (shell, meterpreter, etc.)
            user: User the session is running as
            privilege: Privilege level
            via_vuln_id: Vulnerability used to get the session
            via_cred_id: Credential used to get the session
            
        Returns:
            Session ID
        """
        from ..core.models import SessionType
        
        session = Session(
            mission_id=self._safe_uuid(self._current_mission_id),
            target_id=self._safe_uuid(target_id),
            type=SessionType(session_type),
            user=user,
            privilege=privilege,
            via_vuln_id=self._safe_uuid(via_vuln_id) if via_vuln_id else None,
            via_cred_id=self._safe_uuid(via_cred_id) if via_cred_id else None
        )
        
        session_id = await self.blackboard.add_session(session)
        
        # ═══════════════════════════════════════════════════════════
        # INTEGRATION: Register session with SessionManager
        # ═══════════════════════════════════════════════════════════
        from ..core.session_manager import get_session_manager
        
        try:
            session_manager = get_session_manager(
                blackboard=self.blackboard,
                settings=self.settings
            )
            await session_manager.register_session(
                session_id=session_id,
                target_id=target_id,
                session_type=SessionType(session_type)
            )
            self.logger.debug(
                f"Session {session_id} registered with SessionManager"
            )
        except (ImportError, AttributeError) as e:
            # SEC-01: Handle missing SessionManager or attribute errors
            self.logger.warning(
                f"SessionManager not available: {type(e).__name__}"
            )
        except (ConnectionError, OSError) as e:
            # SEC-01: Handle connection errors
            self.logger.warning(
                f"Failed to register session due to connection error"
            )
        
        # Publish event
        needs_privesc = privilege in (PrivilegeLevel.USER, PrivilegeLevel.UNKNOWN)
        event = NewSessionEvent(
            mission_id=self._safe_uuid(self._current_mission_id),
            session_id=session.id,
            target_id=self._safe_uuid(target_id),
            privilege=privilege,
            needs_privesc=needs_privesc
        )
        await self.publish_event(event)
        
        self.logger.info(f"Added session: {session_type} on {target_id} as {user}")
        return session_id
    
    # ═══════════════════════════════════════════════════════════
    # Properties
    # ═══════════════════════════════════════════════════════════
    
    @property
    def is_running(self) -> bool:
        """Check if specialist is running."""
        return self._running
    
    @property
    def current_mission(self) -> Optional[str]:
        """Get current mission ID."""
        return self._current_mission_id
    
    @property
    def supported_task_types(self) -> Set[TaskType]:
        """Get task types this specialist supports."""
        return self._supported_task_types
    
    @property
    def knowledge(self) -> Optional[EmbeddedKnowledge]:
        """Get the knowledge base instance."""
        if self._knowledge is None:
            try:
                self._knowledge = get_knowledge()
            except (ImportError, AttributeError) as e:
                # SEC-01: Handle missing knowledge base module
                self.logger.warning(f"Knowledge base not available: {type(e).__name__}")
                return None
            except (ValueError, TypeError) as e:
                # SEC-01: Handle configuration errors
                self.logger.warning(f"Knowledge base configuration error")
                return None
        return self._knowledge
    
    @property
    def runner(self) -> Optional['RXModuleRunner']:
        """
        Get the RX Module Runner instance (lazy-loaded).
        
        Returns:
            RXModuleRunner instance or None if not available
        """
        if self._runner is None:
            try:
                from ..executors import get_rx_module_runner
                self._runner = get_rx_module_runner()
                self._execution_mode = "real"
            except (ImportError, AttributeError) as e:
                # SEC-01: Handle missing RX Module Runner
                self.logger.warning(f"RX Module Runner not available: {type(e).__name__}")
                return None
            except (ValueError, TypeError) as e:
                # SEC-01: Handle configuration errors
                self.logger.warning(f"RX Module Runner configuration error")
                return None
        return self._runner
    
    @property
    def executor_factory(self) -> Optional['ExecutorFactory']:
        """
        Get the Executor Factory instance (lazy-loaded).
        
        Returns:
            ExecutorFactory instance or None if not available
        """
        if self._executor_factory is None:
            try:
                from ..executors import get_executor_factory
                self._executor_factory = get_executor_factory()
            except (ImportError, AttributeError) as e:
                # SEC-01: Handle missing Executor Factory
                self.logger.warning(f"Executor Factory not available: {type(e).__name__}")
                return None
            except (ValueError, TypeError) as e:
                # SEC-01: Handle configuration errors
                self.logger.warning(f"Executor Factory configuration error")
                return None
        return self._executor_factory
    
    @property
    def is_real_execution_mode(self) -> bool:
        """Check if specialist is in real execution mode (using Runner)."""
        return self._execution_mode == "real" and self.runner is not None
    
    # ═══════════════════════════════════════════════════════════
    # Knowledge Base Helper Methods
    # ═══════════════════════════════════════════════════════════
    
    def get_module_for_vuln(
        self, 
        vuln_type: str, 
        platform: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Get the best RX module for exploiting a vulnerability.
        
        Args:
            vuln_type: CVE or vulnerability identifier
            platform: Target platform
            
        Returns:
            Best matching RX module or None
        """
        if not self.knowledge or not self.knowledge.is_loaded():
            return None
        
        modules = self.knowledge.get_exploit_modules(
            vuln_type=vuln_type,
            platform=platform
        )
        
        return modules[0] if modules else None
    
    def get_recon_modules(self, platform: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get RX modules for reconnaissance.
        
        Args:
            platform: Target platform
            
        Returns:
            List of recon modules
        """
        if not self.knowledge or not self.knowledge.is_loaded():
            return []
        
        return self.knowledge.get_recon_modules(platform=platform)
    
    def get_credential_modules(self, platform: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get RX modules for credential harvesting.
        
        Args:
            platform: Target platform
            
        Returns:
            List of credential modules
        """
        if not self.knowledge or not self.knowledge.is_loaded():
            return []
        
        return self.knowledge.get_credential_modules(platform=platform)
    
    def get_privesc_modules(self, platform: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get RX modules for privilege escalation.
        
        Args:
            platform: Target platform
            
        Returns:
            List of privesc modules
        """
        if not self.knowledge or not self.knowledge.is_loaded():
            return []
        
        return self.knowledge.get_privesc_modules(platform=platform)
    
    def get_technique_modules(
        self, 
        technique_id: str,
        platform: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get RX modules for a specific MITRE technique.
        
        Args:
            technique_id: MITRE technique ID (e.g., T1003)
            platform: Target platform
            
        Returns:
            List of modules for the technique
        """
        if not self.knowledge or not self.knowledge.is_loaded():
            return []
        
        return self.knowledge.get_modules_for_technique(
            technique_id=technique_id,
            platform=platform
        )
    
    def search_modules(
        self, 
        query: str, 
        platform: Optional[str] = None,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Search for RX modules by keyword.
        
        Args:
            query: Search query
            platform: Target platform
            limit: Maximum results
            
        Returns:
            List of matching modules
        """
        if not self.knowledge or not self.knowledge.is_loaded():
            return []
        
        return self.knowledge.search_modules(
            query=query,
            platform=platform,
            limit=limit
        )
    
    # ═══════════════════════════════════════════════════════════
    # Execution Layer Helper Methods
    # ═══════════════════════════════════════════════════════════
    
    async def execute_rx_module(
        self,
        rx_module_id: str,
        target_host: str,
        target_platform: str,
        variables: Optional[Dict[str, str]] = None,
        connection_config: Optional[Any] = None,
        task_id: Optional[str] = None,
        check_prerequisites: bool = True,
        run_cleanup: bool = False,
        timeout: int = 300
    ) -> Dict[str, Any]:
        """
        Execute an RX Module on a target using the Runner.
        
        This method wraps the RXModuleRunner with proper error handling
        and returns a standardized result for task processing.
        
        Args:
            rx_module_id: RX Module ID (e.g., rx-t1003-001)
            target_host: Target IP or hostname
            target_platform: Platform (linux, windows, macos)
            variables: Variable substitutions for the module
            connection_config: Connection configuration (SSHConfig, WinRMConfig, etc.)
            task_id: Associated task ID for tracking
            check_prerequisites: Whether to check prerequisites
            run_cleanup: Whether to run cleanup after execution
            timeout: Execution timeout in seconds
            
        Returns:
            Dictionary with execution results:
            - success: bool
            - stdout: str (command output)
            - stderr: str (error output)
            - exit_code: int
            - duration_ms: int
            - parsed_data: dict (extracted data like IPs, usernames)
            - error_context: dict (if failed, for Reflexion)
            - execution_logs: list (detailed logs)
        """
        from ..executors import RXModuleRequest, Platform
        from uuid import UUID
        
        # Default result for failures
        default_result = {
            "success": False,
            "stdout": "",
            "stderr": "",
            "exit_code": -1,
            "duration_ms": 0,
            "parsed_data": {},
            "error_context": None,
            "execution_logs": []
        }
        
        # Check if runner is available
        if not self.runner:
            self.logger.warning(
                f"RXModuleRunner not available, falling back to simulation for {rx_module_id}"
            )
            default_result["error_context"] = {
                "error_type": "runner_unavailable",
                "error_message": "RXModuleRunner not available",
                "module_used": rx_module_id
            }
            return default_result
        
        try:
            # Map platform string to enum
            platform_map = {
                "linux": Platform.LINUX,
                "windows": Platform.WINDOWS,
                "macos": Platform.MACOS,
                "darwin": Platform.MACOS,
            }
            platform_enum = platform_map.get(
                target_platform.lower(), 
                Platform.UNKNOWN
            )
            
            # Build request
            request = RXModuleRequest(
                rx_module_id=rx_module_id,
                target_host=target_host,
                target_platform=platform_enum,
                variables=variables or {},
                connection_config=connection_config,
                check_prerequisites=check_prerequisites,
                run_cleanup=run_cleanup,
                timeout=timeout,
                task_id=UUID(task_id) if task_id else None,
                mission_id=UUID(self._current_mission_id) if self._current_mission_id else None
            )
            
            # Execute via runner
            self.logger.info(f"Executing RX module {rx_module_id} on {target_host}")
            result = await self.runner.execute_module(request)
            
            # ═══════════════════════════════════════════════════════════
            # INTEGRATION: Send heartbeat after command execution
            # ═══════════════════════════════════════════════════════════
            # If this is session-based execution, send heartbeat
            if connection_config and hasattr(connection_config, 'session_id'):
                try:
                    from ..core.session_manager import get_session_manager
                    session_manager = get_session_manager(
                        blackboard=self.blackboard,
                        settings=self.settings
                    )
                    session_id = connection_config.session_id
                    await session_manager.heartbeat(
                        session_id=session_id,
                        activity=True  # This is actual activity (command execution)
                    )
                    await session_manager.record_command_execution(
                        session_id=session_id,
                        success=result.success
                    )
                    self.logger.debug(
                        f"Heartbeat sent for session {session_id}"
                    )
                except (ImportError, AttributeError) as e:
                    # SEC-01: Handle missing SessionManager
                    self.logger.debug(
                        f"SessionManager not available for heartbeat"
                    )
                except (ConnectionError, OSError) as e:
                    # SEC-01: Handle connection errors
                    self.logger.debug(
                        f"Connection error during heartbeat"
                    )
            
            # Build response
            response = {
                "success": result.success,
                "stdout": result.main_result.stdout if result.main_result else "",
                "stderr": result.main_result.stderr if result.main_result else "",
                "exit_code": result.main_result.exit_code if result.main_result else -1,
                "duration_ms": result.total_duration_ms,
                "parsed_data": result.parsed_data,
                "error_context": result.error_context if not result.success else None,
                "execution_logs": []
            }
            
            # Add execution logs
            if result.main_result:
                response["execution_logs"].append(result.main_result.to_execution_log())
            
            for prereq_result in result.prerequisite_results:
                response["execution_logs"].append(prereq_result.to_execution_log())
            
            if result.cleanup_result:
                response["execution_logs"].append(result.cleanup_result.to_execution_log())
            
            return response
            
        except asyncio.TimeoutError as e:
            # SEC-01: Handle execution timeout
            self.logger.error(f"RX module {rx_module_id} timed out")
            default_result["error_context"] = {
                "error_type": "timeout",
                "error_message": "Execution timed out",
                "module_used": rx_module_id,
                "target_host": target_host
            }
            return default_result
        except (ConnectionError, OSError) as e:
            # SEC-01: Handle connection errors
            self.logger.error(f"Connection error executing RX module {rx_module_id}")
            default_result["error_context"] = {
                "error_type": "connection_error",
                "error_message": f"Connection error: {type(e).__name__}",
                "module_used": rx_module_id,
                "target_host": target_host
            }
            return default_result
        except (ImportError, AttributeError) as e:
            # SEC-01: Handle missing dependencies
            self.logger.error(f"Missing dependency for RX module {rx_module_id}")
            default_result["error_context"] = {
                "error_type": "dependency_error",
                "error_message": f"Missing dependency: {type(e).__name__}",
                "module_used": rx_module_id,
                "target_host": target_host
            }
            return default_result
        except (ValueError, TypeError) as e:
            # SEC-01: Handle validation errors
            self.logger.error(f"Validation error executing RX module {rx_module_id}")
            default_result["error_context"] = {
                "error_type": "validation_error",
                "error_message": f"Invalid parameters: {type(e).__name__}",
                "module_used": rx_module_id,
                "target_host": target_host
            }
            return default_result
    
    async def execute_command_direct(
        self,
        command: str,
        target_host: str,
        target_platform: str,
        connection_config: Optional[Any] = None,
        timeout: int = 300,
        shell: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Execute a direct command on a target (without RX Module).
        
        Useful for ad-hoc commands during reconnaissance.
        
        Args:
            command: Shell command to execute
            target_host: Target IP or hostname
            target_platform: Platform (linux, windows, macos)
            connection_config: Connection configuration
            timeout: Execution timeout
            shell: Shell type (bash, powershell, cmd)
            
        Returns:
            Dictionary with execution results
        """
        from ..executors import (
            ExecutionRequest, Platform, ShellType,
            LocalConfig
        )
        
        default_result = {
            "success": False,
            "stdout": "",
            "stderr": "",
            "exit_code": -1,
            "duration_ms": 0
        }
        
        # Check if factory is available
        if not self.executor_factory:
            self.logger.warning("ExecutorFactory not available")
            return default_result
        
        try:
            # Map platform
            platform_map = {
                "linux": Platform.LINUX,
                "windows": Platform.WINDOWS,
                "macos": Platform.MACOS,
            }
            platform_enum = platform_map.get(target_platform.lower(), Platform.LINUX)
            
            # Map shell
            shell_map = {
                "bash": ShellType.BASH,
                "sh": ShellType.SH,
                "powershell": ShellType.POWERSHELL,
                "cmd": ShellType.CMD,
            }
            shell_type = shell_map.get(shell.lower() if shell else "", None)
            
            # Use LocalConfig for localhost
            if target_host in ("localhost", "127.0.0.1"):
                connection_config = connection_config or LocalConfig()
            
            # Execute via factory
            result = await self.executor_factory.execute_on_target(
                target_host=target_host,
                target_platform=platform_enum,
                command=command,
                connection_config=connection_config,
                timeout=timeout
            )
            
            return {
                "success": result.success,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "exit_code": result.exit_code or 0,
                "duration_ms": result.duration_ms
            }
            
        except asyncio.TimeoutError as e:
            # SEC-01: Handle command timeout
            self.logger.error(f"Command execution timed out")
            default_result["stderr"] = "Command execution timed out"
            return default_result
        except (ConnectionError, OSError) as e:
            # SEC-01: Handle connection errors
            self.logger.error(f"Connection error executing command")
            default_result["stderr"] = f"Connection error: {type(e).__name__}"
            return default_result
        except (ImportError, AttributeError) as e:
            # SEC-01: Handle missing dependencies
            self.logger.error(f"Missing dependency for command execution")
            default_result["stderr"] = f"Missing dependency"
            return default_result
        except (ValueError, TypeError) as e:
            # SEC-01: Handle validation errors
            self.logger.error(f"Validation error in command execution")
            default_result["stderr"] = f"Invalid parameters"
            return default_result
    
    async def log_execution_to_blackboard(
        self,
        task_id: str,
        execution_result: Dict[str, Any]
    ) -> None:
        """
        Log execution results to the Blackboard for analysis.
        
        This enables the Reflexion pattern by storing error context
        and execution logs that AnalysisSpecialist can process.
        
        Args:
            task_id: Task ID
            execution_result: Result from execute_rx_module or execute_command_direct
        """
        if not self._current_mission_id:
            return
        
        try:
            # Log the execution result
            await self.blackboard.log_result(
                self._current_mission_id,
                "execution_completed",
                {
                    "task_id": task_id,
                    "worker_id": self.worker_id,
                    "success": execution_result.get("success"),
                    "duration_ms": execution_result.get("duration_ms"),
                    "has_error_context": execution_result.get("error_context") is not None
                }
            )
            
            # If failed, store error context for Reflexion analysis
            if not execution_result.get("success") and execution_result.get("error_context"):
                await self.blackboard.log_result(
                    self._current_mission_id,
                    "execution_failed",
                    {
                        "task_id": task_id,
                        "error_context": execution_result["error_context"],
                        "execution_logs": execution_result.get("execution_logs", [])
                    }
                )
                
        except (ConnectionError, OSError) as e:
            # SEC-01: Handle connection errors
            self.logger.error(f"Connection error logging to Blackboard")
        except (KeyError, ValueError, TypeError) as e:
            # SEC-01: Handle data errors
            self.logger.error(f"Data error logging to Blackboard: {type(e).__name__}")
    
    async def cleanup_connections(self) -> None:
        """
        Cleanup executor connections.
        
        Should be called when specialist is stopping or when
        connection cleanup is needed for resource management.
        """
        if self._executor_factory:
            try:
                await self._executor_factory.cleanup_dead_connections()
                self.logger.debug("Cleaned up dead connections")
            except (ConnectionError, OSError) as e:
                # SEC-01: Handle connection errors during cleanup
                self.logger.warning(f"Connection error during cleanup")
            except (AttributeError, RuntimeError) as e:
                # SEC-01: Handle already closed connections
                self.logger.warning(f"Cleanup error: {type(e).__name__}")
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get specialist statistics including task semaphore metrics.
        
        Returns:
            Dict with stats including task_semaphore_active, task_semaphore_available
        """
        stats = {
            "worker_id": self.worker_id,
            "specialist_type": self.specialist_type,
            "is_running": self._running,
            "current_mission_id": self._current_mission_id,
            "task_semaphore_active": 0,
            "task_semaphore_available": 0,
            "task_semaphore_limit": 0
        }
        
        if hasattr(self, '_task_semaphore') and self._task_semaphore:
            # Semaphore._value is internal but safe to read
            stats["task_semaphore_available"] = self._task_semaphore._value
            stats["task_semaphore_limit"] = getattr(self, '_max_concurrent_tasks', 0)
            stats["task_semaphore_active"] = stats["task_semaphore_limit"] - stats["task_semaphore_available"]
        
        return stats
