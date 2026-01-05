"""
═══════════════════════════════════════════════════════════════════════════════
RAGLOX v3.0 - Graceful Shutdown Manager
═══════════════════════════════════════════════════════════════════════════════

GAP-C08 FIX: Enterprise-Grade Graceful Shutdown System

This module provides comprehensive graceful shutdown handling including:
1. Signal handling (SIGTERM, SIGINT, SIGHUP)
2. Coordinated component shutdown
3. Task completion before exit
4. State persistence
5. Resource cleanup
6. Shutdown timeout management
7. Emergency force shutdown

Key Features:
- Multi-phase shutdown process
- Configurable shutdown timeout
- Component dependency management
- State snapshot before shutdown
- Clean resource deallocation
- Observable shutdown metrics
- Emergency abort on timeout

Architecture:
┌──────────────────┐
│ Shutdown Manager │←─── Signal Handler
│                  │
└────────┬─────────┘
         │
    ┌────┴─────────┐
    │  Shutdown    │
    │  Coordinator │
    └────┬─────────┘
         │
    ┌────┴─────┐
    │Component │
    │ Registry │
    └──────────┘

Shutdown Phases:
1. INITIATED: Shutdown signal received
2. DRAINING: Stop accepting new tasks
3. COMPLETING: Wait for active tasks to complete
4. PERSISTING: Save state to disk/database
5. CLEANUP: Release resources (connections, files, etc.)
6. STOPPED: All components stopped
7. TERMINATED: Process exit

Usage:
    # Initialize shutdown manager
    shutdown_mgr = ShutdownManager()
    
    # Register components
    shutdown_mgr.register_component(
        name="mission_controller",
        component=mission_controller,
        priority=1,  # Higher priority = shutdown first
        shutdown_timeout=30.0
    )
    
    # Setup signal handlers
    shutdown_mgr.setup_signal_handlers()
    
    # Start application
    await app.run()
    
    # Shutdown is automatic on signal
    # Or manual:
    await shutdown_mgr.shutdown(reason="manual")

Author: RAGLOX Core Team
License: Proprietary
"""

import asyncio
import logging
import signal
import time
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set
from dataclasses import dataclass, field


# ═══════════════════════════════════════════════════════════
# Shutdown States & Configuration
# ═══════════════════════════════════════════════════════════

class ShutdownPhase(str, Enum):
    """Shutdown process phases."""
    RUNNING = "running"
    INITIATED = "initiated"
    DRAINING = "draining"
    COMPLETING = "completing"
    PERSISTING = "persisting"
    CLEANUP = "cleanup"
    STOPPED = "stopped"
    TERMINATED = "terminated"


class ShutdownReason(str, Enum):
    """Reasons for shutdown."""
    SIGTERM = "sigterm"
    SIGINT = "sigint"
    SIGHUP = "sighup"
    MANUAL = "manual"
    ERROR = "error"
    TIMEOUT = "timeout"
    EMERGENCY = "emergency"


@dataclass
class ShutdownConfig:
    """Shutdown configuration."""
    # Timeout for each phase (seconds)
    drain_timeout: float = 10.0  # Stop accepting new work
    completion_timeout: float = 60.0  # Wait for active tasks
    persistence_timeout: float = 30.0  # Save state
    cleanup_timeout: float = 20.0  # Release resources
    
    # Total maximum shutdown time
    total_timeout: float = 120.0  # 2 minutes max
    
    # Force shutdown after timeout
    force_shutdown_on_timeout: bool = True
    
    # Save state before shutdown
    persist_state: bool = True
    
    # Graceful task completion
    wait_for_task_completion: bool = True


@dataclass
class ComponentRegistration:
    """Registered component for shutdown."""
    name: str
    component: Any
    priority: int  # Higher priority = shutdown first
    shutdown_timeout: float
    shutdown_method: str = "stop"  # Method name to call
    is_async: bool = True
    dependencies: List[str] = field(default_factory=list)


@dataclass
class ShutdownMetrics:
    """Shutdown process metrics."""
    shutdown_initiated_at: Optional[datetime] = None
    shutdown_completed_at: Optional[datetime] = None
    shutdown_reason: Optional[ShutdownReason] = None
    total_shutdown_time: float = 0.0
    
    # Phase timings
    drain_time: float = 0.0
    completion_time: float = 0.0
    persistence_time: float = 0.0
    cleanup_time: float = 0.0
    
    # Component stats
    components_shutdown_success: int = 0
    components_shutdown_failed: int = 0
    components_forced_shutdown: int = 0
    
    # Task stats
    active_tasks_at_shutdown: int = 0
    tasks_completed_during_shutdown: int = 0
    tasks_cancelled: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "shutdown_initiated_at": self.shutdown_initiated_at.isoformat() if self.shutdown_initiated_at else None,
            "shutdown_completed_at": self.shutdown_completed_at.isoformat() if self.shutdown_completed_at else None,
            "shutdown_reason": self.shutdown_reason.value if self.shutdown_reason else None,
            "total_shutdown_time": round(self.total_shutdown_time, 2),
            "drain_time": round(self.drain_time, 2),
            "completion_time": round(self.completion_time, 2),
            "persistence_time": round(self.persistence_time, 2),
            "cleanup_time": round(self.cleanup_time, 2),
            "components_shutdown_success": self.components_shutdown_success,
            "components_shutdown_failed": self.components_shutdown_failed,
            "components_forced_shutdown": self.components_forced_shutdown,
            "active_tasks_at_shutdown": self.active_tasks_at_shutdown,
            "tasks_completed_during_shutdown": self.tasks_completed_during_shutdown,
            "tasks_cancelled": self.tasks_cancelled
        }


# ═══════════════════════════════════════════════════════════
# Graceful Shutdown Manager
# ═══════════════════════════════════════════════════════════

class ShutdownManager:
    """
    Comprehensive graceful shutdown manager.
    
    Responsibilities:
    - Signal handling and graceful shutdown coordination
    - Multi-phase shutdown process
    - Component registration and dependency management
    - Task completion coordination
    - State persistence before shutdown
    - Resource cleanup
    - Shutdown metrics and observability
    """
    
    def __init__(self, config: Optional[ShutdownConfig] = None):
        """
        Initialize shutdown manager.
        
        Args:
            config: Shutdown configuration
        """
        self.config = config or ShutdownConfig()
        self.logger = logging.getLogger("raglox.shutdown_manager")
        
        # State
        self._current_phase = ShutdownPhase.RUNNING
        self._shutdown_initiated = False
        self._shutdown_event = asyncio.Event()
        
        # Component registry
        self._components: Dict[str, ComponentRegistration] = {}
        self._component_order: List[str] = []  # Shutdown order
        
        # Active tasks tracking
        self._active_tasks: Set[asyncio.Task] = set()
        
        # Metrics
        self._metrics = ShutdownMetrics()
        
        # Callbacks
        self._pre_shutdown_callbacks: List[Callable] = []
        self._post_shutdown_callbacks: List[Callable] = []
        
        self.logger.info("ShutdownManager initialized")
    
    # ═══════════════════════════════════════════════════════════
    # Signal Handling
    # ═══════════════════════════════════════════════════════════
    
    def setup_signal_handlers(self) -> None:
        """
        Setup signal handlers for graceful shutdown.
        
        Handles:
        - SIGTERM: Graceful shutdown (from systemd, docker, etc.)
        - SIGINT: Graceful shutdown (Ctrl+C)
        - SIGHUP: Reload configuration (treated as shutdown for now)
        """
        loop = asyncio.get_event_loop()
        
        # SIGTERM handler
        def handle_sigterm():
            self.logger.warning("Received SIGTERM signal")
            asyncio.create_task(self.shutdown(reason=ShutdownReason.SIGTERM))
        
        # SIGINT handler (Ctrl+C)
        def handle_sigint():
            self.logger.warning("Received SIGINT signal (Ctrl+C)")
            asyncio.create_task(self.shutdown(reason=ShutdownReason.SIGINT))
        
        # SIGHUP handler
        def handle_sighup():
            self.logger.warning("Received SIGHUP signal")
            asyncio.create_task(self.shutdown(reason=ShutdownReason.SIGHUP))
        
        try:
            loop.add_signal_handler(signal.SIGTERM, handle_sigterm)
            loop.add_signal_handler(signal.SIGINT, handle_sigint)
            loop.add_signal_handler(signal.SIGHUP, handle_sighup)
            
            self.logger.info("Signal handlers registered (SIGTERM, SIGINT, SIGHUP)")
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            self.logger.warning("Signal handlers not supported on this platform")
    
    # ═══════════════════════════════════════════════════════════
    # Component Registration
    # ═══════════════════════════════════════════════════════════
    
    def register_component(
        self,
        name: str,
        component: Any,
        priority: int = 50,
        shutdown_timeout: float = 30.0,
        shutdown_method: str = "stop",
        is_async: bool = True,
        dependencies: Optional[List[str]] = None
    ) -> None:
        """
        Register a component for graceful shutdown.
        
        Args:
            name: Component name
            component: Component instance
            priority: Shutdown priority (higher = shutdown first)
            shutdown_timeout: Max time to wait for component shutdown
            shutdown_method: Method name to call for shutdown
            is_async: Whether shutdown method is async
            dependencies: List of component names this depends on
        """
        registration = ComponentRegistration(
            name=name,
            component=component,
            priority=priority,
            shutdown_timeout=shutdown_timeout,
            shutdown_method=shutdown_method,
            is_async=is_async,
            dependencies=dependencies or []
        )
        
        self._components[name] = registration
        
        # Update shutdown order (sort by priority, descending)
        self._component_order = sorted(
            self._components.keys(),
            key=lambda n: self._components[n].priority,
            reverse=True
        )
        
        self.logger.info(
            f"Component registered: {name} (priority={priority}, "
            f"timeout={shutdown_timeout}s, method={shutdown_method})"
        )
    
    def unregister_component(self, name: str) -> None:
        """Unregister a component."""
        if name in self._components:
            del self._components[name]
            self._component_order.remove(name)
            self.logger.info(f"Component unregistered: {name}")
    
    # ═══════════════════════════════════════════════════════════
    # Callbacks
    # ═══════════════════════════════════════════════════════════
    
    def add_pre_shutdown_callback(self, callback: Callable) -> None:
        """Add callback to run before shutdown."""
        self._pre_shutdown_callbacks.append(callback)
    
    def add_post_shutdown_callback(self, callback: Callable) -> None:
        """Add callback to run after shutdown."""
        self._post_shutdown_callbacks.append(callback)
    
    # ═══════════════════════════════════════════════════════════
    # Task Tracking
    # ═══════════════════════════════════════════════════════════
    
    def track_task(self, task: asyncio.Task) -> None:
        """Track an active task."""
        self._active_tasks.add(task)
        task.add_done_callback(lambda t: self._active_tasks.discard(t))
    
    # ═══════════════════════════════════════════════════════════
    # Shutdown Orchestration
    # ═══════════════════════════════════════════════════════════
    
    async def shutdown(
        self,
        reason: ShutdownReason = ShutdownReason.MANUAL,
        timeout: Optional[float] = None
    ) -> None:
        """
        ═══════════════════════════════════════════════════════════════
        GAP-C08 FIX: Graceful Shutdown Orchestration
        ═══════════════════════════════════════════════════════════════
        
        Perform graceful shutdown with multiple phases.
        
        Phases:
        1. INITIATED: Mark shutdown started, run pre-shutdown callbacks
        2. DRAINING: Stop accepting new tasks
        3. COMPLETING: Wait for active tasks to complete
        4. PERSISTING: Save state to disk/database
        5. CLEANUP: Release resources (connections, files, etc.)
        6. STOPPED: All components stopped
        7. TERMINATED: Process ready to exit
        
        Args:
            reason: Reason for shutdown
            timeout: Override default total timeout
        """
        if self._shutdown_initiated:
            self.logger.warning("Shutdown already in progress")
            return
        
        self._shutdown_initiated = True
        self._metrics.shutdown_initiated_at = datetime.utcnow()
        self._metrics.shutdown_reason = reason
        start_time = time.time()
        
        timeout = timeout or self.config.total_timeout
        
        self.logger.warning(
            f"╔═══════════════════════════════════════════════════════════╗"
        )
        self.logger.warning(
            f"║  GRACEFUL SHUTDOWN INITIATED - Reason: {reason.value:15s} ║"
        )
        self.logger.warning(
            f"╚═══════════════════════════════════════════════════════════╝"
        )
        
        try:
            # Create shutdown task with timeout
            shutdown_task = asyncio.create_task(self._execute_shutdown())
            
            try:
                await asyncio.wait_for(shutdown_task, timeout=timeout)
                self.logger.info("✅ Graceful shutdown completed successfully")
            except asyncio.TimeoutError:
                self.logger.error(
                    f"❌ Shutdown timeout exceeded ({timeout}s), "
                    f"forcing emergency shutdown"
                )
                await self._emergency_shutdown()
        
        except Exception as e:
            self.logger.error(f"❌ Error during shutdown: {e}", exc_info=True)
            await self._emergency_shutdown()
        
        finally:
            # Record total time
            self._metrics.shutdown_completed_at = datetime.utcnow()
            self._metrics.total_shutdown_time = time.time() - start_time
            
            # Set shutdown event
            self._shutdown_event.set()
            
            self.logger.warning(
                f"Shutdown completed in {self._metrics.total_shutdown_time:.2f}s"
            )
            self.logger.info(f"Shutdown metrics: {self._metrics.to_dict()}")
    
    async def _execute_shutdown(self) -> None:
        """Execute shutdown phases."""
        try:
            # Phase 1: INITIATED - Pre-shutdown callbacks
            await self._phase_initiated()
            
            # Phase 2: DRAINING - Stop accepting new work
            await self._phase_draining()
            
            # Phase 3: COMPLETING - Wait for active tasks
            if self.config.wait_for_task_completion:
                await self._phase_completing()
            
            # Phase 4: PERSISTING - Save state
            if self.config.persist_state:
                await self._phase_persisting()
            
            # Phase 5: CLEANUP - Shutdown components
            await self._phase_cleanup()
            
            # Phase 6: STOPPED
            self._current_phase = ShutdownPhase.STOPPED
            
            # Phase 7: Post-shutdown callbacks
            await self._run_post_shutdown_callbacks()
            
            self._current_phase = ShutdownPhase.TERMINATED
        
        except Exception as e:
            self.logger.error(f"Error in shutdown execution: {e}", exc_info=True)
            raise
    
    async def _phase_initiated(self) -> None:
        """Phase 1: Shutdown initiated."""
        self._current_phase = ShutdownPhase.INITIATED
        self.logger.info("Phase 1/5: INITIATED - Running pre-shutdown callbacks")
        
        # Run pre-shutdown callbacks
        for callback in self._pre_shutdown_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback()
                else:
                    callback()
            except Exception as e:
                self.logger.error(f"Pre-shutdown callback failed: {e}")
    
    async def _phase_draining(self) -> None:
        """Phase 2: Stop accepting new work."""
        self._current_phase = ShutdownPhase.DRAINING
        self.logger.info("Phase 2/5: DRAINING - Stopping new task acceptance")
        
        phase_start = time.time()
        
        try:
            # Signal all components to stop accepting new work
            for name in self._component_order:
                component = self._components[name].component
                
                # Call pause/drain method if available
                if hasattr(component, 'pause'):
                    try:
                        await asyncio.wait_for(
                            component.pause(),
                            timeout=self.config.drain_timeout
                        )
                        self.logger.debug(f"Component {name} paused")
                    except Exception as e:
                        self.logger.warning(f"Failed to pause {name}: {e}")
            
            # Small delay to ensure no new tasks are starting
            await asyncio.sleep(0.5)
        
        finally:
            self._metrics.drain_time = time.time() - phase_start
    
    async def _phase_completing(self) -> None:
        """Phase 3: Wait for active tasks to complete."""
        self._current_phase = ShutdownPhase.COMPLETING
        self.logger.info(
            f"Phase 3/5: COMPLETING - Waiting for {len(self._active_tasks)} "
            f"active tasks"
        )
        
        phase_start = time.time()
        self._metrics.active_tasks_at_shutdown = len(self._active_tasks)
        
        try:
            if self._active_tasks:
                # Wait for active tasks with timeout
                done, pending = await asyncio.wait(
                    self._active_tasks,
                    timeout=self.config.completion_timeout,
                    return_when=asyncio.ALL_COMPLETED
                )
                
                self._metrics.tasks_completed_during_shutdown = len(done)
                self._metrics.tasks_cancelled = len(pending)
                
                if pending:
                    self.logger.warning(
                        f"Cancelling {len(pending)} tasks that didn't complete "
                        f"within timeout"
                    )
                    for task in pending:
                        task.cancel()
                    
                    # Wait briefly for cancellation
                    await asyncio.sleep(0.5)
                
                self.logger.info(
                    f"Task completion: {len(done)} completed, "
                    f"{len(pending)} cancelled"
                )
        
        finally:
            self._metrics.completion_time = time.time() - phase_start
    
    async def _phase_persisting(self) -> None:
        """Phase 4: Persist state."""
        self._current_phase = ShutdownPhase.PERSISTING
        self.logger.info("Phase 4/5: PERSISTING - Saving state")
        
        phase_start = time.time()
        
        try:
            # Call persist/save methods on components
            for name in self._component_order:
                component = self._components[name].component
                
                if hasattr(component, 'persist_state'):
                    try:
                        await asyncio.wait_for(
                            component.persist_state(),
                            timeout=self.config.persistence_timeout
                        )
                        self.logger.debug(f"Component {name} state persisted")
                    except Exception as e:
                        self.logger.error(f"Failed to persist {name}: {e}")
        
        finally:
            self._metrics.persistence_time = time.time() - phase_start
    
    async def _phase_cleanup(self) -> None:
        """Phase 5: Cleanup resources."""
        self._current_phase = ShutdownPhase.CLEANUP
        self.logger.info(
            f"Phase 5/5: CLEANUP - Shutting down {len(self._components)} "
            f"components"
        )
        
        phase_start = time.time()
        
        # Shutdown components in priority order
        for name in self._component_order:
            registration = self._components[name]
            
            try:
                self.logger.info(f"Shutting down component: {name}")
                
                # Get shutdown method
                shutdown_method = getattr(
                    registration.component,
                    registration.shutdown_method,
                    None
                )
                
                if shutdown_method is None:
                    self.logger.warning(
                        f"Component {name} has no {registration.shutdown_method} method"
                    )
                    continue
                
                # Call shutdown method with timeout
                if registration.is_async:
                    await asyncio.wait_for(
                        shutdown_method(),
                        timeout=registration.shutdown_timeout
                    )
                else:
                    shutdown_method()
                
                self._metrics.components_shutdown_success += 1
                self.logger.info(f"✅ Component {name} shutdown successfully")
            
            except asyncio.TimeoutError:
                self._metrics.components_shutdown_failed += 1
                self._metrics.components_forced_shutdown += 1
                self.logger.error(
                    f"❌ Component {name} shutdown timeout "
                    f"({registration.shutdown_timeout}s)"
                )
            
            except Exception as e:
                self._metrics.components_shutdown_failed += 1
                self.logger.error(
                    f"❌ Component {name} shutdown failed: {e}",
                    exc_info=True
                )
        
        self._metrics.cleanup_time = time.time() - phase_start
    
    async def _run_post_shutdown_callbacks(self) -> None:
        """Run post-shutdown callbacks."""
        self.logger.info("Running post-shutdown callbacks")
        
        for callback in self._post_shutdown_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback()
                else:
                    callback()
            except Exception as e:
                self.logger.error(f"Post-shutdown callback failed: {e}")
    
    async def _emergency_shutdown(self) -> None:
        """Emergency force shutdown."""
        self.logger.critical("⚠️  EMERGENCY SHUTDOWN INITIATED")
        
        # Cancel all active tasks
        for task in self._active_tasks:
            task.cancel()
        
        # Force stop all components
        for name, registration in self._components.items():
            try:
                if hasattr(registration.component, 'force_stop'):
                    registration.component.force_stop()
            except Exception as e:
                self.logger.error(f"Emergency stop failed for {name}: {e}")
        
        self._current_phase = ShutdownPhase.TERMINATED
    
    # ═══════════════════════════════════════════════════════════
    # Status & Metrics
    # ═══════════════════════════════════════════════════════════
    
    def is_shutting_down(self) -> bool:
        """Check if shutdown is in progress."""
        return self._shutdown_initiated
    
    def get_current_phase(self) -> ShutdownPhase:
        """Get current shutdown phase."""
        return self._current_phase
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get shutdown metrics."""
        return self._metrics.to_dict()
    
    async def wait_for_shutdown(self) -> None:
        """Wait for shutdown to complete."""
        await self._shutdown_event.wait()


# ═══════════════════════════════════════════════════════════
# Global Singleton Instance
# ═══════════════════════════════════════════════════════════

_global_shutdown_manager: Optional[ShutdownManager] = None


def get_shutdown_manager(
    config: Optional[ShutdownConfig] = None
) -> ShutdownManager:
    """Get global shutdown manager singleton."""
    global _global_shutdown_manager
    if _global_shutdown_manager is None:
        _global_shutdown_manager = ShutdownManager(config)
    return _global_shutdown_manager
