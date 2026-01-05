# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Mission Controller
# Central orchestration for missions
# ═══════════════════════════════════════════════════════════════

import asyncio
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set
from uuid import UUID, uuid4

# Note: uuid4 is used for generating new UUIDs in HITL functionality
import logging

from ..core.blackboard import Blackboard
from ..core.models import (
    Mission, MissionCreate, MissionStatus, MissionStats,
    Target, TargetStatus,
    Vulnerability, Severity,
    Task, TaskType, TaskStatus, SpecialistType,
    GoalStatus, GoalAchievedEvent,
    # HITL Models
    ApprovalAction, ApprovalStatus, ApprovalRequestEvent, ApprovalResponseEvent,
    ActionType, RiskLevel, ChatMessage, ChatEvent
)
from ..core.config import Settings, get_settings
from ..specialists.recon import ReconSpecialist
from ..specialists.attack import AttackSpecialist

# ═══════════════════════════════════════════════════════════════
# INTEGRATION: New Management Systems
# ═══════════════════════════════════════════════════════════════
from ..core.session_manager import SessionManager, get_session_manager
from ..core.shutdown_manager import ShutdownManager, get_shutdown_manager
from ..core.stats_manager import StatsManager, get_stats_manager
from ..core.transaction_manager import TransactionManager, get_transaction_manager
from ..core.retry_policy import get_retry_manager


class MissionController:
    """
    Mission Controller - Central orchestration for RAGLOX missions.
    
    Responsibilities:
    - Mission lifecycle management (create, start, pause, resume, stop)
    - Specialist coordination
    - Goal tracking
    - Statistics monitoring
    - Task prioritization
    
    Design Principles:
    - Single point of control for missions
    - Reads from and writes to Blackboard
    - Does not directly communicate with specialists
    - Uses Pub/Sub for control commands
    """
    
    def __init__(
        self,
        blackboard: Optional[Blackboard] = None,
        settings: Optional[Settings] = None
    ):
        """
        Initialize the Mission Controller.
        
        Args:
            blackboard: Blackboard instance
            settings: Application settings
        """
        self.settings = settings or get_settings()
        self.blackboard = blackboard or Blackboard(settings=self.settings)
        
        # Logging
        self.logger = logging.getLogger("raglox.controller.mission")
        
        # State
        self._active_missions: Dict[str, Dict[str, Any]] = {}
        self._running = False
        
        # Specialist instances
        self._specialists: Dict[str, List[Any]] = {
            "recon": [],
            "attack": [],
        }
        
        # Monitor interval (seconds)
        self._monitor_interval = 5
        
        # Task Watchdog settings
        self._watchdog_interval = 30  # Check every 30 seconds
        self._task_timeout = timedelta(minutes=5)  # Tasks stale after 5 minutes
        self._max_task_retries = 3  # Max retries before marking FAILED
        
        # HITL: Pending approval actions
        self._pending_approvals: Dict[str, ApprovalAction] = {}
        
        # HITL: Chat history per mission
        self._chat_history: Dict[str, List[ChatMessage]] = {}
        
        # ═══════════════════════════════════════════════════════════
        # INTEGRATION: Initialize Management Systems
        # ═══════════════════════════════════════════════════════════
        
        # Session Manager: Tracks session lifecycle, heartbeat, timeout
        self.session_manager = SessionManager(
            blackboard=self.blackboard,
            settings=self.settings
        )
        
        # Shutdown Manager: Graceful shutdown coordination
        self.shutdown_manager = ShutdownManager()
        
        # Stats Manager: Real-time metrics and monitoring
        self.stats_manager = StatsManager()
        
        # Transaction Manager: ACID operations with rollback
        self.transaction_manager = TransactionManager(
            blackboard=self.blackboard
        )
        
        # Retry Manager: Centralized retry policies
        self.retry_manager = get_retry_manager()
        
        # Register MissionController with shutdown manager
        self.shutdown_manager.register_component(
            name="mission_controller",
            component=self,
            priority=100,  # High priority - shutdown first
            shutdown_timeout=60.0,
            shutdown_method="stop"
        )
        
        self.logger.info(
            "MissionController initialized with all management systems: "
            "SessionManager, ShutdownManager, StatsManager, TransactionManager, RetryManager"
        )
    
    # ═══════════════════════════════════════════════════════════
    # Mission Lifecycle
    # ═══════════════════════════════════════════════════════════
    
    async def create_mission(self, mission_data: MissionCreate) -> str:
        """
        Create a new mission.
        
        Args:
            mission_data: Mission creation data
            
        Returns:
            Mission ID
        """
        self.logger.info(f"Creating mission: {mission_data.name}")
        
        # Connect to Blackboard if needed
        if not await self.blackboard.health_check():
            await self.blackboard.connect()
        
        # Convert goals list to dict with status
        goals_dict = {
            goal: GoalStatus.PENDING for goal in mission_data.goals
        }
        
        # Create Mission object
        mission = Mission(
            name=mission_data.name,
            description=mission_data.description,
            scope=mission_data.scope,
            goals=goals_dict,
            constraints=mission_data.constraints,
            status=MissionStatus.CREATED
        )
        
        # Store in Blackboard
        mission_id = await self.blackboard.create_mission(mission)
        
        # Track locally
        self._active_missions[mission_id] = {
            "mission": mission,
            "status": MissionStatus.CREATED,
            "specialists": [],
            "created_at": datetime.utcnow()
        }
        
        self.logger.info(f"Mission created: {mission_id}")
        return mission_id
    
    async def start_mission(self, mission_id: str) -> bool:
        """
        Start a mission.
        
        Args:
            mission_id: Mission to start
            
        Returns:
            True if started successfully
        """
        self.logger.info(f"Starting mission: {mission_id}")
        
        # Verify mission exists
        mission_data = await self.blackboard.get_mission(mission_id)
        if not mission_data:
            self.logger.error(f"Mission {mission_id} not found")
            return False
        
        # Check current status
        current_status = mission_data.get("status")
        if current_status not in ("created", "paused"):
            self.logger.error(f"Cannot start mission in status: {current_status}")
            return False
        
        # Update status to starting
        await self.blackboard.update_mission_status(mission_id, MissionStatus.STARTING)
        
        # Create initial network scan task based on scope
        mission_scope = mission_data.get("scope", [])
        if isinstance(mission_scope, str):
            import json
            mission_scope = json.loads(mission_scope)
        
        if mission_scope:
            await self._create_initial_scan_task(mission_id)
        
        # Start specialists
        await self._start_specialists(mission_id)
        
        # ═══════════════════════════════════════════════════════════
        # INTEGRATION: Start Management Systems
        # ═══════════════════════════════════════════════════════════
        
        # Start Session Manager for this mission
        await self.session_manager.start()
        self.logger.info(f\"SessionManager started for mission {mission_id}\")\n        \n        # Start Stats Manager for real-time metrics\n        await self.stats_manager.start()\n        self.logger.info(\"StatsManager started for real-time monitoring\")\n        \n        # Update mission start metric\n        await self.stats_manager.increment_counter(\n            \"missions_total\",\n            labels={\"status\": \"started\"}\n        )\n        \n        # Update status to running
        await self.blackboard.update_mission_status(mission_id, MissionStatus.RUNNING)
        
        # Update local tracking
        if mission_id in self._active_missions:
            self._active_missions[mission_id]["status"] = MissionStatus.RUNNING
        
        # Start monitor loop
        if not self._running:
            self._running = True
            asyncio.create_task(self._monitor_loop())
            asyncio.create_task(self._watchdog_loop())  # Start Task Watchdog
        
        self.logger.info(f"Mission {mission_id} started successfully")
        return True
    
    async def pause_mission(self, mission_id: str) -> bool:
        """
        Pause a running mission.
        
        Args:
            mission_id: Mission to pause
            
        Returns:
            True if paused successfully
        """
        self.logger.info(f"Pausing mission: {mission_id}")
        
        mission_data = await self.blackboard.get_mission(mission_id)
        if not mission_data:
            return False
        
        if mission_data.get("status") != "running":
            self.logger.error("Can only pause running missions")
            return False
        
        # Send pause command to specialists
        await self._send_control_command(mission_id, "pause")
        
        # Update status
        await self.blackboard.update_mission_status(mission_id, MissionStatus.PAUSED)
        
        if mission_id in self._active_missions:
            self._active_missions[mission_id]["status"] = MissionStatus.PAUSED
        
        self.logger.info(f"Mission {mission_id} paused")
        return True
    
    async def resume_mission(self, mission_id: str) -> bool:
        """
        Resume a paused mission.
        
        Args:
            mission_id: Mission to resume
            
        Returns:
            True if resumed successfully
        """
        self.logger.info(f"Resuming mission: {mission_id}")
        
        mission_data = await self.blackboard.get_mission(mission_id)
        if not mission_data:
            return False
        
        if mission_data.get("status") != "paused":
            self.logger.error("Can only resume paused missions")
            return False
        
        # Send resume command to specialists
        await self._send_control_command(mission_id, "resume")
        
        # Update status
        await self.blackboard.update_mission_status(mission_id, MissionStatus.RUNNING)
        
        if mission_id in self._active_missions:
            self._active_missions[mission_id]["status"] = MissionStatus.RUNNING
        
        self.logger.info(f"Mission {mission_id} resumed")
        return True
    
    async def stop_mission(self, mission_id: str) -> bool:
        """
        Stop a mission.
        
        Args:
            mission_id: Mission to stop
            
        Returns:
            True if stopped successfully
        """
        self.logger.info(f"Stopping mission: {mission_id}")
        
        try:
            mission_data = await self.blackboard.get_mission(mission_id)
            if not mission_data:
                return False
            
            # Update status to completing
            await self.blackboard.update_mission_status(mission_id, MissionStatus.COMPLETING)
            
            # Send stop command to specialists
            await self._send_control_command(mission_id, "stop")
            
            # Update status to stopped BEFORE stopping specialists
            # This is important because _stop_specialists calls blackboard.disconnect()
            # on the shared blackboard instance, which would cause subsequent
            # blackboard operations to fail
            await self.blackboard.update_mission_status(mission_id, MissionStatus.STOPPED)
            
            # Clean up local tracking
            if mission_id in self._active_missions:
                del self._active_missions[mission_id]
            
            # Stop specialists (this disconnects their blackboard connections)
            await self._stop_specialists(mission_id)
            
            # ═══════════════════════════════════════════════════════════
            # INTEGRATION: Stop Management Systems
            # ═══════════════════════════════════════════════════════════
            
            # Stop Session Manager
            await self.session_manager.stop()
            self.logger.info(f"SessionManager stopped for mission {mission_id}")
            
            # Stop Stats Manager
            await self.stats_manager.stop()
            self.logger.info("StatsManager stopped")
            
            self.logger.info(f"Mission {mission_id} stopped")
            return True
        except Exception as e:
            self.logger.error(f"Error stopping mission {mission_id}: {e}")
            # Re-raise to allow the API layer to handle it properly
            raise
    
    async def get_mission_status(self, mission_id: str) -> Optional[Dict[str, Any]]:
        """
        Get comprehensive mission status.
        
        First tries to get mission from Redis, then falls back to local cache.
        
        Args:
            mission_id: Mission ID
            
        Returns:
            Status dictionary
        """
        mission_data = await self.blackboard.get_mission(mission_id)
        
        # If not in Redis, check local cache (for in-memory missions)
        if not mission_data:
            if mission_id in self._active_missions:
                local_mission = self._active_missions[mission_id]
                mission = local_mission.get("mission")
                if mission:
                    # Reconstruct from local cache
                    goals_dict = {}
                    if hasattr(mission, 'goals'):
                        goals_dict = {
                            k: v.value if hasattr(v, 'value') else str(v) 
                            for k, v in mission.goals.items()
                        }
                    
                    return {
                        "mission_id": mission_id,
                        "name": getattr(mission, 'name', 'Unknown'),
                        "status": local_mission.get("status", MissionStatus.CREATED).value if hasattr(local_mission.get("status"), 'value') else str(local_mission.get("status", "unknown")),
                        "scope": getattr(mission, 'scope', []),
                        "goals": goals_dict,
                        "statistics": {
                            "targets_discovered": 0,
                            "vulns_found": 0,
                            "creds_harvested": 0,
                            "sessions_established": 0,
                            "goals_achieved": 0
                        },
                        "target_count": 0,
                        "vuln_count": 0,
                        "created_at": local_mission.get("created_at", datetime.utcnow()).isoformat() if hasattr(local_mission.get("created_at"), 'isoformat') else str(local_mission.get("created_at")),
                        "started_at": None,
                        "completed_at": None
                    }
            return None
        
        # Get statistics
        stats = await self.blackboard.get_mission_stats(mission_id)
        
        # Get goals
        goals = await self.blackboard.get_mission_goals(mission_id)
        
        # Get targets
        targets = await self.blackboard.get_mission_targets(mission_id)
        
        # Get vulnerabilities
        vulns = await self.blackboard.get_mission_vulns(mission_id)
        
        return {
            "mission_id": mission_id,
            "name": mission_data.get("name"),
            "status": mission_data.get("status"),
            "scope": mission_data.get("scope"),
            "goals": goals,
            "statistics": {
                "targets_discovered": stats.targets_discovered,
                "vulns_found": stats.vulns_found,
                "creds_harvested": stats.creds_harvested,
                "sessions_established": stats.sessions_established,
                "goals_achieved": stats.goals_achieved
            },
            "target_count": len(targets),
            "vuln_count": len(vulns),
            "created_at": mission_data.get("created_at"),
            "started_at": mission_data.get("started_at"),
            "completed_at": mission_data.get("completed_at")
        }
    
    # ═══════════════════════════════════════════════════════════
    # Specialist Management
    # ═══════════════════════════════════════════════════════════
    
    async def _start_specialists(self, mission_id: str) -> None:
        """Start specialist workers for a mission."""
        self.logger.info(f"Starting specialists for mission {mission_id}")
        
        # Create and start Recon specialist
        # Each specialist gets its own Blackboard instance to avoid connection conflicts
        recon = ReconSpecialist(
            blackboard=Blackboard(settings=self.settings),
            settings=self.settings
        )
        await recon.start(mission_id)
        self._specialists["recon"].append(recon)
        
        # Create and start Attack specialist
        # Initialize Real Exploitation Engine if enabled
        real_exploitation_engine = None
        c2_manager = None
        use_real_exploits = False
        
        if self.settings.use_real_exploits:
            try:
                from ..specialists.attack_integration import get_real_exploitation_engine
                from ..exploitation.c2.session_manager import C2SessionManager
                
                real_exploitation_engine = get_real_exploitation_engine()
                
                # Initialize C2SessionManager if not already available
                c2_manager = C2SessionManager(
                    encryption_enabled=self.settings.c2_encryption_enabled,
                    data_dir=self.settings.c2_data_dir
                )
                
                use_real_exploits = True
                self.logger.info("🎯 Attack specialist using REAL EXPLOITATION")
                self.logger.info(f"🌐 C2 Session Manager initialized for mission {mission_id}")
            except Exception as e:
                self.logger.error(f"Failed to initialize real exploitation: {e}")
                self.logger.warning("Attack specialist falling back to SIMULATION mode")
        
        attack = AttackSpecialist(
            blackboard=Blackboard(settings=self.settings),
            settings=self.settings,
            use_real_exploits=use_real_exploits,
            real_exploitation_engine=real_exploitation_engine
        )
        await attack.start(mission_id)
        self._specialists["attack"].append(attack)
        
        # Store C2SessionManager reference for cleanup
        if c2_manager:
            if not hasattr(self, '_c2_managers'):
                self._c2_managers = {}
            self._c2_managers[mission_id] = c2_manager
        
        self.logger.info(f"Specialists started for mission {mission_id}")
    
    async def _stop_specialists(self, mission_id: str) -> None:
        """Stop specialist workers for a mission."""
        self.logger.info(f"Stopping specialists for mission {mission_id}")
        
        # Stop all specialists
        for specialist_type, specialists in self._specialists.items():
            for specialist in specialists:
                if specialist.current_mission == mission_id:
                    await specialist.stop()
        
        # Cleanup C2 sessions for this mission
        if hasattr(self, '_c2_managers') and mission_id in self._c2_managers:
            try:
                c2_manager = self._c2_managers[mission_id]
                await c2_manager.cleanup_all_sessions()
                del self._c2_managers[mission_id]
                self.logger.info(f"🌐 C2 sessions cleaned up for mission {mission_id}")
            except Exception as e:
                self.logger.error(f"Error cleaning up C2 sessions: {e}")
        
        self.logger.info(f"Specialists stopped for mission {mission_id}")
    
    # ═══════════════════════════════════════════════════════════
    # Task Management
    # ═══════════════════════════════════════════════════════════
    
    async def _create_initial_scan_task(self, mission_id: str) -> str:
        """Create the initial network scan task."""
        task = Task(
            mission_id=UUID(mission_id),
            type=TaskType.NETWORK_SCAN,
            specialist=SpecialistType.RECON,
            priority=10  # Highest priority
        )
        
        task_id = await self.blackboard.add_task(task)
        self.logger.info(f"Created initial scan task: {task_id}")
        return task_id
    
    async def create_exploit_tasks_for_critical_vulns(self, mission_id: str) -> int:
        """
        Create exploit tasks for critical vulnerabilities.
        
        Called by monitor to ensure high-value vulns get attacked.
        """
        vulns = await self.blackboard.get_mission_vulns(mission_id)
        tasks_created = 0
        
        for vuln_key in vulns:
            vuln_id = vuln_key.replace("vuln:", "")
            vuln = await self.blackboard.get_vulnerability(vuln_id)
            
            if not vuln:
                continue
            
            # Check if vuln is critical/high and exploitable
            severity = vuln.get("severity")
            exploit_available = vuln.get("exploit_available")
            status = vuln.get("status", "discovered")
            
            if severity in ("critical", "high") and exploit_available and status == "discovered":
                # Create exploit task
                task = Task(
                    mission_id=UUID(mission_id),
                    type=TaskType.EXPLOIT,
                    specialist=SpecialistType.ATTACK,
                    priority=9 if severity == "critical" else 8,
                    vuln_id=UUID(vuln_id),
                    target_id=UUID(vuln.get("target_id")) if vuln.get("target_id") else None
                )
                
                await self.blackboard.add_task(task)
                await self.blackboard.update_vuln_status(vuln_id, "pending_exploit")
                tasks_created += 1
        
        return tasks_created
    
    # ═══════════════════════════════════════════════════════════
    # Control Commands
    # ═══════════════════════════════════════════════════════════
    
    async def _send_control_command(self, mission_id: str, command: str) -> None:
        """Send a control command to all specialists via Pub/Sub."""
        channel = self.blackboard.get_channel(mission_id, "control")
        
        event = {
            "event": "control",
            "command": command,
            "mission_id": mission_id,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        await self.blackboard.publish_dict(channel, event)
        self.logger.info(f"Sent {command} command for mission {mission_id}")
    
    # ═══════════════════════════════════════════════════════════
    # Monitoring
    # ═══════════════════════════════════════════════════════════
    
    async def _monitor_loop(self) -> None:
        """Main monitoring loop for active missions."""
        while self._running and self._active_missions:
            try:
                for mission_id in list(self._active_missions.keys()):
                    await self._monitor_mission(mission_id)
                
                await asyncio.sleep(self._monitor_interval)
                
            except Exception as e:
                self.logger.error(f"Error in monitor loop: {e}")
                await asyncio.sleep(1)
    
    async def _monitor_mission(self, mission_id: str) -> None:
        """Monitor a single mission."""
        mission_data = await self.blackboard.get_mission(mission_id)
        if not mission_data:
            return
        
        status = mission_data.get("status")
        
        if status != "running":
            return
        
        # Check goals
        goals = await self.blackboard.get_mission_goals(mission_id)
        all_achieved = all(g == "achieved" for g in goals.values()) if goals else False
        
        if all_achieved and goals:
            self.logger.info(f"🎯 All goals achieved for mission {mission_id}")
            await self.stop_mission(mission_id)
            return
        
        # Create exploit tasks for new critical vulns
        await self.create_exploit_tasks_for_critical_vulns(mission_id)
        
        # Check heartbeats (detect dead specialists)
        heartbeats = await self.blackboard.get_heartbeats(mission_id)
        if not heartbeats:
            self.logger.warning(f"No heartbeats for mission {mission_id}")
    
    # ═══════════════════════════════════════════════════════════
    # Task Watchdog (Zombie Task Hunter)
    # ═══════════════════════════════════════════════════════════
    
    async def _watchdog_loop(self) -> None:
        """
        Background task that monitors for zombie/stale tasks.
        
        Runs periodically to detect tasks that are:
        - Status: RUNNING but haven't been updated for too long
        - Likely abandoned by a crashed specialist
        
        Actions:
        - Re-queue task if retry count < max_retries
        - Mark as FAILED if retry count >= max_retries
        """
        self.logger.info("🐕 Task Watchdog started")
        
        while self._running and self._active_missions:
            try:
                for mission_id in list(self._active_missions.keys()):
                    await self._check_zombie_tasks(mission_id)
                
                await asyncio.sleep(self._watchdog_interval)
                
            except Exception as e:
                self.logger.error(f"Error in watchdog loop: {e}")
                await asyncio.sleep(5)
        
        self.logger.info("🐕 Task Watchdog stopped")
    
    async def _check_zombie_tasks(self, mission_id: str) -> None:
        """
        Check for and recover zombie tasks in a mission.
        
        A zombie task is one that:
        - Has status RUNNING
        - Has not been updated within the timeout period
        
        Args:
            mission_id: Mission ID to check
        """
        try:
            # Get all running tasks
            running_tasks = await self.blackboard.get_running_tasks(mission_id)
            
            if not running_tasks:
                return
            
            now = datetime.utcnow()
            zombies_found = 0
            
            for task_key in running_tasks:
                task_id = task_key.replace("task:", "")
                task = await self.blackboard.get_task(task_id)
                
                if not task:
                    continue
                
                # Check last update time
                updated_at_str = task.get("updated_at") or task.get("started_at")
                if not updated_at_str:
                    continue
                
                try:
                    updated_at = datetime.fromisoformat(updated_at_str)
                except ValueError:
                    self.logger.warning(f"Invalid timestamp for task {task_id}: {updated_at_str}")
                    continue
                
                # Check if task is stale
                if now - updated_at > self._task_timeout:
                    zombies_found += 1
                    retry_count = int(task.get("retry_count", 0))
                    
                    if retry_count < self._max_task_retries:
                        # Re-queue the task
                        self.logger.warning(
                            f"🧟 Zombie task detected: {task_id} "
                            f"(stale for {now - updated_at}). Re-queuing (attempt {retry_count + 1}/{self._max_task_retries})"
                        )
                        await self.blackboard.requeue_task(
                            mission_id=mission_id,
                            task_id=task_id,
                            reason=f"watchdog_timeout_after_{(now - updated_at).total_seconds():.0f}s"
                        )
                    else:
                        # Mark as permanently failed
                        self.logger.error(
                            f"💀 Task {task_id} exceeded max retries ({self._max_task_retries}). "
                            f"Marking as FAILED."
                        )
                        await self.blackboard.mark_task_failed_permanently(
                            mission_id=mission_id,
                            task_id=task_id,
                            reason=f"max_retries_exceeded_after_{retry_count}_attempts"
                        )
            
            if zombies_found > 0:
                self.logger.info(f"🐕 Watchdog processed {zombies_found} zombie task(s) for mission {mission_id}")
                
        except Exception as e:
            self.logger.error(f"Error checking zombie tasks: {e}")
    
    # ═══════════════════════════════════════════════════════════
    # Utility Methods
    # ═══════════════════════════════════════════════════════════
    
    async def get_active_missions(self) -> List[str]:
        """Get list of active mission IDs."""
        return list(self._active_missions.keys())
    
    # ═══════════════════════════════════════════════════════════
    # HITL (Human-in-the-Loop) Methods
    # ═══════════════════════════════════════════════════════════
    
    async def request_approval(
        self,
        mission_id: str,
        action: ApprovalAction
    ) -> str:
        """
        Request user approval for a high-risk action.
        
        This pauses the mission (sets status to WAITING_FOR_APPROVAL)
        and broadcasts an ApprovalRequestEvent via WebSocket.
        
        Args:
            mission_id: Mission ID
            action: ApprovalAction with details of what needs approval
            
        Returns:
            Action ID
        """
        action_type_str = action.action_type.value if hasattr(action.action_type, 'value') else str(action.action_type)
        self.logger.info(f"🔐 Requesting approval for action: {action_type_str}")
        
        action_id = str(action.id)
        
        # Store pending approval
        self._pending_approvals[action_id] = action
        
        # Update mission status to waiting
        await self.blackboard.update_mission_status(mission_id, MissionStatus.WAITING_FOR_APPROVAL)
        
        if mission_id in self._active_missions:
            self._active_missions[mission_id]["status"] = MissionStatus.WAITING_FOR_APPROVAL
        
        # Publish approval request event
        event = ApprovalRequestEvent(
            mission_id=UUID(mission_id),
            action_id=action.id,
            action_type=action.action_type,
            action_description=action.action_description,
            target_ip=action.target_ip,
            target_hostname=action.target_hostname,
            risk_level=action.risk_level,
            risk_reasons=action.risk_reasons,
            potential_impact=action.potential_impact,
            command_preview=action.command_preview,
            expires_at=action.expires_at
        )
        
        # Publish to blackboard for WebSocket broadcast
        channel = self.blackboard.get_channel(mission_id, "approvals")
        await self.blackboard.publish(channel, event)
        
        self.logger.info(f"⏳ Mission {mission_id} waiting for approval: {action_id}")
        
        return action_id
    
    async def approve_action(
        self,
        mission_id: str,
        action_id: str,
        user_comment: Optional[str] = None
    ) -> bool:
        """
        Approve a pending action and resume mission execution.
        
        Args:
            mission_id: Mission ID
            action_id: Action ID to approve
            user_comment: Optional comment from user
            
        Returns:
            True if approved successfully
        """
        self.logger.info(f"✅ Approving action: {action_id}")
        
        # Verify action exists
        if action_id not in self._pending_approvals:
            self.logger.error(f"Action {action_id} not found in pending approvals")
            return False
        
        action = self._pending_approvals[action_id]
        
        # Verify mission matches
        if str(action.mission_id) != mission_id:
            self.logger.error(f"Action {action_id} does not belong to mission {mission_id}")
            return False
        
        # Update action status
        action.status = ApprovalStatus.APPROVED
        action.responded_at = datetime.utcnow()
        action.user_comment = user_comment
        
        # Remove from pending
        del self._pending_approvals[action_id]
        
        # Resume mission
        await self.blackboard.update_mission_status(mission_id, MissionStatus.RUNNING)
        
        if mission_id in self._active_missions:
            self._active_missions[mission_id]["status"] = MissionStatus.RUNNING
        
        # Publish approval response
        response_event = ApprovalResponseEvent(
            mission_id=UUID(mission_id),
            action_id=UUID(action_id),
            approved=True,
            user_comment=user_comment
        )
        
        channel = self.blackboard.get_channel(mission_id, "approvals")
        await self.blackboard.publish(channel, response_event)
        
        # Resume specialists
        await self._send_control_command(mission_id, "resume")
        
        # If there was a task waiting, re-queue it
        if action.task_id:
            await self._resume_approved_task(mission_id, action)
        
        self.logger.info(f"▶️ Mission {mission_id} resumed after approval")
        
        return True
    
    async def reject_action(
        self,
        mission_id: str,
        action_id: str,
        rejection_reason: Optional[str] = None,
        user_comment: Optional[str] = None
    ) -> bool:
        """
        Reject a pending action and prompt AnalysisSpecialist for alternative.
        
        Args:
            mission_id: Mission ID
            action_id: Action ID to reject
            rejection_reason: Reason for rejection
            user_comment: Optional comment from user
            
        Returns:
            True if rejected successfully
        """
        self.logger.info(f"❌ Rejecting action: {action_id}")
        
        # Verify action exists
        if action_id not in self._pending_approvals:
            self.logger.error(f"Action {action_id} not found in pending approvals")
            return False
        
        action = self._pending_approvals[action_id]
        
        # Verify mission matches
        if str(action.mission_id) != mission_id:
            self.logger.error(f"Action {action_id} does not belong to mission {mission_id}")
            return False
        
        # Update action status
        action.status = ApprovalStatus.REJECTED
        action.responded_at = datetime.utcnow()
        action.rejection_reason = rejection_reason
        action.user_comment = user_comment
        
        # Remove from pending
        del self._pending_approvals[action_id]
        
        # Publish rejection response
        response_event = ApprovalResponseEvent(
            mission_id=UUID(mission_id),
            action_id=UUID(action_id),
            approved=False,
            rejection_reason=rejection_reason,
            user_comment=user_comment
        )
        
        channel = self.blackboard.get_channel(mission_id, "approvals")
        await self.blackboard.publish(channel, response_event)
        
        # Request AnalysisSpecialist to find alternative
        if action.task_id:
            await self._request_alternative_analysis(mission_id, action, rejection_reason)
        
        # Resume mission (to allow alternative actions)
        await self.blackboard.update_mission_status(mission_id, MissionStatus.RUNNING)
        
        if mission_id in self._active_missions:
            self._active_missions[mission_id]["status"] = MissionStatus.RUNNING
        
        await self._send_control_command(mission_id, "resume")
        
        self.logger.info(f"▶️ Mission {mission_id} resumed, seeking alternatives")
        
        return True
    
    async def get_pending_approvals(self, mission_id: str) -> List[Dict[str, Any]]:
        """
        Get all pending approval requests for a mission.
        
        Args:
            mission_id: Mission ID
            
        Returns:
            List of pending approval actions
        """
        pending = []
        for action_id, action in self._pending_approvals.items():
            if str(action.mission_id) == mission_id:
                # Handle both enum and string values for action_type and risk_level
                action_type = action.action_type.value if hasattr(action.action_type, 'value') else str(action.action_type)
                risk_level = action.risk_level.value if hasattr(action.risk_level, 'value') else str(action.risk_level)
                
                pending.append({
                    "action_id": action_id,
                    "action_type": action_type,
                    "action_description": action.action_description,
                    "target_ip": action.target_ip,
                    "risk_level": risk_level,
                    "risk_reasons": action.risk_reasons,
                    "potential_impact": action.potential_impact,
                    "command_preview": action.command_preview,
                    "requested_at": action.requested_at.isoformat(),
                    "expires_at": action.expires_at.isoformat() if action.expires_at else None
                })
        return pending
    
    async def _resume_approved_task(self, mission_id: str, action: ApprovalAction) -> None:
        """
        Resume a task that was waiting for approval.
        """
        task_id = str(action.task_id)
        
        # Create a new task with the approved action
        task = Task(
            mission_id=UUID(mission_id),
            type=TaskType.EXPLOIT if action.action_type == ActionType.EXPLOIT else TaskType.LATERAL,
            specialist=SpecialistType.ATTACK,
            priority=9,  # High priority for approved actions
            rx_module=action.module_to_execute,
        )
        
        # Add approval metadata
        task.metadata["approved_action_id"] = str(action.id)
        task.metadata["user_approved"] = True
        task.metadata["parameters"] = action.parameters
        
        await self.blackboard.add_task(task)
        self.logger.info(f"Re-queued approved task: {task.id}")
    
    async def _request_alternative_analysis(
        self,
        mission_id: str,
        rejected_action: ApprovalAction,
        rejection_reason: Optional[str]
    ) -> None:
        """
        Request AnalysisSpecialist to find an alternative approach.
        """
        # Publish analysis request event
        from ..core.models import TaskAnalysisRequestEvent
        
        event = TaskAnalysisRequestEvent(
            mission_id=UUID(mission_id),
            task_id=rejected_action.task_id or uuid4(),
            task_type=TaskType.EXPLOIT,
            error_context={
                "error_type": "user_rejected",
                "error_message": rejection_reason or "User rejected the proposed action",
                "rejected_module": rejected_action.module_to_execute,
                "rejection_reason": rejection_reason,
                "original_action_type": rejected_action.action_type.value if hasattr(rejected_action.action_type, 'value') else str(rejected_action.action_type),
                "target_ip": rejected_action.target_ip,
            },
            execution_logs=[],
            priority=9
        )
        
        channel = self.blackboard.get_channel(mission_id, "analysis")
        await self.blackboard.publish(channel, event)
        
        self.logger.info(f"Requested alternative analysis after rejection")
    
    # ═══════════════════════════════════════════════════════════
    # Chat / Interactive Methods
    # ═══════════════════════════════════════════════════════════
    
    async def send_chat_message(
        self,
        mission_id: str,
        content: str,
        related_task_id: Optional[str] = None,
        related_action_id: Optional[str] = None
    ) -> ChatMessage:
        """
        Send a chat message from user to the system.
        
        This allows users to provide instructions or ask questions
        during mission execution.
        
        Args:
            mission_id: Mission ID
            content: Message content
            related_task_id: Optional related task
            related_action_id: Optional related approval action
            
        Returns:
            ChatMessage object
        """
        self.logger.info(f"💬 Chat message received for mission {mission_id}")
        
        # Create message - handle both UUID strings and regular strings
        try:
            mission_uuid = UUID(mission_id) if isinstance(mission_id, str) and len(mission_id) == 36 else uuid4()
        except ValueError:
            mission_uuid = uuid4()
        
        message = ChatMessage(
            mission_id=mission_uuid,
            role="user",
            content=content,
            related_task_id=UUID(related_task_id) if related_task_id and len(related_task_id) == 36 else None,
            related_action_id=UUID(related_action_id) if related_action_id and len(related_action_id) == 36 else None
        )
        
        # Store in history
        if mission_id not in self._chat_history:
            self._chat_history[mission_id] = []
        self._chat_history[mission_id].append(message)
        
        # Publish chat event
        event = ChatEvent(
            mission_id=UUID(mission_id),
            message_id=message.id,
            role=message.role,
            content=message.content,
            related_task_id=message.related_task_id,
            related_action_id=message.related_action_id
        )
        
        channel = self.blackboard.get_channel(mission_id, "chat")
        # Use publish_dict instead of publish for Pydantic models if publish is not available
        if hasattr(self.blackboard, 'publish'):
            await self.blackboard.publish(channel, event)
        else:
            await self.blackboard.publish_dict(channel, event.model_dump())
        
        # Process the message and generate response
        response = await self._process_chat_message(mission_id, message)
        
        if response:
            self._chat_history[mission_id].append(response)
            
            # Publish response event
            response_event = ChatEvent(
                mission_id=UUID(mission_id),
                message_id=response.id,
                role=response.role,
                content=response.content,
                related_task_id=response.related_task_id,
                related_action_id=response.related_action_id
            )
            if hasattr(self.blackboard, 'publish'):
                await self.blackboard.publish(channel, response_event)
            else:
                await self.blackboard.publish_dict(channel, response_event.model_dump())
        
        return message
    
    async def get_chat_history(self, mission_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get chat history for a mission.
        
        Args:
            mission_id: Mission ID
            limit: Max messages to return
            
        Returns:
            List of chat messages
        """
        history = self._chat_history.get(mission_id, [])
        return [
            {
                "id": str(msg.id),
                "role": msg.role,
                "content": msg.content,
                "timestamp": msg.timestamp.isoformat(),
                "related_task_id": str(msg.related_task_id) if msg.related_task_id else None,
                "related_action_id": str(msg.related_action_id) if msg.related_action_id else None
            }
            for msg in history[-limit:]
        ]
    
    async def _process_chat_message(
        self,
        mission_id: str,
        message: ChatMessage
    ) -> Optional[ChatMessage]:
        """
        Process a chat message and generate a system response.
        
        Uses LLM for intelligent responses with fallback to simple commands.
        """
        content = message.content.lower()
        response_content = None
        
        # Check for simple commands first (fast path)
        if "status" in content:
            status = await self.get_mission_status(mission_id)
            if status:
                response_content = (
                    f"📊 Mission Status: {status.get('status', 'unknown')}\n"
                    f"Targets: {status.get('target_count', 0)}\n"
                    f"Vulnerabilities: {status.get('vuln_count', 0)}\n"
                    f"Goals: {status.get('statistics', {}).get('goals_achieved', 0)}/"
                    f"{len(status.get('goals', {}))}"
                )
        
        elif "pause" in content or "ايقاف" in content:
            await self.pause_mission(mission_id)
            response_content = "⏸️ Mission paused as requested."
        
        elif "resume" in content or "استئناف" in content:
            await self.resume_mission(mission_id)
            response_content = "▶️ Mission resumed."
        
        elif "pending" in content or "approvals" in content or "موافق" in content:
            pending = await self.get_pending_approvals(mission_id)
            if pending:
                response_content = f"🔐 Pending approvals: {len(pending)}\n"
                for p in pending:
                    response_content += f"  - {p['action_type']}: {p['action_description'][:50]}...\n"
            else:
                response_content = "✅ No pending approvals."
        
        elif "help" in content or "مساعدة" in content:
            response_content = (
                "📖 Available commands:\n"
                "  - 'status': Get mission status\n"
                "  - 'pause': Pause the mission\n"
                "  - 'resume': Resume the mission\n"
                "  - 'pending': List pending approvals\n"
                "  - 'help': Show this help message\n"
                "\nYou can also ask me anything about the mission!"
            )
        
        else:
            # Use LLM for general questions
            response_content = await self._get_llm_response(mission_id, message.content)
        
        if response_content:
            return ChatMessage(
                mission_id=UUID(mission_id),
                role="system",
                content=response_content,
                related_task_id=message.related_task_id,
                related_action_id=message.related_action_id
            )
        
        return None
    
    async def _get_llm_response(self, mission_id: str, user_message: str) -> str:
        """
        Get LLM response for a chat message.
        
        Args:
            mission_id: Mission ID
            user_message: User's message
            
        Returns:
            LLM response or fallback message
        """
        try:
            from ..core.llm.service import get_llm_service
            from ..core.llm.base import LLMMessage, MessageRole
            
            llm_service = get_llm_service()
            
            if not llm_service or not llm_service.providers:
                self.logger.warning("LLM service not available, using fallback")
                return f"🤖 Received your message: '{user_message}'. Use 'help' to see available commands."
            
            # Get mission context
            status = await self.get_mission_status(mission_id)
            mission_context = ""
            if status:
                mission_context = f"""
Current Mission Status:
- Name: {status.get('name', 'Unknown')}
- Status: {status.get('status', 'unknown')}
- Targets: {status.get('target_count', 0)}
- Vulnerabilities: {status.get('vuln_count', 0)}
- Goals: {status.get('statistics', {}).get('goals_achieved', 0)}/{len(status.get('goals', {}))}
"""
            
            # Build messages
            system_prompt = f"""You are RAGLOX, an AI-powered Red Team Automation assistant.
You help operators manage and monitor penetration testing missions.

{mission_context}

Be concise, professional, and helpful. If asked about something outside your scope,
politely redirect the user to relevant commands.

Available commands the user can use:
- 'status': Get mission status
- 'pause': Pause the mission
- 'resume': Resume the mission
- 'pending': List pending approvals
- 'help': Show help message"""

            messages = [
                LLMMessage(role=MessageRole.SYSTEM, content=system_prompt),
                LLMMessage(role=MessageRole.USER, content=user_message)
            ]
            
            # Get response from LLM
            response = await llm_service.generate(messages)
            
            if response and response.content:
                return f"🤖 {response.content}"
            else:
                return f"🤖 Received your message. Use 'help' to see available commands."
                
        except Exception as e:
            self.logger.error(f"LLM error: {e}")
            return f"🤖 Received your message: '{user_message}'. Use 'help' to see available commands."
    
    async def shutdown(self) -> None:
        """
        ═══════════════════════════════════════════════════════════════
        INTEGRATION: Graceful Shutdown with All Managers
        ═══════════════════════════════════════════════════════════════
        
        Shutdown the controller gracefully using ShutdownManager.
        """
        self.logger.info("Shutting down Mission Controller")
        
        self._running = False
        
        # Stop all active missions
        for mission_id in list(self._active_missions.keys()):
            await self.stop_mission(mission_id)
        
        # Stop Session Manager
        await self.session_manager.stop()
        
        # Stop Stats Manager
        await self.stats_manager.stop()
        
        # Disconnect from Blackboard
        await self.blackboard.disconnect()
        
        self.logger.info("Mission Controller shutdown complete")
    
    async def stop(self) -> None:
        """Alias for shutdown (used by ShutdownManager)."""
        await self.shutdown()
