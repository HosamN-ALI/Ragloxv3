# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Mission Controller
# Central orchestration for missions
# ═══════════════════════════════════════════════════════════════

import asyncio
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set
from uuid import UUID, uuid4
import logging

from ..core.blackboard import Blackboard
from ..core.models import (
    Mission, MissionCreate, MissionStatus, MissionStats,
    Target, TargetStatus,
    Vulnerability, Severity,
    Task, TaskType, TaskStatus, SpecialistType,
    GoalStatus, GoalAchievedEvent
)
from ..core.config import Settings, get_settings
from ..specialists.recon import ReconSpecialist
from ..specialists.attack import AttackSpecialist


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
        
        # Update status to running
        await self.blackboard.update_mission_status(mission_id, MissionStatus.RUNNING)
        
        # Update local tracking
        if mission_id in self._active_missions:
            self._active_missions[mission_id]["status"] = MissionStatus.RUNNING
        
        # Start monitor loop
        if not self._running:
            self._running = True
            asyncio.create_task(self._monitor_loop())
        
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
        
        mission_data = await self.blackboard.get_mission(mission_id)
        if not mission_data:
            return False
        
        # Update status to completing
        await self.blackboard.update_mission_status(mission_id, MissionStatus.COMPLETING)
        
        # Send stop command to specialists
        await self._send_control_command(mission_id, "stop")
        
        # Stop specialists
        await self._stop_specialists(mission_id)
        
        # Update status to completed
        await self.blackboard.update_mission_status(mission_id, MissionStatus.COMPLETED)
        
        # Clean up local tracking
        if mission_id in self._active_missions:
            del self._active_missions[mission_id]
        
        self.logger.info(f"Mission {mission_id} stopped")
        return True
    
    async def get_mission_status(self, mission_id: str) -> Optional[Dict[str, Any]]:
        """
        Get comprehensive mission status.
        
        Args:
            mission_id: Mission ID
            
        Returns:
            Status dictionary
        """
        mission_data = await self.blackboard.get_mission(mission_id)
        if not mission_data:
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
        recon = ReconSpecialist(
            blackboard=self.blackboard,
            settings=self.settings
        )
        await recon.start(mission_id)
        self._specialists["recon"].append(recon)
        
        # Create and start Attack specialist
        attack = AttackSpecialist(
            blackboard=self.blackboard,
            settings=self.settings
        )
        await attack.start(mission_id)
        self._specialists["attack"].append(attack)
        
        self.logger.info(f"Specialists started for mission {mission_id}")
    
    async def _stop_specialists(self, mission_id: str) -> None:
        """Stop specialist workers for a mission."""
        self.logger.info(f"Stopping specialists for mission {mission_id}")
        
        # Stop all specialists
        for specialist_type, specialists in self._specialists.items():
            for specialist in specialists:
                if specialist.current_mission == mission_id:
                    await specialist.stop()
        
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
    # Utility Methods
    # ═══════════════════════════════════════════════════════════
    
    async def get_active_missions(self) -> List[str]:
        """Get list of active mission IDs."""
        return list(self._active_missions.keys())
    
    async def shutdown(self) -> None:
        """Shutdown the controller gracefully."""
        self.logger.info("Shutting down Mission Controller")
        
        self._running = False
        
        # Stop all active missions
        for mission_id in list(self._active_missions.keys()):
            await self.stop_mission(mission_id)
        
        # Disconnect from Blackboard
        await self.blackboard.disconnect()
        
        self.logger.info("Mission Controller shutdown complete")
