"""
═══════════════════════════════════════════════════════════════════════════════
RAGLOX v3.0 - Session Management System
═══════════════════════════════════════════════════════════════════════════════

GAP-C02 FIX: Enterprise-Grade Session Timeout and Heartbeat Management

This module provides comprehensive session lifecycle management including:
1. Session heartbeat monitoring
2. Automatic timeout detection
3. Stale session cleanup
4. Session health tracking
5. Connection keepalive
6. Graceful session termination

Key Features:
- Configurable session timeouts (idle, absolute, keepalive)
- Automatic heartbeat mechanism
- Stale session detection and cleanup
- Session health scoring
- Observable session metrics
- Connection pool management
- Graceful degradation on timeout

Architecture:
┌──────────────────┐
│ Session Manager  │←─── Configuration
│                  │
└────────┬─────────┘
         │
    ┌────┴──────┐
    │ Heartbeat │
    │  Monitor  │
    └────┬──────┘
         │
    ┌────┴──────┐
    │  Timeout  │
    │  Detector │
    └───────────┘

Usage:
    # Initialize session manager
    session_mgr = SessionManager(blackboard, settings)
    
    # Start monitoring (background task)
    await session_mgr.start()
    
    # Register session
    await session_mgr.register_session(session_id, target_id, session_type)
    
    # Update heartbeat
    await session_mgr.heartbeat(session_id)
    
    # Check if session is alive
    if await session_mgr.is_session_alive(session_id):
        # Execute command
        result = await executor.execute(session_id, command)
    
    # Clean up
    await session_mgr.stop()

Author: RAGLOX Core Team
License: Proprietary
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set
from uuid import UUID
from dataclasses import dataclass, field

from .blackboard import Blackboard
from .config import Settings
from .models import Session, SessionStatus, SessionType


# ═══════════════════════════════════════════════════════════
# Session Configuration
# ═══════════════════════════════════════════════════════════

@dataclass
class SessionTimeout:
    """Session timeout configuration."""
    idle_timeout: int = 300  # 5 minutes - max time without activity
    absolute_timeout: int = 7200  # 2 hours - max session lifetime
    keepalive_interval: int = 30  # 30 seconds - heartbeat interval
    grace_period: int = 60  # 1 minute - grace before marking DEAD
    cleanup_interval: int = 60  # 1 minute - cleanup cycle interval


@dataclass
class SessionHealth:
    """Session health metrics."""
    session_id: str
    last_heartbeat: datetime
    last_activity: datetime
    established_at: datetime
    heartbeat_failures: int = 0
    command_executions: int = 0
    command_failures: int = 0
    is_responsive: bool = True
    time_since_last_heartbeat: float = 0.0  # seconds
    time_since_last_activity: float = 0.0  # seconds
    health_score: float = 100.0  # 0-100
    
    def calculate_health_score(self) -> float:
        """
        Calculate session health score (0-100).
        
        Factors:
        - Heartbeat failures (reduces score)
        - Command success rate (affects score)
        - Responsiveness (binary factor)
        - Time since last heartbeat (penalty)
        """
        score = 100.0
        
        # Heartbeat penalty (max -30 points)
        heartbeat_penalty = min(self.heartbeat_failures * 10, 30)
        score -= heartbeat_penalty
        
        # Command failure penalty (max -20 points)
        if self.command_executions > 0:
            failure_rate = self.command_failures / self.command_executions
            score -= failure_rate * 20
        
        # Responsiveness penalty (-30 points if not responsive)
        if not self.is_responsive:
            score -= 30
        
        # Time since heartbeat penalty (max -20 points)
        if self.time_since_last_heartbeat > 300:  # >5 minutes
            time_penalty = min((self.time_since_last_heartbeat / 300) * 20, 20)
            score -= time_penalty
        
        return max(0.0, score)


# ═══════════════════════════════════════════════════════════
# Session Metrics
# ═══════════════════════════════════════════════════════════

@dataclass
class SessionMetrics:
    """Session management metrics."""
    total_sessions_created: int = 0
    active_sessions: int = 0
    stale_sessions: int = 0
    dead_sessions: int = 0
    sessions_timed_out_idle: int = 0
    sessions_timed_out_absolute: int = 0
    sessions_cleaned_up: int = 0
    total_heartbeats_sent: int = 0
    total_heartbeats_failed: int = 0
    average_session_lifetime: float = 0.0  # seconds
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_sessions_created": self.total_sessions_created,
            "active_sessions": self.active_sessions,
            "stale_sessions": self.stale_sessions,
            "dead_sessions": self.dead_sessions,
            "sessions_timed_out_idle": self.sessions_timed_out_idle,
            "sessions_timed_out_absolute": self.sessions_timed_out_absolute,
            "sessions_cleaned_up": self.sessions_cleaned_up,
            "total_heartbeats_sent": self.total_heartbeats_sent,
            "total_heartbeats_failed": self.total_heartbeats_failed,
            "heartbeat_success_rate": round(
                (self.total_heartbeats_sent - self.total_heartbeats_failed) / 
                self.total_heartbeats_sent * 100, 2
            ) if self.total_heartbeats_sent > 0 else 0.0,
            "average_session_lifetime_minutes": round(self.average_session_lifetime / 60, 2)
        }


# ═══════════════════════════════════════════════════════════
# Session Manager
# ═══════════════════════════════════════════════════════════

class SessionManager:
    """
    Comprehensive session lifecycle manager.
    
    Responsibilities:
    - Session registration and tracking
    - Heartbeat monitoring and keepalive
    - Timeout detection (idle and absolute)
    - Stale session cleanup
    - Session health tracking
    - Metrics and observability
    """
    
    def __init__(
        self,
        blackboard: Blackboard,
        settings: Optional[Settings] = None,
        timeout_config: Optional[SessionTimeout] = None
    ):
        """
        Initialize session manager.
        
        Args:
            blackboard: Blackboard instance for session state
            settings: Application settings
            timeout_config: Session timeout configuration
        """
        self.blackboard = blackboard
        self.settings = settings
        self.timeout_config = timeout_config or SessionTimeout()
        
        self.logger = logging.getLogger("raglox.session_manager")
        
        # Session tracking
        self._sessions: Dict[str, SessionHealth] = {}
        self._session_locks: Dict[str, asyncio.Lock] = {}
        
        # Background tasks
        self._running = False
        self._monitor_task: Optional[asyncio.Task] = None
        self._cleanup_task: Optional[asyncio.Task] = None
        
        # Metrics
        self._metrics = SessionMetrics()
        
        self.logger.info(
            f"SessionManager initialized with timeouts: "
            f"idle={self.timeout_config.idle_timeout}s, "
            f"absolute={self.timeout_config.absolute_timeout}s, "
            f"keepalive={self.timeout_config.keepalive_interval}s"
        )
    
    # ═══════════════════════════════════════════════════════════
    # Lifecycle Management
    # ═══════════════════════════════════════════════════════════
    
    async def start(self) -> None:
        """Start session manager background tasks."""
        if self._running:
            self.logger.warning("SessionManager already running")
            return
        
        self._running = True
        
        # Start monitoring and cleanup tasks
        self._monitor_task = asyncio.create_task(self._monitor_loop())
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        
        self.logger.info("SessionManager started successfully")
    
    async def stop(self) -> None:
        """Stop session manager and cleanup resources."""
        self.logger.info("Stopping SessionManager...")
        
        self._running = False
        
        # Cancel background tasks
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        
        # Close all sessions gracefully
        session_ids = list(self._sessions.keys())
        for session_id in session_ids:
            try:
                await self.close_session(session_id, reason="shutdown")
            except Exception as e:
                self.logger.warning(f"Error closing session {session_id}: {e}")
        
        self.logger.info("SessionManager stopped")
    
    # ═══════════════════════════════════════════════════════════
    # Session Registration
    # ═══════════════════════════════════════════════════════════
    
    async def register_session(
        self,
        session_id: str,
        target_id: str,
        session_type: SessionType = SessionType.SHELL
    ) -> None:
        """
        Register a new session for monitoring.
        
        Args:
            session_id: UUID of the session
            target_id: Target ID this session is connected to
            session_type: Type of session (SHELL, METERPRETER, etc.)
        """
        now = datetime.utcnow()
        
        health = SessionHealth(
            session_id=session_id,
            last_heartbeat=now,
            last_activity=now,
            established_at=now
        )
        
        self._sessions[session_id] = health
        self._session_locks[session_id] = asyncio.Lock()
        
        self._metrics.total_sessions_created += 1
        self._metrics.active_sessions += 1
        
        self.logger.info(
            f"Session registered: {session_id} (type={session_type.value}, "
            f"target={target_id})"
        )
        
        # Update session in Blackboard
        try:
            await self.blackboard.update_session_status(
                session_id,
                SessionStatus.ACTIVE
            )
        except Exception as e:
            self.logger.error(f"Failed to update session in Blackboard: {e}")
    
    async def unregister_session(self, session_id: str) -> None:
        """
        Unregister a session from monitoring.
        
        Args:
            session_id: UUID of the session
        """
        if session_id in self._sessions:
            health = self._sessions[session_id]
            
            # Calculate session lifetime
            lifetime = (datetime.utcnow() - health.established_at).total_seconds()
            
            # Update average lifetime
            total_sessions = self._metrics.total_sessions_created
            current_avg = self._metrics.average_session_lifetime
            self._metrics.average_session_lifetime = (
                (current_avg * (total_sessions - 1) + lifetime) / total_sessions
            )
            
            del self._sessions[session_id]
            del self._session_locks[session_id]
            
            self._metrics.active_sessions = len(self._sessions)
            
            self.logger.info(f"Session unregistered: {session_id} (lifetime={lifetime:.1f}s)")
    
    # ═══════════════════════════════════════════════════════════
    # Heartbeat Management
    # ═══════════════════════════════════════════════════════════
    
    async def heartbeat(self, session_id: str, activity: bool = False) -> bool:
        """
        Update session heartbeat.
        
        Args:
            session_id: UUID of the session
            activity: Whether this represents actual activity (command execution)
            
        Returns:
            True if heartbeat successful, False otherwise
        """
        if session_id not in self._sessions:
            self.logger.warning(f"Heartbeat for unregistered session: {session_id}")
            return False
        
        async with self._session_locks[session_id]:
            health = self._sessions[session_id]
            now = datetime.utcnow()
            
            health.last_heartbeat = now
            if activity:
                health.last_activity = now
            
            # Reset failure count on successful heartbeat
            health.heartbeat_failures = 0
            health.is_responsive = True
            
            self._metrics.total_heartbeats_sent += 1
            
            # Update session last_activity in Blackboard
            try:
                await self.blackboard.update_session_last_activity(session_id, now)
            except Exception as e:
                self.logger.debug(f"Failed to update session activity: {e}")
            
            return True
    
    async def record_command_execution(
        self,
        session_id: str,
        success: bool
    ) -> None:
        """
        Record command execution for session health tracking.
        
        Args:
            session_id: UUID of the session
            success: Whether command succeeded
        """
        if session_id not in self._sessions:
            return
        
        async with self._session_locks[session_id]:
            health = self._sessions[session_id]
            health.command_executions += 1
            if not success:
                health.command_failures += 1
            
            # Update heartbeat and activity
            await self.heartbeat(session_id, activity=True)
    
    # ═══════════════════════════════════════════════════════════
    # Session Health & Status
    # ═══════════════════════════════════════════════════════════
    
    async def is_session_alive(self, session_id: str) -> bool:
        """
        Check if session is alive and responsive.
        
        Args:
            session_id: UUID of the session
            
        Returns:
            True if session is alive
        """
        if session_id not in self._sessions:
            return False
        
        health = self._sessions[session_id]
        now = datetime.utcnow()
        
        # Update time since last heartbeat
        health.time_since_last_heartbeat = (
            now - health.last_heartbeat
        ).total_seconds()
        
        # Session is dead if:
        # 1. No heartbeat for idle_timeout + grace_period
        # 2. Absolute timeout exceeded
        
        idle_timeout_exceeded = (
            health.time_since_last_heartbeat > 
            self.timeout_config.idle_timeout + self.timeout_config.grace_period
        )
        
        session_lifetime = (now - health.established_at).total_seconds()
        absolute_timeout_exceeded = (
            session_lifetime > self.timeout_config.absolute_timeout
        )
        
        if idle_timeout_exceeded or absolute_timeout_exceeded:
            return False
        
        return True
    
    async def get_session_health(self, session_id: str) -> Optional[SessionHealth]:
        """
        Get session health metrics.
        
        Args:
            session_id: UUID of the session
            
        Returns:
            SessionHealth object or None
        """
        if session_id not in self._sessions:
            return None
        
        health = self._sessions[session_id]
        now = datetime.utcnow()
        
        # Update time metrics
        health.time_since_last_heartbeat = (
            now - health.last_heartbeat
        ).total_seconds()
        health.time_since_last_activity = (
            now - health.last_activity
        ).total_seconds()
        
        # Calculate health score
        health.health_score = health.calculate_health_score()
        
        return health
    
    async def close_session(
        self,
        session_id: str,
        reason: str = "manual_close"
    ) -> None:
        """
        Close a session gracefully.
        
        Args:
            session_id: UUID of the session
            reason: Reason for closing (timeout, manual, error, etc.)
        """
        if session_id not in self._sessions:
            self.logger.warning(f"Attempted to close unregistered session: {session_id}")
            return
        
        self.logger.info(f"Closing session {session_id} (reason={reason})")
        
        # Update session status in Blackboard
        try:
            await self.blackboard.update_session_status(
                session_id,
                SessionStatus.CLOSED
            )
            
            # Log closure
            await self.blackboard.log_result(
                None,  # mission_id might not be available
                "session_closed",
                {
                    "session_id": session_id,
                    "reason": reason,
                    "timestamp": datetime.utcnow().isoformat()
                }
            )
        except Exception as e:
            self.logger.error(f"Failed to update session status: {e}")
        
        # Unregister from monitoring
        await self.unregister_session(session_id)
    
    # ═══════════════════════════════════════════════════════════
    # Background Monitoring
    # ═══════════════════════════════════════════════════════════
    
    async def _monitor_loop(self) -> None:
        """
        Main monitoring loop for session health and timeouts.
        
        Checks all sessions periodically and:
        - Detects idle timeouts
        - Detects absolute timeouts
        - Updates session health scores
        - Marks stale sessions
        """
        self.logger.info("Session monitor loop started")
        
        while self._running:
            try:
                await asyncio.sleep(self.timeout_config.keepalive_interval)
                
                if not self._running:
                    break
                
                await self._check_session_timeouts()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in monitor loop: {e}", exc_info=True)
                await asyncio.sleep(5)
        
        self.logger.info("Session monitor loop stopped")
    
    async def _check_session_timeouts(self) -> None:
        """Check all sessions for timeouts."""
        now = datetime.utcnow()
        session_ids = list(self._sessions.keys())
        
        for session_id in session_ids:
            try:
                health = self._sessions[session_id]
                
                # Calculate timeouts
                idle_time = (now - health.last_activity).total_seconds()
                session_lifetime = (now - health.established_at).total_seconds()
                
                # Check idle timeout
                if idle_time > self.timeout_config.idle_timeout:
                    if health.is_responsive:
                        # First timeout - mark as stale
                        health.is_responsive = False
                        self._metrics.stale_sessions += 1
                        self.logger.warning(
                            f"Session {session_id} idle timeout "
                            f"({idle_time:.1f}s > {self.timeout_config.idle_timeout}s)"
                        )
                    
                    # Grace period exceeded - close session
                    if idle_time > self.timeout_config.idle_timeout + self.timeout_config.grace_period:
                        self._metrics.sessions_timed_out_idle += 1
                        await self.close_session(session_id, reason="idle_timeout")
                        continue
                
                # Check absolute timeout
                if session_lifetime > self.timeout_config.absolute_timeout:
                    self._metrics.sessions_timed_out_absolute += 1
                    await self.close_session(session_id, reason="absolute_timeout")
                    continue
                
                # Update health score
                health.health_score = health.calculate_health_score()
                
            except Exception as e:
                self.logger.error(f"Error checking session {session_id}: {e}")
    
    async def _cleanup_loop(self) -> None:
        """
        Cleanup loop for dead sessions.
        
        Removes sessions that are no longer valid or have been orphaned.
        """
        self.logger.info("Session cleanup loop started")
        
        while self._running:
            try:
                await asyncio.sleep(self.timeout_config.cleanup_interval)
                
                if not self._running:
                    break
                
                await self._cleanup_dead_sessions()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in cleanup loop: {e}", exc_info=True)
                await asyncio.sleep(10)
        
        self.logger.info("Session cleanup loop stopped")
    
    async def _cleanup_dead_sessions(self) -> None:
        """Clean up dead sessions from Blackboard."""
        try:
            # Get all sessions from Blackboard
            # (This would need a method in Blackboard)
            # For now, we only clean up sessions we're tracking
            
            session_ids = list(self._sessions.keys())
            for session_id in session_ids:
                if not await self.is_session_alive(session_id):
                    self._metrics.dead_sessions += 1
                    self._metrics.sessions_cleaned_up += 1
                    await self.close_session(session_id, reason="cleanup_dead")
        
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")
    
    # ═══════════════════════════════════════════════════════════
    # Metrics & Observability
    # ═══════════════════════════════════════════════════════════
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get session management metrics."""
        return self._metrics.to_dict()
    
    def get_all_session_health(self) -> List[Dict[str, Any]]:
        """Get health metrics for all sessions."""
        result = []
        for session_id, health in self._sessions.items():
            now = datetime.utcnow()
            health.time_since_last_heartbeat = (
                now - health.last_heartbeat
            ).total_seconds()
            health.health_score = health.calculate_health_score()
            
            result.append({
                "session_id": session_id,
                "health_score": health.health_score,
                "is_responsive": health.is_responsive,
                "heartbeat_failures": health.heartbeat_failures,
                "time_since_last_heartbeat": round(health.time_since_last_heartbeat, 2),
                "time_since_last_activity": round(
                    (now - health.last_activity).total_seconds(), 2
                ),
                "command_success_rate": round(
                    (health.command_executions - health.command_failures) / 
                    health.command_executions * 100, 2
                ) if health.command_executions > 0 else 100.0
            })
        
        return result


# ═══════════════════════════════════════════════════════════
# Global Singleton Instance
# ═══════════════════════════════════════════════════════════

_global_session_manager: Optional[SessionManager] = None


def get_session_manager(
    blackboard: Optional[Blackboard] = None,
    settings: Optional[Settings] = None
) -> SessionManager:
    """Get global session manager singleton."""
    global _global_session_manager
    if _global_session_manager is None:
        if blackboard is None:
            raise ValueError("Blackboard required for SessionManager initialization")
        _global_session_manager = SessionManager(blackboard, settings)
    return _global_session_manager
