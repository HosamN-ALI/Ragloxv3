# ===================================================================
# RAGLOX v3.0 - Mission Repository
# PostgreSQL-backed mission management
# ===================================================================
"""
Mission Repository for multi-tenant SaaS platform.

Provides persistent storage for mission data alongside Redis
(which handles real-time state during active operations).

Architecture:
- Redis: Active mission state (real-time, temporary)
- PostgreSQL: Mission history, configuration, statistics

This allows fast operations during missions while maintaining
durable records for reporting and audit.
"""

from typing import Optional, Any, Dict, List
from uuid import UUID
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import logging

from .base_repository import BaseRepository
from .connection import DatabasePool

logger = logging.getLogger("raglox.database.mission")


# ===================================================================
# Mission Status Enum
# ===================================================================

class MissionStatus(str, Enum):
    """Mission lifecycle states."""
    CREATED = "created"
    STARTING = "starting"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETING = "completing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


# ===================================================================
# Mission Entity
# ===================================================================

@dataclass
class MissionRecord:
    """
    Mission entity for PostgreSQL storage.
    
    Note: This is the persistent record. Active mission state
    is managed by Blackboard in Redis.
    """
    id: UUID
    organization_id: UUID
    created_by: Optional[UUID] = None
    
    # Mission details
    name: str = ""
    description: Optional[str] = None
    status: str = "created"
    
    # Configuration
    scope: List[str] = field(default_factory=list)
    goals: List[str] = field(default_factory=list)
    constraints: Dict[str, Any] = field(default_factory=dict)
    
    # Environment
    environment_type: str = "simulated"  # simulated, ssh, vm, hybrid
    environment_config: Dict[str, Any] = field(default_factory=dict)
    
    # Statistics (cached from Redis on completion)
    targets_discovered: int = 0
    vulns_found: int = 0
    creds_harvested: int = 0
    sessions_established: int = 0
    goals_achieved: int = 0
    goals_total: int = 0
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Timestamps
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    def duration_hours(self) -> Optional[float]:
        """Calculate mission duration in hours."""
        if not self.started_at:
            return None
        end_time = self.completed_at or datetime.utcnow()
        return (end_time - self.started_at).total_seconds() / 3600
    
    def is_active(self) -> bool:
        """Check if mission is currently active."""
        return self.status in [MissionStatus.STARTING, MissionStatus.RUNNING, MissionStatus.PAUSED]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "id": str(self.id),
            "organization_id": str(self.organization_id),
            "created_by": str(self.created_by) if self.created_by else None,
            "name": self.name,
            "description": self.description,
            "status": self.status,
            "scope": self.scope,
            "goals": self.goals,
            "constraints": self.constraints,
            "environment_type": self.environment_type,
            "statistics": {
                "targets_discovered": self.targets_discovered,
                "vulns_found": self.vulns_found,
                "creds_harvested": self.creds_harvested,
                "sessions_established": self.sessions_established,
                "goals_achieved": self.goals_achieved,
                "goals_total": self.goals_total,
            },
            "duration_hours": self.duration_hours(),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


# ===================================================================
# Mission Repository
# ===================================================================

class MissionRepository(BaseRepository[MissionRecord]):
    """
    PostgreSQL repository for Mission entities.
    
    This repository handles persistent mission records.
    For active mission state, use Blackboard (Redis).
    
    Example:
        repo = MissionRepository(pool)
        
        # Create mission record
        mission = await repo.create(MissionRecord(
            organization_id=org_id,
            name="Q4 Pentest",
            scope=["10.0.0.0/24"],
            goals=["domain_admin"]
        ))
        
        # Get organization missions
        missions = await repo.get_organization_missions(org_id)
        
        # Archive completed mission with stats
        await repo.archive_mission(mission_id, stats_from_redis)
    """
    
    table_name = "missions"
    
    def _record_to_entity(self, record: Any) -> Optional[MissionRecord]:
        """Convert database record to MissionRecord entity."""
        if not record:
            return None
        
        return MissionRecord(
            id=record["id"],
            organization_id=record["organization_id"],
            created_by=record.get("created_by"),
            name=record["name"],
            description=record.get("description"),
            status=record.get("status", "created"),
            scope=record.get("scope", []),
            goals=record.get("goals", []),
            constraints=record.get("constraints", {}),
            environment_type=record.get("environment_type", "simulated"),
            environment_config=record.get("environment_config", {}),
            targets_discovered=record.get("targets_discovered", 0),
            vulns_found=record.get("vulns_found", 0),
            creds_harvested=record.get("creds_harvested", 0),
            sessions_established=record.get("sessions_established", 0),
            goals_achieved=record.get("goals_achieved", 0),
            goals_total=record.get("goals_total", 0),
            metadata=record.get("metadata", {}),
            created_at=record.get("created_at"),
            updated_at=record.get("updated_at"),
            started_at=record.get("started_at"),
            completed_at=record.get("completed_at"),
        )
    
    def _entity_to_dict(self, entity: MissionRecord) -> Dict[str, Any]:
        """Convert MissionRecord entity to dictionary for database."""
        return {
            "id": entity.id,
            "organization_id": entity.organization_id,
            "created_by": entity.created_by,
            "name": entity.name,
            "description": entity.description,
            "status": entity.status,
            "scope": entity.scope,
            "goals": entity.goals,
            "constraints": entity.constraints,
            "environment_type": entity.environment_type,
            "environment_config": entity.environment_config,
            "targets_discovered": entity.targets_discovered,
            "vulns_found": entity.vulns_found,
            "creds_harvested": entity.creds_harvested,
            "sessions_established": entity.sessions_established,
            "goals_achieved": entity.goals_achieved,
            "goals_total": entity.goals_total,
            "metadata": entity.metadata,
        }
    
    # ===================================================================
    # Mission-Specific Queries
    # ===================================================================
    
    async def get_organization_missions(
        self,
        organization_id: UUID,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[MissionRecord]:
        """
        Get missions for an organization.
        
        Args:
            organization_id: Organization UUID
            status: Optional status filter
            limit: Maximum results
            offset: Skip N results
            
        Returns:
            List of missions
        """
        if status:
            query = """
                SELECT * FROM missions
                WHERE organization_id = $1 AND status = $2
                ORDER BY created_at DESC
                LIMIT $3 OFFSET $4
            """
            rows = await self.pool.fetch(query, organization_id, status, limit, offset)
        else:
            query = """
                SELECT * FROM missions
                WHERE organization_id = $1
                ORDER BY created_at DESC
                LIMIT $2 OFFSET $3
            """
            rows = await self.pool.fetch(query, organization_id, limit, offset)
        
        return [self._record_to_entity(row) for row in rows]
    
    async def get_active_missions(
        self,
        organization_id: UUID
    ) -> List[MissionRecord]:
        """Get currently active (running/paused) missions."""
        query = """
            SELECT * FROM missions
            WHERE organization_id = $1 AND status IN ('starting', 'running', 'paused')
            ORDER BY started_at DESC
        """
        rows = await self.pool.fetch(query, organization_id)
        return [self._record_to_entity(row) for row in rows]
    
    async def get_recent_missions(
        self,
        organization_id: UUID,
        days: int = 30,
        limit: int = 20
    ) -> List[MissionRecord]:
        """Get missions from the last N days."""
        cutoff = datetime.utcnow() - timedelta(days=days)
        
        query = """
            SELECT * FROM missions
            WHERE organization_id = $1 AND created_at >= $2
            ORDER BY created_at DESC
            LIMIT $3
        """
        rows = await self.pool.fetch(query, organization_id, cutoff, limit)
        return [self._record_to_entity(row) for row in rows]
    
    async def count_active_missions(self, organization_id: UUID) -> int:
        """Count currently active missions."""
        query = """
            SELECT COUNT(*) FROM missions
            WHERE organization_id = $1 AND status IN ('starting', 'running', 'paused')
        """
        return await self.pool.fetchval(query, organization_id) or 0
    
    async def count_missions_this_month(self, organization_id: UUID) -> int:
        """Count missions created this month."""
        first_of_month = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        
        query = """
            SELECT COUNT(*) FROM missions
            WHERE organization_id = $1 AND created_at >= $2
        """
        return await self.pool.fetchval(query, organization_id, first_of_month) or 0
    
    # ===================================================================
    # Status Updates
    # ===================================================================
    
    async def update_status(
        self,
        mission_id: UUID,
        organization_id: UUID,
        status: str,
        timestamp_field: Optional[str] = None
    ) -> Optional[MissionRecord]:
        """
        Update mission status with optional timestamp.
        
        Args:
            mission_id: Mission UUID
            organization_id: Organization UUID for isolation
            status: New status
            timestamp_field: Optional field to update (e.g., "started_at")
            
        Returns:
            Updated mission
        """
        updates = {"status": status}
        
        if timestamp_field:
            updates[timestamp_field] = datetime.utcnow()
        
        return await self.update(mission_id, updates, organization_id)
    
    async def start_mission(
        self,
        mission_id: UUID,
        organization_id: UUID
    ) -> Optional[MissionRecord]:
        """Mark mission as started."""
        return await self.update_status(
            mission_id,
            organization_id,
            MissionStatus.RUNNING,
            "started_at"
        )
    
    async def pause_mission(
        self,
        mission_id: UUID,
        organization_id: UUID
    ) -> Optional[MissionRecord]:
        """Mark mission as paused."""
        return await self.update_status(
            mission_id,
            organization_id,
            MissionStatus.PAUSED
        )
    
    async def resume_mission(
        self,
        mission_id: UUID,
        organization_id: UUID
    ) -> Optional[MissionRecord]:
        """Mark mission as running (resumed)."""
        return await self.update_status(
            mission_id,
            organization_id,
            MissionStatus.RUNNING
        )
    
    async def complete_mission(
        self,
        mission_id: UUID,
        organization_id: UUID,
        statistics: Optional[Dict[str, int]] = None
    ) -> Optional[MissionRecord]:
        """
        Mark mission as completed with final statistics.
        
        Args:
            mission_id: Mission UUID
            organization_id: Organization UUID
            statistics: Final stats from Redis
            
        Returns:
            Updated mission
        """
        updates = {
            "status": MissionStatus.COMPLETED,
            "completed_at": datetime.utcnow(),
        }
        
        if statistics:
            updates.update({
                "targets_discovered": statistics.get("targets_discovered", 0),
                "vulns_found": statistics.get("vulns_found", 0),
                "creds_harvested": statistics.get("creds_harvested", 0),
                "sessions_established": statistics.get("sessions_established", 0),
                "goals_achieved": statistics.get("goals_achieved", 0),
                "goals_total": statistics.get("goals_total", 0),
            })
        
        return await self.update(mission_id, updates, organization_id)
    
    async def fail_mission(
        self,
        mission_id: UUID,
        organization_id: UUID,
        error_message: Optional[str] = None
    ) -> Optional[MissionRecord]:
        """Mark mission as failed."""
        updates = {
            "status": MissionStatus.FAILED,
            "completed_at": datetime.utcnow(),
        }
        
        if error_message:
            updates["metadata"] = {"error": error_message}
        
        return await self.update(mission_id, updates, organization_id)
    
    async def cancel_mission(
        self,
        mission_id: UUID,
        organization_id: UUID,
        cancelled_by: Optional[UUID] = None
    ) -> Optional[MissionRecord]:
        """Mark mission as cancelled."""
        updates = {
            "status": MissionStatus.CANCELLED,
            "completed_at": datetime.utcnow(),
        }
        
        if cancelled_by:
            updates["metadata"] = {"cancelled_by": str(cancelled_by)}
        
        return await self.update(mission_id, updates, organization_id)
    
    # ===================================================================
    # Statistics & Aggregation
    # ===================================================================
    
    async def get_organization_stats(
        self,
        organization_id: UUID
    ) -> Dict[str, Any]:
        """
        Get aggregate statistics for an organization.
        
        Returns mission counts by status and totals.
        """
        query = """
            SELECT
                COUNT(*) as total_missions,
                COUNT(*) FILTER (WHERE status = 'completed') as completed_missions,
                COUNT(*) FILTER (WHERE status = 'failed') as failed_missions,
                COUNT(*) FILTER (WHERE status IN ('running', 'paused')) as active_missions,
                COALESCE(SUM(targets_discovered), 0) as total_targets,
                COALESCE(SUM(vulns_found), 0) as total_vulns,
                COALESCE(SUM(creds_harvested), 0) as total_creds,
                COALESCE(SUM(sessions_established), 0) as total_sessions,
                COALESCE(SUM(goals_achieved), 0) as total_goals_achieved
            FROM missions
            WHERE organization_id = $1
        """
        
        row = await self.pool.fetchrow(query, organization_id)
        
        return {
            "total_missions": row["total_missions"],
            "completed_missions": row["completed_missions"],
            "failed_missions": row["failed_missions"],
            "active_missions": row["active_missions"],
            "total_targets": row["total_targets"],
            "total_vulns": row["total_vulns"],
            "total_creds": row["total_creds"],
            "total_sessions": row["total_sessions"],
            "total_goals_achieved": row["total_goals_achieved"],
        }
    
    async def get_mission_timeline(
        self,
        organization_id: UUID,
        days: int = 30
    ) -> List[Dict[str, Any]]:
        """
        Get mission activity timeline (for charts).
        
        Returns daily counts of created and completed missions.
        """
        cutoff = datetime.utcnow() - timedelta(days=days)
        
        query = """
            SELECT
                DATE(created_at) as date,
                COUNT(*) as created,
                COUNT(*) FILTER (WHERE status = 'completed') as completed,
                COUNT(*) FILTER (WHERE status = 'failed') as failed
            FROM missions
            WHERE organization_id = $1 AND created_at >= $2
            GROUP BY DATE(created_at)
            ORDER BY date ASC
        """
        
        rows = await self.pool.fetch(query, organization_id, cutoff)
        
        return [
            {
                "date": row["date"].isoformat(),
                "created": row["created"],
                "completed": row["completed"],
                "failed": row["failed"],
            }
            for row in rows
        ]
    
    # ===================================================================
    # Search
    # ===================================================================
    
    async def search_missions(
        self,
        organization_id: UUID,
        search_term: str,
        limit: int = 20
    ) -> List[MissionRecord]:
        """
        Search missions by name or description.
        
        Uses pg_trgm for fuzzy matching.
        """
        query = """
            SELECT * FROM missions
            WHERE organization_id = $1
              AND (
                name ILIKE $2
                OR description ILIKE $2
              )
            ORDER BY
                CASE WHEN name ILIKE $3 THEN 0 ELSE 1 END,
                created_at DESC
            LIMIT $4
        """
        
        pattern = f"%{search_term}%"
        exact_pattern = f"{search_term}%"
        
        rows = await self.pool.fetch(query, organization_id, pattern, exact_pattern, limit)
        return [self._record_to_entity(row) for row in rows]
    
    # ===================================================================
    # Archive Operations
    # ===================================================================
    
    async def archive_mission(
        self,
        mission_id: UUID,
        organization_id: UUID,
        final_state: Dict[str, Any]
    ) -> Optional[MissionRecord]:
        """
        Archive a completed mission with full state snapshot.
        
        This stores the final Redis state in PostgreSQL for
        long-term storage and analysis.
        
        Args:
            mission_id: Mission UUID
            organization_id: Organization UUID
            final_state: Full state from Redis
            
        Returns:
            Updated mission record
        """
        # Extract statistics from final state
        stats = {
            "targets_discovered": len(final_state.get("targets", [])),
            "vulns_found": len(final_state.get("vulnerabilities", [])),
            "creds_harvested": len(final_state.get("credentials", [])),
            "sessions_established": len(final_state.get("sessions", [])),
            "goals_achieved": sum(1 for g in final_state.get("goals", []) if g.get("status") == "achieved"),
            "goals_total": len(final_state.get("goals", [])),
        }
        
        updates = {
            "status": "completed",
            "completed_at": datetime.utcnow(),
            "metadata": {
                "archived": True,
                "archived_at": datetime.utcnow().isoformat(),
                "final_state_keys": list(final_state.keys()),
            },
            **stats,
        }
        
        return await self.update(mission_id, updates, organization_id)
    
    async def get_archived_missions(
        self,
        organization_id: UUID,
        limit: int = 50,
        offset: int = 0
    ) -> List[MissionRecord]:
        """Get archived (completed) missions."""
        query = """
            SELECT * FROM missions
            WHERE organization_id = $1
              AND status IN ('completed', 'failed', 'cancelled')
            ORDER BY completed_at DESC
            LIMIT $2 OFFSET $3
        """
        rows = await self.pool.fetch(query, organization_id, limit, offset)
        return [self._record_to_entity(row) for row in rows]
