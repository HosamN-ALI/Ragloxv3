# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Approval State Persistence (REL-02)
# Persistent storage for HITL approval actions and chat history
# ═══════════════════════════════════════════════════════════════

"""
REL-02: Approval State Persistence

This module provides persistent storage for HITL (Human-in-the-Loop) state:
- Pending approval actions
- Chat history
- Approval audit logs

Key Features:
- Redis-based persistence (survives server restarts)
- Automatic expiration for pending approvals
- Efficient retrieval and search
- Audit trail for compliance

Storage Keys:
- approval:{action_id} - Individual approval action
- mission:{mission_id}:approvals:pending - Set of pending approval IDs
- mission:{mission_id}:approvals:completed - List of completed approvals
- mission:{mission_id}:chat - Stream of chat messages
- approval:audit:{action_id} - Audit log for approval decisions
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from uuid import UUID

import redis.asyncio as aioredis
from pydantic import BaseModel

from .config import Settings, get_settings
from .models import (
    ApprovalAction, ApprovalStatus, ActionType, RiskLevel,
    ChatMessage
)

logger = logging.getLogger("raglox.approval_store")


class ApprovalAuditEntry(BaseModel):
    """Audit log entry for approval decisions."""
    action_id: str
    mission_id: str
    action_type: str
    risk_level: str
    status: str
    requested_at: datetime
    responded_at: Optional[datetime] = None
    responded_by: Optional[str] = None
    response_reason: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None


class ApprovalStore:
    """
    Persistent storage for approval actions and chat history.
    
    REL-02: Approval State Persistence
    
    Uses Redis for persistence to ensure state survives server restarts.
    All approval actions and chat messages are stored with TTL for
    automatic cleanup of stale data.
    """
    
    # Default TTLs
    APPROVAL_TTL = 86400  # 24 hours for pending approvals
    COMPLETED_APPROVAL_TTL = 604800  # 7 days for completed approvals
    CHAT_TTL = 2592000  # 30 days for chat history
    AUDIT_TTL = 7776000  # 90 days for audit logs
    
    def __init__(
        self,
        redis_client: Optional[aioredis.Redis] = None,
        settings: Optional[Settings] = None
    ):
        """
        Initialize the ApprovalStore.
        
        Args:
            redis_client: Optional Redis client (will create if not provided)
            settings: Application settings
        """
        self.settings = settings or get_settings()
        self._redis = redis_client
        self._connected = False
        
    async def connect(self, redis_client: Optional[aioredis.Redis] = None) -> None:
        """
        Connect to Redis.
        
        Args:
            redis_client: Optional pre-existing Redis client
        """
        if redis_client:
            self._redis = redis_client
            self._connected = True
        elif not self._connected:
            self._redis = await aioredis.from_url(
                self.settings.redis_url,
                encoding="utf-8",
                decode_responses=True,
                max_connections=20
            )
            self._connected = True
            
    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        if self._redis and not self._connected:
            await self._redis.close()
            self._redis = None
            self._connected = False
    
    @property
    def redis(self) -> aioredis.Redis:
        """Get Redis client."""
        if not self._redis:
            raise RuntimeError("ApprovalStore not connected. Call connect() first.")
        return self._redis
    
    # ═══════════════════════════════════════════════════════════
    # Approval Operations
    # ═══════════════════════════════════════════════════════════
    
    async def save_approval(self, approval: ApprovalAction) -> str:
        """
        Save an approval action to Redis.
        
        Args:
            approval: ApprovalAction to save
            
        Returns:
            Approval action ID
        """
        action_id = str(approval.id)
        mission_id = str(approval.mission_id)
        
        # Serialize the approval
        data = self._serialize_approval(approval)
        
        # Store in Redis hash
        key = f"approval:{action_id}"
        await self.redis.hset(key, mapping=data)
        
        # Set TTL based on status
        if approval.status == ApprovalStatus.PENDING:
            await self.redis.expire(key, self.APPROVAL_TTL)
            # Add to pending set
            await self.redis.sadd(f"mission:{mission_id}:approvals:pending", action_id)
        else:
            await self.redis.expire(key, self.COMPLETED_APPROVAL_TTL)
            # Remove from pending, add to completed
            await self.redis.srem(f"mission:{mission_id}:approvals:pending", action_id)
            await self.redis.lpush(f"mission:{mission_id}:approvals:completed", action_id)
            # Trim completed list to last 1000 entries
            await self.redis.ltrim(f"mission:{mission_id}:approvals:completed", 0, 999)
        
        logger.debug(f"Saved approval {action_id} for mission {mission_id}")
        return action_id
    
    async def get_approval(self, action_id: str) -> Optional[ApprovalAction]:
        """
        Get an approval action by ID.
        
        Args:
            action_id: Approval action ID
            
        Returns:
            ApprovalAction if found, None otherwise
        """
        key = f"approval:{action_id}"
        data = await self.redis.hgetall(key)
        
        if not data:
            return None
            
        return self._deserialize_approval(data)
    
    async def get_pending_approvals(self, mission_id: str) -> List[ApprovalAction]:
        """
        Get all pending approval actions for a mission.
        
        Args:
            mission_id: Mission ID
            
        Returns:
            List of pending ApprovalAction objects
        """
        # Get pending action IDs
        pending_ids = await self.redis.smembers(f"mission:{mission_id}:approvals:pending")
        
        if not pending_ids:
            return []
        
        approvals = []
        for action_id in pending_ids:
            approval = await self.get_approval(action_id)
            if approval:
                # Check if expired
                if approval.expires_at and approval.expires_at < datetime.utcnow():
                    # Mark as expired
                    approval.status = ApprovalStatus.EXPIRED
                    await self.save_approval(approval)
                    await self._log_audit(approval, "system", "Expired due to timeout")
                else:
                    approvals.append(approval)
            else:
                # Remove stale ID
                await self.redis.srem(f"mission:{mission_id}:approvals:pending", action_id)
        
        # Sort by requested_at (newest first)
        approvals.sort(key=lambda a: a.requested_at, reverse=True)
        return approvals
    
    async def update_approval_status(
        self,
        action_id: str,
        status: ApprovalStatus,
        responded_by: Optional[str] = None,
        rejection_reason: Optional[str] = None,
        user_comment: Optional[str] = None,
        audit_info: Optional[Dict[str, str]] = None
    ) -> bool:
        """
        Update the status of an approval action.
        
        Args:
            action_id: Approval action ID
            status: New status
            responded_by: Who responded (user ID or name)
            rejection_reason: Reason for rejection (if rejected)
            user_comment: User's comment
            audit_info: Additional audit info (IP, user agent, etc.)
            
        Returns:
            True if updated successfully, False otherwise
        """
        approval = await self.get_approval(action_id)
        if not approval:
            logger.warning(f"Approval {action_id} not found for update")
            return False
        
        # Update fields
        approval.status = status
        approval.responded_at = datetime.utcnow()
        approval.responded_by = responded_by
        approval.rejection_reason = rejection_reason
        approval.user_comment = user_comment
        
        # Save updated approval
        await self.save_approval(approval)
        
        # Log audit entry
        await self._log_audit(
            approval,
            responded_by or "unknown",
            rejection_reason or user_comment or f"Status changed to {status.value}",
            audit_info
        )
        
        logger.info(f"Updated approval {action_id} to status {status.value}")
        return True
    
    async def delete_approval(self, action_id: str) -> bool:
        """
        Delete an approval action.
        
        Args:
            action_id: Approval action ID
            
        Returns:
            True if deleted, False otherwise
        """
        approval = await self.get_approval(action_id)
        if not approval:
            return False
            
        mission_id = str(approval.mission_id)
        
        # Remove from sets and delete
        await self.redis.srem(f"mission:{mission_id}:approvals:pending", action_id)
        await self.redis.lrem(f"mission:{mission_id}:approvals:completed", 0, action_id)
        await self.redis.delete(f"approval:{action_id}")
        
        return True
    
    async def get_approval_stats(self, mission_id: str) -> Dict[str, Any]:
        """
        Get approval statistics for a mission.
        
        Args:
            mission_id: Mission ID
            
        Returns:
            Statistics dictionary
        """
        pending_count = await self.redis.scard(f"mission:{mission_id}:approvals:pending")
        completed_count = await self.redis.llen(f"mission:{mission_id}:approvals:completed")
        
        # Get completed approvals for breakdown
        completed_ids = await self.redis.lrange(
            f"mission:{mission_id}:approvals:completed", 0, 99
        )
        
        approved = 0
        rejected = 0
        expired = 0
        
        for action_id in completed_ids:
            approval = await self.get_approval(action_id)
            if approval:
                if approval.status == ApprovalStatus.APPROVED:
                    approved += 1
                elif approval.status == ApprovalStatus.REJECTED:
                    rejected += 1
                elif approval.status == ApprovalStatus.EXPIRED:
                    expired += 1
        
        return {
            "pending": pending_count,
            "completed": completed_count,
            "approved": approved,
            "rejected": rejected,
            "expired": expired
        }
    
    # ═══════════════════════════════════════════════════════════
    # Chat History Operations
    # ═══════════════════════════════════════════════════════════
    
    async def save_chat_message(self, message: ChatMessage) -> str:
        """
        Save a chat message to Redis.
        
        Args:
            message: ChatMessage to save
            
        Returns:
            Message ID
        """
        message_id = str(message.id)
        mission_id = str(message.mission_id)
        
        # Serialize message
        data = {
            "id": message_id,
            "mission_id": mission_id,
            "role": message.role,
            "content": message.content,
            "timestamp": message.timestamp.isoformat(),
            "related_task_id": str(message.related_task_id) if message.related_task_id else "",
            "related_action_id": str(message.related_action_id) if message.related_action_id else "",
            "metadata": json.dumps(message.metadata) if message.metadata else "{}"
        }
        
        # Add to stream
        stream_key = f"mission:{mission_id}:chat"
        await self.redis.xadd(stream_key, data, maxlen=1000)  # Keep last 1000 messages
        
        # Set TTL on stream (refreshed with each add)
        await self.redis.expire(stream_key, self.CHAT_TTL)
        
        logger.debug(f"Saved chat message {message_id} for mission {mission_id}")
        return message_id
    
    async def get_chat_history(
        self,
        mission_id: str,
        limit: int = 50,
        after: Optional[str] = None
    ) -> List[ChatMessage]:
        """
        Get chat history for a mission.
        
        Args:
            mission_id: Mission ID
            limit: Maximum messages to return
            after: Optional stream ID to get messages after
            
        Returns:
            List of ChatMessage objects
        """
        stream_key = f"mission:{mission_id}:chat"
        
        # Read from stream
        start = after or "-"
        entries = await self.redis.xrevrange(stream_key, count=limit)
        
        messages = []
        for entry_id, data in entries:
            try:
                message = ChatMessage(
                    id=UUID(data.get("id", "")),
                    mission_id=UUID(data.get("mission_id", "")),
                    role=data.get("role", "user"),
                    content=data.get("content", ""),
                    timestamp=datetime.fromisoformat(data.get("timestamp", datetime.utcnow().isoformat())),
                    related_task_id=UUID(data["related_task_id"]) if data.get("related_task_id") else None,
                    related_action_id=UUID(data["related_action_id"]) if data.get("related_action_id") else None,
                    metadata=json.loads(data.get("metadata", "{}"))
                )
                messages.append(message)
            except (ValueError, KeyError) as e:
                logger.warning(f"Error deserializing chat message: {e}")
                continue
        
        # Reverse to get chronological order
        messages.reverse()
        return messages
    
    async def clear_chat_history(self, mission_id: str) -> int:
        """
        Clear chat history for a mission.
        
        Args:
            mission_id: Mission ID
            
        Returns:
            Number of messages deleted
        """
        stream_key = f"mission:{mission_id}:chat"
        
        # Get count before deletion
        info = await self.redis.xinfo_stream(stream_key)
        count = info.get("length", 0) if info else 0
        
        # Delete the stream
        await self.redis.delete(stream_key)
        
        return count
    
    # ═══════════════════════════════════════════════════════════
    # Audit Log Operations
    # ═══════════════════════════════════════════════════════════
    
    async def _log_audit(
        self,
        approval: ApprovalAction,
        actor: str,
        reason: str,
        extra_info: Optional[Dict[str, str]] = None
    ) -> None:
        """
        Log an audit entry for an approval decision.
        
        Args:
            approval: ApprovalAction
            actor: Who performed the action
            reason: Reason for the action
            extra_info: Additional info (IP, user agent, etc.)
        """
        action_id = str(approval.id)
        action_type = approval.action_type.value if hasattr(approval.action_type, 'value') else str(approval.action_type)
        risk_level = approval.risk_level.value if hasattr(approval.risk_level, 'value') else str(approval.risk_level)
        status = approval.status.value if hasattr(approval.status, 'value') else str(approval.status)
        
        entry = ApprovalAuditEntry(
            action_id=action_id,
            mission_id=str(approval.mission_id),
            action_type=action_type,
            risk_level=risk_level,
            status=status,
            requested_at=approval.requested_at,
            responded_at=approval.responded_at,
            responded_by=actor,
            response_reason=reason,
            ip_address=extra_info.get("ip_address") if extra_info else None,
            user_agent=extra_info.get("user_agent") if extra_info else None
        )
        
        # Store in Redis stream
        await self.redis.xadd(
            f"approval:audit:{action_id}",
            entry.model_dump(mode="json"),
            maxlen=100  # Keep last 100 audit entries per approval
        )
        await self.redis.expire(f"approval:audit:{action_id}", self.AUDIT_TTL)
        
        # Also add to mission-wide audit stream
        await self.redis.xadd(
            f"mission:{approval.mission_id}:audit",
            {"type": "approval", **entry.model_dump(mode="json")},
            maxlen=10000
        )
    
    async def get_audit_log(
        self,
        action_id: str,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get audit log for an approval action.
        
        Args:
            action_id: Approval action ID
            limit: Maximum entries to return
            
        Returns:
            List of audit entries
        """
        stream_key = f"approval:audit:{action_id}"
        entries = await self.redis.xrange(stream_key, count=limit)
        
        return [
            {"stream_id": entry_id, **fields}
            for entry_id, fields in entries
        ]
    
    # ═══════════════════════════════════════════════════════════
    # Serialization Helpers
    # ═══════════════════════════════════════════════════════════
    
    def _serialize_approval(self, approval: ApprovalAction) -> Dict[str, str]:
        """Serialize an ApprovalAction to a Redis-compatible dict."""
        action_type = approval.action_type.value if hasattr(approval.action_type, 'value') else str(approval.action_type)
        risk_level = approval.risk_level.value if hasattr(approval.risk_level, 'value') else str(approval.risk_level)
        status = approval.status.value if hasattr(approval.status, 'value') else str(approval.status)
        
        return {
            "id": str(approval.id),
            "mission_id": str(approval.mission_id),
            "task_id": str(approval.task_id) if approval.task_id else "",
            "action_type": action_type,
            "action_description": approval.action_description,
            "target_ip": approval.target_ip or "",
            "target_hostname": approval.target_hostname or "",
            "risk_level": risk_level,
            "risk_reasons": json.dumps(approval.risk_reasons),
            "potential_impact": approval.potential_impact or "",
            "module_to_execute": approval.module_to_execute or "",
            "command_preview": approval.command_preview or "",
            "parameters": json.dumps(approval.parameters),
            "status": status,
            "requested_at": approval.requested_at.isoformat(),
            "expires_at": approval.expires_at.isoformat() if approval.expires_at else "",
            "responded_at": approval.responded_at.isoformat() if approval.responded_at else "",
            "responded_by": approval.responded_by or "",
            "rejection_reason": approval.rejection_reason or "",
            "user_comment": approval.user_comment or "",
            "created_at": approval.created_at.isoformat(),
            "metadata": json.dumps(approval.metadata)
        }
    
    def _deserialize_approval(self, data: Dict[str, str]) -> ApprovalAction:
        """Deserialize a Redis hash to an ApprovalAction."""
        return ApprovalAction(
            id=UUID(data["id"]),
            mission_id=UUID(data["mission_id"]),
            task_id=UUID(data["task_id"]) if data.get("task_id") else None,
            action_type=ActionType(data["action_type"]),
            action_description=data["action_description"],
            target_ip=data.get("target_ip") or None,
            target_hostname=data.get("target_hostname") or None,
            risk_level=RiskLevel(data.get("risk_level", "medium")),
            risk_reasons=json.loads(data.get("risk_reasons", "[]")),
            potential_impact=data.get("potential_impact") or None,
            module_to_execute=data.get("module_to_execute") or None,
            command_preview=data.get("command_preview") or None,
            parameters=json.loads(data.get("parameters", "{}")),
            status=ApprovalStatus(data.get("status", "pending")),
            requested_at=datetime.fromisoformat(data["requested_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]) if data.get("expires_at") else None,
            responded_at=datetime.fromisoformat(data["responded_at"]) if data.get("responded_at") else None,
            responded_by=data.get("responded_by") or None,
            rejection_reason=data.get("rejection_reason") or None,
            user_comment=data.get("user_comment") or None,
            created_at=datetime.fromisoformat(data.get("created_at", datetime.utcnow().isoformat())),
            metadata=json.loads(data.get("metadata", "{}"))
        )


# ═══════════════════════════════════════════════════════════════
# Singleton Instance
# ═══════════════════════════════════════════════════════════════

_approval_store: Optional[ApprovalStore] = None


def get_approval_store() -> ApprovalStore:
    """Get the global ApprovalStore instance."""
    global _approval_store
    if _approval_store is None:
        _approval_store = ApprovalStore()
    return _approval_store


async def init_approval_store(redis_client: Optional[aioredis.Redis] = None) -> ApprovalStore:
    """
    Initialize the global ApprovalStore.
    
    Args:
        redis_client: Optional Redis client to use
        
    Returns:
        Initialized ApprovalStore
    """
    store = get_approval_store()
    await store.connect(redis_client)
    return store
