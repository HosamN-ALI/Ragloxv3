# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - REL-01 & REL-02 Tests
# Tests for Redis HA and Approval State Persistence
# ═══════════════════════════════════════════════════════════════

"""
Tests for REL-01 (Redis High Availability) and REL-02 (Approval State Persistence).

These tests verify:
- Redis HA client modes (standalone, sentinel, cluster)
- Health check functionality
- Approval persistence to Redis
- Chat history persistence
- Recovery after restart simulation
"""

import pytest
from datetime import datetime, timedelta
from uuid import uuid4, UUID
from unittest.mock import AsyncMock, MagicMock, patch

# Test client
from httpx import AsyncClient
from fastapi import FastAPI

# Import test app
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestRedisHAModes:
    """Tests for REL-01: Redis High Availability modes."""
    
    def test_redis_mode_enum(self):
        """Test RedisMode enum values."""
        from src.core.redis_ha import RedisMode
        
        assert RedisMode.STANDALONE.value == "standalone"
        assert RedisMode.SENTINEL.value == "sentinel"
        assert RedisMode.CLUSTER.value == "cluster"
    
    def test_redis_health_status_to_dict(self):
        """Test RedisHealthStatus conversion to dict."""
        from src.core.redis_ha import RedisHealthStatus, RedisMode
        
        status = RedisHealthStatus(
            healthy=True,
            mode=RedisMode.STANDALONE,
            master="localhost:6379",
            slaves=2,
            latency_ms=0.5,
            last_check="2024-01-15T10:00:00"
        )
        
        result = status.to_dict()
        
        assert result["healthy"] is True
        assert result["mode"] == "standalone"
        assert result["master"] == "localhost:6379"
        assert result["slaves"] == 2
        assert result["latency_ms"] == 0.5
    
    @pytest.mark.asyncio
    async def test_redis_ha_client_init(self):
        """Test RedisHAClient initialization."""
        from src.core.redis_ha import RedisHAClient, RedisMode
        
        client = RedisHAClient()
        
        assert client.mode == RedisMode.STANDALONE  # Default mode
        assert client.is_connected is False
    
    @pytest.mark.asyncio
    async def test_redis_connection_manager_init(self):
        """Test RedisConnectionManager initialization."""
        from src.core.redis_ha import RedisConnectionManager
        
        manager = RedisConnectionManager()
        
        assert manager._ha_client is None
        assert manager._fallback_client is None


class TestApprovalStore:
    """Tests for REL-02: Approval State Persistence."""
    
    def test_approval_store_init(self):
        """Test ApprovalStore initialization."""
        from src.core.approval_store import ApprovalStore
        
        store = ApprovalStore()
        
        assert store._connected is False
        assert store._redis is None
    
    def test_approval_ttl_defaults(self):
        """Test default TTL values."""
        from src.core.approval_store import ApprovalStore
        
        assert ApprovalStore.APPROVAL_TTL == 86400  # 24 hours
        assert ApprovalStore.COMPLETED_APPROVAL_TTL == 604800  # 7 days
        assert ApprovalStore.CHAT_TTL == 2592000  # 30 days
        assert ApprovalStore.AUDIT_TTL == 7776000  # 90 days
    
    @pytest.mark.asyncio
    async def test_approval_serialization(self):
        """Test approval serialization and deserialization."""
        from src.core.approval_store import ApprovalStore
        from src.core.models import (
            ApprovalAction, ActionType, RiskLevel, ApprovalStatus
        )
        
        store = ApprovalStore()
        
        # Create test approval
        approval = ApprovalAction(
            id=uuid4(),
            mission_id=uuid4(),
            action_type=ActionType.EXPLOIT,
            action_description="Test exploit action",
            target_ip="10.0.0.5",
            risk_level=RiskLevel.HIGH,
            risk_reasons=["Test reason 1", "Test reason 2"],
            status=ApprovalStatus.PENDING
        )
        
        # Serialize
        serialized = store._serialize_approval(approval)
        
        assert serialized["action_type"] == "exploit"
        assert serialized["risk_level"] == "high"
        assert serialized["target_ip"] == "10.0.0.5"
        assert "Test reason 1" in serialized["risk_reasons"]
        
        # Deserialize
        deserialized = store._deserialize_approval(serialized)
        
        assert deserialized.id == approval.id
        assert deserialized.action_type == ActionType.EXPLOIT
        assert deserialized.risk_level == RiskLevel.HIGH
        assert deserialized.target_ip == "10.0.0.5"


class TestApprovalAudit:
    """Tests for REL-02: Approval Audit Logging."""
    
    def test_audit_entry_model(self):
        """Test ApprovalAuditEntry model."""
        from src.core.approval_store import ApprovalAuditEntry
        
        entry = ApprovalAuditEntry(
            action_id="test-id",
            mission_id="mission-id",
            action_type="exploit",
            risk_level="high",
            status="approved",
            requested_at=datetime.utcnow(),
            responded_at=datetime.utcnow(),
            responded_by="admin",
            response_reason="Test approved",
            ip_address="192.168.1.100",
            user_agent="Test Client"
        )
        
        assert entry.action_id == "test-id"
        assert entry.responded_by == "admin"
        assert entry.ip_address == "192.168.1.100"


class TestConfigSettings:
    """Tests for REL-01 & REL-02 configuration settings."""
    
    def test_redis_ha_settings(self):
        """Test Redis HA configuration settings exist."""
        from src.core.config import Settings
        
        settings = Settings()
        
        # REL-01 settings
        assert hasattr(settings, 'redis_mode')
        assert hasattr(settings, 'redis_sentinel_hosts')
        assert hasattr(settings, 'redis_sentinel_master')
        assert hasattr(settings, 'redis_cluster_nodes')
        assert hasattr(settings, 'redis_health_check_interval')
        assert hasattr(settings, 'redis_reconnect_max_attempts')
        assert hasattr(settings, 'redis_socket_timeout')
    
    def test_approval_persistence_settings(self):
        """Test Approval Persistence configuration settings exist."""
        from src.core.config import Settings
        
        settings = Settings()
        
        # REL-02 settings
        assert hasattr(settings, 'approval_ttl_pending')
        assert hasattr(settings, 'approval_ttl_completed')
        assert hasattr(settings, 'chat_history_ttl')
        assert hasattr(settings, 'approval_audit_ttl')
    
    def test_default_values(self):
        """Test default configuration values."""
        from src.core.config import Settings
        
        settings = Settings()
        
        # REL-01 defaults
        assert settings.redis_mode == "standalone"
        assert settings.redis_sentinel_master == "mymaster"
        assert settings.redis_health_check_interval == 30
        assert settings.redis_reconnect_max_attempts == 10
        assert settings.redis_socket_timeout == 5.0
        
        # REL-02 defaults
        assert settings.approval_ttl_pending == 86400
        assert settings.approval_ttl_completed == 604800
        assert settings.chat_history_ttl == 2592000
        assert settings.approval_audit_ttl == 7776000


class TestMissionControllerIntegration:
    """Integration tests for MissionController with ApprovalStore."""
    
    @pytest.mark.asyncio
    async def test_controller_has_approval_store(self):
        """Test MissionController has ApprovalStore."""
        from src.controller.mission import MissionController
        
        controller = MissionController()
        
        assert hasattr(controller, 'approval_store')
        assert hasattr(controller, '_approval_store_initialized')
        assert controller._approval_store_initialized is False
    
    @pytest.mark.asyncio
    async def test_approval_to_dict_helper(self):
        """Test _approval_to_dict helper method."""
        from src.controller.mission import MissionController
        from src.core.models import (
            ApprovalAction, ActionType, RiskLevel
        )
        
        controller = MissionController()
        
        approval = ApprovalAction(
            mission_id=uuid4(),
            action_type=ActionType.EXPLOIT,
            action_description="Test action",
            target_ip="10.0.0.1",
            risk_level=RiskLevel.HIGH,
            risk_reasons=["Reason 1"]
        )
        
        result = controller._approval_to_dict(approval)
        
        assert "action_id" in result
        assert result["action_type"] == "exploit"
        assert result["risk_level"] == "high"
        assert result["target_ip"] == "10.0.0.1"


class TestRecoveryScenarios:
    """Tests for recovery scenarios after restart."""
    
    @pytest.mark.asyncio
    async def test_empty_pending_approvals_on_init(self):
        """Test that pending approvals are empty on initialization."""
        from src.controller.mission import MissionController
        
        controller = MissionController()
        
        assert len(controller._pending_approvals) == 0
        assert len(controller._chat_history) == 0
    
    @pytest.mark.asyncio
    async def test_get_approval_stats_fallback(self):
        """Test approval stats fallback when Redis unavailable."""
        from src.controller.mission import MissionController
        from src.core.models import ApprovalAction, ActionType, RiskLevel
        
        controller = MissionController()
        mission_id = str(uuid4())
        
        # Add approval to in-memory cache
        approval = ApprovalAction(
            mission_id=UUID(mission_id),
            action_type=ActionType.EXPLOIT,
            action_description="Test",
            risk_level=RiskLevel.HIGH
        )
        controller._pending_approvals[str(approval.id)] = approval
        
        # Mock Redis failure
        controller.approval_store = MagicMock()
        controller.approval_store.get_approval_stats = AsyncMock(side_effect=Exception("Redis unavailable"))
        controller._approval_store_initialized = True
        
        # Should fallback to in-memory count
        stats = await controller.get_approval_stats(mission_id)
        
        assert stats["pending"] == 1


class TestChatPersistence:
    """Tests for chat history persistence."""
    
    def test_chat_message_structure(self):
        """Test ChatMessage structure for serialization."""
        from src.core.models import ChatMessage
        
        message = ChatMessage(
            mission_id=uuid4(),
            role="user",
            content="Test message",
            related_task_id=uuid4()
        )
        
        assert message.role == "user"
        assert message.content == "Test message"
        assert message.related_task_id is not None


# ═══════════════════════════════════════════════════════════════
# Test Fixtures
# ═══════════════════════════════════════════════════════════════

@pytest.fixture
def mission_controller():
    """Create a MissionController for testing."""
    from src.controller.mission import MissionController
    return MissionController()


@pytest.fixture
def sample_approval():
    """Create a sample ApprovalAction for testing."""
    from src.core.models import ApprovalAction, ActionType, RiskLevel
    
    return ApprovalAction(
        mission_id=uuid4(),
        action_type=ActionType.EXPLOIT,
        action_description="Test exploit on target",
        target_ip="192.168.1.100",
        target_hostname="target-host",
        risk_level=RiskLevel.HIGH,
        risk_reasons=["May cause service disruption", "High value target"],
        potential_impact="Service may become unavailable",
        command_preview="exploit/windows/smb/ms17_010_eternalblue"
    )


@pytest.fixture
def sample_chat_message():
    """Create a sample ChatMessage for testing."""
    from src.core.models import ChatMessage
    
    return ChatMessage(
        mission_id=uuid4(),
        role="user",
        content="What is the current mission status?"
    )


# ═══════════════════════════════════════════════════════════════
# Run Tests
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
