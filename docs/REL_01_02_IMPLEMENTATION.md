# REL-01 & REL-02 Implementation Documentation

## Overview

This document describes the implementation of two reliability features for RAGLOX v3.0:

- **REL-01: Redis High Availability** - Sentinel and Cluster support for Redis
- **REL-02: Approval State Persistence** - Persistent storage for HITL approval actions

---

## REL-01: Redis High Availability

### Purpose

Ensure Redis connections survive failures and support horizontal scaling through:
- Redis Sentinel for automatic failover
- Redis Cluster for data sharding
- Automatic reconnection with exponential backoff

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    RedisConnectionManager                    │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  Standalone  │  │   Sentinel   │  │   Cluster    │      │
│  │    Mode      │  │    Mode      │  │    Mode      │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│          │                 │                 │              │
│          └─────────────────┼─────────────────┘              │
│                            │                                │
│                   ┌────────▼────────┐                       │
│                   │  RedisHAClient  │                       │
│                   │  - Health Check │                       │
│                   │  - Auto Reconnect│                      │
│                   │  - Retry Logic  │                       │
│                   └─────────────────┘                       │
└─────────────────────────────────────────────────────────────┘
```

### Configuration

Add these environment variables to configure Redis HA:

```env
# Redis Mode: standalone (default), sentinel, cluster
REDIS_MODE=standalone

# For Sentinel Mode
REDIS_SENTINEL_HOSTS=sentinel1:26379,sentinel2:26379,sentinel3:26379
REDIS_SENTINEL_MASTER=mymaster

# For Cluster Mode
REDIS_CLUSTER_NODES=node1:6379,node2:6379,node3:6379

# Connection Settings
REDIS_HEALTH_CHECK_INTERVAL=30
REDIS_RECONNECT_MAX_ATTEMPTS=10
REDIS_SOCKET_TIMEOUT=5.0
```

### Usage

```python
from src.core.redis_ha import get_redis_manager, get_redis_client

# Get a Redis client with HA support
client = await get_redis_client()

# Use the client as normal
await client.set("key", "value")
value = await client.get("key")

# Check health status
manager = get_redis_manager()
health = await manager.health_check()
print(health)
# {
#     "ha_mode": "sentinel",
#     "ha_connected": true,
#     "health": {
#         "healthy": true,
#         "mode": "sentinel",
#         "master": "10.0.0.1:6379",
#         "slaves": 2,
#         "latency_ms": 0.45
#     }
# }
```

### Features

1. **Automatic Mode Detection**: Reads `REDIS_MODE` from settings
2. **Health Monitoring**: Background task checks connection health every 30 seconds
3. **Exponential Backoff**: Reconnects with increasing delays (0.5s → 30s max)
4. **Graceful Fallback**: Falls back to standalone mode if HA connection fails
5. **Connection Pooling**: Maintains efficient connection pool per mode

### Error Handling

```python
from redis.exceptions import ConnectionError, TimeoutError

try:
    await client.set("key", "value")
except ConnectionError:
    # Connection lost, client will auto-reconnect
    pass
except TimeoutError:
    # Operation timed out
    pass
```

---

## REL-02: Approval State Persistence

### Purpose

Ensure HITL (Human-in-the-Loop) state survives server restarts:
- Pending approval actions
- Chat history
- Approval audit logs

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    MissionController                         │
│                                                             │
│  ┌─────────────────┐    ┌─────────────────┐                 │
│  │ In-Memory Cache │ ←→ │  ApprovalStore  │                 │
│  │ (Fast Access)   │    │ (Redis Persist) │                 │
│  └─────────────────┘    └─────────────────┘                 │
│                                 │                           │
│                         ┌───────▼───────┐                   │
│                         │     Redis     │                   │
│                         │   - Approvals │                   │
│                         │   - Chat      │                   │
│                         │   - Audit     │                   │
│                         └───────────────┘                   │
└─────────────────────────────────────────────────────────────┘
```

### Redis Key Structure

```
# Approval Storage
approval:{action_id}                      # Hash: Approval details
mission:{mission_id}:approvals:pending    # Set: Pending approval IDs
mission:{mission_id}:approvals:completed  # List: Completed approval IDs

# Chat Storage
mission:{mission_id}:chat                 # Stream: Chat messages

# Audit Logs
approval:audit:{action_id}                # Stream: Audit entries per approval
mission:{mission_id}:audit                # Stream: Mission-wide audit log
```

### TTL Settings

| Data Type | Default TTL | Config Key |
|-----------|-------------|------------|
| Pending Approvals | 24 hours | `APPROVAL_TTL_PENDING` |
| Completed Approvals | 7 days | `APPROVAL_TTL_COMPLETED` |
| Chat History | 30 days | `CHAT_HISTORY_TTL` |
| Audit Logs | 90 days | `APPROVAL_AUDIT_TTL` |

### Configuration

```env
# Approval Persistence Settings
APPROVAL_TTL_PENDING=86400      # 24 hours
APPROVAL_TTL_COMPLETED=604800   # 7 days
CHAT_HISTORY_TTL=2592000        # 30 days
APPROVAL_AUDIT_TTL=7776000      # 90 days
```

### Usage

#### Request Approval (Persisted)
```python
from src.core.models import ApprovalAction, ActionType, RiskLevel

action = ApprovalAction(
    mission_id=mission_uuid,
    action_type=ActionType.EXPLOIT,
    action_description="Execute MS17-010 on 10.0.0.5",
    target_ip="10.0.0.5",
    risk_level=RiskLevel.HIGH,
    risk_reasons=["Exploit may cause service disruption"]
)

# Automatically persisted to Redis
action_id = await controller.request_approval(mission_id, action)
```

#### Approve/Reject with Audit
```python
# Approve with audit info
await controller.approve_action(
    mission_id=mission_id,
    action_id=action_id,
    user_comment="Approved for testing",
    audit_info={
        "user_id": "admin",
        "ip_address": "192.168.1.100",
        "user_agent": "RAGLOX Client/1.0"
    }
)
```

#### Get Pending Approvals (Survives Restart)
```python
# Returns approvals from both memory and Redis
pending = await controller.get_pending_approvals(mission_id)
```

#### Get Approval Statistics
```python
stats = await controller.get_approval_stats(mission_id)
# {
#     "pending": 2,
#     "completed": 15,
#     "approved": 12,
#     "rejected": 2,
#     "expired": 1
# }
```

#### Chat History (Persisted)
```python
# Send message - automatically persisted
message = await controller.send_chat_message(
    mission_id=mission_id,
    content="What is the status?"
)

# Get history - survives restart
history = await controller.get_chat_history(mission_id, limit=50)
```

### Audit Trail

Every approval decision is logged with:
- Action ID and Mission ID
- Action type and risk level
- Status change (PENDING → APPROVED/REJECTED/EXPIRED)
- Timestamp of request and response
- Who responded (user ID)
- IP address and user agent
- Rejection reason (if applicable)

### Recovery Flow

On server restart:
1. MissionController initializes with empty in-memory cache
2. When `get_pending_approvals()` is called:
   - Checks in-memory cache first
   - Queries Redis for any persisted approvals
   - Restores approvals to in-memory cache
3. When `approve_action()` is called:
   - Tries in-memory first
   - Falls back to Redis if not found
   - Updates both stores

---

## API Endpoints

### Health Check (REL-01)
```http
GET /api/v1/health/redis
```

Response:
```json
{
    "ha_mode": "sentinel",
    "ha_connected": true,
    "fallback_connected": true,
    "health": {
        "healthy": true,
        "mode": "sentinel",
        "master": "10.0.0.1:6379",
        "slaves": 2,
        "latency_ms": 0.45,
        "last_check": "2024-01-15T10:30:00Z"
    }
}
```

### Approval Statistics (REL-02)
```http
GET /api/v1/missions/{mission_id}/approvals/stats
```

Response:
```json
{
    "pending": 2,
    "completed": 15,
    "approved": 12,
    "rejected": 2,
    "expired": 1
}
```

---

## Testing

### REL-01 Tests
```bash
# Run Redis HA tests
pytest tests/test_rel_01_redis_ha.py -v
```

### REL-02 Tests
```bash
# Run Approval Persistence tests
pytest tests/test_rel_02_approval_persistence.py -v
```

---

## Files Changed/Created

### New Files
- `src/core/redis_ha.py` - Redis High Availability client
- `src/core/approval_store.py` - Approval state persistence
- `docs/REL_01_02_IMPLEMENTATION.md` - This documentation

### Modified Files
- `src/core/config.py` - Added HA and persistence settings
- `src/controller/mission.py` - Integrated ApprovalStore

---

## Production Recommendations

### Redis Sentinel Setup
```yaml
# docker-compose.yml
services:
  redis-master:
    image: redis:7
    command: redis-server --appendonly yes
    
  redis-slave-1:
    image: redis:7
    command: redis-server --slaveof redis-master 6379
    
  redis-slave-2:
    image: redis:7
    command: redis-server --slaveof redis-master 6379
    
  sentinel-1:
    image: redis:7
    command: redis-sentinel /etc/sentinel.conf
    volumes:
      - ./sentinel.conf:/etc/sentinel.conf
```

### Monitoring
- Monitor `redis_reconnect_count` metric
- Alert on `redis_error_count` increase
- Track `redis_latency_ms` for performance
- Watch `approval_pending_count` for stuck approvals

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2024-01-15 | Initial implementation of REL-01 and REL-02 |
