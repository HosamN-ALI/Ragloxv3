# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Redis High Availability (REL-01)
# Sentinel and Cluster support for Redis
# ═══════════════════════════════════════════════════════════════

"""
REL-01: Redis High Availability

This module provides high availability support for Redis:
- Redis Sentinel for automatic failover
- Redis Cluster for horizontal scaling
- Connection pooling with health checks
- Automatic reconnection with exponential backoff

Configuration:
- REDIS_MODE: standalone (default), sentinel, cluster
- REDIS_SENTINEL_HOSTS: comma-separated list of sentinel hosts
- REDIS_SENTINEL_MASTER: master name for sentinel
- REDIS_CLUSTER_NODES: comma-separated list of cluster nodes
"""

import asyncio
import logging
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import redis.asyncio as aioredis
from redis.asyncio.sentinel import Sentinel
from redis.asyncio.cluster import RedisCluster
from redis.exceptions import (
    ConnectionError as RedisConnectionError,
    TimeoutError as RedisTimeoutError,
    ClusterError,
    RedisError
)

from .config import Settings, get_settings

logger = logging.getLogger("raglox.redis_ha")


class RedisMode(str, Enum):
    """Redis deployment modes."""
    STANDALONE = "standalone"
    SENTINEL = "sentinel"
    CLUSTER = "cluster"


class RedisHealthStatus:
    """Health status for Redis connections."""
    def __init__(
        self,
        healthy: bool,
        mode: RedisMode,
        master: Optional[str] = None,
        slaves: int = 0,
        cluster_nodes: int = 0,
        latency_ms: float = 0.0,
        last_check: Optional[str] = None,
        error: Optional[str] = None
    ):
        self.healthy = healthy
        self.mode = mode
        self.master = master
        self.slaves = slaves
        self.cluster_nodes = cluster_nodes
        self.latency_ms = latency_ms
        self.last_check = last_check
        self.error = error
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "healthy": self.healthy,
            "mode": self.mode.value,
            "master": self.master,
            "slaves": self.slaves,
            "cluster_nodes": self.cluster_nodes,
            "latency_ms": round(self.latency_ms, 2),
            "last_check": self.last_check,
            "error": self.error
        }


class RedisHAClient:
    """
    High Availability Redis Client.
    
    REL-01: Redis High Availability
    
    Supports three deployment modes:
    1. Standalone: Single Redis instance
    2. Sentinel: Automatic failover with master/slave replication
    3. Cluster: Horizontal scaling with data sharding
    
    Features:
    - Automatic reconnection with exponential backoff
    - Connection pooling with health checks
    - Graceful degradation on failures
    - Metrics and monitoring
    """
    
    # Reconnection settings
    MAX_RECONNECT_ATTEMPTS = 10
    INITIAL_RECONNECT_DELAY = 0.5  # seconds
    MAX_RECONNECT_DELAY = 30.0  # seconds
    
    # Health check settings
    HEALTH_CHECK_INTERVAL = 30  # seconds
    HEALTH_CHECK_TIMEOUT = 5  # seconds
    
    def __init__(
        self,
        settings: Optional[Settings] = None,
        mode: Optional[RedisMode] = None
    ):
        """
        Initialize the HA Redis client.
        
        Args:
            settings: Application settings
            mode: Redis mode (overrides settings)
        """
        self.settings = settings or get_settings()
        self._mode = mode or self._detect_mode()
        
        # Clients
        self._client: Optional[aioredis.Redis] = None
        self._sentinel: Optional[Sentinel] = None
        self._cluster: Optional[RedisCluster] = None
        
        # State
        self._connected = False
        self._reconnect_task: Optional[asyncio.Task] = None
        self._health_check_task: Optional[asyncio.Task] = None
        self._last_health: Optional[RedisHealthStatus] = None
        
        # Metrics
        self._reconnect_count = 0
        self._error_count = 0
        
    def _detect_mode(self) -> RedisMode:
        """Detect Redis mode from settings."""
        mode_str = getattr(self.settings, 'redis_mode', 'standalone').lower()
        try:
            return RedisMode(mode_str)
        except ValueError:
            logger.warning(f"Invalid redis_mode: {mode_str}, defaulting to standalone")
            return RedisMode.STANDALONE
    
    @property
    def mode(self) -> RedisMode:
        """Get current Redis mode."""
        return self._mode
    
    @property
    def is_connected(self) -> bool:
        """Check if connected."""
        return self._connected
    
    async def connect(self) -> None:
        """
        Connect to Redis based on configured mode.
        
        Raises:
            RedisConnectionError: If connection fails after retries
        """
        if self._connected:
            return
            
        try:
            if self._mode == RedisMode.STANDALONE:
                await self._connect_standalone()
            elif self._mode == RedisMode.SENTINEL:
                await self._connect_sentinel()
            elif self._mode == RedisMode.CLUSTER:
                await self._connect_cluster()
            else:
                raise ValueError(f"Unknown Redis mode: {self._mode}")
                
            self._connected = True
            logger.info(f"Connected to Redis in {self._mode.value} mode")
            
            # Start health check
            self._start_health_check()
            
        except (RedisConnectionError, RedisTimeoutError, ClusterError) as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise
    
    async def _connect_standalone(self) -> None:
        """Connect to standalone Redis."""
        self._client = await aioredis.from_url(
            self.settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
            max_connections=self.settings.redis_max_connections,
            socket_timeout=5.0,
            socket_connect_timeout=5.0,
            retry_on_timeout=True
        )
        
        # Test connection
        await self._client.ping()
    
    async def _connect_sentinel(self) -> None:
        """Connect to Redis via Sentinel."""
        # Parse sentinel hosts
        sentinel_hosts = self._parse_sentinel_hosts()
        master_name = getattr(self.settings, 'redis_sentinel_master', 'mymaster')
        password = self.settings.redis_password
        
        if not sentinel_hosts:
            raise RedisConnectionError("No Sentinel hosts configured")
        
        # Create Sentinel connection
        self._sentinel = Sentinel(
            sentinel_hosts,
            socket_timeout=5.0,
            password=password
        )
        
        # Get master client
        self._client = self._sentinel.master_for(
            master_name,
            socket_timeout=5.0,
            encoding="utf-8",
            decode_responses=True
        )
        
        # Test connection
        await self._client.ping()
        logger.info(f"Connected to Sentinel master: {master_name}")
    
    async def _connect_cluster(self) -> None:
        """Connect to Redis Cluster."""
        # Parse cluster nodes
        cluster_nodes = self._parse_cluster_nodes()
        
        if not cluster_nodes:
            raise RedisConnectionError("No Cluster nodes configured")
        
        # First node for initial connection
        first_node = cluster_nodes[0]
        
        self._cluster = RedisCluster(
            host=first_node[0],
            port=first_node[1],
            password=self.settings.redis_password,
            decode_responses=True,
            skip_full_coverage_check=True
        )
        
        # Use cluster as client
        self._client = self._cluster
        
        # Test connection
        await self._client.ping()
        logger.info(f"Connected to Redis Cluster with {len(cluster_nodes)} initial nodes")
    
    def _parse_sentinel_hosts(self) -> List[Tuple[str, int]]:
        """Parse Sentinel hosts from settings."""
        hosts_str = getattr(self.settings, 'redis_sentinel_hosts', '')
        if not hosts_str:
            return []
        
        hosts = []
        for host_str in hosts_str.split(','):
            host_str = host_str.strip()
            if ':' in host_str:
                host, port = host_str.split(':')
                hosts.append((host, int(port)))
            else:
                hosts.append((host_str, 26379))  # Default Sentinel port
        
        return hosts
    
    def _parse_cluster_nodes(self) -> List[Tuple[str, int]]:
        """Parse Cluster nodes from settings."""
        nodes_str = getattr(self.settings, 'redis_cluster_nodes', '')
        if not nodes_str:
            # Fall back to redis_url
            parsed = urlparse(self.settings.redis_url)
            return [(parsed.hostname or 'localhost', parsed.port or 6379)]
        
        nodes = []
        for node_str in nodes_str.split(','):
            node_str = node_str.strip()
            if ':' in node_str:
                host, port = node_str.split(':')
                nodes.append((host, int(port)))
            else:
                nodes.append((node_str, 6379))
        
        return nodes
    
    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        self._connected = False
        
        # Stop health check
        if self._health_check_task:
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass
            self._health_check_task = None
        
        # Close connections
        if self._client:
            await self._client.close()
            self._client = None
        
        if self._cluster:
            await self._cluster.close()
            self._cluster = None
        
        self._sentinel = None
        
        logger.info("Disconnected from Redis")
    
    @property
    def client(self) -> aioredis.Redis:
        """
        Get the Redis client.
        
        Returns:
            Redis client
            
        Raises:
            RuntimeError: If not connected
        """
        if not self._client:
            raise RuntimeError("Redis HA client not connected. Call connect() first.")
        return self._client
    
    async def execute_with_retry(
        self,
        operation,
        *args,
        max_retries: int = 3,
        **kwargs
    ) -> Any:
        """
        Execute a Redis operation with automatic retry.
        
        Args:
            operation: Async callable to execute
            *args: Positional arguments
            max_retries: Maximum retry attempts
            **kwargs: Keyword arguments
            
        Returns:
            Operation result
        """
        last_error = None
        delay = self.INITIAL_RECONNECT_DELAY
        
        for attempt in range(max_retries):
            try:
                return await operation(*args, **kwargs)
            except (RedisConnectionError, RedisTimeoutError) as e:
                last_error = e
                self._error_count += 1
                
                if attempt < max_retries - 1:
                    logger.warning(
                        f"Redis operation failed (attempt {attempt + 1}/{max_retries}): {e}"
                    )
                    await asyncio.sleep(delay)
                    delay = min(delay * 2, self.MAX_RECONNECT_DELAY)
                    
                    # Try to reconnect
                    await self._reconnect()
        
        logger.error(f"Redis operation failed after {max_retries} attempts: {last_error}")
        raise last_error
    
    async def _reconnect(self) -> None:
        """Attempt to reconnect to Redis."""
        self._connected = False
        self._reconnect_count += 1
        
        try:
            await self.connect()
            logger.info(f"Reconnected to Redis (attempt {self._reconnect_count})")
        except (RedisConnectionError, RedisTimeoutError, ClusterError) as e:
            logger.error(f"Reconnection failed: {e}")
            raise
    
    def _start_health_check(self) -> None:
        """Start background health check task."""
        if self._health_check_task:
            return
        
        async def health_check_loop():
            while self._connected:
                try:
                    await self._perform_health_check()
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"Health check error: {e}")
                
                await asyncio.sleep(self.HEALTH_CHECK_INTERVAL)
        
        self._health_check_task = asyncio.create_task(health_check_loop())
    
    async def _perform_health_check(self) -> RedisHealthStatus:
        """Perform a health check on the Redis connection."""
        import time
        from datetime import datetime
        
        try:
            start = time.perf_counter()
            
            if self._mode == RedisMode.STANDALONE:
                await self._client.ping()
                info = await self._client.info()
                latency = (time.perf_counter() - start) * 1000
                
                self._last_health = RedisHealthStatus(
                    healthy=True,
                    mode=self._mode,
                    master=self.settings.redis_url,
                    slaves=int(info.get('connected_slaves', 0)),
                    latency_ms=latency,
                    last_check=datetime.utcnow().isoformat()
                )
                
            elif self._mode == RedisMode.SENTINEL:
                await self._client.ping()
                master_name = getattr(self.settings, 'redis_sentinel_master', 'mymaster')
                
                # Get master info from sentinel
                master_info = await self._sentinel.discover_master(master_name)
                slaves = await self._sentinel.discover_slaves(master_name)
                
                latency = (time.perf_counter() - start) * 1000
                
                self._last_health = RedisHealthStatus(
                    healthy=True,
                    mode=self._mode,
                    master=f"{master_info[0]}:{master_info[1]}" if master_info else None,
                    slaves=len(slaves) if slaves else 0,
                    latency_ms=latency,
                    last_check=datetime.utcnow().isoformat()
                )
                
            elif self._mode == RedisMode.CLUSTER:
                await self._cluster.ping()
                
                # Get cluster info
                cluster_info = await self._cluster.cluster_info()
                latency = (time.perf_counter() - start) * 1000
                
                self._last_health = RedisHealthStatus(
                    healthy=True,
                    mode=self._mode,
                    cluster_nodes=int(cluster_info.get('cluster_known_nodes', 0)),
                    latency_ms=latency,
                    last_check=datetime.utcnow().isoformat()
                )
            
            return self._last_health
            
        except (RedisConnectionError, RedisTimeoutError, ClusterError, RedisError) as e:
            self._last_health = RedisHealthStatus(
                healthy=False,
                mode=self._mode,
                error=str(e),
                last_check=datetime.utcnow().isoformat()
            )
            return self._last_health
    
    async def health_check(self) -> RedisHealthStatus:
        """
        Get the current health status.
        
        Returns:
            RedisHealthStatus object
        """
        if self._last_health:
            return self._last_health
        return await self._perform_health_check()
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get connection statistics.
        
        Returns:
            Statistics dictionary
        """
        return {
            "mode": self._mode.value,
            "connected": self._connected,
            "reconnect_count": self._reconnect_count,
            "error_count": self._error_count,
            "health": self._last_health.to_dict() if self._last_health else None
        }


# ═══════════════════════════════════════════════════════════════
# Connection Manager
# ═══════════════════════════════════════════════════════════════

class RedisConnectionManager:
    """
    Manager for Redis connections with automatic failover.
    
    Provides a unified interface for all Redis operations,
    handling connection management, failover, and recovery.
    """
    
    def __init__(self, settings: Optional[Settings] = None):
        """
        Initialize the connection manager.
        
        Args:
            settings: Application settings
        """
        self.settings = settings or get_settings()
        self._ha_client: Optional[RedisHAClient] = None
        self._fallback_client: Optional[aioredis.Redis] = None
    
    async def get_client(self) -> aioredis.Redis:
        """
        Get a Redis client with HA support.
        
        Returns:
            Redis client
        """
        if self._ha_client and self._ha_client.is_connected:
            return self._ha_client.client
        
        # Initialize HA client
        self._ha_client = RedisHAClient(self.settings)
        
        try:
            await self._ha_client.connect()
            return self._ha_client.client
        except (RedisConnectionError, RedisTimeoutError, ClusterError) as e:
            logger.error(f"HA connection failed, trying fallback: {e}")
            
            # Fallback to standalone connection
            return await self._get_fallback_client()
    
    async def _get_fallback_client(self) -> aioredis.Redis:
        """Get a fallback standalone Redis client."""
        if self._fallback_client:
            return self._fallback_client
        
        self._fallback_client = await aioredis.from_url(
            self.settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
            max_connections=self.settings.redis_max_connections
        )
        
        return self._fallback_client
    
    async def close(self) -> None:
        """Close all connections."""
        if self._ha_client:
            await self._ha_client.disconnect()
            self._ha_client = None
        
        if self._fallback_client:
            await self._fallback_client.close()
            self._fallback_client = None
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Get health status of Redis connections.
        
        Returns:
            Health status dictionary
        """
        result = {
            "ha_mode": None,
            "ha_connected": False,
            "fallback_connected": False,
            "health": None
        }
        
        if self._ha_client:
            result["ha_mode"] = self._ha_client.mode.value
            result["ha_connected"] = self._ha_client.is_connected
            health = await self._ha_client.health_check()
            result["health"] = health.to_dict()
        
        if self._fallback_client:
            try:
                await self._fallback_client.ping()
                result["fallback_connected"] = True
            except (RedisConnectionError, RedisTimeoutError):
                result["fallback_connected"] = False
        
        return result


# ═══════════════════════════════════════════════════════════════
# Singleton Instance
# ═══════════════════════════════════════════════════════════════

_redis_manager: Optional[RedisConnectionManager] = None


def get_redis_manager() -> RedisConnectionManager:
    """Get the global Redis connection manager."""
    global _redis_manager
    if _redis_manager is None:
        _redis_manager = RedisConnectionManager()
    return _redis_manager


async def get_redis_client() -> aioredis.Redis:
    """
    Get a Redis client from the connection manager.
    
    Returns:
        Redis client with HA support
    """
    manager = get_redis_manager()
    return await manager.get_client()


async def close_redis() -> None:
    """Close Redis connections."""
    global _redis_manager
    if _redis_manager:
        await _redis_manager.close()
        _redis_manager = None
