# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Executor Factory
# Factory pattern for creating appropriate executors
# ═══════════════════════════════════════════════════════════════

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Type, TypeVar
from uuid import UUID, uuid4
from weakref import WeakValueDictionary

from .base import BaseExecutor
from .local import LocalExecutor
from .ssh import SSHExecutor
from .winrm import WinRMExecutor
from .models import (
    ExecutorType,
    ExecutionRequest,
    ExecutionResult,
    ExecutionStatus,
    ConnectionConfig,
    SSHConfig,
    WinRMConfig,
    LocalConfig,
    Platform,
    ConnectionInfo,
)

logger = logging.getLogger("raglox.executors.factory")

# Type variable for executors
ExecutorT = TypeVar('ExecutorT', bound=BaseExecutor)


class ExecutorFactory:
    """
    Factory for creating and managing executors.
    
    This factory provides:
    - Automatic executor selection based on target platform
    - Connection pooling and reuse
    - Centralized executor management
    - Health checking and reconnection
    
    Usage:
        factory = ExecutorFactory()
        
        # Get executor for a target
        executor = await factory.get_executor(
            target_host="192.168.1.100",
            target_platform=Platform.LINUX,
            connection_config=ssh_config,
        )
        
        # Execute a command
        result = await executor.execute(request)
        
        # Release when done
        await factory.release_executor(executor)
    """
    
    # Executor class registry
    _executor_classes: Dict[ExecutorType, Type[BaseExecutor]] = {
        ExecutorType.LOCAL: LocalExecutor,
        ExecutorType.SSH: SSHExecutor,
        ExecutorType.WINRM: WinRMExecutor,
    }
    
    # Platform to executor type mapping
    _platform_mapping: Dict[Platform, List[ExecutorType]] = {
        Platform.LINUX: [ExecutorType.SSH, ExecutorType.LOCAL],
        Platform.MACOS: [ExecutorType.SSH, ExecutorType.LOCAL],
        Platform.WINDOWS: [ExecutorType.WINRM, ExecutorType.SSH, ExecutorType.LOCAL],
        Platform.UNKNOWN: [ExecutorType.LOCAL],
    }
    
    def __init__(
        self,
        max_connections_per_host: int = 5,
        connection_timeout: int = 30,
        enable_pooling: bool = True,
    ):
        """
        Initialize executor factory.
        
        Args:
            max_connections_per_host: Maximum concurrent connections per host
            connection_timeout: Default connection timeout
            enable_pooling: Enable connection pooling
        """
        self.max_connections_per_host = max_connections_per_host
        self.connection_timeout = connection_timeout
        self.enable_pooling = enable_pooling
        
        # Connection pools: {host: [executor, ...]}
        self._pools: Dict[str, List[BaseExecutor]] = {}
        
        # Active executors for tracking
        self._active_executors: WeakValueDictionary = WeakValueDictionary()
        
        # Connection info tracking
        self._connections: Dict[UUID, ConnectionInfo] = {}
        
        # Lock for thread-safe pool access
        self._lock = asyncio.Lock()
        
        self.logger = logging.getLogger("raglox.executors.factory")
    
    # ═══════════════════════════════════════════════════════════
    # Executor Creation and Management
    # ═══════════════════════════════════════════════════════════
    
    async def get_executor(
        self,
        target_host: str,
        target_platform: Platform,
        connection_config: Optional[ConnectionConfig] = None,
        executor_type: Optional[ExecutorType] = None,
        force_new: bool = False,
    ) -> BaseExecutor:
        """
        Get an executor for the target.
        
        If pooling is enabled and an executor exists in the pool,
        it will be reused. Otherwise, a new executor is created.
        
        Args:
            target_host: Target hostname or IP
            target_platform: Target platform (Linux, Windows, etc.)
            connection_config: Connection configuration
            executor_type: Specific executor type (auto-select if None)
            force_new: Force creation of new executor
            
        Returns:
            Executor instance
            
        Raises:
            ValueError: If no suitable executor can be created
        """
        # Determine executor type if not specified
        if executor_type is None:
            executor_type = self._select_executor_type(
                target_platform,
                connection_config,
            )
        
        # Try to get from pool
        if self.enable_pooling and not force_new:
            executor = await self._get_from_pool(target_host, executor_type)
            if executor is not None:
                self.logger.debug(f"Reusing pooled executor for {target_host}")
                return executor
        
        # Create new executor
        executor = await self._create_executor(
            target_host=target_host,
            target_platform=target_platform,
            executor_type=executor_type,
            connection_config=connection_config,
        )
        
        return executor
    
    async def release_executor(
        self,
        executor: BaseExecutor,
        force_close: bool = False,
    ) -> None:
        """
        Release an executor back to the pool.
        
        If pooling is enabled and the executor is healthy,
        it will be returned to the pool for reuse.
        
        Args:
            executor: Executor to release
            force_close: Force close instead of pooling
        """
        if force_close or not self.enable_pooling:
            await self._close_executor(executor)
            return
        
        # Check if executor is still healthy
        if executor.is_connected:
            await self._return_to_pool(executor)
        else:
            await self._close_executor(executor)
    
    async def close_all(self) -> None:
        """Close all executors and clear pools."""
        async with self._lock:
            # Close all pooled executors
            for host, executors in self._pools.items():
                for executor in executors:
                    try:
                        await executor.disconnect()
                    except Exception as e:
                        self.logger.warning(f"Error closing executor: {e}")
            
            self._pools.clear()
            self._connections.clear()
            self.logger.info("All executors closed")
    
    # ═══════════════════════════════════════════════════════════
    # Executor Creation
    # ═══════════════════════════════════════════════════════════
    
    async def _create_executor(
        self,
        target_host: str,
        target_platform: Platform,
        executor_type: ExecutorType,
        connection_config: Optional[ConnectionConfig] = None,
    ) -> BaseExecutor:
        """
        Create a new executor instance.
        
        Args:
            target_host: Target host
            target_platform: Target platform
            executor_type: Type of executor to create
            connection_config: Connection configuration
            
        Returns:
            New executor instance
        """
        # Get executor class
        executor_class = self._executor_classes.get(executor_type)
        if executor_class is None:
            raise ValueError(f"Unknown executor type: {executor_type}")
        
        # Create or validate config
        config = self._prepare_config(
            target_host=target_host,
            target_platform=target_platform,
            executor_type=executor_type,
            connection_config=connection_config,
        )
        
        # Create executor
        executor = executor_class(config)
        
        # Connect
        try:
            await executor.connect()
        except Exception as e:
            self.logger.error(f"Failed to connect to {target_host}: {e}")
            raise
        
        # Track connection
        conn_id = uuid4()
        self._connections[conn_id] = ConnectionInfo(
            id=conn_id,
            executor_type=executor_type,
            host=target_host,
            port=getattr(config, 'port', 0),
            username=getattr(config, 'username', None),
        )
        
        self._active_executors[conn_id] = executor
        
        self.logger.info(f"Created {executor_type.value} executor for {target_host}")
        return executor
    
    def _prepare_config(
        self,
        target_host: str,
        target_platform: Platform,
        executor_type: ExecutorType,
        connection_config: Optional[ConnectionConfig] = None,
    ) -> ConnectionConfig:
        """
        Prepare connection configuration.
        
        Args:
            target_host: Target host
            target_platform: Target platform
            executor_type: Executor type
            connection_config: Existing config or None
            
        Returns:
            Valid connection configuration
        """
        if connection_config is not None:
            # Update host if different
            if hasattr(connection_config, 'host'):
                connection_config.host = target_host
            return connection_config
        
        # Create default config based on executor type
        if executor_type == ExecutorType.LOCAL:
            return LocalConfig()
        
        elif executor_type == ExecutorType.SSH:
            return SSHConfig(
                host=target_host,
                username="root",  # Default, should be overridden
                timeout=self.connection_timeout,
            )
        
        elif executor_type == ExecutorType.WINRM:
            return WinRMConfig(
                host=target_host,
                username="Administrator",  # Default, should be overridden
                timeout=self.connection_timeout,
            )
        
        raise ValueError(f"Cannot create default config for {executor_type}")
    
    def _select_executor_type(
        self,
        target_platform: Platform,
        connection_config: Optional[ConnectionConfig] = None,
    ) -> ExecutorType:
        """
        Select appropriate executor type for platform.
        
        Args:
            target_platform: Target platform
            connection_config: Connection config (may indicate preferred type)
            
        Returns:
            Selected executor type
        """
        # If config provided, infer type from it
        if connection_config is not None:
            if isinstance(connection_config, SSHConfig):
                return ExecutorType.SSH
            elif isinstance(connection_config, WinRMConfig):
                return ExecutorType.WINRM
            elif isinstance(connection_config, LocalConfig):
                return ExecutorType.LOCAL
        
        # Select based on platform
        preferred_types = self._platform_mapping.get(
            target_platform,
            [ExecutorType.LOCAL]
        )
        
        # Return first available type
        for exec_type in preferred_types:
            if exec_type in self._executor_classes:
                return exec_type
        
        return ExecutorType.LOCAL
    
    # ═══════════════════════════════════════════════════════════
    # Connection Pooling
    # ═══════════════════════════════════════════════════════════
    
    async def _get_from_pool(
        self,
        host: str,
        executor_type: ExecutorType,
    ) -> Optional[BaseExecutor]:
        """
        Get an executor from the pool.
        
        Args:
            host: Target host
            executor_type: Required executor type
            
        Returns:
            Pooled executor or None
        """
        async with self._lock:
            pool_key = f"{host}:{executor_type.value}"
            
            if pool_key not in self._pools:
                return None
            
            pool = self._pools[pool_key]
            
            # Find a healthy executor
            for executor in pool[:]:
                if executor.is_connected and executor.executor_type == executor_type:
                    pool.remove(executor)
                    return executor
                else:
                    # Remove dead executor
                    pool.remove(executor)
            
            return None
    
    async def _return_to_pool(self, executor: BaseExecutor) -> None:
        """
        Return an executor to the pool.
        
        Args:
            executor: Executor to return
        """
        async with self._lock:
            pool_key = f"{executor.config.host}:{executor.executor_type.value}"
            
            if pool_key not in self._pools:
                self._pools[pool_key] = []
            
            pool = self._pools[pool_key]
            
            # Check if pool is full
            if len(pool) >= self.max_connections_per_host:
                # Close the oldest connection
                if pool:
                    old_executor = pool.pop(0)
                    await self._close_executor(old_executor)
            
            pool.append(executor)
            self.logger.debug(f"Returned executor to pool: {pool_key}")
    
    async def _close_executor(self, executor: BaseExecutor) -> None:
        """
        Close and cleanup an executor.
        
        Args:
            executor: Executor to close
        """
        try:
            await executor.disconnect()
        except Exception as e:
            self.logger.warning(f"Error closing executor: {e}")
        
        # Remove from tracking
        for conn_id, conn_info in list(self._connections.items()):
            if conn_info.host == executor.config.host:
                del self._connections[conn_id]
                break
    
    # ═══════════════════════════════════════════════════════════
    # Health Checking
    # ═══════════════════════════════════════════════════════════
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Check health of all connections.
        
        Returns:
            Health status dictionary
        """
        status = {
            "total_connections": len(self._connections),
            "pooled_connections": sum(len(p) for p in self._pools.values()),
            "pools": {},
            "connections": [],
        }
        
        # Check each pool
        for pool_key, pool in self._pools.items():
            healthy = sum(1 for e in pool if e.is_connected)
            status["pools"][pool_key] = {
                "total": len(pool),
                "healthy": healthy,
            }
        
        # List active connections
        for conn_id, conn_info in self._connections.items():
            status["connections"].append({
                "id": str(conn_id),
                "host": conn_info.host,
                "type": conn_info.executor_type.value,
                "active": conn_info.is_active,
            })
        
        return status
    
    async def cleanup_dead_connections(self) -> int:
        """
        Remove dead connections from pools.
        
        Returns:
            Number of connections removed
        """
        removed = 0
        
        async with self._lock:
            for pool_key, pool in list(self._pools.items()):
                for executor in pool[:]:
                    if not executor.is_connected:
                        pool.remove(executor)
                        removed += 1
                
                # Remove empty pools
                if not pool:
                    del self._pools[pool_key]
        
        if removed:
            self.logger.info(f"Removed {removed} dead connections")
        
        return removed
    
    # ═══════════════════════════════════════════════════════════
    # Convenience Methods
    # ═══════════════════════════════════════════════════════════
    
    async def execute_on_target(
        self,
        target_host: str,
        target_platform: Platform,
        command: str,
        connection_config: Optional[ConnectionConfig] = None,
        timeout: int = 300,
    ) -> ExecutionResult:
        """
        Execute a command on a target (convenience method).
        
        This method handles executor creation, execution, and release.
        
        Args:
            target_host: Target host
            target_platform: Target platform
            command: Command to execute
            connection_config: Connection configuration
            timeout: Execution timeout
            
        Returns:
            Execution result
        """
        executor = await self.get_executor(
            target_host=target_host,
            target_platform=target_platform,
            connection_config=connection_config,
        )
        
        try:
            result = await executor.execute(
                ExecutionRequest(command=command, timeout=timeout)
            )
            return result
            
        finally:
            await self.release_executor(executor)
    
    def get_supported_platforms(self) -> List[Platform]:
        """Get list of supported platforms."""
        return list(self._platform_mapping.keys())
    
    def get_available_executors(self) -> List[ExecutorType]:
        """Get list of available executor types."""
        return list(self._executor_classes.keys())
    
    # ═══════════════════════════════════════════════════════════
    # Context Manager Support
    # ═══════════════════════════════════════════════════════════
    
    async def __aenter__(self) -> 'ExecutorFactory':
        """Async context manager entry."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.close_all()


# ═══════════════════════════════════════════════════════════════
# Global Factory Instance (Singleton Pattern)
# ═══════════════════════════════════════════════════════════════

_global_factory: Optional[ExecutorFactory] = None


def get_executor_factory() -> ExecutorFactory:
    """
    Get the global executor factory instance.
    
    Returns:
        Global ExecutorFactory instance
    """
    global _global_factory
    
    if _global_factory is None:
        _global_factory = ExecutorFactory()
    
    return _global_factory


async def execute_command(
    target_host: str,
    target_platform: Platform,
    command: str,
    connection_config: Optional[ConnectionConfig] = None,
    timeout: int = 300,
) -> ExecutionResult:
    """
    Convenience function to execute a command.
    
    Uses the global factory instance.
    
    Args:
        target_host: Target host
        target_platform: Target platform
        command: Command to execute
        connection_config: Connection configuration
        timeout: Execution timeout
        
    Returns:
        Execution result
    """
    factory = get_executor_factory()
    return await factory.execute_on_target(
        target_host=target_host,
        target_platform=target_platform,
        command=command,
        connection_config=connection_config,
        timeout=timeout,
    )
