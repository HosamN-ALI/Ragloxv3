"""
RAGLOX v3.0 - Environment Manager
Manages agent execution environments (Remote SSH or Sandbox).

Author: RAGLOX Team
Version: 3.0.0
"""

import asyncio
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field
import uuid

from ..ssh.connection_manager import SSHConnectionManager, SSHConnectionConfig
from ..cloud_provider.vm_manager import VMManager, VMConfiguration, VMInstance, VMStatus


logger = logging.getLogger("raglox.infrastructure.orchestrator.environment_manager")


class EnvironmentType(str, Enum):
    """Environment type"""
    REMOTE_SSH = "remote_ssh"      # User-provided remote server
    SANDBOX = "sandbox"             # OneProvider VM sandbox


class EnvironmentStatus(str, Enum):
    """Environment status"""
    CREATING = "creating"
    READY = "ready"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"
    DESTROYING = "destroying"
    DESTROYED = "destroyed"


@dataclass
class EnvironmentConfig:
    """Environment configuration"""
    environment_type: EnvironmentType
    name: str
    
    # For Remote SSH
    ssh_config: Optional[SSHConnectionConfig] = None
    
    # For Sandbox
    vm_config: Optional[VMConfiguration] = None
    
    # User/tenant info
    user_id: str = ""
    tenant_id: str = ""
    
    # Tags
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class AgentEnvironment:
    """Agent environment instance"""
    environment_id: str
    environment_type: EnvironmentType
    status: EnvironmentStatus
    name: str
    
    # User/tenant
    user_id: str
    tenant_id: str
    
    # SSH connection (for both types)
    ssh_manager: Optional[SSHConnectionManager] = None
    connection_id: Optional[str] = None
    
    # VM instance (for sandbox only)
    vm_instance: Optional[VMInstance] = None
    
    # Timestamps
    created_at: datetime = field(default_factory=datetime.utcnow)
    connected_at: Optional[datetime] = None
    last_activity: Optional[datetime] = None
    
    # Tags
    tags: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "environment_id": self.environment_id,
            "environment_type": self.environment_type,
            "status": self.status,
            "name": self.name,
            "user_id": self.user_id,
            "tenant_id": self.tenant_id,
            "connection_id": self.connection_id,
            "vm_instance": self.vm_instance.to_dict() if self.vm_instance else None,
            "created_at": self.created_at.isoformat(),
            "connected_at": self.connected_at.isoformat() if self.connected_at else None,
            "last_activity": self.last_activity.isoformat() if self.last_activity else None,
            "tags": self.tags
        }


class EnvironmentManager:
    """
    Environment Manager
    
    Orchestrates agent execution environments:
    - Creates and manages Remote SSH connections
    - Provisions and manages Sandbox VMs
    - Handles environment lifecycle
    - Multi-tenant isolation
    """
    
    def __init__(
        self,
        vm_manager: Optional[VMManager] = None,
        max_environments_per_user: int = 10
    ):
        """
        Initialize Environment Manager
        
        Args:
            vm_manager: VM manager for sandbox provisioning
            max_environments_per_user: Maximum environments per user
        """
        self.vm_manager = vm_manager
        self.max_environments_per_user = max_environments_per_user
        
        # Environment registry
        self._environments: Dict[str, AgentEnvironment] = {}
        self._user_environments: Dict[str, List[str]] = {}  # user_id -> [env_ids]
        
        # Lock for thread safety
        self._lock = asyncio.Lock()
    
    async def create_environment(
        self,
        config: EnvironmentConfig
    ) -> AgentEnvironment:
        """
        Create a new agent environment
        
        Args:
            config: Environment configuration
        
        Returns:
            Created environment
        
        Raises:
            ValueError: If configuration invalid or user limit reached
        """
        async with self._lock:
            # Check user limit
            user_envs = self._user_environments.get(config.user_id, [])
            if len(user_envs) >= self.max_environments_per_user:
                raise ValueError(
                    f"User {config.user_id} has reached maximum "
                    f"environments ({self.max_environments_per_user})"
                )
            
            # Generate environment ID
            env_id = str(uuid.uuid4())
            
            # Create environment based on type
            if config.environment_type == EnvironmentType.REMOTE_SSH:
                env = await self._create_remote_ssh_environment(
                    env_id,
                    config
                )
            else:  # SANDBOX
                env = await self._create_sandbox_environment(
                    env_id,
                    config
                )
            
            # Register environment
            self._environments[env_id] = env
            
            if config.user_id not in self._user_environments:
                self._user_environments[config.user_id] = []
            self._user_environments[config.user_id].append(env_id)
            
            logger.info(
                f"Created {config.environment_type} environment {env_id} "
                f"for user {config.user_id}"
            )
            
            return env
    
    async def _create_remote_ssh_environment(
        self,
        env_id: str,
        config: EnvironmentConfig
    ) -> AgentEnvironment:
        """Create remote SSH environment"""
        if not config.ssh_config:
            raise ValueError("SSH configuration required for remote environment")
        
        # Create SSH manager
        ssh_manager = SSHConnectionManager()
        
        # Create environment
        env = AgentEnvironment(
            environment_id=env_id,
            environment_type=EnvironmentType.REMOTE_SSH,
            status=EnvironmentStatus.READY,
            name=config.name,
            user_id=config.user_id,
            tenant_id=config.tenant_id,
            ssh_manager=ssh_manager,
            tags=config.tags
        )
        
        # Attempt initial connection
        try:
            env.status = EnvironmentStatus.CONNECTING
            connection_id = await ssh_manager.connect(config.ssh_config)
            
            env.connection_id = connection_id
            env.status = EnvironmentStatus.CONNECTED
            env.connected_at = datetime.utcnow()
            
            logger.info(f"Remote SSH environment {env_id} connected")
            
        except Exception as e:
            logger.error(f"Failed to connect SSH environment {env_id}: {str(e)}")
            env.status = EnvironmentStatus.ERROR
        
        return env
    
    async def _create_sandbox_environment(
        self,
        env_id: str,
        config: EnvironmentConfig
    ) -> AgentEnvironment:
        """Create sandbox environment with VM provisioning"""
        if not self.vm_manager:
            raise ValueError("VM manager required for sandbox environment")
        
        if not config.vm_config:
            # Use default VM config
            config.vm_config = VMConfiguration(
                hostname=f"raglox-sandbox-{env_id[:8]}",
                plan_id="8GB-2CORE",
                os_id="ubuntu-22.04",
                tags={
                    "environment_id": env_id,
                    "user_id": config.user_id,
                    "tenant_id": config.tenant_id
                }
            )
        
        # Create environment
        env = AgentEnvironment(
            environment_id=env_id,
            environment_type=EnvironmentType.SANDBOX,
            status=EnvironmentStatus.CREATING,
            name=config.name,
            user_id=config.user_id,
            tenant_id=config.tenant_id,
            tags=config.tags
        )
        
        try:
            # Create VM
            logger.info(f"Provisioning VM for sandbox {env_id}")
            vm_instance = await self.vm_manager.create_vm(
                config.vm_config,
                wait_for_ready=True
            )
            
            env.vm_instance = vm_instance
            env.status = EnvironmentStatus.READY
            
            logger.info(
                f"Sandbox {env_id} provisioned with VM {vm_instance.vm_id}"
            )
            
            # Create SSH connection to VM
            if vm_instance.ipv4:
                ssh_config = SSHConnectionConfig(
                    host=vm_instance.ipv4,
                    port=22,
                    username=config.vm_config.agent_user or "root",
                    key_filename=None,  # Use keys from VM config
                    password=config.vm_config.password
                )
                
                ssh_manager = SSHConnectionManager()
                
                try:
                    env.status = EnvironmentStatus.CONNECTING
                    connection_id = await ssh_manager.connect(ssh_config)
                    
                    env.ssh_manager = ssh_manager
                    env.connection_id = connection_id
                    env.status = EnvironmentStatus.CONNECTED
                    env.connected_at = datetime.utcnow()
                    
                    logger.info(f"Sandbox {env_id} SSH connection established")
                    
                except Exception as e:
                    logger.error(f"Failed to connect to sandbox VM: {str(e)}")
                    env.status = EnvironmentStatus.READY  # VM ready but not connected
            
        except Exception as e:
            logger.error(f"Failed to provision sandbox {env_id}: {str(e)}")
            env.status = EnvironmentStatus.ERROR
        
        return env
    
    async def destroy_environment(
        self,
        environment_id: str
    ) -> bool:
        """
        Destroy an environment
        
        Args:
            environment_id: Environment ID
        
        Returns:
            True if destroyed successfully
        """
        async with self._lock:
            env = self._environments.get(environment_id)
            
            if not env:
                logger.warning(f"Environment {environment_id} not found")
                return False
            
            try:
                env.status = EnvironmentStatus.DESTROYING
                
                # Disconnect SSH
                if env.ssh_manager and env.connection_id:
                    try:
                        await env.ssh_manager.disconnect(env.connection_id)
                    except Exception as e:
                        logger.error(f"Error disconnecting SSH: {str(e)}")
                
                # Destroy VM if sandbox
                if env.environment_type == EnvironmentType.SANDBOX:
                    if env.vm_instance and self.vm_manager:
                        try:
                            await self.vm_manager.destroy_vm(
                                env.vm_instance.vm_id
                            )
                        except Exception as e:
                            logger.error(f"Error destroying VM: {str(e)}")
                
                # Update status
                env.status = EnvironmentStatus.DESTROYED
                
                # Remove from registry
                del self._environments[environment_id]
                
                # Remove from user environments
                if env.user_id in self._user_environments:
                    self._user_environments[env.user_id].remove(environment_id)
                
                logger.info(f"Environment {environment_id} destroyed")
                return True
                
            except Exception as e:
                logger.error(f"Failed to destroy environment {environment_id}: {str(e)}")
                env.status = EnvironmentStatus.ERROR
                return False
    
    async def get_environment(
        self,
        environment_id: str
    ) -> Optional[AgentEnvironment]:
        """Get environment by ID"""
        return self._environments.get(environment_id)
    
    async def list_user_environments(
        self,
        user_id: str
    ) -> List[AgentEnvironment]:
        """List all environments for a user"""
        env_ids = self._user_environments.get(user_id, [])
        return [
            self._environments[env_id]
            for env_id in env_ids
            if env_id in self._environments
        ]
    
    async def reconnect_environment(
        self,
        environment_id: str
    ) -> bool:
        """
        Reconnect a disconnected environment
        
        Args:
            environment_id: Environment ID
        
        Returns:
            True if reconnected successfully
        """
        env = self._environments.get(environment_id)
        
        if not env:
            logger.error(f"Environment {environment_id} not found")
            return False
        
        if env.status == EnvironmentStatus.CONNECTED:
            logger.info(f"Environment {environment_id} already connected")
            return True
        
        if not env.ssh_manager or not env.connection_id:
            logger.error(f"Environment {environment_id} has no SSH manager")
            return False
        
        try:
            env.status = EnvironmentStatus.CONNECTING
            
            # Get original connection config
            # (In production, store this in environment)
            # For now, attempt to reconnect existing connection
            connection = await env.ssh_manager.get_connection(env.connection_id)
            
            if connection:
                env.status = EnvironmentStatus.CONNECTED
                env.connected_at = datetime.utcnow()
                logger.info(f"Environment {environment_id} reconnected")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to reconnect environment {environment_id}: {str(e)}")
            env.status = EnvironmentStatus.ERROR
            return False
    
    async def health_check(
        self,
        environment_id: str
    ) -> Dict[str, Any]:
        """
        Perform health check on environment
        
        Args:
            environment_id: Environment ID
        
        Returns:
            Health check results
        """
        env = self._environments.get(environment_id)
        
        if not env:
            return {
                "environment_id": environment_id,
                "healthy": False,
                "error": "Environment not found"
            }
        
        health = {
            "environment_id": environment_id,
            "status": env.status,
            "healthy": False,
            "checks": {}
        }
        
        # Check SSH connection
        if env.ssh_manager and env.connection_id:
            try:
                connection = await env.ssh_manager.get_connection(env.connection_id)
                health["checks"]["ssh"] = connection is not None
            except Exception:
                health["checks"]["ssh"] = False
        
        # Check VM status (for sandbox)
        if env.vm_instance and self.vm_manager:
            try:
                vm = await self.vm_manager.get_vm(env.vm_instance.vm_id)
                health["checks"]["vm"] = (
                    vm is not None and
                    vm.status in [VMStatus.READY, VMStatus.RUNNING]
                )
            except Exception:
                health["checks"]["vm"] = False
        
        # Overall health
        health["healthy"] = all(health["checks"].values())
        
        return health
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get environment statistics"""
        stats = {
            "total_environments": len(self._environments),
            "by_type": {
                "remote_ssh": 0,
                "sandbox": 0
            },
            "by_status": {},
            "total_users": len(self._user_environments)
        }
        
        for env in self._environments.values():
            # Count by type
            if env.environment_type == EnvironmentType.REMOTE_SSH:
                stats["by_type"]["remote_ssh"] += 1
            else:
                stats["by_type"]["sandbox"] += 1
            
            # Count by status
            status = env.status
            if status not in stats["by_status"]:
                stats["by_status"][status] = 0
            stats["by_status"][status] += 1
        
        return stats
