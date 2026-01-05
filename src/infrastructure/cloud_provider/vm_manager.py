"""
RAGLOX v3.0 - VM Manager
High-level VM lifecycle management for OneProvider.

Author: RAGLOX Team
Version: 3.0.0
"""

import asyncio
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field

from .oneprovider_client import OneProviderClient, VMState


logger = logging.getLogger("raglox.infrastructure.cloud_provider.vm_manager")


class VMStatus(str, Enum):
    """High-level VM status"""
    CREATING = "creating"
    READY = "ready"
    RUNNING = "running"
    STOPPED = "stopped"
    ERROR = "error"
    DESTROYING = "destroying"
    DESTROYED = "destroyed"


@dataclass
class VMConfiguration:
    """VM configuration specification"""
    hostname: str
    plan_id: str = "8GB-2CORE"  # Default: 8GB RAM, 2 Cores
    os_id: str = "ubuntu-22.04"  # Default: Ubuntu 22.04
    location_id: str = "us-east"  # Default location
    ssh_keys: List[str] = field(default_factory=list)
    password: Optional[str] = None
    ipv6: bool = False
    private_network: bool = False
    auto_backups: bool = False
    
    # Agent configuration
    install_agent: bool = True
    agent_user: str = "raglox"
    agent_port: int = 22
    
    # Resource limits
    max_bandwidth_gb: Optional[float] = None
    max_disk_gb: Optional[float] = None
    
    # Tags for organization
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class VMInstance:
    """VM instance details"""
    vm_id: str
    hostname: str
    status: VMStatus
    project_uuid: str
    
    # Configuration
    plan_id: str
    os_id: str
    location_id: str
    
    # Network
    ipv4: Optional[str] = None
    ipv6: Optional[str] = None
    private_ip: Optional[str] = None
    
    # Resources
    cpu_cores: int = 0
    memory_mb: int = 0
    disk_gb: int = 0
    
    # Bandwidth
    bandwidth_used_gb: float = 0.0
    bandwidth_limit_gb: Optional[float] = None
    
    # Status details
    is_installing: bool = False
    installation_progress: int = 0
    installation_message: str = ""
    
    # Timestamps
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    # Additional metadata
    tags: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "vm_id": self.vm_id,
            "hostname": self.hostname,
            "status": self.status,
            "project_uuid": self.project_uuid,
            "plan_id": self.plan_id,
            "os_id": self.os_id,
            "location_id": self.location_id,
            "ipv4": self.ipv4,
            "ipv6": self.ipv6,
            "private_ip": self.private_ip,
            "cpu_cores": self.cpu_cores,
            "memory_mb": self.memory_mb,
            "disk_gb": self.disk_gb,
            "bandwidth_used_gb": self.bandwidth_used_gb,
            "bandwidth_limit_gb": self.bandwidth_limit_gb,
            "is_installing": self.is_installing,
            "installation_progress": self.installation_progress,
            "installation_message": self.installation_message,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "tags": self.tags
        }


class VMManager:
    """
    VM Manager for OneProvider
    
    Provides high-level VM lifecycle management:
    - VM creation with configuration
    - VM destruction with cleanup
    - Status monitoring
    - Resource tracking
    - Agent installation
    """
    
    def __init__(
        self,
        client: OneProviderClient,
        default_project_uuid: str
    ):
        """
        Initialize VM Manager
        
        Args:
            client: OneProvider client
            default_project_uuid: Default project for VMs
        """
        self.client = client
        self.default_project_uuid = default_project_uuid
        self._vm_cache: Dict[str, VMInstance] = {}
        self._lock = asyncio.Lock()
    
    async def create_vm(
        self,
        config: VMConfiguration,
        project_uuid: Optional[str] = None,
        wait_for_ready: bool = True,
        ready_timeout: int = 600
    ) -> VMInstance:
        """
        Create a new VM
        
        Args:
            config: VM configuration
            project_uuid: Project UUID (uses default if not provided)
            wait_for_ready: Wait for VM to be ready
            ready_timeout: Maximum wait time for VM to be ready
        
        Returns:
            Created VM instance
        
        Raises:
            OneProviderError: If creation fails
        """
        project_uuid = project_uuid or self.default_project_uuid
        
        logger.info(f"Creating VM: {config.hostname}")
        
        # Create VM via API
        result = await self.client.create_vm(
            project_uuid=project_uuid,
            hostname=config.hostname,
            plan_id=config.plan_id,
            os_id=config.os_id,
            location_id=config.location_id,
            ssh_keys=config.ssh_keys,
            password=config.password,
            ipv6=config.ipv6,
            private_network=config.private_network,
            auto_backups=config.auto_backups
        )
        
        vm_id = result.get("vm_id")
        
        if not vm_id:
            raise ValueError("VM creation did not return VM ID")
        
        # Get initial VM info
        vm_info = await self.client.get_vm_info(vm_id)
        
        # Create VM instance
        vm = self._parse_vm_info(vm_info, config.tags)
        
        # Cache VM
        async with self._lock:
            self._vm_cache[vm_id] = vm
        
        logger.info(f"VM created: {vm_id} ({config.hostname})")
        
        # Wait for VM to be ready if requested
        if wait_for_ready:
            logger.info(f"Waiting for VM {vm_id} to be ready...")
            ready = await self.client.wait_for_vm_ready(
                vm_id,
                timeout=ready_timeout
            )
            
            if not ready:
                logger.error(f"VM {vm_id} not ready after {ready_timeout}s")
                vm.status = VMStatus.ERROR
            else:
                # Update VM info
                vm = await self.get_vm(vm_id, refresh=True)
                
                # Install agent if requested
                if config.install_agent:
                    await self._install_agent(vm, config)
        
        return vm
    
    async def destroy_vm(
        self,
        vm_id: str,
        confirm_close: bool = True
    ) -> bool:
        """
        Destroy a VM
        
        Args:
            vm_id: VM ID
            confirm_close: Confirm even with bandwidth overages
        
        Returns:
            True if destroyed successfully
        """
        logger.info(f"Destroying VM: {vm_id}")
        
        try:
            await self.client.destroy_vm(vm_id, confirm_close=confirm_close)
            
            # Remove from cache
            async with self._lock:
                if vm_id in self._vm_cache:
                    self._vm_cache[vm_id].status = VMStatus.DESTROYED
                    del self._vm_cache[vm_id]
            
            logger.info(f"VM destroyed: {vm_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to destroy VM {vm_id}: {str(e)}")
            return False
    
    async def get_vm(
        self,
        vm_id: str,
        refresh: bool = False
    ) -> Optional[VMInstance]:
        """
        Get VM details
        
        Args:
            vm_id: VM ID
            refresh: Force refresh from API
        
        Returns:
            VM instance or None if not found
        """
        # Check cache first
        if not refresh and vm_id in self._vm_cache:
            return self._vm_cache[vm_id]
        
        try:
            # Fetch from API
            vm_info = await self.client.get_vm_info(vm_id)
            vm = self._parse_vm_info(vm_info)
            
            # Update cache
            async with self._lock:
                self._vm_cache[vm_id] = vm
            
            return vm
            
        except Exception as e:
            logger.error(f"Failed to get VM {vm_id}: {str(e)}")
            return None
    
    async def list_vms(
        self,
        project_uuid: Optional[str] = None,
        refresh: bool = False
    ) -> List[VMInstance]:
        """
        List all VMs in project
        
        Args:
            project_uuid: Project UUID
            refresh: Force refresh from API
        
        Returns:
            List of VM instances
        """
        project_uuid = project_uuid or self.default_project_uuid
        
        try:
            vms_data = await self.client.list_vms(project_uuid)
            vms = []
            
            for vm_data in vms_data:
                vm = self._parse_vm_info(vm_data)
                vms.append(vm)
                
                # Update cache
                if refresh:
                    async with self._lock:
                        self._vm_cache[vm.vm_id] = vm
            
            return vms
            
        except Exception as e:
            logger.error(f"Failed to list VMs: {str(e)}")
            return []
    
    async def start_vm(self, vm_id: str) -> bool:
        """Start a stopped VM"""
        try:
            await self.client.start_vm(vm_id)
            
            # Update status
            if vm_id in self._vm_cache:
                self._vm_cache[vm_id].status = VMStatus.RUNNING
            
            return True
        except Exception as e:
            logger.error(f"Failed to start VM {vm_id}: {str(e)}")
            return False
    
    async def stop_vm(self, vm_id: str, force: bool = False) -> bool:
        """Stop a running VM"""
        try:
            await self.client.stop_vm(vm_id, force=force)
            
            # Update status
            if vm_id in self._vm_cache:
                self._vm_cache[vm_id].status = VMStatus.STOPPED
            
            return True
        except Exception as e:
            logger.error(f"Failed to stop VM {vm_id}: {str(e)}")
            return False
    
    async def reboot_vm(self, vm_id: str, force: bool = False) -> bool:
        """Reboot a VM"""
        try:
            await self.client.reboot_vm(vm_id, force=force)
            return True
        except Exception as e:
            logger.error(f"Failed to reboot VM {vm_id}: {str(e)}")
            return False
    
    def _parse_vm_info(
        self,
        vm_data: Dict[str, Any],
        tags: Optional[Dict[str, str]] = None
    ) -> VMInstance:
        """
        Parse VM data from API response
        
        Args:
            vm_data: VM data from API
            tags: Additional tags
        
        Returns:
            VMInstance
        """
        # Determine status
        state = vm_data.get("state", "").lower()
        is_installing = vm_data.get("is_installing", False)
        
        if is_installing:
            status = VMStatus.CREATING
        elif state == "running":
            status = VMStatus.READY if not is_installing else VMStatus.CREATING
        elif state == "stopped":
            status = VMStatus.STOPPED
        elif state in ["destroying", "destroyed"]:
            status = VMStatus.DESTROYED
        else:
            status = VMStatus.ERROR
        
        # Parse timestamps
        created_at = None
        if "created_at" in vm_data:
            try:
                created_at = datetime.fromisoformat(
                    vm_data["created_at"].replace("Z", "+00:00")
                )
            except Exception:
                pass
        
        # Parse bandwidth
        bandwidth_data = vm_data.get("bandwidth", {})
        bandwidth_used = bandwidth_data.get("total_used_gb", 0.0)
        bandwidth_limit = bandwidth_data.get("limit_gb")
        
        # Create instance
        return VMInstance(
            vm_id=vm_data.get("vm_id", ""),
            hostname=vm_data.get("hostname", ""),
            status=status,
            project_uuid=vm_data.get("project_uuid", ""),
            plan_id=vm_data.get("plan_id", ""),
            os_id=vm_data.get("os_id", ""),
            location_id=vm_data.get("location_id", ""),
            ipv4=vm_data.get("ipv4"),
            ipv6=vm_data.get("ipv6"),
            private_ip=vm_data.get("private_ip"),
            cpu_cores=vm_data.get("cpu_cores", 0),
            memory_mb=vm_data.get("memory_mb", 0),
            disk_gb=vm_data.get("disk_gb", 0),
            bandwidth_used_gb=bandwidth_used,
            bandwidth_limit_gb=bandwidth_limit,
            is_installing=is_installing,
            installation_progress=vm_data.get("progress", 0),
            installation_message=vm_data.get("message", ""),
            created_at=created_at,
            updated_at=datetime.utcnow(),
            tags=tags or {}
        )
    
    async def _install_agent(
        self,
        vm: VMInstance,
        config: VMConfiguration
    ):
        """
        Install RAGLOX agent on VM
        
        Args:
            vm: VM instance
            config: VM configuration
        """
        logger.info(f"Installing agent on VM {vm.vm_id}")
        
        # TODO: Implement agent installation
        # This will use SSH to:
        # 1. Create agent user
        # 2. Set up SSH keys
        # 3. Install dependencies
        # 4. Deploy agent binary
        # 5. Configure agent service
        
        logger.info(f"Agent installation completed for VM {vm.vm_id}")
