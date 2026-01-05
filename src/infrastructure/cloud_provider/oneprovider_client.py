"""
RAGLOX v3.0 - OneProvider API Client
Client for OneProvider cloud infrastructure API.

Author: RAGLOX Team
Version: 3.0.0
"""

import asyncio
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime
from enum import Enum

import aiohttp


logger = logging.getLogger("raglox.infrastructure.cloud_provider.oneprovider")


class OneProviderError(Exception):
    """OneProvider API error"""
    pass


class VMState(str, Enum):
    """VM states from OneProvider"""
    CREATING = "creating"
    RUNNING = "running"
    STOPPED = "stopped"
    SUSPENDED = "suspended"
    INSTALLING = "installing"
    REINSTALLING = "reinstalling"
    RESIZING = "resizing"
    DESTROYING = "destroying"
    DESTROYED = "destroyed"
    ERROR = "error"


class OneProviderClient:
    """
    OneProvider API Client
    
    Handles all communication with OneProvider API for VM management.
    Supports:
    - Project management
    - VM creation/deletion
    - VM operations (start, stop, reboot)
    - Resource monitoring
    - Billing information
    """
    
    BASE_URL = "https://api.oneprovider.com"
    
    def __init__(
        self,
        api_key: str,
        client_key: str,
        timeout: int = 30,
        max_retries: int = 3
    ):
        """
        Initialize OneProvider client
        
        Args:
            api_key: Personal API key
            client_key: Secret CLIENT key
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
        """
        self.api_key = api_key
        self.client_key = client_key
        self.timeout = timeout
        self.max_retries = max_retries
        self._session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        """Context manager entry"""
        await self._ensure_session()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        await self.close()
    
    async def _ensure_session(self):
        """Ensure aiohttp session exists"""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                headers={
                    "X-API-KEY": self.api_key,
                    "X-CLIENT-KEY": self.client_key,
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                },
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            )
    
    async def close(self):
        """Close the client session"""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None
    
    async def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        retry_count: int = 0
    ) -> Dict[str, Any]:
        """
        Make API request with retry logic
        
        Args:
            method: HTTP method
            endpoint: API endpoint
            params: Query parameters
            json: JSON body
            retry_count: Current retry count
        
        Returns:
            API response data
        
        Raises:
            OneProviderError: If request fails
        """
        await self._ensure_session()
        
        url = f"{self.BASE_URL}{endpoint}"
        
        try:
            logger.debug(f"OneProvider API: {method} {url}")
            
            async with self._session.request(
                method,
                url,
                params=params,
                json=json
            ) as response:
                # Read response text
                text = await response.text()
                
                # Log response
                logger.debug(
                    f"OneProvider response: status={response.status}, "
                    f"body={text[:200]}"
                )
                
                # Check status
                if response.status >= 400:
                    error_msg = f"OneProvider API error: {response.status} - {text}"
                    
                    # Retry on server errors
                    if (
                        response.status >= 500
                        and retry_count < self.max_retries
                    ):
                        logger.warning(
                            f"Retrying request ({retry_count + 1}/{self.max_retries})"
                        )
                        await asyncio.sleep(2 ** retry_count)  # Exponential backoff
                        return await self._request(
                            method,
                            endpoint,
                            params,
                            json,
                            retry_count + 1
                        )
                    
                    raise OneProviderError(error_msg)
                
                # Parse JSON
                try:
                    data = await response.json()
                    return data
                except Exception as e:
                    logger.error(f"Failed to parse JSON response: {str(e)}")
                    return {"raw_response": text}
                
        except aiohttp.ClientError as e:
            error_msg = f"OneProvider request failed: {str(e)}"
            logger.error(error_msg)
            
            # Retry on network errors
            if retry_count < self.max_retries:
                logger.warning(
                    f"Retrying request ({retry_count + 1}/{self.max_retries})"
                )
                await asyncio.sleep(2 ** retry_count)
                return await self._request(
                    method,
                    endpoint,
                    params,
                    json,
                    retry_count + 1
                )
            
            raise OneProviderError(error_msg) from e
    
    # ========================================================================
    # Project Management
    # ========================================================================
    
    async def list_projects(self) -> List[Dict[str, Any]]:
        """
        Get list of all projects
        
        Returns:
            List of project details
        """
        data = await self._request("GET", "/vm/project/list")
        return data.get("projects", [])
    
    async def get_project(self, project_uuid: str) -> Dict[str, Any]:
        """
        Get project details
        
        Args:
            project_uuid: Project UUID
        
        Returns:
            Project details
        """
        data = await self._request("GET", f"/vm/project/{project_uuid}")
        return data
    
    # ========================================================================
    # VM Management
    # ========================================================================
    
    async def list_vms(self, project_uuid: str) -> List[Dict[str, Any]]:
        """
        List all VMs in a project
        
        Args:
            project_uuid: Project UUID
        
        Returns:
            List of VM details
        """
        data = await self._request("GET", f"/vm/listing/{project_uuid}")
        return data.get("vms", [])
    
    async def get_vm_info(self, vm_id: str) -> Dict[str, Any]:
        """
        Get detailed VM information
        
        Args:
            vm_id: VM ID
        
        Returns:
            VM details including status, resources, IPs
        """
        data = await self._request("GET", f"/vm/info/{vm_id}")
        return data
    
    async def search_vms(
        self,
        query: Optional[str] = None,
        project_uuid: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Search VMs
        
        Args:
            query: Search query
            project_uuid: Filter by project
        
        Returns:
            List of matching VMs
        """
        params = {}
        if query:
            params["q"] = query
        if project_uuid:
            params["project_uuid"] = project_uuid
        
        data = await self._request("GET", "/vm/search", params=params)
        return data.get("vms", [])
    
    async def create_vm(
        self,
        project_uuid: str,
        hostname: str,
        plan_id: str,
        os_id: str,
        location_id: str,
        ssh_keys: Optional[List[str]] = None,
        password: Optional[str] = None,
        ipv6: bool = False,
        private_network: bool = False,
        auto_backups: bool = False
    ) -> Dict[str, Any]:
        """
        Create a new VM
        
        Args:
            project_uuid: Project UUID
            hostname: VM hostname
            plan_id: Plan/size ID (e.g., "8GB-2CORE")
            os_id: Operating system ID
            location_id: Datacenter location ID
            ssh_keys: List of SSH key IDs
            password: Root password
            ipv6: Enable IPv6
            private_network: Enable private networking
            auto_backups: Enable automatic backups
        
        Returns:
            Created VM details
        """
        payload = {
            "project_uuid": project_uuid,
            "hostname": hostname,
            "plan_id": plan_id,
            "os_id": os_id,
            "location_id": location_id,
            "ipv6": ipv6,
            "private_network": private_network,
            "auto_backups": auto_backups
        }
        
        if ssh_keys:
            payload["ssh_keys"] = ssh_keys
        if password:
            payload["password"] = password
        
        data = await self._request("POST", "/vm/create", json=payload)
        
        logger.info(f"Created VM: {hostname} (ID: {data.get('vm_id')})")
        return data
    
    async def destroy_vm(
        self,
        vm_id: str,
        confirm_close: bool = False
    ) -> Dict[str, Any]:
        """
        Destroy a VM
        
        Args:
            vm_id: VM ID
            confirm_close: Confirm closing even with bandwidth overages
        
        Returns:
            Destruction status
        """
        payload = {
            "vm_id": vm_id,
            "confirm_close": confirm_close
        }
        
        data = await self._request("POST", "/vm/destroy", json=payload)
        
        logger.info(f"Destroyed VM: {vm_id}")
        return data
    
    async def start_vm(self, vm_id: str) -> Dict[str, Any]:
        """Start a stopped VM"""
        data = await self._request("POST", "/vm/start", json={"vm_id": vm_id})
        logger.info(f"Started VM: {vm_id}")
        return data
    
    async def stop_vm(self, vm_id: str, force: bool = False) -> Dict[str, Any]:
        """Stop a running VM"""
        payload = {"vm_id": vm_id, "force": force}
        data = await self._request("POST", "/vm/stop", json=payload)
        logger.info(f"Stopped VM: {vm_id}")
        return data
    
    async def reboot_vm(self, vm_id: str, force: bool = False) -> Dict[str, Any]:
        """Reboot a VM"""
        payload = {"vm_id": vm_id, "force": force}
        data = await self._request("POST", "/vm/reboot", json=payload)
        logger.info(f"Rebooted VM: {vm_id}")
        return data
    
    async def reinstall_vm(
        self,
        vm_id: str,
        os_id: str,
        ssh_keys: Optional[List[str]] = None,
        password: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Reinstall VM with new OS
        
        Args:
            vm_id: VM ID
            os_id: New OS ID
            ssh_keys: SSH key IDs
            password: New root password
        
        Returns:
            Reinstallation status
        """
        payload = {
            "vm_id": vm_id,
            "os_id": os_id
        }
        
        if ssh_keys:
            payload["ssh_keys"] = ssh_keys
        if password:
            payload["password"] = password
        
        data = await self._request("POST", "/vm/reinstall", json=payload)
        
        logger.info(f"Reinstalling VM: {vm_id}")
        return data
    
    async def resize_vm(self, vm_id: str, plan_id: str) -> Dict[str, Any]:
        """
        Resize VM to different plan
        
        Args:
            vm_id: VM ID
            plan_id: New plan ID
        
        Returns:
            Resize status
        """
        payload = {
            "vm_id": vm_id,
            "plan_id": plan_id
        }
        
        data = await self._request("POST", "/vm/resize", json=payload)
        
        logger.info(f"Resizing VM {vm_id} to {plan_id}")
        return data
    
    async def set_hostname(self, vm_id: str, hostname: str) -> Dict[str, Any]:
        """Change VM hostname"""
        payload = {"vm_id": vm_id, "hostname": hostname}
        data = await self._request("POST", "/vm/hostname", json=payload)
        logger.info(f"Set hostname for VM {vm_id}: {hostname}")
        return data
    
    async def set_password(self, vm_id: str, password: str) -> Dict[str, Any]:
        """Change VM root password"""
        payload = {"vm_id": vm_id, "password": password}
        data = await self._request("POST", "/vm/password", json=payload)
        logger.info(f"Changed password for VM {vm_id}")
        return data
    
    # ========================================================================
    # Monitoring
    # ========================================================================
    
    async def get_bandwidth_usage(self, vm_id: str) -> Dict[str, Any]:
        """
        Get bandwidth usage statistics
        
        Args:
            vm_id: VM ID
        
        Returns:
            Bandwidth details (daily, total IN/OUT)
        """
        vm_info = await self.get_vm_info(vm_id)
        return vm_info.get("bandwidth", {})
    
    async def get_installation_progress(self, vm_id: str) -> Dict[str, Any]:
        """
        Get VM installation/provisioning progress
        
        Args:
            vm_id: VM ID
        
        Returns:
            Installation status with progress and message
        """
        vm_info = await self.get_vm_info(vm_id)
        return {
            "is_installing": vm_info.get("is_installing", False),
            "progress": vm_info.get("progress", 0),
            "message": vm_info.get("message", "")
        }
    
    async def wait_for_vm_ready(
        self,
        vm_id: str,
        timeout: int = 600,
        poll_interval: int = 10
    ) -> bool:
        """
        Wait for VM to be ready (installation complete)
        
        Args:
            vm_id: VM ID
            timeout: Maximum wait time in seconds
            poll_interval: Seconds between status checks
        
        Returns:
            True if VM is ready, False if timeout
        """
        start_time = datetime.utcnow()
        
        while (datetime.utcnow() - start_time).total_seconds() < timeout:
            try:
                progress = await self.get_installation_progress(vm_id)
                
                if not progress["is_installing"]:
                    logger.info(f"VM {vm_id} is ready")
                    return True
                
                logger.info(
                    f"VM {vm_id} installing: {progress['progress']}% - "
                    f"{progress['message']}"
                )
                
            except Exception as e:
                logger.warning(f"Error checking VM status: {str(e)}")
            
            await asyncio.sleep(poll_interval)
        
        logger.error(f"VM {vm_id} not ready after {timeout}s")
        return False
