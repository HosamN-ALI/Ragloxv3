"""
RAGLOX v3.0 - Infrastructure API Routes
API routes for agent environment management.

Author: RAGLOX Team
Version: 3.0.0
"""

from fastapi import APIRouter, HTTPException, Depends, status
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from datetime import datetime

from ..infrastructure.orchestrator import (
    EnvironmentManager,
    EnvironmentType,
    EnvironmentConfig,
    AgentExecutor,
    HealthMonitor
)
from ..infrastructure.ssh import SSHConnectionConfig
from ..infrastructure.cloud_provider import VMConfiguration


# Initialize router
router = APIRouter(prefix="/infrastructure", tags=["Infrastructure"])


# ============================================================================
# Request/Response Models
# ============================================================================

class SSHConfigRequest(BaseModel):
    """SSH configuration request"""
    host: str = Field(..., description="SSH host")
    port: int = Field(22, description="SSH port")
    username: str = Field(..., description="SSH username")
    password: Optional[str] = Field(None, description="SSH password")
    key_filename: Optional[str] = Field(None, description="Path to SSH private key")
    passphrase: Optional[str] = Field(None, description="Key passphrase")


class VMConfigRequest(BaseModel):
    """VM configuration request"""
    hostname: str = Field(..., description="VM hostname")
    plan_id: str = Field("8GB-2CORE", description="VM plan")
    os_id: str = Field("ubuntu-22.04", description="Operating system")
    location_id: str = Field("us-east", description="Datacenter location")
    ssh_keys: List[str] = Field(default_factory=list, description="SSH key IDs")
    password: Optional[str] = Field(None, description="Root password")


class CreateEnvironmentRequest(BaseModel):
    """Create environment request"""
    environment_type: EnvironmentType = Field(..., description="Environment type")
    name: str = Field(..., description="Environment name")
    user_id: str = Field(..., description="User ID")
    tenant_id: str = Field(..., description="Tenant ID")
    ssh_config: Optional[SSHConfigRequest] = None
    vm_config: Optional[VMConfigRequest] = None
    tags: Dict[str, str] = Field(default_factory=dict)


class EnvironmentResponse(BaseModel):
    """Environment response"""
    environment_id: str
    environment_type: str
    status: str
    name: str
    user_id: str
    tenant_id: str
    connection_id: Optional[str]
    vm_instance: Optional[Dict[str, Any]]
    created_at: str
    connected_at: Optional[str]
    tags: Dict[str, str]


class ExecuteCommandRequest(BaseModel):
    """Execute command request"""
    command: str = Field(..., description="Command to execute")
    timeout: int = Field(300, description="Timeout in seconds")
    cwd: Optional[str] = Field(None, description="Working directory")
    env: Optional[Dict[str, str]] = Field(None, description="Environment variables")


class ExecuteScriptRequest(BaseModel):
    """Execute script request"""
    script_content: str = Field(..., description="Script content")
    interpreter: str = Field("/bin/bash", description="Script interpreter")
    timeout: int = Field(600, description="Timeout in seconds")
    env: Optional[Dict[str, str]] = Field(None, description="Environment variables")


class ExecutionResponse(BaseModel):
    """Execution result response"""
    task_id: str
    task_type: str
    environment_id: str
    status: str
    exit_code: int
    stdout: str
    stderr: str
    execution_time: float
    started_at: str
    ended_at: str


class HealthCheckResponse(BaseModel):
    """Health check response"""
    environment_id: str
    status: str
    timestamp: str
    checks: Dict[str, bool]
    latency_ms: float
    message: str


# ============================================================================
# Dependencies
# ============================================================================

# Global instances (in production, use dependency injection)
_environment_manager: Optional[EnvironmentManager] = None
_agent_executor: Optional[AgentExecutor] = None
_health_monitor: Optional[HealthMonitor] = None


def get_environment_manager() -> EnvironmentManager:
    """Get environment manager instance"""
    global _environment_manager
    if _environment_manager is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Environment manager not initialized"
        )
    return _environment_manager


def get_agent_executor() -> AgentExecutor:
    """Get agent executor instance"""
    global _agent_executor
    if _agent_executor is None:
        _agent_executor = AgentExecutor()
    return _agent_executor


def get_health_monitor() -> HealthMonitor:
    """Get health monitor instance"""
    global _health_monitor
    if _health_monitor is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Health monitor not initialized"
        )
    return _health_monitor


# ============================================================================
# Environment Management Routes
# ============================================================================

@router.post("/environments", response_model=EnvironmentResponse, status_code=status.HTTP_201_CREATED)
async def create_environment(
    request: CreateEnvironmentRequest,
    manager: EnvironmentManager = Depends(get_environment_manager)
):
    """
    Create a new agent environment
    
    - **Remote SSH**: Connects to user-provided server
    - **Sandbox**: Provisions new VM on OneProvider
    """
    try:
        # Convert request to config
        ssh_config = None
        if request.ssh_config:
            ssh_config = SSHConnectionConfig(
                host=request.ssh_config.host,
                port=request.ssh_config.port,
                username=request.ssh_config.username,
                password=request.ssh_config.password,
                key_filename=request.ssh_config.key_filename,
                passphrase=request.ssh_config.passphrase
            )
        
        vm_config = None
        if request.vm_config:
            vm_config = VMConfiguration(
                hostname=request.vm_config.hostname,
                plan_id=request.vm_config.plan_id,
                os_id=request.vm_config.os_id,
                location_id=request.vm_config.location_id,
                ssh_keys=request.vm_config.ssh_keys,
                password=request.vm_config.password
            )
        
        config = EnvironmentConfig(
            environment_type=request.environment_type,
            name=request.name,
            user_id=request.user_id,
            tenant_id=request.tenant_id,
            ssh_config=ssh_config,
            vm_config=vm_config,
            tags=request.tags
        )
        
        # Create environment
        environment = await manager.create_environment(config)
        
        # Return response
        return EnvironmentResponse(**environment.to_dict())
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create environment: {str(e)}"
        )


@router.get("/environments/{environment_id}", response_model=EnvironmentResponse)
async def get_environment(
    environment_id: str,
    manager: EnvironmentManager = Depends(get_environment_manager)
):
    """Get environment details"""
    environment = await manager.get_environment(environment_id)
    
    if not environment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Environment {environment_id} not found"
        )
    
    return EnvironmentResponse(**environment.to_dict())


@router.get("/users/{user_id}/environments", response_model=List[EnvironmentResponse])
async def list_user_environments(
    user_id: str,
    manager: EnvironmentManager = Depends(get_environment_manager)
):
    """List all environments for a user"""
    environments = await manager.list_user_environments(user_id)
    return [EnvironmentResponse(**env.to_dict()) for env in environments]


@router.delete("/environments/{environment_id}", status_code=status.HTTP_204_NO_CONTENT)
async def destroy_environment(
    environment_id: str,
    manager: EnvironmentManager = Depends(get_environment_manager)
):
    """Destroy an environment"""
    success = await manager.destroy_environment(environment_id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to destroy environment {environment_id}"
        )


@router.post("/environments/{environment_id}/reconnect", status_code=status.HTTP_200_OK)
async def reconnect_environment(
    environment_id: str,
    manager: EnvironmentManager = Depends(get_environment_manager)
):
    """Reconnect a disconnected environment"""
    success = await manager.reconnect_environment(environment_id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to reconnect environment {environment_id}"
        )
    
    return {"message": "Environment reconnected successfully"}


# ============================================================================
# Task Execution Routes
# ============================================================================

@router.post("/environments/{environment_id}/execute/command", response_model=ExecutionResponse)
async def execute_command(
    environment_id: str,
    request: ExecuteCommandRequest,
    manager: EnvironmentManager = Depends(get_environment_manager),
    executor: AgentExecutor = Depends(get_agent_executor)
):
    """Execute a command in environment"""
    import uuid
    
    # Get environment
    environment = await manager.get_environment(environment_id)
    if not environment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Environment {environment_id} not found"
        )
    
    # Generate task ID
    task_id = str(uuid.uuid4())
    
    # Execute command
    result = await executor.execute_command(
        environment,
        request.command,
        task_id,
        timeout=request.timeout,
        cwd=request.cwd,
        env=request.env
    )
    
    return ExecutionResponse(**result.to_dict())


@router.post("/environments/{environment_id}/execute/script", response_model=ExecutionResponse)
async def execute_script(
    environment_id: str,
    request: ExecuteScriptRequest,
    manager: EnvironmentManager = Depends(get_environment_manager),
    executor: AgentExecutor = Depends(get_agent_executor)
):
    """Execute a script in environment"""
    import uuid
    
    # Get environment
    environment = await manager.get_environment(environment_id)
    if not environment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Environment {environment_id} not found"
        )
    
    # Generate task ID
    task_id = str(uuid.uuid4())
    
    # Execute script
    result = await executor.execute_script(
        environment,
        request.script_content,
        task_id,
        interpreter=request.interpreter,
        timeout=request.timeout,
        env=request.env
    )
    
    return ExecutionResponse(**result.to_dict())


@router.get("/environments/{environment_id}/system-info", response_model=ExecutionResponse)
async def get_system_info(
    environment_id: str,
    manager: EnvironmentManager = Depends(get_environment_manager),
    executor: AgentExecutor = Depends(get_agent_executor)
):
    """Get system information from environment"""
    import uuid
    
    # Get environment
    environment = await manager.get_environment(environment_id)
    if not environment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Environment {environment_id} not found"
        )
    
    # Generate task ID
    task_id = str(uuid.uuid4())
    
    # Get system info
    result = await executor.get_system_info(environment, task_id)
    
    return ExecutionResponse(**result.to_dict())


# ============================================================================
# Health Monitoring Routes
# ============================================================================

@router.get("/environments/{environment_id}/health", response_model=HealthCheckResponse)
async def check_environment_health(
    environment_id: str,
    manager: EnvironmentManager = Depends(get_environment_manager),
    monitor: HealthMonitor = Depends(get_health_monitor)
):
    """Check environment health"""
    # Get environment
    environment = await manager.get_environment(environment_id)
    if not environment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Environment {environment_id} not found"
        )
    
    # Perform health check
    health_check = await monitor.check_environment(environment)
    
    return HealthCheckResponse(**health_check.to_dict())


@router.get("/environments/{environment_id}/health/statistics")
async def get_health_statistics(
    environment_id: str,
    hours: int = 24,
    monitor: HealthMonitor = Depends(get_health_monitor)
):
    """Get health statistics for environment"""
    stats = monitor.get_health_statistics(environment_id, hours=hours)
    return stats


@router.get("/statistics")
async def get_infrastructure_statistics(
    manager: EnvironmentManager = Depends(get_environment_manager)
):
    """Get overall infrastructure statistics"""
    stats = await manager.get_statistics()
    return stats
