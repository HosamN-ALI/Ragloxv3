# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Workflow API Routes
# REST API for advanced workflow orchestration
# ═══════════════════════════════════════════════════════════════

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, HTTPException, status, Query
from pydantic import BaseModel, Field

from ..core.workflow_orchestrator import (
    AgentWorkflowOrchestrator,
    WorkflowPhase,
    PhaseStatus,
    get_workflow_orchestrator,
)
from ..infrastructure.tools import (
    ToolManager,
    ToolCategory,
    get_tool_manager,
)


# ═══════════════════════════════════════════════════════════════
# Router Setup
# ═══════════════════════════════════════════════════════════════

router = APIRouter(prefix="/workflow", tags=["Workflow"])


# ═══════════════════════════════════════════════════════════════
# Request/Response Models
# ═══════════════════════════════════════════════════════════════

class WorkflowStartRequest(BaseModel):
    """Request to start a new workflow."""
    mission_id: str = Field(..., description="Mission ID")
    mission_goals: List[str] = Field(
        ..., 
        description="Mission objectives",
        example=["domain_admin", "credential_harvest"]
    )
    scope: List[str] = Field(
        ...,
        description="Target scope (IPs, networks)",
        example=["192.168.1.0/24", "10.0.0.1"]
    )
    
    # Constraints
    stealth_level: str = Field(
        default="normal",
        description="Stealth level: low, normal, high"
    )
    max_duration_hours: float = Field(
        default=4.0,
        description="Maximum workflow duration in hours"
    )
    require_approval_for: List[str] = Field(
        default=["exploit", "lateral"],
        description="Action types requiring HITL approval"
    )
    
    # Environment
    environment_type: str = Field(
        default="simulated",
        description="Execution environment: simulated, ssh, vm"
    )
    ssh_config: Optional[Dict[str, Any]] = Field(
        default=None,
        description="SSH configuration for remote execution"
    )
    vm_config: Optional[Dict[str, Any]] = Field(
        default=None,
        description="VM configuration for cloud execution"
    )


class WorkflowStatusResponse(BaseModel):
    """Workflow status response."""
    mission_id: str
    campaign_id: Optional[str]
    current_phase: str
    environment_type: str
    
    # Progress
    phases_completed: int
    phases_total: int
    
    # Discoveries
    targets_discovered: int
    vulns_discovered: int
    creds_discovered: int
    sessions_established: int
    
    # Goals
    goals_achieved: int
    goals_total: int
    
    # Timing
    started_at: str
    duration_minutes: float
    
    # LLM
    llm_enabled: bool
    llm_decisions_count: int


class PhaseResultResponse(BaseModel):
    """Phase execution result."""
    phase: str
    status: str
    started_at: str
    completed_at: Optional[str]
    duration_seconds: float
    discoveries_count: int
    tasks_created: int
    tasks_completed: int
    errors_count: int


class ToolInfoResponse(BaseModel):
    """Tool information response."""
    name: str
    description: str
    category: str
    platforms: List[str]
    dependencies: List[str]


class ToolInstallRequest(BaseModel):
    """Request to install tools."""
    environment_id: str
    tools: List[str]
    platform: str = "linux"


class ToolInstallResultResponse(BaseModel):
    """Tool installation result."""
    tool_name: str
    status: str
    duration_seconds: float
    error_message: Optional[str]


# ═══════════════════════════════════════════════════════════════
# Workflow Endpoints
# ═══════════════════════════════════════════════════════════════

@router.post(
    "/start",
    response_model=WorkflowStatusResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Start a new workflow"
)
async def start_workflow(request: WorkflowStartRequest):
    """
    Start a new advanced workflow for a penetration testing mission.
    
    The workflow orchestrates all phases of the penetration test:
    1. Initialization - Setup environment and tools
    2. Strategic Planning - Generate attack campaign
    3. Reconnaissance - Network and vulnerability discovery
    4. Initial Access - Exploit vulnerabilities
    5. Post-Exploitation - Privilege escalation and credential harvesting
    6. Lateral Movement - Move through the network
    7. Goal Achievement - Achieve mission objectives
    8. Reporting - Generate findings report
    9. Cleanup - Clean up artifacts
    """
    orchestrator = get_workflow_orchestrator()
    
    # Build environment config
    environment_config = None
    if request.environment_type in ("ssh", "vm"):
        environment_config = {
            "type": request.environment_type,
            "ssh_config": request.ssh_config,
            "vm_config": request.vm_config,
        }
    
    # Build constraints
    constraints = {
        "stealth_level": request.stealth_level,
        "max_duration_hours": request.max_duration_hours,
        "require_approval_for": request.require_approval_for,
    }
    
    try:
        context = await orchestrator.start_workflow(
            mission_id=request.mission_id,
            mission_goals=request.mission_goals,
            scope=request.scope,
            constraints=constraints,
            environment_config=environment_config
        )
        
        return WorkflowStatusResponse(
            mission_id=context.mission_id,
            campaign_id=context.campaign_id,
            current_phase=context.current_phase.value,
            environment_type=context.environment_type,
            phases_completed=0,
            phases_total=len(WorkflowPhase),
            targets_discovered=len(context.discovered_targets),
            vulns_discovered=len(context.discovered_vulns),
            creds_discovered=len(context.discovered_creds),
            sessions_established=len(context.established_sessions),
            goals_achieved=len(context.achieved_goals),
            goals_total=len(context.mission_goals),
            started_at=context.started_at.isoformat(),
            duration_minutes=0.0,
            llm_enabled=context.llm_enabled,
            llm_decisions_count=len(context.llm_decisions)
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to start workflow: {str(e)}"
        )


@router.get(
    "/{mission_id}/status",
    response_model=WorkflowStatusResponse,
    summary="Get workflow status"
)
async def get_workflow_status(mission_id: str):
    """Get the current status of a workflow."""
    orchestrator = get_workflow_orchestrator()
    
    context_data = await orchestrator.get_workflow_status(mission_id)
    
    if not context_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Workflow not found for mission: {mission_id}"
        )
    
    # Calculate duration
    started_at = datetime.fromisoformat(context_data.get("started_at", datetime.utcnow().isoformat()))
    duration_minutes = (datetime.utcnow() - started_at).total_seconds() / 60
    
    return WorkflowStatusResponse(
        mission_id=context_data.get("mission_id"),
        campaign_id=context_data.get("campaign_id"),
        current_phase=context_data.get("current_phase", "unknown"),
        environment_type=context_data.get("environment_type", "simulated"),
        phases_completed=context_data.get("phase_count", 0),
        phases_total=len(WorkflowPhase),
        targets_discovered=context_data.get("discovered_targets", 0),
        vulns_discovered=context_data.get("discovered_vulns", 0),
        creds_discovered=context_data.get("discovered_creds", 0),
        sessions_established=context_data.get("established_sessions", 0),
        goals_achieved=context_data.get("goals_achieved", 0),
        goals_total=context_data.get("goals_total", 0),
        started_at=context_data.get("started_at", ""),
        duration_minutes=duration_minutes,
        llm_enabled=context_data.get("llm_enabled", False),
        llm_decisions_count=len(context_data.get("llm_decisions", []))
    )


@router.get(
    "/{mission_id}/phases",
    response_model=List[PhaseResultResponse],
    summary="Get workflow phase results"
)
async def get_workflow_phases(mission_id: str):
    """Get detailed results for each completed phase."""
    orchestrator = get_workflow_orchestrator()
    
    context_data = await orchestrator.get_workflow_status(mission_id)
    
    if not context_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Workflow not found for mission: {mission_id}"
        )
    
    phase_results = context_data.get("phase_results", {})
    
    results = []
    for phase_name, phase_data in phase_results.items():
        if isinstance(phase_data, dict):
            results.append(PhaseResultResponse(
                phase=phase_data.get("phase", phase_name),
                status=phase_data.get("status", "unknown"),
                started_at=phase_data.get("started_at", ""),
                completed_at=phase_data.get("completed_at"),
                duration_seconds=phase_data.get("duration_seconds", 0),
                discoveries_count=phase_data.get("discoveries_count", 0),
                tasks_created=phase_data.get("tasks_created", 0),
                tasks_completed=phase_data.get("tasks_completed", 0),
                errors_count=phase_data.get("errors_count", 0)
            ))
    
    return results


@router.post(
    "/{mission_id}/pause",
    summary="Pause workflow"
)
async def pause_workflow(mission_id: str):
    """Pause a running workflow."""
    orchestrator = get_workflow_orchestrator()
    
    success = await orchestrator.pause_workflow(mission_id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Workflow not found or not running: {mission_id}"
        )
    
    return {"status": "paused", "mission_id": mission_id}


@router.post(
    "/{mission_id}/resume",
    summary="Resume workflow"
)
async def resume_workflow(mission_id: str):
    """Resume a paused workflow."""
    orchestrator = get_workflow_orchestrator()
    
    success = await orchestrator.resume_workflow(mission_id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Workflow not found or not paused: {mission_id}"
        )
    
    return {"status": "resumed", "mission_id": mission_id}


@router.post(
    "/{mission_id}/stop",
    summary="Stop workflow"
)
async def stop_workflow(mission_id: str):
    """Stop a workflow completely."""
    orchestrator = get_workflow_orchestrator()
    
    success = await orchestrator.stop_workflow(mission_id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Workflow not found: {mission_id}"
        )
    
    return {"status": "stopped", "mission_id": mission_id}


# ═══════════════════════════════════════════════════════════════
# Tool Management Endpoints
# ═══════════════════════════════════════════════════════════════

@router.get(
    "/tools",
    response_model=List[ToolInfoResponse],
    summary="List available tools"
)
async def list_tools(
    category: Optional[str] = Query(None, description="Filter by category"),
    platform: Optional[str] = Query(None, description="Filter by platform")
):
    """
    List available penetration testing tools.
    
    Categories:
    - recon: Reconnaissance tools (nmap, masscan, amass)
    - scanner: Vulnerability scanners (nuclei, nikto, wpscan)
    - exploit: Exploitation tools (metasploit, searchsploit)
    - post_exploit: Post-exploitation tools (linpeas, pspy)
    - credential: Credential tools (hashcat, john, hydra)
    - lateral: Lateral movement tools (impacket, crackmapexec)
    - utility: Utility tools (curl, jq, netcat)
    """
    manager = get_tool_manager()
    
    # Parse category
    cat = None
    if category:
        try:
            cat = ToolCategory(category.lower())
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid category: {category}"
            )
    
    tools = manager.list_tools(category=cat, platform=platform)
    
    return [
        ToolInfoResponse(
            name=t.name,
            description=t.description,
            category=t.category.value,
            platforms=t.platforms,
            dependencies=t.dependencies
        )
        for t in tools
    ]


@router.get(
    "/tools/{tool_name}",
    response_model=ToolInfoResponse,
    summary="Get tool information"
)
async def get_tool_info(tool_name: str):
    """Get detailed information about a tool."""
    manager = get_tool_manager()
    
    manifest = manager.get_tool_manifest(tool_name)
    
    if not manifest:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tool not found: {tool_name}"
        )
    
    return ToolInfoResponse(
        name=manifest.name,
        description=manifest.description,
        category=manifest.category.value,
        platforms=manifest.platforms,
        dependencies=manifest.dependencies
    )


@router.get(
    "/tools/for-goal/{goal}",
    response_model=List[str],
    summary="Get tools for a mission goal"
)
async def get_tools_for_goal(goal: str):
    """
    Get recommended tools for achieving a specific mission goal.
    
    Common goals:
    - domain_admin: Achieve domain administrator access
    - credential_harvest: Harvest credentials from systems
    - lateral_movement: Move laterally through the network
    - data_exfil: Exfiltrate data
    - web_pentest: Web application penetration testing
    - recon: Network reconnaissance
    """
    manager = get_tool_manager()
    tools = manager.get_tools_for_goal(goal)
    return tools


@router.post(
    "/tools/install",
    response_model=Dict[str, ToolInstallResultResponse],
    summary="Install tools on environment"
)
async def install_tools(request: ToolInstallRequest):
    """
    Install penetration testing tools on an execution environment.
    
    Note: This endpoint requires an active SSH/VM environment.
    """
    manager = get_tool_manager()
    
    # For now, simulate installation (no executor provided)
    results = await manager.ensure_tools_installed(
        env_id=request.environment_id,
        tools=request.tools,
        platform=request.platform,
        executor=None  # Would need actual executor in production
    )
    
    return {
        name: ToolInstallResultResponse(
            tool_name=result.tool_name,
            status=result.status.value,
            duration_seconds=result.duration_seconds,
            error_message=result.error_message or None
        )
        for name, result in results.items()
    }


# ═══════════════════════════════════════════════════════════════
# Workflow Phases Info Endpoint
# ═══════════════════════════════════════════════════════════════

@router.get(
    "/phases",
    summary="List workflow phases"
)
async def list_workflow_phases():
    """List all workflow phases and their descriptions."""
    phases = [
        {
            "phase": phase.value,
            "name": phase.name.replace("_", " ").title(),
            "order": idx + 1
        }
        for idx, phase in enumerate(WorkflowPhase)
    ]
    
    descriptions = {
        "initialization": "Setup environment and tools",
        "strategic_planning": "Generate attack campaign",
        "reconnaissance": "Network and vulnerability discovery",
        "initial_access": "Exploit vulnerabilities",
        "post_exploitation": "Privilege escalation and credential harvesting",
        "lateral_movement": "Move through the network",
        "goal_achievement": "Achieve mission objectives",
        "reporting": "Generate findings report",
        "cleanup": "Clean up artifacts"
    }
    
    for phase in phases:
        phase["description"] = descriptions.get(phase["phase"], "")
    
    return phases
