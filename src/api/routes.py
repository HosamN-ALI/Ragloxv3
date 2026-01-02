# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - API Routes
# REST API endpoints for mission management
# ═══════════════════════════════════════════════════════════════

from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from ..core.models import (
    MissionCreate, MissionStatus, MissionStats,
    Target, TargetStatus, Priority,
    Vulnerability, Severity,
    Credential, CredentialType,
    Session, SessionStatus
)
from ..controller.mission import MissionController


router = APIRouter(tags=["Missions"])


# ═══════════════════════════════════════════════════════════════
# Dependencies
# ═══════════════════════════════════════════════════════════════

async def get_controller(request: Request) -> MissionController:
    """Get the mission controller from app state."""
    if not hasattr(request.app.state, 'controller') or not request.app.state.controller:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Controller not initialized"
        )
    return request.app.state.controller


# ═══════════════════════════════════════════════════════════════
# Response Models
# ═══════════════════════════════════════════════════════════════

class MissionResponse(BaseModel):
    """Mission response model."""
    mission_id: str
    name: str
    status: str
    message: str


class MissionStatusResponse(BaseModel):
    """Comprehensive mission status response."""
    mission_id: str
    name: Optional[str] = None
    status: Optional[str] = None
    scope: Optional[List[str]] = None
    goals: Optional[Dict[str, str]] = None
    statistics: Optional[Dict[str, int]] = None
    target_count: int = 0
    vuln_count: int = 0
    created_at: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None


class TargetResponse(BaseModel):
    """Target response model."""
    target_id: str
    ip: str
    hostname: Optional[str] = None
    os: Optional[str] = None
    status: str
    priority: str
    risk_score: Optional[float] = None
    ports: Dict[str, str] = {}


class VulnerabilityResponse(BaseModel):
    """Vulnerability response model."""
    vuln_id: str
    target_id: str
    type: str
    name: Optional[str] = None
    severity: str
    cvss: Optional[float] = None
    status: str
    exploit_available: bool = False


# ═══════════════════════════════════════════════════════════════
# Mission Endpoints
# ═══════════════════════════════════════════════════════════════

@router.post("/missions", response_model=MissionResponse, status_code=status.HTTP_201_CREATED)
async def create_mission(
    mission_data: MissionCreate,
    controller: MissionController = Depends(get_controller)
) -> MissionResponse:
    """
    Create a new mission.
    
    - **name**: Mission name
    - **description**: Optional description
    - **scope**: List of target ranges (CIDRs, IPs, domains)
    - **goals**: List of objectives (e.g., ["domain_admin", "data_exfil"])
    - **constraints**: Optional constraints (e.g., {"stealth": true})
    """
    try:
        mission_id = await controller.create_mission(mission_data)
        
        return MissionResponse(
            mission_id=mission_id,
            name=mission_data.name,
            status="created",
            message="Mission created successfully"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create mission: {str(e)}"
        )


@router.get("/missions", response_model=List[str])
async def list_missions(
    controller: MissionController = Depends(get_controller)
) -> List[str]:
    """List all active mission IDs."""
    return await controller.get_active_missions()


@router.get("/missions/{mission_id}", response_model=MissionStatusResponse)
async def get_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> MissionStatusResponse:
    """Get mission status and details."""
    status_data = await controller.get_mission_status(mission_id)
    
    if not status_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    return MissionStatusResponse(**status_data)


@router.post("/missions/{mission_id}/start", response_model=MissionResponse)
async def start_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> MissionResponse:
    """Start a mission."""
    result = await controller.start_mission(mission_id)
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to start mission {mission_id}"
        )
    
    return MissionResponse(
        mission_id=mission_id,
        name="",
        status="running",
        message="Mission started successfully"
    )


@router.post("/missions/{mission_id}/pause", response_model=MissionResponse)
async def pause_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> MissionResponse:
    """Pause a running mission."""
    result = await controller.pause_mission(mission_id)
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to pause mission {mission_id}"
        )
    
    return MissionResponse(
        mission_id=mission_id,
        name="",
        status="paused",
        message="Mission paused successfully"
    )


@router.post("/missions/{mission_id}/resume", response_model=MissionResponse)
async def resume_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> MissionResponse:
    """Resume a paused mission."""
    result = await controller.resume_mission(mission_id)
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to resume mission {mission_id}"
        )
    
    return MissionResponse(
        mission_id=mission_id,
        name="",
        status="running",
        message="Mission resumed successfully"
    )


@router.post("/missions/{mission_id}/stop", response_model=MissionResponse)
async def stop_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> MissionResponse:
    """Stop a mission."""
    result = await controller.stop_mission(mission_id)
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to stop mission {mission_id}"
        )
    
    return MissionResponse(
        mission_id=mission_id,
        name="",
        status="completed",
        message="Mission stopped successfully"
    )


# ═══════════════════════════════════════════════════════════════
# Target Endpoints
# ═══════════════════════════════════════════════════════════════

@router.get("/missions/{mission_id}/targets", response_model=List[TargetResponse])
async def list_targets(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> List[TargetResponse]:
    """List all targets for a mission."""
    blackboard = controller.blackboard
    
    target_keys = await blackboard.get_mission_targets(mission_id)
    targets = []
    
    for target_key in target_keys:
        target_id = target_key.replace("target:", "")
        target_data = await blackboard.get_target(target_id)
        
        if target_data:
            ports = await blackboard.get_target_ports(target_id)
            targets.append(TargetResponse(
                target_id=target_id,
                ip=target_data.get("ip", ""),
                hostname=target_data.get("hostname"),
                os=target_data.get("os"),
                status=target_data.get("status", "unknown"),
                priority=target_data.get("priority", "medium"),
                risk_score=target_data.get("risk_score"),
                ports=ports
            ))
    
    return targets


@router.get("/missions/{mission_id}/targets/{target_id}", response_model=TargetResponse)
async def get_target(
    mission_id: str,
    target_id: str,
    controller: MissionController = Depends(get_controller)
) -> TargetResponse:
    """Get a specific target."""
    blackboard = controller.blackboard
    
    target_data = await blackboard.get_target(target_id)
    
    if not target_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target {target_id} not found"
        )
    
    ports = await blackboard.get_target_ports(target_id)
    
    return TargetResponse(
        target_id=target_id,
        ip=target_data.get("ip", ""),
        hostname=target_data.get("hostname"),
        os=target_data.get("os"),
        status=target_data.get("status", "unknown"),
        priority=target_data.get("priority", "medium"),
        risk_score=target_data.get("risk_score"),
        ports=ports
    )


# ═══════════════════════════════════════════════════════════════
# Vulnerability Endpoints
# ═══════════════════════════════════════════════════════════════

@router.get("/missions/{mission_id}/vulnerabilities", response_model=List[VulnerabilityResponse])
async def list_vulnerabilities(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> List[VulnerabilityResponse]:
    """List all vulnerabilities for a mission."""
    blackboard = controller.blackboard
    
    vuln_keys = await blackboard.get_mission_vulns(mission_id)
    vulns = []
    
    for vuln_key in vuln_keys:
        vuln_id = vuln_key.replace("vuln:", "")
        vuln_data = await blackboard.get_vulnerability(vuln_id)
        
        if vuln_data:
            vulns.append(VulnerabilityResponse(
                vuln_id=vuln_id,
                target_id=str(vuln_data.get("target_id", "")),
                type=vuln_data.get("type", ""),
                name=vuln_data.get("name"),
                severity=vuln_data.get("severity", "medium"),
                cvss=vuln_data.get("cvss"),
                status=vuln_data.get("status", "discovered"),
                exploit_available=vuln_data.get("exploit_available", False)
            ))
    
    return vulns


# ═══════════════════════════════════════════════════════════════
# Statistics Endpoint
# ═══════════════════════════════════════════════════════════════

@router.get("/missions/{mission_id}/stats")
async def get_mission_stats(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> Dict[str, Any]:
    """Get mission statistics."""
    blackboard = controller.blackboard
    
    stats = await blackboard.get_mission_stats(mission_id)
    goals = await blackboard.get_mission_goals(mission_id)
    
    # Count achieved goals
    achieved = sum(1 for g in goals.values() if g == "achieved")
    total = len(goals)
    
    return {
        "targets_discovered": stats.targets_discovered,
        "vulns_found": stats.vulns_found,
        "creds_harvested": stats.creds_harvested,
        "sessions_established": stats.sessions_established,
        "goals_achieved": achieved,
        "goals_total": total,
        "completion_percentage": (achieved / total * 100) if total > 0 else 0
    }
