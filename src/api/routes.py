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
    Session, SessionStatus,
    # HITL Models
    ApprovalAction, ApprovalStatus, RiskLevel, ActionType
)
from ..core.validators import validate_uuid
from ..core.exceptions import InvalidUUIDError
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


class CredentialResponse(BaseModel):
    """Credential response model."""
    cred_id: str
    target_id: str
    type: str
    username: str
    domain: Optional[str] = None
    privilege_level: str
    source: Optional[str] = None
    verified: bool = False
    created_at: Optional[str] = None


class SessionResponse(BaseModel):
    """Session response model."""
    session_id: str
    target_id: str
    type: str
    user: str
    privilege: str
    status: str
    established_at: Optional[str] = None
    last_activity: Optional[str] = None


# ═══════════════════════════════════════════════════════════════
# HITL Request/Response Models
# ═══════════════════════════════════════════════════════════════

class ApprovalRequest(BaseModel):
    """Request model for approving/rejecting actions."""
    user_comment: Optional[str] = Field(None, description="Optional user comment")


class RejectionRequest(BaseModel):
    """Request model for rejecting actions."""
    rejection_reason: Optional[str] = Field(None, description="Reason for rejection")
    user_comment: Optional[str] = Field(None, description="Optional user comment")


class ChatRequest(BaseModel):
    """Request model for chat messages."""
    content: str = Field(..., min_length=1, max_length=4096, description="Message content")
    related_task_id: Optional[str] = Field(None, description="Related task ID")
    related_action_id: Optional[str] = Field(None, description="Related approval action ID")


class ApprovalResponse(BaseModel):
    """Response model for approval operations."""
    success: bool
    message: str
    action_id: str
    mission_status: str


class PendingApprovalResponse(BaseModel):
    """Response model for pending approvals."""
    action_id: str
    action_type: str
    action_description: str
    target_ip: Optional[str] = None
    risk_level: str
    risk_reasons: List[str] = []
    potential_impact: Optional[str] = None
    command_preview: Optional[str] = None
    requested_at: str
    expires_at: Optional[str] = None


class ChatMessageResponse(BaseModel):
    """Response model for chat messages."""
    id: str
    role: str
    content: str
    timestamp: str
    related_task_id: Optional[str] = None
    related_action_id: Optional[str] = None


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
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
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
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
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
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
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
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
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
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    # Stop the mission
    try:
        result = await controller.stop_mission(mission_id)

        if not result:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to stop mission {mission_id}"
            )

        return MissionResponse(
            mission_id=mission_id,
            name="",
            status="stopped",
            message="Mission stopped successfully"
        )
    except HTTPException:
        # Re-raise HTTP exceptions (like 404, 400)
        raise
    except Exception as e:
        # Log error for debugging
        import logging
        logging.error(f"Error stopping mission {mission_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to stop mission: {str(e)}"
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
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
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
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
        validate_uuid(target_id, "target_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
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
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
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

# ═══════════════════════════════════════════════════════════════
# Credential Endpoints
# ═══════════════════════════════════════════════════════════════

@router.get("/missions/{mission_id}/credentials", response_model=List[CredentialResponse])
async def list_credentials(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> List[CredentialResponse]:
    """List all credentials for a mission."""
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    blackboard = controller.blackboard
    
    cred_keys = await blackboard.get_mission_creds(mission_id)
    creds = []
    
    for cred_key in cred_keys:
        cred_id = cred_key.replace("cred:", "")
        cred_data = await blackboard.get_credential(cred_id)
        
        if cred_data:
            creds.append(CredentialResponse(
                cred_id=cred_id,
                target_id=str(cred_data.get("target_id", "")),
                type=cred_data.get("type", ""),
                username=cred_data.get("username", ""),
                domain=cred_data.get("domain"),
                privilege_level=cred_data.get("privilege_level", "user"),
                source=cred_data.get("source"),
                verified=cred_data.get("verified", "false").lower() == "true",
                created_at=cred_data.get("created_at")
            ))
    
    return creds


# ═══════════════════════════════════════════════════════════════
# Session Endpoints
# ═══════════════════════════════════════════════════════════════

@router.get("/missions/{mission_id}/sessions", response_model=List[SessionResponse])
async def list_sessions(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> List[SessionResponse]:
    """List all active sessions for a mission."""
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    blackboard = controller.blackboard
    
    session_keys = await blackboard.get_mission_sessions(mission_id)
    sessions = []
    
    for session_key in session_keys:
        session_id = session_key.replace("session:", "")
        session_data = await blackboard.get_session(session_id)
        
        if session_data:
            sessions.append(SessionResponse(
                session_id=session_id,
                target_id=str(session_data.get("target_id", "")),
                type=session_data.get("type", "shell"),
                user=session_data.get("user", "unknown"),
                privilege=session_data.get("privilege", "user"),
                status=session_data.get("status", "unknown"),
                established_at=session_data.get("established_at"),
                last_activity=session_data.get("last_activity")
            ))
    
    return sessions


# ═══════════════════════════════════════════════════════════════
# Statistics Endpoint
# ═══════════════════════════════════════════════════════════════

@router.get("/missions/{mission_id}/stats")
async def get_mission_stats(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> Dict[str, Any]:
    """Get mission statistics."""
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
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


# ═══════════════════════════════════════════════════════════════
# HITL (Human-in-the-Loop) Endpoints
# ═══════════════════════════════════════════════════════════════

@router.get("/missions/{mission_id}/approvals", response_model=List[PendingApprovalResponse])
async def list_pending_approvals(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> List[PendingApprovalResponse]:
    """
    List all pending approval requests for a mission.
    
    These are high-risk actions waiting for user consent.
    """
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    pending = await controller.get_pending_approvals(mission_id)
    return [PendingApprovalResponse(**p) for p in pending]


@router.post("/missions/{mission_id}/approve/{action_id}", response_model=ApprovalResponse)
async def approve_action(
    mission_id: str,
    action_id: str,
    request_data: ApprovalRequest = None,
    controller: MissionController = Depends(get_controller)
) -> ApprovalResponse:
    """
    Approve a pending action.
    
    This allows the action to proceed and resumes mission execution.
    
    - **action_id**: ID of the action to approve
    - **user_comment**: Optional comment explaining the approval
    """
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
        validate_uuid(action_id, "action_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    user_comment = request_data.user_comment if request_data else None
    
    result = await controller.approve_action(
        mission_id=mission_id,
        action_id=action_id,
        user_comment=user_comment
    )
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Action {action_id} not found or does not belong to mission {mission_id}"
        )
    
    # Get current mission status
    current_status = mission_data.get("status", "unknown")
    
    return ApprovalResponse(
        success=True,
        message="Action approved successfully. Mission execution resumed.",
        action_id=action_id,
        mission_status=current_status
    )


@router.post("/missions/{mission_id}/reject/{action_id}", response_model=ApprovalResponse)
async def reject_action(
    mission_id: str,
    action_id: str,
    request_data: RejectionRequest = None,
    controller: MissionController = Depends(get_controller)
) -> ApprovalResponse:
    """
    Reject a pending action.
    
    The system will attempt to find an alternative approach.
    
    - **action_id**: ID of the action to reject
    - **rejection_reason**: Reason for rejection
    - **user_comment**: Optional additional comment
    """
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
        validate_uuid(action_id, "action_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    rejection_reason = request_data.rejection_reason if request_data else None
    user_comment = request_data.user_comment if request_data else None
    
    result = await controller.reject_action(
        mission_id=mission_id,
        action_id=action_id,
        rejection_reason=rejection_reason,
        user_comment=user_comment
    )
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Action {action_id} not found or does not belong to mission {mission_id}"
        )
    
    # Get current mission status
    current_status = mission_data.get("status", "unknown")
    
    return ApprovalResponse(
        success=True,
        message="Action rejected. System will seek alternatives.",
        action_id=action_id,
        mission_status=current_status
    )


@router.post("/missions/{mission_id}/chat", response_model=ChatMessageResponse)
async def send_chat_message(
    mission_id: str,
    request_data: ChatRequest,
    controller: MissionController = Depends(get_controller)
) -> ChatMessageResponse:
    """
    Send a chat message to interact with the mission.
    
    This allows users to:
    - Ask about mission status
    - Give instructions (pause, resume)
    - Query pending approvals
    
    - **content**: Message content
    - **related_task_id**: Optional related task
    - **related_action_id**: Optional related approval action
    """
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    try:
        message = await controller.send_chat_message(
            mission_id=mission_id,
            content=request_data.content,
            related_task_id=request_data.related_task_id,
            related_action_id=request_data.related_action_id
        )
        
        return ChatMessageResponse(
            id=str(message.id),
            role=message.role,
            content=message.content,
            timestamp=message.timestamp.isoformat(),
            related_task_id=str(message.related_task_id) if message.related_task_id else None,
            related_action_id=str(message.related_action_id) if message.related_action_id else None
        )
    except Exception as e:
        # Log the error for debugging
        import logging
        logging.error(f"Chat message error for mission {mission_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to process chat message: {str(e)}"
        )


@router.get("/missions/{mission_id}/chat", response_model=List[ChatMessageResponse])
async def get_chat_history(
    mission_id: str,
    limit: int = 50,
    controller: MissionController = Depends(get_controller)
) -> List[ChatMessageResponse]:
    """
    Get chat history for a mission.
    
    - **limit**: Maximum number of messages to return (default 50, must be > 0)
    """
    # Validate limit parameter - must be a positive integer
    if limit <= 0:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="limit must be a positive integer greater than 0"
        )
    
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    history = await controller.get_chat_history(mission_id, limit)
    return [ChatMessageResponse(**msg) for msg in history]
