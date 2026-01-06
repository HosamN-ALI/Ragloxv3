# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - API Routes (SaaS Edition)
# REST API endpoints for mission management with multi-tenant isolation
# ═══════════════════════════════════════════════════════════════
"""
Mission management API with organization-level data isolation.

All endpoints require authentication and verify organization ownership
before allowing access to mission data.

Security:
- JWT authentication required for all endpoints
- Organization ID extracted from user context
- Mission ownership verified before each operation
- Audit logging for sensitive operations
"""

from typing import Any, Dict, List, Optional
from uuid import UUID
import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from ..core.models import (
    MissionCreate, MissionStatus, MissionStats,
    Target, TargetStatus, Priority,
    Vulnerability, Severity,
    Credential, CredentialType,
    Session, SessionStatus,
    Mission,
    # HITL Models
    ApprovalAction, ApprovalStatus, RiskLevel, ActionType
)
from ..core.validators import validate_uuid
from ..core.exceptions import InvalidUUIDError
from ..controller.mission import MissionController
from .auth_routes import get_current_user


logger = logging.getLogger("raglox.api.routes")
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


async def verify_mission_ownership(
    mission_id: str,
    user: Dict[str, Any],
    controller: MissionController
) -> Dict[str, Any]:
    """
    Verify that the current user's organization owns the mission.
    
    Args:
        mission_id: Mission UUID string
        user: Current user dict with organization_id
        controller: Mission controller
        
    Returns:
        Mission data if owned by user's organization
        
    Raises:
        HTTPException 404 if mission not found
        HTTPException 403 if mission belongs to different organization
    """
    # Get mission from blackboard
    mission_data = await controller.get_mission_status(mission_id)
    
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    # Get mission's organization_id from Redis
    blackboard = controller.blackboard
    mission_info = await blackboard.get_mission(mission_id)
    
    if mission_info:
        mission_org_id = mission_info.get("organization_id")
        user_org_id = user.get("organization_id")
        
        # Verify ownership (superusers can access all)
        if mission_org_id and user_org_id and mission_org_id != user_org_id:
            if not user.get("is_superuser"):
                logger.warning(
                    f"Access denied: User {user.get('id')} from org {user_org_id} "
                    f"tried to access mission {mission_id} from org {mission_org_id}"
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied: Mission belongs to a different organization"
                )
    
    return mission_data


# ═══════════════════════════════════════════════════════════════
# Response Models
# ═══════════════════════════════════════════════════════════════

class MissionResponse(BaseModel):
    """Mission response model."""
    mission_id: str
    name: str
    status: str
    message: str
    organization_id: Optional[str] = None


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
    organization_id: Optional[str] = None


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
# Mission Endpoints (with Authentication & Isolation)
# ═══════════════════════════════════════════════════════════════

@router.post("/missions", response_model=MissionResponse, status_code=status.HTTP_201_CREATED)
async def create_mission(
    request: Request,
    mission_data: MissionCreate,
    controller: MissionController = Depends(get_controller),
    user: Dict[str, Any] = Depends(get_current_user),
) -> MissionResponse:
    """
    Create a new mission.
    
    The mission will be associated with the user's organization.
    
    - **name**: Mission name
    - **description**: Optional description
    - **scope**: List of target ranges (CIDRs, IPs, domains)
    - **goals**: List of objectives (e.g., ["domain_admin", "data_exfil"])
    - **constraints**: Optional constraints (e.g., {"stealth": true})
    """
    try:
        # Create mission with organization context
        organization_id = user.get("organization_id")
        created_by = user.get("id")
        
        # Create mission through controller with organization context
        mission_id = await controller.create_mission(
            mission_data,
            organization_id=organization_id,
            created_by=created_by
        )
        
        logger.info(f"Mission {mission_id} created by user {created_by} for org {organization_id}")
        
        return MissionResponse(
            mission_id=mission_id,
            name=mission_data.name,
            status="created",
            message="Mission created successfully",
            organization_id=organization_id
        )
    except Exception as e:
        logger.error(f"Failed to create mission: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create mission: {str(e)}"
        )


@router.get("/missions", response_model=List[MissionStatusResponse])
async def list_missions(
    request: Request,
    controller: MissionController = Depends(get_controller),
    user: Dict[str, Any] = Depends(get_current_user),
) -> List[MissionStatusResponse]:
    """
    List all missions for the current organization.
    
    Only missions belonging to the user's organization are returned.
    """
    organization_id = user.get("organization_id")
    
    # Get missions filtered by organization
    missions = await controller.get_organization_missions(organization_id)
    
    return [
        MissionStatusResponse(
            mission_id=m.get("mission_id", ""),
            name=m.get("name"),
            status=m.get("status"),
            scope=m.get("scope"),
            goals=m.get("goals"),
            statistics=m.get("statistics"),
            target_count=m.get("target_count", 0),
            vuln_count=m.get("vuln_count", 0),
            created_at=m.get("created_at"),
            started_at=m.get("started_at"),
            completed_at=m.get("completed_at"),
            organization_id=organization_id
        )
        for m in missions
    ]


@router.get("/missions/{mission_id}", response_model=MissionStatusResponse)
async def get_mission(
    request: Request,
    mission_id: str,
    controller: MissionController = Depends(get_controller),
    user: Dict[str, Any] = Depends(get_current_user),
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
    
    # Verify ownership
    status_data = await verify_mission_ownership(mission_id, user, controller)
    
    return MissionStatusResponse(
        **status_data,
        organization_id=user.get("organization_id")
    )


@router.post("/missions/{mission_id}/start", response_model=MissionResponse)
async def start_mission(
    request: Request,
    mission_id: str,
    controller: MissionController = Depends(get_controller),
    user: Dict[str, Any] = Depends(get_current_user),
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
    
    # Verify ownership
    await verify_mission_ownership(mission_id, user, controller)
    
    result = await controller.start_mission(mission_id)
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to start mission {mission_id}"
        )
    
    logger.info(f"Mission {mission_id} started by user {user.get('id')}")
    
    return MissionResponse(
        mission_id=mission_id,
        name="",
        status="running",
        message="Mission started successfully",
        organization_id=user.get("organization_id")
    )


@router.post("/missions/{mission_id}/pause", response_model=MissionResponse)
async def pause_mission(
    request: Request,
    mission_id: str,
    controller: MissionController = Depends(get_controller),
    user: Dict[str, Any] = Depends(get_current_user),
) -> MissionResponse:
    """Pause a running mission."""
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    await verify_mission_ownership(mission_id, user, controller)
    
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
        message="Mission paused successfully",
        organization_id=user.get("organization_id")
    )


@router.post("/missions/{mission_id}/resume", response_model=MissionResponse)
async def resume_mission(
    request: Request,
    mission_id: str,
    controller: MissionController = Depends(get_controller),
    user: Dict[str, Any] = Depends(get_current_user),
) -> MissionResponse:
    """Resume a paused mission."""
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    await verify_mission_ownership(mission_id, user, controller)
    
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
        message="Mission resumed successfully",
        organization_id=user.get("organization_id")
    )


@router.post("/missions/{mission_id}/stop", response_model=MissionResponse)
async def stop_mission(
    request: Request,
    mission_id: str,
    controller: MissionController = Depends(get_controller),
    user: Dict[str, Any] = Depends(get_current_user),
) -> MissionResponse:
    """Stop a mission."""
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    await verify_mission_ownership(mission_id, user, controller)
    
    try:
        result = await controller.stop_mission(mission_id)

        if not result:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to stop mission {mission_id}"
            )

        logger.info(f"Mission {mission_id} stopped by user {user.get('id')}")

        return MissionResponse(
            mission_id=mission_id,
            name="",
            status="stopped",
            message="Mission stopped successfully",
            organization_id=user.get("organization_id")
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error stopping mission {mission_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to stop mission: {str(e)}"
        )


# ═══════════════════════════════════════════════════════════════
# Target Endpoints
# ═══════════════════════════════════════════════════════════════

@router.get("/missions/{mission_id}/targets", response_model=List[TargetResponse])
async def list_targets(
    request: Request,
    mission_id: str,
    controller: MissionController = Depends(get_controller),
    user: Dict[str, Any] = Depends(get_current_user),
) -> List[TargetResponse]:
    """List all targets for a mission."""
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    await verify_mission_ownership(mission_id, user, controller)
    
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
    request: Request,
    mission_id: str,
    target_id: str,
    controller: MissionController = Depends(get_controller),
    user: Dict[str, Any] = Depends(get_current_user),
) -> TargetResponse:
    """Get a specific target."""
    try:
        validate_uuid(mission_id, "mission_id")
        validate_uuid(target_id, "target_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    await verify_mission_ownership(mission_id, user, controller)
    
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
    request: Request,
    mission_id: str,
    controller: MissionController = Depends(get_controller),
    user: Dict[str, Any] = Depends(get_current_user),
) -> List[VulnerabilityResponse]:
    """List all vulnerabilities for a mission."""
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    await verify_mission_ownership(mission_id, user, controller)
    
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
# Credential Endpoints
# ═══════════════════════════════════════════════════════════════

@router.get("/missions/{mission_id}/credentials", response_model=List[CredentialResponse])
async def list_credentials(
    request: Request,
    mission_id: str,
    controller: MissionController = Depends(get_controller),
    user: Dict[str, Any] = Depends(get_current_user),
) -> List[CredentialResponse]:
    """List all credentials for a mission."""
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    await verify_mission_ownership(mission_id, user, controller)
    
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
    request: Request,
    mission_id: str,
    controller: MissionController = Depends(get_controller),
    user: Dict[str, Any] = Depends(get_current_user),
) -> List[SessionResponse]:
    """List all active sessions for a mission."""
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    await verify_mission_ownership(mission_id, user, controller)
    
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
    request: Request,
    mission_id: str,
    controller: MissionController = Depends(get_controller),
    user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get mission statistics."""
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    await verify_mission_ownership(mission_id, user, controller)
    
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
    request: Request,
    mission_id: str,
    controller: MissionController = Depends(get_controller),
    user: Dict[str, Any] = Depends(get_current_user),
) -> List[PendingApprovalResponse]:
    """List all pending approval requests for a mission."""
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    await verify_mission_ownership(mission_id, user, controller)
    
    pending = await controller.get_pending_approvals(mission_id)
    return [PendingApprovalResponse(**p) for p in pending]


@router.post("/missions/{mission_id}/approve/{action_id}", response_model=ApprovalResponse)
async def approve_action(
    request: Request,
    mission_id: str,
    action_id: str,
    request_data: ApprovalRequest = None,
    controller: MissionController = Depends(get_controller),
    user: Dict[str, Any] = Depends(get_current_user),
) -> ApprovalResponse:
    """Approve a pending action."""
    try:
        validate_uuid(mission_id, "mission_id")
        validate_uuid(action_id, "action_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    mission_data = await verify_mission_ownership(mission_id, user, controller)
    
    user_comment = request_data.user_comment if request_data else None
    
    result = await controller.approve_action(
        mission_id=mission_id,
        action_id=action_id,
        user_comment=user_comment,
        approved_by=user.get("id")
    )
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Action {action_id} not found or does not belong to mission {mission_id}"
        )
    
    current_status = mission_data.get("status", "unknown")
    
    logger.info(f"Action {action_id} approved by user {user.get('id')}")
    
    return ApprovalResponse(
        success=True,
        message="Action approved successfully. Mission execution resumed.",
        action_id=action_id,
        mission_status=current_status
    )


@router.post("/missions/{mission_id}/reject/{action_id}", response_model=ApprovalResponse)
async def reject_action(
    request: Request,
    mission_id: str,
    action_id: str,
    request_data: RejectionRequest = None,
    controller: MissionController = Depends(get_controller),
    user: Dict[str, Any] = Depends(get_current_user),
) -> ApprovalResponse:
    """Reject a pending action."""
    try:
        validate_uuid(mission_id, "mission_id")
        validate_uuid(action_id, "action_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    mission_data = await verify_mission_ownership(mission_id, user, controller)
    
    rejection_reason = request_data.rejection_reason if request_data else None
    user_comment = request_data.user_comment if request_data else None
    
    result = await controller.reject_action(
        mission_id=mission_id,
        action_id=action_id,
        rejection_reason=rejection_reason,
        user_comment=user_comment,
        rejected_by=user.get("id")
    )
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Action {action_id} not found or does not belong to mission {mission_id}"
        )
    
    current_status = mission_data.get("status", "unknown")
    
    logger.info(f"Action {action_id} rejected by user {user.get('id')}")
    
    return ApprovalResponse(
        success=True,
        message="Action rejected. System will seek alternatives.",
        action_id=action_id,
        mission_status=current_status
    )


@router.post("/missions/{mission_id}/chat", response_model=ChatMessageResponse)
async def send_chat_message(
    request: Request,
    mission_id: str,
    request_data: ChatRequest,
    controller: MissionController = Depends(get_controller),
    user: Dict[str, Any] = Depends(get_current_user),
) -> ChatMessageResponse:
    """Send a chat message to interact with the mission."""
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    await verify_mission_ownership(mission_id, user, controller)
    
    try:
        message = await controller.send_chat_message(
            mission_id=mission_id,
            content=request_data.content,
            related_task_id=request_data.related_task_id,
            related_action_id=request_data.related_action_id,
            user_id=user.get("id")
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
        logger.error(f"Chat message error for mission {mission_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to process chat message: {str(e)}"
        )


@router.get("/missions/{mission_id}/chat", response_model=List[ChatMessageResponse])
async def get_chat_history(
    request: Request,
    mission_id: str,
    limit: int = 50,
    controller: MissionController = Depends(get_controller),
    user: Dict[str, Any] = Depends(get_current_user),
) -> List[ChatMessageResponse]:
    """Get chat history for a mission."""
    if limit <= 0:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="limit must be a positive integer greater than 0"
        )
    
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    await verify_mission_ownership(mission_id, user, controller)
    
    history = await controller.get_chat_history(mission_id, limit)
    return [ChatMessageResponse(**msg) for msg in history]


# ═══════════════════════════════════════════════════════════════
# INTEGRATION: Real-Time Statistics & Monitoring Endpoints
# ═══════════════════════════════════════════════════════════════

@router.get("/stats/system")
async def get_system_stats(
    user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Get current system-wide statistics.
    
    Requires authentication.
    """
    from ..core.stats_manager import get_stats_manager
    
    stats_manager = get_stats_manager()
    stats = await stats_manager.get_all_metrics()
    
    return {
        "status": "success",
        "data": stats,
        "timestamp": stats.get("timestamp")
    }


@router.get("/stats/retry-policies")
async def get_retry_policy_stats(
    user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get statistics for all retry policies."""
    from ..core.retry_policy import get_retry_manager
    
    retry_manager = get_retry_manager()
    
    policies_stats = {}
    for policy_name, policy in retry_manager._policies.items():
        cb = policy.circuit_breaker
        metrics = policy.metrics
        
        policies_stats[policy_name] = {
            "circuit_breaker": {
                "state": cb.state.value,
                "failure_count": cb.failure_count,
                "success_count": cb.success_count,
                "failure_threshold": cb.failure_threshold,
                "health_percentage": (
                    cb.success_count / (cb.success_count + cb.failure_count) * 100
                    if (cb.success_count + cb.failure_count) > 0 else 100.0
                )
            },
            "metrics": {
                "total_attempts": metrics.total_attempts,
                "successful_attempts": metrics.successful_attempts,
                "failed_attempts": metrics.failed_attempts,
                "avg_latency_ms": metrics.average_latency_ms,
                "success_rate": (
                    metrics.successful_attempts / metrics.total_attempts * 100
                    if metrics.total_attempts > 0 else 0.0
                )
            },
            "policy_config": {
                "max_retries": policy.max_retries,
                "base_delay": policy.base_delay,
                "max_delay": policy.max_delay,
                "strategy": policy.backoff_strategy.value
            }
        }
    
    return {
        "status": "success",
        "data": policies_stats
    }


@router.get("/stats/sessions")
async def get_session_stats(
    user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get statistics for active sessions."""
    from ..core.session_manager import get_session_manager
    from ..core.config import get_settings
    
    settings = get_settings()
    
    try:
        session_manager = get_session_manager(
            blackboard=None,
            settings=settings
        )
        
        stats = await session_manager.get_statistics()
        
        return {
            "status": "success",
            "data": stats
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to retrieve session stats: {str(e)}",
            "data": {}
        }


@router.get("/stats/circuit-breakers")
async def get_circuit_breaker_states(
    user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get current states of all circuit breakers."""
    from ..core.retry_policy import get_retry_manager, CircuitState
    
    retry_manager = get_retry_manager()
    
    states = {}
    alerts = []
    
    for policy_name, policy in retry_manager._policies.items():
        cb = policy.circuit_breaker
        state = cb.state
        
        states[policy_name] = {
            "state": state.value,
            "healthy": state == CircuitState.CLOSED,
            "failure_count": cb.failure_count,
            "success_count": cb.success_count
        }
        
        if state == CircuitState.OPEN:
            alerts.append({
                "severity": "critical",
                "policy": policy_name,
                "message": f"Circuit breaker '{policy_name}' is OPEN - System protection active"
            })
        elif state == CircuitState.HALF_OPEN:
            alerts.append({
                "severity": "warning",
                "policy": policy_name,
                "message": f"Circuit breaker '{policy_name}' is HALF-OPEN - Recovery attempt in progress"
            })
    
    return {
        "status": "success",
        "data": {
            "circuit_breakers": states,
            "alerts": alerts,
            "healthy_count": sum(1 for s in states.values() if s["healthy"]),
            "total_count": len(states)
        }
    }
