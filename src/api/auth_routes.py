# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Authentication Routes (SaaS Edition)
# PostgreSQL + Redis backed authentication with multi-tenancy
# ═══════════════════════════════════════════════════════════════
"""
Authentication system refactored for SaaS multi-tenancy.

Changes from v2.x:
- Replaced in-memory UserStore with PostgreSQL UserRepository
- Replaced in-memory token storage with Redis TokenStore
- Added organization_id isolation for all operations
- Added Stripe billing integration hooks

Architecture:
- PostgreSQL: User data, organizations, persistent storage
- Redis: JWT tokens, sessions, real-time data
- Every user belongs to an organization (multi-tenancy)
"""

import logging
import secrets
import asyncio
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from enum import Enum
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, Depends, status, BackgroundTasks, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr, field_validator
import jwt
import bcrypt

from ..core.config import get_settings
from ..core.database import UserRepository, OrganizationRepository
from ..core.database.user_repository import User
from ..core.database.organization_repository import Organization
from ..core.token_store import TokenStore, get_token_store, init_token_store


logger = logging.getLogger("raglox.api.auth")
router = APIRouter(prefix="/auth", tags=["Authentication"])

# Security scheme
security = HTTPBearer(auto_error=False)


# ═══════════════════════════════════════════════════════════════
# Enums
# ═══════════════════════════════════════════════════════════════

class UserRole(str, Enum):
    """User roles"""
    ADMIN = "admin"
    OPERATOR = "operator"
    ANALYST = "analyst"
    VIEWER = "viewer"


class UserStatus(str, Enum):
    """User account status"""
    PENDING = "pending"           # Awaiting email verification
    PROVISIONING = "provisioning" # VM being created
    ACTIVE = "active"             # Fully active
    SUSPENDED = "suspended"       # Temporarily disabled
    DELETED = "deleted"           # Soft deleted


class VMProvisionStatus(str, Enum):
    """VM provisioning status"""
    PENDING = "pending"
    CREATING = "creating"
    CONFIGURING = "configuring"
    READY = "ready"
    FAILED = "failed"


# ═══════════════════════════════════════════════════════════════
# Pydantic Models
# ═══════════════════════════════════════════════════════════════

class VMConfiguration(BaseModel):
    """VM configuration for user environment"""
    plan: str = Field(default="8GB-2CORE", description="VM plan (8GB-2CORE, 16GB-4CORE, etc.)")
    location: str = Field(default="us-east", description="Datacenter location")
    os: str = Field(default="ubuntu-22.04", description="Operating system")


class RegisterRequest(BaseModel):
    """User registration request"""
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., min_length=8, max_length=128, description="User password")
    full_name: str = Field(..., min_length=2, max_length=100, description="User full name")
    organization_name: Optional[str] = Field(None, max_length=100, description="Organization name (creates new org)")
    invite_code: Optional[str] = Field(None, description="Invitation code to join existing org")
    vm_config: Optional[VMConfiguration] = Field(default_factory=VMConfiguration, description="VM configuration")
    
    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        """Validate password strength"""
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v


class LoginRequest(BaseModel):
    """User login request"""
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., description="User password")
    remember_me: bool = Field(default=False, description="Extend session duration")


class TokenResponse(BaseModel):
    """Authentication token response"""
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds
    user: "UserResponse"


class UserResponse(BaseModel):
    """User response model"""
    id: str
    email: str
    full_name: Optional[str]
    organization_id: str
    organization_name: Optional[str] = None
    role: str
    status: str
    vm_status: Optional[str] = None
    vm_ip: Optional[str] = None
    created_at: datetime
    last_login: Optional[datetime] = None


class UserProfileUpdate(BaseModel):
    """User profile update request"""
    full_name: Optional[str] = Field(None, min_length=2, max_length=100)


class PasswordChangeRequest(BaseModel):
    """Password change request"""
    current_password: str = Field(..., description="Current password")
    new_password: str = Field(..., min_length=8, max_length=128, description="New password")
    
    @field_validator("new_password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        """Validate password strength"""
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v


# ═══════════════════════════════════════════════════════════════
# Helper Functions: Repository Access
# ═══════════════════════════════════════════════════════════════

def get_user_repo(request: Request) -> UserRepository:
    """Get UserRepository from app state."""
    repo = getattr(request.app.state, 'user_repo', None)
    if not repo:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database service unavailable"
        )
    return repo


def get_org_repo(request: Request) -> OrganizationRepository:
    """Get OrganizationRepository from app state."""
    repo = getattr(request.app.state, 'org_repo', None)
    if not repo:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database service unavailable"
        )
    return repo


async def get_token_store_from_request(request: Request) -> TokenStore:
    """Get TokenStore from app state."""
    store = getattr(request.app.state, 'token_store', None)
    if not store:
        # Fallback: try to get from global
        store = get_token_store()
    if not store:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Token service unavailable"
        )
    return store


# ═══════════════════════════════════════════════════════════════
# JWT Utilities
# ═══════════════════════════════════════════════════════════════

async def create_access_token(
    user_id: str,
    organization_id: str,
    token_store: TokenStore,
    expires_hours: int = None
) -> tuple[str, int]:
    """
    Create JWT access token and store in Redis.
    
    Args:
        user_id: User UUID string
        organization_id: Organization UUID string
        token_store: Redis token store
        expires_hours: Token validity in hours
        
    Returns:
        Tuple of (token, expires_in_seconds)
    """
    settings = get_settings()
    
    if expires_hours is None:
        expires_hours = settings.jwt_expiration_hours
    
    expires_delta = timedelta(hours=expires_hours)
    expire = datetime.utcnow() + expires_delta
    expires_seconds = int(expires_delta.total_seconds())
    
    payload = {
        "sub": user_id,
        "org": organization_id,  # Include org for quick access
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "access",
    }
    
    token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    
    # Store token in Redis
    await token_store.store_token(token, user_id, expires_seconds)
    
    return token, expires_seconds


def decode_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode and validate JWT token."""
    settings = get_settings()
    
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm]
        )
        return payload
    except jwt.ExpiredSignatureError:
        logger.warning("Token expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid token: {e}")
        return None


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> Dict[str, Any]:
    """
    Get current authenticated user.
    
    Returns user dict with organization_id for downstream use.
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = credentials.credentials
    
    # Get token store
    token_store = getattr(request.app.state, 'token_store', None) or get_token_store()
    if not token_store:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service unavailable"
        )
    
    # Validate token in Redis
    stored_user_id = await token_store.validate_token(token)
    if not stored_user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked or is invalid",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Decode JWT
    payload = decode_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user_id = payload.get("sub")
    org_id = payload.get("org")
    
    # Get user from PostgreSQL
    user_repo = get_user_repo(request)
    
    try:
        user_uuid = UUID(user_id)
        org_uuid = UUID(org_id) if org_id else None
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token data"
        )
    
    user = await user_repo.get_by_id(user_uuid, org_uuid)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is suspended",
        )
    
    # Return as dict for compatibility
    return {
        "id": str(user.id),
        "organization_id": str(user.organization_id),
        "email": user.email,
        "username": user.username,
        "full_name": user.full_name,
        "role": user.role,
        "is_active": user.is_active,
        "is_superuser": user.is_superuser,
        "is_org_owner": user.is_org_owner,
        "last_login_at": user.last_login_at,
        "created_at": user.created_at,
        "metadata": user.metadata or {},
    }


async def get_optional_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> Optional[Dict[str, Any]]:
    """Get current user if authenticated, None otherwise."""
    if not credentials:
        return None
    
    try:
        return await get_current_user(request, credentials)
    except HTTPException:
        return None


def require_role(*roles: str):
    """Dependency to require specific roles."""
    async def role_checker(
        request: Request,
        credentials: HTTPAuthorizationCredentials = Depends(security)
    ):
        user = await get_current_user(request, credentials)
        if user["role"] not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of roles: {list(roles)}",
            )
        return user
    return role_checker


def require_org_owner():
    """Dependency to require organization owner."""
    async def owner_checker(
        request: Request,
        credentials: HTTPAuthorizationCredentials = Depends(security)
    ):
        user = await get_current_user(request, credentials)
        if not user.get("is_org_owner") and not user.get("is_superuser"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Organization owner privileges required",
            )
        return user
    return owner_checker


# ═══════════════════════════════════════════════════════════════
# VM Provisioning (Background Task)
# ═══════════════════════════════════════════════════════════════

async def provision_user_vm(
    user_id: str,
    organization_id: str,
    vm_config: VMConfiguration,
    user_repo: UserRepository
):
    """
    Background task to provision VM for new user.
    Uses OneProvider integration.
    """
    logger.info(f"Starting VM provisioning for user {user_id}")
    
    try:
        user_uuid = UUID(user_id)
        org_uuid = UUID(organization_id)
        
        # Update status to provisioning
        await user_repo.update(user_uuid, {
            "metadata": {"vm_status": VMProvisionStatus.CREATING.value}
        }, org_uuid)
        
        settings = get_settings()
        
        # Check if OneProvider is enabled
        if not settings.oneprovider_enabled:
            logger.warning("OneProvider not enabled, skipping VM provisioning")
            await user_repo.update(user_uuid, {
                "metadata": {"vm_status": None}
            }, org_uuid)
            return
        
        # Import VM manager
        from ..infrastructure.cloud_provider.vm_manager import VMManager, VMConfiguration as VMConfig
        from ..infrastructure.cloud_provider.oneprovider_client import OneProviderClient
        
        # Create client
        client = OneProviderClient(
            api_key=settings.oneprovider_api_key,
            client_key=settings.oneprovider_client_key,
        )
        
        vm_manager = VMManager(
            client=client,
            default_project_uuid=settings.oneprovider_project_uuid,
        )
        
        # Create VM configuration
        hostname = f"raglox-{user_id[:8]}"
        
        # Generate secure password for SSH access
        import secrets
        import string
        vm_password = ''.join(secrets.choice(string.ascii_letters + string.digits + "!@#$%") for _ in range(24))
        
        # Use settings values instead of vm_config to ensure correct OneProvider values
        config = VMConfig(
            hostname=hostname,
            plan_id=settings.oneprovider_default_plan,  # Use settings value (86)
            os_id=settings.oneprovider_default_os,      # Use settings value (1197)
            location_id=settings.oneprovider_default_location,  # Use settings value (34)
            password=vm_password,  # SSH password for VM access
            tags={"user_id": user_id, "org_id": organization_id, "managed_by": "raglox"},
        )
        
        # Update status
        await user_repo.update(user_uuid, {
            "metadata": {"vm_status": VMProvisionStatus.CREATING.value}
        }, org_uuid)
        
        # Create VM
        vm_instance = await vm_manager.create_vm(config)
        
        if vm_instance:
            # Wait for VM to be ready
            await user_repo.update(user_uuid, {
                "metadata": {"vm_status": VMProvisionStatus.CONFIGURING.value}
            }, org_uuid)
            
            # Poll for ready state with IP assignment
            # Wait initial time for VM to become available in API
            await asyncio.sleep(15)  # Give OneProvider time to register the VM
            
            vm_ready = False
            for attempt in range(60):  # 5 minutes max
                await asyncio.sleep(5)
                try:
                    # Refresh VM instance to get updated status
                    refreshed_vm = await vm_manager.get_vm(vm_instance.vm_id)
                    if refreshed_vm and (refreshed_vm.ipv4 or refreshed_vm.ipv6):
                        vm_instance = refreshed_vm
                        vm_ready = True
                        break
                except Exception as e:
                    # VM might not be available in API yet, continue waiting
                    logger.debug(f"VM not yet available (attempt {attempt+1}/60): {e}")
                    continue
            
            if vm_ready:
                # Update user with VM details including SSH credentials
                # Note: In production, consider encrypting the password before storage
                vm_ip = vm_instance.ipv4 or vm_instance.ipv6  # Use IPv4 if available, otherwise IPv6
                await user_repo.update(user_uuid, {
                    "metadata": {
                        "vm_status": VMProvisionStatus.READY.value,
                        "vm_id": vm_instance.vm_id,
                        "vm_ip": vm_ip,
                        "vm_ssh_user": "root",  # Default SSH user for OneProvider VMs
                        "vm_ssh_password": vm_password,  # Store password for SSH access
                        "vm_ssh_port": 22,
                    }
                }, org_uuid)
                
                logger.info(f"VM provisioned for user {user_id}: {vm_ip}")
            else:
                raise Exception("VM created but failed to get IP address within timeout")
        else:
            raise Exception("VM creation returned None")
            
    except Exception as e:
        logger.error(f"VM provisioning failed for user {user_id}: {e}")
        try:
            await user_repo.update(UUID(user_id), {
                "metadata": {"vm_status": VMProvisionStatus.FAILED.value}
            }, UUID(organization_id))
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════
# Routes
# ═══════════════════════════════════════════════════════════════

@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(
    request: Request,
    data: RegisterRequest,
    background_tasks: BackgroundTasks,
):
    """
    Register a new user account.
    
    - Creates organization if organization_name provided
    - Joins existing organization if invite_code provided
    - Creates user account
    - Provisions VM in background (8GB RAM, 2 Core by default)
    - Returns access token
    """
    user_repo = get_user_repo(request)
    org_repo = get_org_repo(request)
    token_store = await get_token_store_from_request(request)
    
    # Check if email already exists globally
    existing = await user_repo.get_by_email_global(data.email)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )
    
    organization_id: UUID
    org_name: str = "Personal"
    is_org_owner: bool = False
    
    # Determine organization
    if data.invite_code:
        # Join existing organization via invite
        invitation = await org_repo.get_pending_invitation_by_code(data.invite_code)
        if not invitation:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired invitation code"
            )
        organization_id = invitation["organization_id"]
        org = await org_repo.get_by_id(organization_id)
        org_name = org.name if org else "Organization"
        
        # Mark invitation as used
        await org_repo.accept_invitation_by_code(data.invite_code, data.email)
        
    elif data.organization_name:
        # Create new organization
        org_id = uuid4()
        new_org = Organization(
            id=org_id,
            name=data.organization_name,
            slug=data.organization_name.lower().replace(" ", "-"),
            owner_email=data.email,
            plan="free",
            is_active=True,
        )
        created_org = await org_repo.create(new_org)
        organization_id = created_org.id
        org_name = created_org.name
        is_org_owner = True
        
    else:
        # Create personal organization
        org_id = uuid4()
        personal_org = Organization(
            id=org_id,
            name=f"{data.full_name}'s Workspace",
            slug=f"personal-{secrets.token_hex(4)}",
            owner_email=data.email,
            plan="free",
            is_active=True,
        )
        created_org = await org_repo.create(personal_org)
        organization_id = created_org.id
        org_name = created_org.name
        is_org_owner = True
    
    # Hash password
    password_hash = bcrypt.hashpw(data.password.encode(), bcrypt.gensalt()).decode()
    
    # Create user
    user_id = uuid4()
    new_user = User(
        id=user_id,
        organization_id=organization_id,
        username=data.email.split("@")[0],
        email=data.email.lower(),
        password_hash=password_hash,
        full_name=data.full_name,
        role="admin" if is_org_owner else "operator",
        is_active=True,
        is_org_owner=is_org_owner,
        metadata={"vm_status": VMProvisionStatus.PENDING.value},
    )
    
    user = await user_repo.create(new_user)
    
    # Create access token
    access_token, expires_in = await create_access_token(
        str(user.id),
        str(user.organization_id),
        token_store
    )
    
    # Start VM provisioning in background
    vm_config = data.vm_config or VMConfiguration()
    background_tasks.add_task(
        provision_user_vm,
        str(user.id),
        str(user.organization_id),
        vm_config,
        user_repo
    )
    
    logger.info(f"New user registered: {user.email} in org {org_name}")
    
    return TokenResponse(
        access_token=access_token,
        expires_in=expires_in,
        user=UserResponse(
            id=str(user.id),
            email=user.email,
            full_name=user.full_name,
            organization_id=str(user.organization_id),
            organization_name=org_name,
            role=user.role,
            status="pending",
            vm_status=user.metadata.get("vm_status") if user.metadata else None,
            vm_ip=user.metadata.get("vm_ip") if user.metadata else None,
            created_at=user.created_at or datetime.utcnow(),
            last_login=None,
        ),
    )


@router.post("/login", response_model=TokenResponse)
async def login(request: Request, data: LoginRequest):
    """
    Authenticate user and return access token.
    """
    user_repo = get_user_repo(request)
    org_repo = get_org_repo(request)
    token_store = await get_token_store_from_request(request)
    
    # Get user by email (global search for login)
    user = await user_repo.get_by_email_global(data.email)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    
    # Check if account is locked
    if user.is_locked():
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Account is temporarily locked. Please try again later.",
        )
    
    # Verify password
    if not bcrypt.checkpw(data.password.encode(), user.password_hash.encode()):
        # Record failed attempt
        is_locked = await user_repo.record_failed_login(user.id)
        
        if is_locked:
            logger.warning(f"Account locked due to failed attempts: {user.email}")
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    
    # Check account status
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is suspended. Please contact support.",
        )
    
    # Record successful login
    client_ip = request.client.host if request.client else "unknown"
    await user_repo.record_login(user.id, client_ip)
    
    # Get organization name
    org = await org_repo.get_by_id(user.organization_id)
    org_name = org.name if org else "Organization"
    
    # Create access token (extended if remember_me)
    expires_hours = 168 if data.remember_me else None  # 7 days if remember me
    access_token, expires_in = await create_access_token(
        str(user.id),
        str(user.organization_id),
        token_store,
        expires_hours
    )
    
    logger.info(f"User logged in: {user.email}")
    
    return TokenResponse(
        access_token=access_token,
        expires_in=expires_in,
        user=UserResponse(
            id=str(user.id),
            email=user.email,
            full_name=user.full_name,
            organization_id=str(user.organization_id),
            organization_name=org_name,
            role=user.role,
            status="active" if user.is_active else "suspended",
            vm_status=user.metadata.get("vm_status") if user.metadata else None,
            vm_ip=user.metadata.get("vm_ip") if user.metadata else None,
            created_at=user.created_at or datetime.utcnow(),
            last_login=datetime.utcnow(),
        ),
    )


@router.post("/logout")
async def logout(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Logout and invalidate current access token.
    """
    token = credentials.credentials
    token_store = await get_token_store_from_request(request)
    
    await token_store.revoke_token(token)
    
    logger.info(f"User logged out: {user['email']}")
    
    return {"message": "Successfully logged out"}


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    request: Request,
    user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get current user information.
    """
    org_repo = get_org_repo(request)
    org = await org_repo.get_by_id(UUID(user["organization_id"]))
    org_name = org.name if org else "Organization"
    
    return UserResponse(
        id=user["id"],
        email=user["email"],
        full_name=user.get("full_name"),
        organization_id=user["organization_id"],
        organization_name=org_name,
        role=user["role"],
        status="active" if user.get("is_active", True) else "suspended",
        vm_status=user.get("metadata", {}).get("vm_status"),
        vm_ip=user.get("metadata", {}).get("vm_ip"),
        created_at=user.get("created_at") or datetime.utcnow(),
        last_login=user.get("last_login_at"),
    )


@router.put("/me", response_model=UserResponse)
async def update_profile(
    request: Request,
    updates: UserProfileUpdate,
    user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Update current user profile.
    """
    user_repo = get_user_repo(request)
    org_repo = get_org_repo(request)
    
    update_data = {}
    
    if updates.full_name is not None:
        update_data["full_name"] = updates.full_name
    
    if update_data:
        updated_user = await user_repo.update(
            UUID(user["id"]),
            update_data,
            UUID(user["organization_id"])
        )
        if updated_user:
            user["full_name"] = updated_user.full_name
    
    org = await org_repo.get_by_id(UUID(user["organization_id"]))
    org_name = org.name if org else "Organization"
    
    return UserResponse(
        id=user["id"],
        email=user["email"],
        full_name=user.get("full_name"),
        organization_id=user["organization_id"],
        organization_name=org_name,
        role=user["role"],
        status="active" if user.get("is_active", True) else "suspended",
        vm_status=user.get("metadata", {}).get("vm_status"),
        vm_ip=user.get("metadata", {}).get("vm_ip"),
        created_at=user.get("created_at") or datetime.utcnow(),
        last_login=user.get("last_login_at"),
    )


@router.post("/change-password")
async def change_password(
    request: Request,
    data: PasswordChangeRequest,
    user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Change current user password.
    """
    user_repo = get_user_repo(request)
    token_store = await get_token_store_from_request(request)
    
    # Get full user with password hash
    full_user = await user_repo.get_by_id(
        UUID(user["id"]),
        UUID(user["organization_id"])
    )
    
    if not full_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Verify current password
    if not bcrypt.checkpw(data.current_password.encode(), full_user.password_hash.encode()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect",
        )
    
    # Hash new password
    new_hash = bcrypt.hashpw(data.new_password.encode(), bcrypt.gensalt()).decode()
    
    # Update password
    await user_repo.update_password(full_user.id, new_hash)
    
    # Revoke all existing tokens (force re-login)
    await token_store.revoke_all_user_tokens(user["id"])
    
    logger.info(f"Password changed for user: {user['email']}")
    
    return {"message": "Password changed successfully. Please login again."}


@router.get("/vm/status")
async def get_vm_status(
    request: Request,
    user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get current user's VM provisioning status.
    """
    metadata = user.get("metadata", {})
    
    return {
        "vm_status": metadata.get("vm_status"),
        "vm_id": metadata.get("vm_id"),
        "vm_ip": metadata.get("vm_ip"),
        "message": _get_vm_status_message(metadata.get("vm_status")),
    }


def _get_vm_status_message(status: Optional[str]) -> str:
    """Get human-readable VM status message"""
    if status is None:
        return "VM not provisioned"
    
    messages = {
        VMProvisionStatus.PENDING.value: "VM provisioning queued",
        VMProvisionStatus.CREATING.value: "Creating your VM instance...",
        VMProvisionStatus.CONFIGURING.value: "Configuring VM environment...",
        VMProvisionStatus.READY.value: "VM is ready to use",
        VMProvisionStatus.FAILED.value: "VM provisioning failed. Please contact support.",
    }
    return messages.get(status, "Unknown status")


@router.post("/vm/reprovision")
async def reprovision_vm(
    request: Request,
    background_tasks: BackgroundTasks,
    vm_config: Optional[VMConfiguration] = None,
    user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Re-provision user's VM (if failed or needs reset).
    """
    metadata = user.get("metadata", {})
    
    if metadata.get("vm_status") == VMProvisionStatus.CREATING.value:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="VM is currently being provisioned",
        )
    
    user_repo = get_user_repo(request)
    
    # Reset VM status
    await user_repo.update(
        UUID(user["id"]),
        {"metadata": {"vm_status": VMProvisionStatus.PENDING.value, "vm_id": None, "vm_ip": None}},
        UUID(user["organization_id"])
    )
    
    # Start provisioning
    config = vm_config or VMConfiguration()
    background_tasks.add_task(
        provision_user_vm,
        user["id"],
        user["organization_id"],
        config,
        user_repo
    )
    
    return {"message": "VM re-provisioning started"}


# ═══════════════════════════════════════════════════════════════
# Admin Routes (Organization-scoped)
# ═══════════════════════════════════════════════════════════════

@router.get("/admin/users", response_model=List[UserResponse])
async def list_organization_users(
    request: Request,
    user: Dict[str, Any] = Depends(require_role("admin")),
):
    """
    List all users in the current organization (Admin only).
    
    Note: This is organization-scoped, not global.
    """
    user_repo = get_user_repo(request)
    org_repo = get_org_repo(request)
    
    org_id = UUID(user["organization_id"])
    
    users = await user_repo.get_organization_users(org_id)
    org = await org_repo.get_by_id(org_id)
    org_name = org.name if org else "Organization"
    
    return [
        UserResponse(
            id=str(u.id),
            email=u.email,
            full_name=u.full_name,
            organization_id=str(u.organization_id),
            organization_name=org_name,
            role=u.role,
            status="active" if u.is_active else "suspended",
            vm_status=u.metadata.get("vm_status") if u.metadata else None,
            vm_ip=u.metadata.get("vm_ip") if u.metadata else None,
            created_at=u.created_at or datetime.utcnow(),
            last_login=u.last_login_at,
        )
        for u in users
    ]


@router.put("/admin/users/{user_id}/status")
async def update_user_status(
    request: Request,
    user_id: str,
    new_status: str,  # "active" or "suspended"
    admin: Dict[str, Any] = Depends(require_role("admin")),
):
    """
    Update user status within organization (Admin only).
    """
    user_repo = get_user_repo(request)
    token_store = await get_token_store_from_request(request)
    
    org_id = UUID(admin["organization_id"])
    target_user_id = UUID(user_id)
    
    # Get target user (must be in same org)
    target_user = await user_repo.get_by_id(target_user_id, org_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found in your organization")
    
    # Prevent self-suspension
    if admin["id"] == user_id and new_status == "suspended":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot suspend your own account",
        )
    
    # Update status
    is_active = new_status == "active"
    await user_repo.update(target_user_id, {"is_active": is_active}, org_id)
    
    # Revoke tokens if suspending
    if not is_active:
        await token_store.revoke_all_user_tokens(user_id)
    
    logger.info(f"Admin {admin['email']} changed user {user_id} status to {new_status}")
    
    return {"message": f"User status updated to {new_status}"}


@router.put("/admin/users/{user_id}/role")
async def update_user_role(
    request: Request,
    user_id: str,
    new_role: str,  # admin, operator, analyst, viewer
    admin: Dict[str, Any] = Depends(require_role("admin")),
):
    """
    Update user role within organization (Admin only).
    """
    user_repo = get_user_repo(request)
    
    org_id = UUID(admin["organization_id"])
    target_user_id = UUID(user_id)
    
    # Get target user (must be in same org)
    target_user = await user_repo.get_by_id(target_user_id, org_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found in your organization")
    
    # Validate role
    valid_roles = ["admin", "operator", "analyst", "viewer"]
    if new_role not in valid_roles:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role. Must be one of: {valid_roles}"
        )
    
    await user_repo.update_role(target_user_id, org_id, new_role)
    
    logger.info(f"Admin {admin['email']} changed user {user_id} role to {new_role}")
    
    return {"message": f"User role updated to {new_role}"}


# ═══════════════════════════════════════════════════════════════
# Organization Management Routes
# ═══════════════════════════════════════════════════════════════

@router.get("/organization")
async def get_organization_info(
    request: Request,
    user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Get current user's organization information.
    """
    org_repo = get_org_repo(request)
    
    org = await org_repo.get_by_id(UUID(user["organization_id"]))
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    return {
        "id": str(org.id),
        "name": org.name,
        "slug": org.slug,
        "plan": org.plan,
        "is_active": org.is_active,
        "created_at": org.created_at,
        "settings": org.settings or {},
    }


@router.post("/organization/invite")
async def invite_user_to_organization(
    request: Request,
    email: EmailStr,
    role: str = "operator",
    admin: Dict[str, Any] = Depends(require_role("admin")),
):
    """
    Invite a user to join the organization (Admin only).
    """
    org_repo = get_org_repo(request)
    user_repo = get_user_repo(request)
    
    org_id = UUID(admin["organization_id"])
    
    # Check if user already exists in this org
    existing = await user_repo.get_by_email(org_id, email)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User already exists in this organization"
        )
    
    # Create invitation
    invite_code = secrets.token_urlsafe(32)
    await org_repo.create_invitation(
        organization_id=org_id,
        email=email,
        role=role,
        token=invite_code,
        invited_by=UUID(admin["id"]),
    )
    
    logger.info(f"Invitation sent to {email} for org {org_id}")
    
    return {
        "message": f"Invitation sent to {email}",
        "invite_code": invite_code,  # In production, send this via email
    }
