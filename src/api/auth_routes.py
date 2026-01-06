# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Authentication Routes
# Complete authentication system with user management and VM provisioning
# ═══════════════════════════════════════════════════════════════

import logging
import secrets
import asyncio
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from enum import Enum

from fastapi import APIRouter, HTTPException, Depends, status, BackgroundTasks, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr, field_validator
import jwt
import bcrypt

from ..core.config import get_settings


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
    organization: Optional[str] = Field(None, max_length=100, description="Organization name")
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
    full_name: str
    organization: Optional[str]
    role: UserRole
    status: UserStatus
    vm_status: Optional[VMProvisionStatus]
    vm_ip: Optional[str]
    created_at: datetime
    last_login: Optional[datetime]


class UserProfileUpdate(BaseModel):
    """User profile update request"""
    full_name: Optional[str] = Field(None, min_length=2, max_length=100)
    organization: Optional[str] = Field(None, max_length=100)


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
# In-Memory User Store (Production should use PostgreSQL)
# ═══════════════════════════════════════════════════════════════

class UserStore:
    """
    In-memory user store for development.
    In production, this should be replaced with PostgreSQL/Redis.
    """
    
    def __init__(self):
        self._users: Dict[str, Dict[str, Any]] = {}
        self._email_index: Dict[str, str] = {}  # email -> user_id
        self._tokens: Dict[str, str] = {}  # token -> user_id
        self._refresh_tokens: Dict[str, str] = {}  # refresh_token -> user_id
        
        # Create default admin user
        self._create_default_admin()
    
    def _create_default_admin(self):
        """Create default admin user for initial access"""
        settings = get_settings()
        admin_id = "admin-001"
        admin_email = "admin@raglox.io"
        
        # Hash default password
        password_hash = bcrypt.hashpw("Admin@123".encode(), bcrypt.gensalt()).decode()
        
        self._users[admin_id] = {
            "id": admin_id,
            "email": admin_email,
            "password_hash": password_hash,
            "full_name": "System Administrator",
            "organization": "RAGLOX",
            "role": UserRole.ADMIN,
            "status": UserStatus.ACTIVE,
            "vm_status": None,
            "vm_id": None,
            "vm_ip": None,
            "created_at": datetime.utcnow(),
            "last_login": None,
            "login_attempts": 0,
            "locked_until": None,
        }
        self._email_index[admin_email] = admin_id
        
        logger.info(f"Default admin user created: {admin_email}")
    
    def get_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Get user by email"""
        user_id = self._email_index.get(email.lower())
        if user_id:
            return self._users.get(user_id)
        return None
    
    def get_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user by ID"""
        return self._users.get(user_id)
    
    def create(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new user"""
        user_id = f"user-{secrets.token_hex(8)}"
        user_data["id"] = user_id
        user_data["created_at"] = datetime.utcnow()
        user_data["last_login"] = None
        user_data["login_attempts"] = 0
        user_data["locked_until"] = None
        
        self._users[user_id] = user_data
        self._email_index[user_data["email"].lower()] = user_id
        
        return user_data
    
    def update(self, user_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Update user"""
        if user_id not in self._users:
            return None
        
        self._users[user_id].update(updates)
        return self._users[user_id]
    
    def list_all(self) -> List[Dict[str, Any]]:
        """List all users"""
        return list(self._users.values())
    
    def store_token(self, token: str, user_id: str):
        """Store active token"""
        self._tokens[token] = user_id
    
    def validate_token(self, token: str) -> Optional[str]:
        """Validate token and return user_id"""
        return self._tokens.get(token)
    
    def revoke_token(self, token: str):
        """Revoke token"""
        self._tokens.pop(token, None)
    
    def revoke_all_user_tokens(self, user_id: str):
        """Revoke all tokens for a user"""
        tokens_to_remove = [t for t, uid in self._tokens.items() if uid == user_id]
        for token in tokens_to_remove:
            del self._tokens[token]


# Global user store instance
user_store = UserStore()


# ═══════════════════════════════════════════════════════════════
# JWT Utilities
# ═══════════════════════════════════════════════════════════════

def create_access_token(user_id: str, expires_hours: int = None) -> tuple[str, int]:
    """Create JWT access token"""
    settings = get_settings()
    
    if expires_hours is None:
        expires_hours = settings.jwt_expiration_hours
    
    expires_delta = timedelta(hours=expires_hours)
    expire = datetime.utcnow() + expires_delta
    
    payload = {
        "sub": user_id,
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "access",
    }
    
    token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    
    # Store token for validation
    user_store.store_token(token, user_id)
    
    return token, int(expires_delta.total_seconds())


def decode_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode and validate JWT token"""
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
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> Dict[str, Any]:
    """Get current authenticated user"""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = credentials.credentials
    
    # Check if token is valid and not revoked
    stored_user_id = user_store.validate_token(token)
    if not stored_user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked or is invalid",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Decode token
    payload = decode_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user_id = payload.get("sub")
    user = user_store.get_by_id(user_id)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if user["status"] == UserStatus.SUSPENDED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is suspended",
        )
    
    if user["status"] == UserStatus.DELETED:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account has been deleted",
        )
    
    return user


async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> Optional[Dict[str, Any]]:
    """Get current user if authenticated, None otherwise"""
    if not credentials:
        return None
    
    try:
        return await get_current_user(credentials)
    except HTTPException:
        return None


def require_role(*roles: UserRole):
    """Dependency to require specific roles"""
    async def role_checker(user: Dict[str, Any] = Depends(get_current_user)):
        if user["role"] not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of roles: {[r.value for r in roles]}",
            )
        return user
    return role_checker


# ═══════════════════════════════════════════════════════════════
# VM Provisioning (Background Task)
# ═══════════════════════════════════════════════════════════════

async def provision_user_vm(user_id: str, vm_config: VMConfiguration):
    """
    Background task to provision VM for new user.
    Uses OneProvider integration.
    """
    logger.info(f"Starting VM provisioning for user {user_id}")
    
    try:
        # Update status to provisioning
        user_store.update(user_id, {
            "status": UserStatus.PROVISIONING,
            "vm_status": VMProvisionStatus.CREATING,
        })
        
        settings = get_settings()
        
        # Check if OneProvider is enabled
        if not settings.oneprovider_enabled:
            logger.warning("OneProvider not enabled, skipping VM provisioning")
            user_store.update(user_id, {
                "status": UserStatus.ACTIVE,
                "vm_status": None,
            })
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
        user = user_store.get_by_id(user_id)
        hostname = f"raglox-{user_id[:8]}"
        
        config = VMConfig(
            hostname=hostname,
            plan_id=vm_config.plan,
            os_id=vm_config.os,
            location_id=vm_config.location,
            tags={"user_id": user_id, "managed_by": "raglox"},
        )
        
        # Update status
        user_store.update(user_id, {"vm_status": VMProvisionStatus.CREATING})
        
        # Create VM
        vm_instance = await vm_manager.create_vm(config)
        
        if vm_instance:
            # Wait for VM to be ready
            user_store.update(user_id, {"vm_status": VMProvisionStatus.CONFIGURING})
            
            # Poll for ready state
            for _ in range(60):  # 5 minutes max
                await asyncio.sleep(5)
                status = await vm_manager.get_vm_status(vm_instance.vm_id)
                if status and status.ipv4:
                    break
            
            # Update user with VM details
            user_store.update(user_id, {
                "status": UserStatus.ACTIVE,
                "vm_status": VMProvisionStatus.READY,
                "vm_id": vm_instance.vm_id,
                "vm_ip": vm_instance.ipv4,
            })
            
            logger.info(f"VM provisioned for user {user_id}: {vm_instance.ipv4}")
        else:
            raise Exception("VM creation returned None")
            
    except Exception as e:
        logger.error(f"VM provisioning failed for user {user_id}: {e}")
        user_store.update(user_id, {
            "status": UserStatus.ACTIVE,  # Allow access even if VM failed
            "vm_status": VMProvisionStatus.FAILED,
        })


# ═══════════════════════════════════════════════════════════════
# Routes
# ═══════════════════════════════════════════════════════════════

@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(
    request: RegisterRequest,
    background_tasks: BackgroundTasks,
):
    """
    Register a new user account.
    
    - Creates user account
    - Provisions VM in background (8GB RAM, 2 Core by default)
    - Returns access token
    """
    # Check if email already exists
    existing = user_store.get_by_email(request.email)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )
    
    # Hash password
    password_hash = bcrypt.hashpw(request.password.encode(), bcrypt.gensalt()).decode()
    
    # Create user
    user_data = {
        "email": request.email.lower(),
        "password_hash": password_hash,
        "full_name": request.full_name,
        "organization": request.organization,
        "role": UserRole.OPERATOR,  # Default role
        "status": UserStatus.PENDING,
        "vm_status": VMProvisionStatus.PENDING,
        "vm_id": None,
        "vm_ip": None,
    }
    
    user = user_store.create(user_data)
    
    # Create access token
    access_token, expires_in = create_access_token(user["id"])
    
    # Start VM provisioning in background
    vm_config = request.vm_config or VMConfiguration()
    background_tasks.add_task(provision_user_vm, user["id"], vm_config)
    
    logger.info(f"New user registered: {user['email']}")
    
    return TokenResponse(
        access_token=access_token,
        expires_in=expires_in,
        user=UserResponse(
            id=user["id"],
            email=user["email"],
            full_name=user["full_name"],
            organization=user["organization"],
            role=user["role"],
            status=user["status"],
            vm_status=user["vm_status"],
            vm_ip=user["vm_ip"],
            created_at=user["created_at"],
            last_login=user["last_login"],
        ),
    )


@router.post("/login", response_model=TokenResponse)
async def login(request: LoginRequest):
    """
    Authenticate user and return access token.
    """
    # Get user by email
    user = user_store.get_by_email(request.email)
    
    if not user:
        # Use same error message to prevent user enumeration
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    
    # Check if account is locked
    if user.get("locked_until") and user["locked_until"] > datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Account is temporarily locked. Please try again later.",
        )
    
    # Verify password
    if not bcrypt.checkpw(request.password.encode(), user["password_hash"].encode()):
        # Increment failed attempts
        attempts = user.get("login_attempts", 0) + 1
        updates = {"login_attempts": attempts}
        
        # Lock account after 5 failed attempts
        if attempts >= 5:
            updates["locked_until"] = datetime.utcnow() + timedelta(minutes=15)
            logger.warning(f"Account locked due to failed attempts: {user['email']}")
        
        user_store.update(user["id"], updates)
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    
    # Check account status
    if user["status"] == UserStatus.SUSPENDED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is suspended. Please contact support.",
        )
    
    if user["status"] == UserStatus.DELETED:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account has been deleted",
        )
    
    # Reset failed attempts and update last login
    user_store.update(user["id"], {
        "login_attempts": 0,
        "locked_until": None,
        "last_login": datetime.utcnow(),
    })
    
    # Create access token (extended if remember_me)
    expires_hours = 168 if request.remember_me else None  # 7 days if remember me
    access_token, expires_in = create_access_token(user["id"], expires_hours)
    
    logger.info(f"User logged in: {user['email']}")
    
    return TokenResponse(
        access_token=access_token,
        expires_in=expires_in,
        user=UserResponse(
            id=user["id"],
            email=user["email"],
            full_name=user["full_name"],
            organization=user["organization"],
            role=user["role"],
            status=user["status"],
            vm_status=user.get("vm_status"),
            vm_ip=user.get("vm_ip"),
            created_at=user["created_at"],
            last_login=datetime.utcnow(),
        ),
    )


@router.post("/logout")
async def logout(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Logout and invalidate current access token.
    """
    token = credentials.credentials
    user_store.revoke_token(token)
    
    logger.info(f"User logged out: {user['email']}")
    
    return {"message": "Successfully logged out"}


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(user: Dict[str, Any] = Depends(get_current_user)):
    """
    Get current user information.
    """
    return UserResponse(
        id=user["id"],
        email=user["email"],
        full_name=user["full_name"],
        organization=user["organization"],
        role=user["role"],
        status=user["status"],
        vm_status=user.get("vm_status"),
        vm_ip=user.get("vm_ip"),
        created_at=user["created_at"],
        last_login=user.get("last_login"),
    )


@router.put("/me", response_model=UserResponse)
async def update_profile(
    updates: UserProfileUpdate,
    user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Update current user profile.
    """
    update_data = {}
    
    if updates.full_name is not None:
        update_data["full_name"] = updates.full_name
    
    if updates.organization is not None:
        update_data["organization"] = updates.organization
    
    if update_data:
        user = user_store.update(user["id"], update_data)
    
    return UserResponse(
        id=user["id"],
        email=user["email"],
        full_name=user["full_name"],
        organization=user["organization"],
        role=user["role"],
        status=user["status"],
        vm_status=user.get("vm_status"),
        vm_ip=user.get("vm_ip"),
        created_at=user["created_at"],
        last_login=user.get("last_login"),
    )


@router.post("/change-password")
async def change_password(
    request: PasswordChangeRequest,
    user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Change current user password.
    """
    # Verify current password
    if not bcrypt.checkpw(request.current_password.encode(), user["password_hash"].encode()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect",
        )
    
    # Hash new password
    new_hash = bcrypt.hashpw(request.new_password.encode(), bcrypt.gensalt()).decode()
    
    # Update password
    user_store.update(user["id"], {"password_hash": new_hash})
    
    # Revoke all existing tokens (force re-login)
    user_store.revoke_all_user_tokens(user["id"])
    
    logger.info(f"Password changed for user: {user['email']}")
    
    return {"message": "Password changed successfully. Please login again."}


@router.get("/vm/status")
async def get_vm_status(user: Dict[str, Any] = Depends(get_current_user)):
    """
    Get current user's VM provisioning status.
    """
    return {
        "vm_status": user.get("vm_status"),
        "vm_id": user.get("vm_id"),
        "vm_ip": user.get("vm_ip"),
        "message": _get_vm_status_message(user.get("vm_status")),
    }


def _get_vm_status_message(status: Optional[VMProvisionStatus]) -> str:
    """Get human-readable VM status message"""
    if status is None:
        return "VM not provisioned"
    
    messages = {
        VMProvisionStatus.PENDING: "VM provisioning queued",
        VMProvisionStatus.CREATING: "Creating your VM instance...",
        VMProvisionStatus.CONFIGURING: "Configuring VM environment...",
        VMProvisionStatus.READY: "VM is ready to use",
        VMProvisionStatus.FAILED: "VM provisioning failed. Please contact support.",
    }
    return messages.get(status, "Unknown status")


@router.post("/vm/reprovision")
async def reprovision_vm(
    background_tasks: BackgroundTasks,
    vm_config: Optional[VMConfiguration] = None,
    user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Re-provision user's VM (if failed or needs reset).
    """
    if user.get("vm_status") == VMProvisionStatus.CREATING:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="VM is currently being provisioned",
        )
    
    # Reset VM status
    user_store.update(user["id"], {
        "vm_status": VMProvisionStatus.PENDING,
        "vm_id": None,
        "vm_ip": None,
    })
    
    # Start provisioning
    config = vm_config or VMConfiguration()
    background_tasks.add_task(provision_user_vm, user["id"], config)
    
    return {"message": "VM re-provisioning started"}


# ═══════════════════════════════════════════════════════════════
# Admin Routes
# ═══════════════════════════════════════════════════════════════

@router.get("/admin/users", response_model=List[UserResponse])
async def list_users(
    user: Dict[str, Any] = Depends(require_role(UserRole.ADMIN)),
):
    """
    List all users (Admin only).
    """
    users = user_store.list_all()
    return [
        UserResponse(
            id=u["id"],
            email=u["email"],
            full_name=u["full_name"],
            organization=u["organization"],
            role=u["role"],
            status=u["status"],
            vm_status=u.get("vm_status"),
            vm_ip=u.get("vm_ip"),
            created_at=u["created_at"],
            last_login=u.get("last_login"),
        )
        for u in users
    ]


@router.put("/admin/users/{user_id}/status")
async def update_user_status(
    user_id: str,
    new_status: UserStatus,
    admin: Dict[str, Any] = Depends(require_role(UserRole.ADMIN)),
):
    """
    Update user status (Admin only).
    """
    target_user = user_store.get_by_id(user_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Prevent self-suspension
    if admin["id"] == user_id and new_status in [UserStatus.SUSPENDED, UserStatus.DELETED]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot suspend or delete your own account",
        )
    
    user_store.update(user_id, {"status": new_status})
    
    # Revoke tokens if suspending/deleting
    if new_status in [UserStatus.SUSPENDED, UserStatus.DELETED]:
        user_store.revoke_all_user_tokens(user_id)
    
    logger.info(f"Admin {admin['email']} changed user {user_id} status to {new_status}")
    
    return {"message": f"User status updated to {new_status}"}


@router.put("/admin/users/{user_id}/role")
async def update_user_role(
    user_id: str,
    new_role: UserRole,
    admin: Dict[str, Any] = Depends(require_role(UserRole.ADMIN)),
):
    """
    Update user role (Admin only).
    """
    target_user = user_store.get_by_id(user_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user_store.update(user_id, {"role": new_role})
    
    logger.info(f"Admin {admin['email']} changed user {user_id} role to {new_role}")
    
    return {"message": f"User role updated to {new_role}"}
