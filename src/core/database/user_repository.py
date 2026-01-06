# ===================================================================
# RAGLOX v3.0 - User Repository
# PostgreSQL-backed user management
# ===================================================================
"""
User Repository for multi-tenant SaaS platform.

Replaces the in-memory UserStore with PostgreSQL-backed storage.

Features:
- Multi-tenant user isolation by organization
- Secure password handling (bcrypt)
- Token management
- Login tracking and lockout
- Email verification support
"""

from typing import Optional, Any, Dict, List
from uuid import UUID
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
import logging

from .base_repository import BaseRepository
from .connection import DatabasePool

logger = logging.getLogger("raglox.database.user")


# ===================================================================
# User Entity
# ===================================================================

@dataclass
class User:
    """
    User entity representing a platform user.
    
    All users belong to an organization (multi-tenancy).
    """
    id: UUID
    organization_id: UUID
    
    # Identity
    username: str
    email: str
    password_hash: str
    full_name: Optional[str] = None
    avatar_url: Optional[str] = None
    
    # Role & Permissions
    role: str = "operator"  # admin, operator, viewer, api
    permissions: List[str] = field(default_factory=list)
    
    # Status
    is_active: bool = True
    is_superuser: bool = False  # Platform admin
    is_org_owner: bool = False  # Organization owner
    
    # Email verification
    email_verified: bool = False
    email_verification_token: Optional[str] = None
    
    # Password reset
    password_reset_token: Optional[str] = None
    password_reset_expires: Optional[datetime] = None
    
    # 2FA
    two_factor_enabled: bool = False
    two_factor_secret: Optional[str] = None
    
    # Login tracking
    last_login_at: Optional[datetime] = None
    last_login_ip: Optional[str] = None
    login_attempts: int = 0
    locked_until: Optional[datetime] = None
    
    # Settings & Metadata
    settings: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Timestamps
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    def is_locked(self) -> bool:
        """Check if account is locked."""
        if self.locked_until is None:
            return False
        return datetime.utcnow() < self.locked_until
    
    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """
        Convert to dictionary for API responses.
        
        Args:
            include_sensitive: Include password hash and tokens
        """
        data = {
            "id": str(self.id),
            "organization_id": str(self.organization_id),
            "username": self.username,
            "email": self.email,
            "full_name": self.full_name,
            "avatar_url": self.avatar_url,
            "role": self.role,
            "permissions": self.permissions,
            "is_active": self.is_active,
            "is_superuser": self.is_superuser,
            "is_org_owner": self.is_org_owner,
            "email_verified": self.email_verified,
            "two_factor_enabled": self.two_factor_enabled,
            "last_login_at": self.last_login_at.isoformat() if self.last_login_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
        
        if include_sensitive:
            data["password_hash"] = self.password_hash
            
        return data


# ===================================================================
# User Repository
# ===================================================================

class UserRepository(BaseRepository[User]):
    """
    PostgreSQL repository for User entities.
    
    Provides all user CRUD operations with multi-tenant isolation.
    
    Example:
        repo = UserRepository(pool)
        
        # Get user by email within organization
        user = await repo.get_by_email(org_id, "user@example.com")
        
        # Create new user
        user = await repo.create(User(
            organization_id=org_id,
            username="newuser",
            email="new@example.com",
            password_hash=hash_password("secret")
        ))
        
        # Record login
        await repo.record_login(user.id, "192.168.1.1")
    """
    
    table_name = "users"
    
    def _record_to_entity(self, record: Any) -> Optional[User]:
        """Convert database record to User entity."""
        if not record:
            return None
        
        return User(
            id=record["id"],
            organization_id=record["organization_id"],
            username=record["username"],
            email=record["email"],
            password_hash=record["password_hash"],
            full_name=record.get("full_name"),
            avatar_url=record.get("avatar_url"),
            role=record.get("role", "operator"),
            permissions=record.get("permissions", []),
            is_active=record.get("is_active", True),
            is_superuser=record.get("is_superuser", False),
            is_org_owner=record.get("is_org_owner", False),
            email_verified=record.get("email_verified", False),
            email_verification_token=record.get("email_verification_token"),
            password_reset_token=record.get("password_reset_token"),
            password_reset_expires=record.get("password_reset_expires"),
            two_factor_enabled=record.get("two_factor_enabled", False),
            two_factor_secret=record.get("two_factor_secret"),
            last_login_at=record.get("last_login_at"),
            last_login_ip=record.get("last_login_ip"),
            login_attempts=record.get("login_attempts", 0),
            locked_until=record.get("locked_until"),
            settings=record.get("settings", {}),
            metadata=record.get("metadata", {}),
            created_at=record.get("created_at"),
            updated_at=record.get("updated_at"),
        )
    
    def _entity_to_dict(self, entity: User) -> Dict[str, Any]:
        """Convert User entity to dictionary for database."""
        return {
            "id": entity.id,
            "organization_id": entity.organization_id,
            "username": entity.username,
            "email": entity.email,
            "password_hash": entity.password_hash,
            "full_name": entity.full_name,
            "avatar_url": entity.avatar_url,
            "role": entity.role,
            "permissions": entity.permissions,
            "is_active": entity.is_active,
            "is_superuser": entity.is_superuser,
            "is_org_owner": entity.is_org_owner,
            "email_verified": entity.email_verified,
            "email_verification_token": entity.email_verification_token,
            "password_reset_token": entity.password_reset_token,
            "password_reset_expires": entity.password_reset_expires,
            "two_factor_enabled": entity.two_factor_enabled,
            "two_factor_secret": entity.two_factor_secret,
            "last_login_at": entity.last_login_at,
            "last_login_ip": entity.last_login_ip,
            "login_attempts": entity.login_attempts,
            "locked_until": entity.locked_until,
            "settings": entity.settings,
            "metadata": entity.metadata,
        }
    
    # ===================================================================
    # User-Specific Queries
    # ===================================================================
    
    async def get_by_email(
        self,
        organization_id: UUID,
        email: str
    ) -> Optional[User]:
        """
        Get user by email within organization.
        
        Args:
            organization_id: Organization UUID
            email: User email address
            
        Returns:
            User or None
        """
        query = """
            SELECT * FROM users
            WHERE organization_id = $1 AND email = $2
        """
        row = await self.pool.fetchrow(query, organization_id, email.lower())
        return self._record_to_entity(row)
    
    async def get_by_email_global(self, email: str) -> Optional[User]:
        """
        Get user by email across all organizations.
        
        Used for login when organization is not yet known.
        
        Args:
            email: User email address
            
        Returns:
            User or None
        """
        query = "SELECT * FROM users WHERE email = $1"
        row = await self.pool.fetchrow(query, email.lower())
        return self._record_to_entity(row)
    
    async def get_by_username(
        self,
        organization_id: UUID,
        username: str
    ) -> Optional[User]:
        """
        Get user by username within organization.
        
        Args:
            organization_id: Organization UUID
            username: Username
            
        Returns:
            User or None
        """
        query = """
            SELECT * FROM users
            WHERE organization_id = $1 AND username = $2
        """
        row = await self.pool.fetchrow(query, organization_id, username)
        return self._record_to_entity(row)
    
    async def get_organization_users(
        self,
        organization_id: UUID,
        include_inactive: bool = False
    ) -> List[User]:
        """
        Get all users in an organization.
        
        Args:
            organization_id: Organization UUID
            include_inactive: Include deactivated users
            
        Returns:
            List of users
        """
        if include_inactive:
            query = """
                SELECT * FROM users
                WHERE organization_id = $1
                ORDER BY created_at DESC
            """
            rows = await self.pool.fetch(query, organization_id)
        else:
            query = """
                SELECT * FROM users
                WHERE organization_id = $1 AND is_active = true
                ORDER BY created_at DESC
            """
            rows = await self.pool.fetch(query, organization_id)
        
        return [self._record_to_entity(row) for row in rows]
    
    async def email_exists(
        self,
        organization_id: UUID,
        email: str
    ) -> bool:
        """Check if email already exists in organization."""
        query = """
            SELECT EXISTS(
                SELECT 1 FROM users
                WHERE organization_id = $1 AND email = $2
            )
        """
        return await self.pool.fetchval(query, organization_id, email.lower())
    
    async def username_exists(
        self,
        organization_id: UUID,
        username: str
    ) -> bool:
        """Check if username already exists in organization."""
        query = """
            SELECT EXISTS(
                SELECT 1 FROM users
                WHERE organization_id = $1 AND username = $2
            )
        """
        return await self.pool.fetchval(query, organization_id, username)
    
    # ===================================================================
    # Login & Security
    # ===================================================================
    
    async def record_login(
        self,
        user_id: UUID,
        ip_address: str
    ) -> None:
        """
        Record successful login.
        
        Args:
            user_id: User UUID
            ip_address: Client IP address
        """
        query = """
            UPDATE users
            SET last_login_at = $1,
                last_login_ip = $2,
                login_attempts = 0,
                locked_until = NULL
            WHERE id = $3
        """
        await self.pool.execute(query, datetime.utcnow(), ip_address, user_id)
    
    async def record_failed_login(
        self,
        user_id: UUID,
        max_attempts: int = 5,
        lockout_minutes: int = 15
    ) -> bool:
        """
        Record failed login attempt and potentially lock account.
        
        Args:
            user_id: User UUID
            max_attempts: Max attempts before lockout
            lockout_minutes: Lockout duration in minutes
            
        Returns:
            True if account is now locked
        """
        # Increment attempts
        query = """
            UPDATE users
            SET login_attempts = login_attempts + 1
            WHERE id = $1
            RETURNING login_attempts
        """
        attempts = await self.pool.fetchval(query, user_id)
        
        # Lock if exceeded
        if attempts >= max_attempts:
            lockout_until = datetime.utcnow() + timedelta(minutes=lockout_minutes)
            await self.update(user_id, {"locked_until": lockout_until})
            return True
        
        return False
    
    async def update_password(
        self,
        user_id: UUID,
        password_hash: str
    ) -> bool:
        """
        Update user password.
        
        Args:
            user_id: User UUID
            password_hash: New bcrypt hash
            
        Returns:
            True if updated
        """
        query = """
            UPDATE users
            SET password_hash = $1,
                password_reset_token = NULL,
                password_reset_expires = NULL,
                updated_at = $2
            WHERE id = $3
        """
        result = await self.pool.execute(query, password_hash, datetime.utcnow(), user_id)
        return "UPDATE 1" in result
    
    async def set_password_reset_token(
        self,
        user_id: UUID,
        token: str,
        expires_hours: int = 24
    ) -> bool:
        """
        Set password reset token.
        
        Args:
            user_id: User UUID
            token: Reset token
            expires_hours: Token validity in hours
            
        Returns:
            True if updated
        """
        expires = datetime.utcnow() + timedelta(hours=expires_hours)
        
        query = """
            UPDATE users
            SET password_reset_token = $1,
                password_reset_expires = $2
            WHERE id = $3
        """
        result = await self.pool.execute(query, token, expires, user_id)
        return "UPDATE 1" in result
    
    async def verify_reset_token(self, token: str) -> Optional[User]:
        """
        Verify password reset token and return user.
        
        Args:
            token: Reset token
            
        Returns:
            User if token valid, None otherwise
        """
        query = """
            SELECT * FROM users
            WHERE password_reset_token = $1
              AND password_reset_expires > $2
        """
        row = await self.pool.fetchrow(query, token, datetime.utcnow())
        return self._record_to_entity(row)
    
    # ===================================================================
    # Email Verification
    # ===================================================================
    
    async def set_verification_token(
        self,
        user_id: UUID,
        token: str
    ) -> bool:
        """Set email verification token."""
        return await self.update(user_id, {"email_verification_token": token}) is not None
    
    async def verify_email(self, token: str) -> Optional[User]:
        """
        Verify email with token.
        
        Args:
            token: Verification token
            
        Returns:
            User if verified, None if token invalid
        """
        query = """
            UPDATE users
            SET email_verified = true,
                email_verification_token = NULL
            WHERE email_verification_token = $1
            RETURNING *
        """
        row = await self.pool.fetchrow(query, token)
        return self._record_to_entity(row)
    
    # ===================================================================
    # Role Management
    # ===================================================================
    
    async def update_role(
        self,
        user_id: UUID,
        organization_id: UUID,
        new_role: str
    ) -> Optional[User]:
        """
        Update user role within organization.
        
        Args:
            user_id: User UUID
            organization_id: Organization UUID
            new_role: New role (admin, operator, viewer, api)
            
        Returns:
            Updated user or None
        """
        valid_roles = ["admin", "operator", "viewer", "api"]
        if new_role not in valid_roles:
            raise ValueError(f"Invalid role: {new_role}")
        
        return await self.update(user_id, {"role": new_role}, organization_id)
    
    async def get_organization_admins(
        self,
        organization_id: UUID
    ) -> List[User]:
        """Get all admins in an organization."""
        query = """
            SELECT * FROM users
            WHERE organization_id = $1 AND role = 'admin' AND is_active = true
        """
        rows = await self.pool.fetch(query, organization_id)
        return [self._record_to_entity(row) for row in rows]
    
    # ===================================================================
    # Superuser Operations (Platform-level)
    # ===================================================================
    
    async def get_superusers(self) -> List[User]:
        """Get all platform superusers."""
        query = "SELECT * FROM users WHERE is_superuser = true"
        rows = await self.pool.fetch(query)
        return [self._record_to_entity(row) for row in rows]
    
    async def get_all_users_global(
        self,
        limit: int = 100,
        offset: int = 0
    ) -> List[User]:
        """
        Get all users across all organizations.
        
        Platform admin only.
        """
        query = """
            SELECT * FROM users
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
        """
        rows = await self.pool.fetch(query, limit, offset)
        return [self._record_to_entity(row) for row in rows]
