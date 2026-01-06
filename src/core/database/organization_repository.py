# ===================================================================
# RAGLOX v3.0 - Organization Repository
# PostgreSQL-backed organization management for SaaS
# ===================================================================
"""
Organization Repository for multi-tenant SaaS platform.

Organizations are the core tenant isolation unit.
Every resource (users, missions, targets, etc.) belongs to an organization.

Features:
- Subscription/billing management
- Usage limits and tracking
- Member invitations
- Plan upgrades/downgrades
"""

from typing import Optional, Any, Dict, List
from uuid import UUID
from datetime import datetime, timedelta
from dataclasses import dataclass, field
import logging

from .base_repository import BaseRepository
from .connection import DatabasePool

logger = logging.getLogger("raglox.database.organization")


# ===================================================================
# Plan Definitions
# ===================================================================

PLANS = {
    "free": {
        "name": "Free",
        "max_users": 3,
        "max_missions_per_month": 5,
        "max_concurrent_missions": 1,
        "max_targets_per_mission": 10,
        "features": ["basic_scanning", "limited_reports"],
    },
    "starter": {
        "name": "Starter",
        "max_users": 10,
        "max_missions_per_month": 25,
        "max_concurrent_missions": 3,
        "max_targets_per_mission": 50,
        "features": ["basic_scanning", "full_reports", "api_access"],
    },
    "professional": {
        "name": "Professional",
        "max_users": 50,
        "max_missions_per_month": 100,
        "max_concurrent_missions": 10,
        "max_targets_per_mission": 200,
        "features": ["advanced_scanning", "full_reports", "api_access", "integrations"],
    },
    "enterprise": {
        "name": "Enterprise",
        "max_users": 1000,
        "max_missions_per_month": 10000,
        "max_concurrent_missions": 100,
        "max_targets_per_mission": 1000,
        "features": ["all_features", "sso", "audit_logs", "priority_support"],
    },
}


# ===================================================================
# Organization Entity
# ===================================================================

@dataclass
class Organization:
    """
    Organization entity representing a tenant.
    
    Every resource belongs to an organization for data isolation.
    """
    id: UUID
    name: str
    slug: str  # URL-friendly identifier (e.g., "acme-corp")
    description: Optional[str] = None
    
    # Subscription & Billing
    plan: str = "free"
    stripe_customer_id: Optional[str] = None
    stripe_subscription_id: Optional[str] = None
    billing_email: Optional[str] = None
    
    # Limits (from plan)
    max_users: int = 3
    max_missions_per_month: int = 5
    max_concurrent_missions: int = 1
    max_targets_per_mission: int = 10
    
    # Usage tracking
    missions_this_month: int = 0
    missions_reset_at: Optional[datetime] = None
    
    # Status
    status: str = "active"  # active, suspended, cancelled
    is_trial: bool = True
    trial_ends_at: Optional[datetime] = None
    
    # Settings & Metadata
    settings: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Timestamps
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    def is_trial_expired(self) -> bool:
        """Check if trial period has expired."""
        if not self.is_trial:
            return False
        if not self.trial_ends_at:
            return False
        return datetime.utcnow() > self.trial_ends_at
    
    def can_create_mission(self) -> bool:
        """Check if organization can create more missions."""
        return self.missions_this_month < self.max_missions_per_month
    
    def get_plan_features(self) -> List[str]:
        """Get features for current plan."""
        return PLANS.get(self.plan, PLANS["free"])["features"]
    
    def to_dict(self, include_billing: bool = False) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        data = {
            "id": str(self.id),
            "name": self.name,
            "slug": self.slug,
            "description": self.description,
            "plan": self.plan,
            "plan_name": PLANS.get(self.plan, PLANS["free"])["name"],
            "status": self.status,
            "is_trial": self.is_trial,
            "trial_ends_at": self.trial_ends_at.isoformat() if self.trial_ends_at else None,
            "limits": {
                "max_users": self.max_users,
                "max_missions_per_month": self.max_missions_per_month,
                "max_concurrent_missions": self.max_concurrent_missions,
                "max_targets_per_mission": self.max_targets_per_mission,
            },
            "usage": {
                "missions_this_month": self.missions_this_month,
                "missions_reset_at": self.missions_reset_at.isoformat() if self.missions_reset_at else None,
            },
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
        
        if include_billing:
            data["billing"] = {
                "stripe_customer_id": self.stripe_customer_id,
                "billing_email": self.billing_email,
            }
        
        return data


# ===================================================================
# Organization Invitation Entity
# ===================================================================

@dataclass
class OrganizationInvitation:
    """Invitation to join an organization."""
    id: UUID
    organization_id: UUID
    email: str
    role: str = "operator"
    invited_by: Optional[UUID] = None
    token: str = ""
    status: str = "pending"  # pending, accepted, expired, cancelled
    expires_at: Optional[datetime] = None
    accepted_at: Optional[datetime] = None
    created_at: Optional[datetime] = None


# ===================================================================
# Organization Repository
# ===================================================================

class OrganizationRepository(BaseRepository[Organization]):
    """
    PostgreSQL repository for Organization entities.
    
    Example:
        repo = OrganizationRepository(pool)
        
        # Create organization
        org = await repo.create(Organization(
            name="Acme Corp",
            slug="acme-corp"
        ))
        
        # Check limits
        if await repo.can_create_mission(org.id):
            # Create mission
            pass
    """
    
    table_name = "organizations"
    
    def _record_to_entity(self, record: Any) -> Optional[Organization]:
        """Convert database record to Organization entity."""
        if not record:
            return None
        
        return Organization(
            id=record["id"],
            name=record["name"],
            slug=record["slug"],
            description=record.get("description"),
            plan=record.get("plan", "free"),
            stripe_customer_id=record.get("stripe_customer_id"),
            stripe_subscription_id=record.get("stripe_subscription_id"),
            billing_email=record.get("billing_email"),
            max_users=record.get("max_users", 3),
            max_missions_per_month=record.get("max_missions_per_month", 5),
            max_concurrent_missions=record.get("max_concurrent_missions", 1),
            max_targets_per_mission=record.get("max_targets_per_mission", 10),
            missions_this_month=record.get("missions_this_month", 0),
            missions_reset_at=record.get("missions_reset_at"),
            status=record.get("status", "active"),
            is_trial=record.get("is_trial", True),
            trial_ends_at=record.get("trial_ends_at"),
            settings=record.get("settings", {}),
            metadata=record.get("metadata", {}),
            created_at=record.get("created_at"),
            updated_at=record.get("updated_at"),
        )
    
    def _entity_to_dict(self, entity: Organization) -> Dict[str, Any]:
        """Convert Organization entity to dictionary for database."""
        return {
            "id": entity.id,
            "name": entity.name,
            "slug": entity.slug,
            "description": entity.description,
            "plan": entity.plan,
            "stripe_customer_id": entity.stripe_customer_id,
            "stripe_subscription_id": entity.stripe_subscription_id,
            "billing_email": entity.billing_email,
            "max_users": entity.max_users,
            "max_missions_per_month": entity.max_missions_per_month,
            "max_concurrent_missions": entity.max_concurrent_missions,
            "max_targets_per_mission": entity.max_targets_per_mission,
            "missions_this_month": entity.missions_this_month,
            "missions_reset_at": entity.missions_reset_at,
            "status": entity.status,
            "is_trial": entity.is_trial,
            "trial_ends_at": entity.trial_ends_at,
            "settings": entity.settings,
            "metadata": entity.metadata,
        }
    
    # ===================================================================
    # Organization-Specific Queries
    # ===================================================================
    
    async def get_by_slug(self, slug: str) -> Optional[Organization]:
        """
        Get organization by slug.
        
        Args:
            slug: URL-friendly identifier
            
        Returns:
            Organization or None
        """
        query = "SELECT * FROM organizations WHERE slug = $1"
        row = await self.pool.fetchrow(query, slug.lower())
        return self._record_to_entity(row)
    
    async def slug_exists(self, slug: str) -> bool:
        """Check if slug already exists."""
        query = "SELECT EXISTS(SELECT 1 FROM organizations WHERE slug = $1)"
        return await self.pool.fetchval(query, slug.lower())
    
    async def get_by_stripe_customer(
        self,
        stripe_customer_id: str
    ) -> Optional[Organization]:
        """Get organization by Stripe customer ID."""
        query = "SELECT * FROM organizations WHERE stripe_customer_id = $1"
        row = await self.pool.fetchrow(query, stripe_customer_id)
        return self._record_to_entity(row)
    
    async def get_active_organizations(
        self,
        limit: int = 100,
        offset: int = 0
    ) -> List[Organization]:
        """Get all active organizations."""
        query = """
            SELECT * FROM organizations
            WHERE status = 'active'
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
        """
        rows = await self.pool.fetch(query, limit, offset)
        return [self._record_to_entity(row) for row in rows]
    
    # ===================================================================
    # Usage & Limits
    # ===================================================================
    
    async def can_create_mission(self, organization_id: UUID) -> bool:
        """
        Check if organization can create more missions.
        
        Args:
            organization_id: Organization UUID
            
        Returns:
            True if under limit
        """
        query = """
            SELECT missions_this_month < max_missions_per_month
            FROM organizations
            WHERE id = $1
        """
        return await self.pool.fetchval(query, organization_id) or False
    
    async def can_add_user(self, organization_id: UUID) -> bool:
        """
        Check if organization can add more users.
        
        Args:
            organization_id: Organization UUID
            
        Returns:
            True if under limit
        """
        query = """
            SELECT (
                SELECT COUNT(*) FROM users WHERE organization_id = $1
            ) < max_users
            FROM organizations
            WHERE id = $1
        """
        return await self.pool.fetchval(query, organization_id) or False
    
    async def get_current_user_count(self, organization_id: UUID) -> int:
        """Get current number of users in organization."""
        query = "SELECT COUNT(*) FROM users WHERE organization_id = $1"
        return await self.pool.fetchval(query, organization_id) or 0
    
    async def get_current_mission_count(self, organization_id: UUID) -> int:
        """Get current number of running missions."""
        query = """
            SELECT COUNT(*) FROM missions
            WHERE organization_id = $1 AND status = 'running'
        """
        return await self.pool.fetchval(query, organization_id) or 0
    
    async def increment_mission_count(self, organization_id: UUID) -> None:
        """Increment monthly mission counter."""
        query = """
            UPDATE organizations
            SET missions_this_month = missions_this_month + 1
            WHERE id = $1
        """
        await self.pool.execute(query, organization_id)
    
    async def reset_monthly_counters(self) -> int:
        """
        Reset monthly counters for all organizations.
        
        Should be called by a scheduled job.
        
        Returns:
            Number of organizations reset
        """
        query = """
            UPDATE organizations
            SET missions_this_month = 0,
                missions_reset_at = date_trunc('month', CURRENT_TIMESTAMP) + INTERVAL '1 month'
            WHERE missions_reset_at <= CURRENT_TIMESTAMP
        """
        result = await self.pool.execute(query)
        return int(result.split()[-1])
    
    # ===================================================================
    # Subscription & Billing
    # ===================================================================
    
    async def update_subscription(
        self,
        organization_id: UUID,
        plan: str,
        stripe_subscription_id: Optional[str] = None
    ) -> Optional[Organization]:
        """
        Update organization subscription plan.
        
        Args:
            organization_id: Organization UUID
            plan: New plan name
            stripe_subscription_id: Stripe subscription ID
            
        Returns:
            Updated organization
        """
        if plan not in PLANS:
            raise ValueError(f"Invalid plan: {plan}")
        
        plan_config = PLANS[plan]
        
        updates = {
            "plan": plan,
            "max_users": plan_config["max_users"],
            "max_missions_per_month": plan_config["max_missions_per_month"],
            "max_concurrent_missions": plan_config["max_concurrent_missions"],
            "max_targets_per_mission": plan_config["max_targets_per_mission"],
            "is_trial": False,  # No longer trial after subscribing
        }
        
        if stripe_subscription_id:
            updates["stripe_subscription_id"] = stripe_subscription_id
        
        return await self.update(organization_id, updates)
    
    async def set_stripe_customer(
        self,
        organization_id: UUID,
        stripe_customer_id: str,
        billing_email: Optional[str] = None
    ) -> Optional[Organization]:
        """Link Stripe customer to organization."""
        updates = {"stripe_customer_id": stripe_customer_id}
        if billing_email:
            updates["billing_email"] = billing_email
        
        return await self.update(organization_id, updates)
    
    async def suspend_organization(
        self,
        organization_id: UUID,
        reason: Optional[str] = None
    ) -> Optional[Organization]:
        """
        Suspend an organization (e.g., for payment failure).
        
        Args:
            organization_id: Organization UUID
            reason: Suspension reason
            
        Returns:
            Updated organization
        """
        metadata_update = {}
        if reason:
            metadata_update["suspension_reason"] = reason
            metadata_update["suspended_at"] = datetime.utcnow().isoformat()
        
        return await self.update(organization_id, {
            "status": "suspended",
            "metadata": metadata_update
        })
    
    async def reactivate_organization(
        self,
        organization_id: UUID
    ) -> Optional[Organization]:
        """Reactivate a suspended organization."""
        return await self.update(organization_id, {"status": "active"})
    
    # ===================================================================
    # Trial Management
    # ===================================================================
    
    async def extend_trial(
        self,
        organization_id: UUID,
        days: int = 7
    ) -> Optional[Organization]:
        """Extend trial period."""
        query = """
            UPDATE organizations
            SET trial_ends_at = trial_ends_at + INTERVAL '%s days'
            WHERE id = $1
            RETURNING *
        """ % days
        
        row = await self.pool.fetchrow(query, organization_id)
        return self._record_to_entity(row)
    
    async def get_expiring_trials(
        self,
        days_remaining: int = 3
    ) -> List[Organization]:
        """Get organizations with trials expiring soon."""
        cutoff = datetime.utcnow() + timedelta(days=days_remaining)
        
        query = """
            SELECT * FROM organizations
            WHERE is_trial = true
              AND trial_ends_at <= $1
              AND status = 'active'
        """
        rows = await self.pool.fetch(query, cutoff)
        return [self._record_to_entity(row) for row in rows]
    
    # ===================================================================
    # Invitations
    # ===================================================================
    
    async def create_invitation(
        self,
        organization_id: UUID,
        email: str,
        role: str,
        invited_by: UUID,
        token: str,
        expires_days: int = 7
    ) -> OrganizationInvitation:
        """
        Create organization invitation.
        
        Args:
            organization_id: Organization UUID
            email: Invitee email
            role: Role to assign
            invited_by: Inviting user UUID
            token: Unique invitation token
            expires_days: Days until expiration
            
        Returns:
            Created invitation
        """
        expires_at = datetime.utcnow() + timedelta(days=expires_days)
        
        query = """
            INSERT INTO organization_invitations
            (organization_id, email, role, invited_by, token, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
        """
        
        row = await self.pool.fetchrow(
            query,
            organization_id,
            email.lower(),
            role,
            invited_by,
            token,
            expires_at
        )
        
        return OrganizationInvitation(
            id=row["id"],
            organization_id=row["organization_id"],
            email=row["email"],
            role=row["role"],
            invited_by=row["invited_by"],
            token=row["token"],
            status=row["status"],
            expires_at=row["expires_at"],
            created_at=row["created_at"],
        )
    
    async def get_invitation_by_token(
        self,
        token: str
    ) -> Optional[OrganizationInvitation]:
        """Get invitation by token."""
        query = """
            SELECT * FROM organization_invitations
            WHERE token = $1 AND status = 'pending' AND expires_at > $2
        """
        row = await self.pool.fetchrow(query, token, datetime.utcnow())
        
        if not row:
            return None
        
        return OrganizationInvitation(
            id=row["id"],
            organization_id=row["organization_id"],
            email=row["email"],
            role=row["role"],
            invited_by=row["invited_by"],
            token=row["token"],
            status=row["status"],
            expires_at=row["expires_at"],
            created_at=row["created_at"],
        )
    
    async def accept_invitation(self, invitation_id: UUID) -> bool:
        """Mark invitation as accepted."""
        query = """
            UPDATE organization_invitations
            SET status = 'accepted', accepted_at = $1
            WHERE id = $2
        """
        result = await self.pool.execute(query, datetime.utcnow(), invitation_id)
        return "UPDATE 1" in result
    
    async def get_pending_invitations(
        self,
        organization_id: UUID
    ) -> List[OrganizationInvitation]:
        """Get pending invitations for organization."""
        query = """
            SELECT * FROM organization_invitations
            WHERE organization_id = $1 AND status = 'pending' AND expires_at > $2
            ORDER BY created_at DESC
        """
        rows = await self.pool.fetch(query, organization_id, datetime.utcnow())
        
        return [
            OrganizationInvitation(
                id=row["id"],
                organization_id=row["organization_id"],
                email=row["email"],
                role=row["role"],
                invited_by=row["invited_by"],
                token=row["token"],
                status=row["status"],
                expires_at=row["expires_at"],
                created_at=row["created_at"],
            )
            for row in rows
        ]
