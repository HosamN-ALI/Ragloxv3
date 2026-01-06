# ===================================================================
# RAGLOX v3.0 - Billing Models
# Data models for billing and subscriptions
# ===================================================================
"""
Billing data models for Stripe integration.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any, List
from uuid import UUID


class SubscriptionPlan(str, Enum):
    """Available subscription plans."""
    FREE = "free"
    STARTER = "starter"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"


class SubscriptionStatus(str, Enum):
    """Subscription statuses."""
    ACTIVE = "active"
    PAST_DUE = "past_due"
    CANCELED = "canceled"
    INCOMPLETE = "incomplete"
    TRIALING = "trialing"
    UNPAID = "unpaid"
    PAUSED = "paused"


class BillingEventType(str, Enum):
    """Types of billing events."""
    SUBSCRIPTION_CREATED = "subscription.created"
    SUBSCRIPTION_UPDATED = "subscription.updated"
    SUBSCRIPTION_CANCELED = "subscription.canceled"
    PAYMENT_SUCCEEDED = "payment.succeeded"
    PAYMENT_FAILED = "payment.failed"
    INVOICE_PAID = "invoice.paid"
    INVOICE_PAYMENT_FAILED = "invoice.payment_failed"
    CUSTOMER_CREATED = "customer.created"
    CUSTOMER_UPDATED = "customer.updated"


# ===================================================================
# Plan Configuration
# ===================================================================

PLAN_PRICING = {
    SubscriptionPlan.FREE: {
        "name": "Free",
        "price_monthly": 0,
        "price_yearly": 0,
        "stripe_price_id_monthly": None,
        "stripe_price_id_yearly": None,
        "stripe_product_id": None,
        "features": {
            "max_users": 3,
            "max_missions_per_month": 5,
            "max_concurrent_missions": 1,
            "max_targets_per_mission": 10,
            "api_access": False,
            "priority_support": False,
            "advanced_reports": False,
            "sso": False,
        },
    },
    SubscriptionPlan.STARTER: {
        "name": "Starter",
        "price_monthly": 49,
        "price_yearly": 490,
        "stripe_price_id_monthly": "price_1SmboIQZf6X1AyY5gi4OLgb7",
        "stripe_price_id_yearly": "price_1SmboIQZf6X1AyY5B7Ntt03v",
        "stripe_product_id": "prod_Tk60BT981KuchB",
        "features": {
            "max_users": 10,
            "max_missions_per_month": 25,
            "max_concurrent_missions": 3,
            "max_targets_per_mission": 50,
            "api_access": True,
            "priority_support": False,
            "advanced_reports": True,
            "sso": False,
        },
    },
    SubscriptionPlan.PROFESSIONAL: {
        "name": "Professional",
        "price_monthly": 199,
        "price_yearly": 1990,
        "stripe_price_id_monthly": "price_1SmboIQZf6X1AyY5MZX03Dog",
        "stripe_price_id_yearly": "price_1SmboJQZf6X1AyY5MVnuF8TP",
        "stripe_product_id": "prod_Tk60dEs9zht87z",
        "features": {
            "max_users": 50,
            "max_missions_per_month": 100,
            "max_concurrent_missions": 10,
            "max_targets_per_mission": 200,
            "api_access": True,
            "priority_support": True,
            "advanced_reports": True,
            "sso": False,
        },
    },
    SubscriptionPlan.ENTERPRISE: {
        "name": "Enterprise",
        "price_monthly": 499,
        "price_yearly": 4990,
        "stripe_price_id_monthly": "price_1SVje7QZf6X1AyY5ZspNTBDo",
        "stripe_price_id_yearly": "price_1SVje8QZf6X1AyY5aQpJxo0A",
        "stripe_product_id": "prod_TSeyNNEx9WnH11",
        "features": {
            "max_users": 1000,
            "max_missions_per_month": 10000,
            "max_concurrent_missions": 100,
            "max_targets_per_mission": 1000,
            "api_access": True,
            "priority_support": True,
            "advanced_reports": True,
            "sso": True,
        },
    },
}


# ===================================================================
# Data Classes
# ===================================================================

@dataclass
class BillingCustomer:
    """
    Represents a Stripe customer linked to an organization.
    """
    id: UUID
    organization_id: UUID
    stripe_customer_id: str
    email: str
    name: Optional[str] = None
    
    # Payment method
    default_payment_method_id: Optional[str] = None
    payment_method_type: Optional[str] = None  # card, bank_transfer, etc.
    card_last4: Optional[str] = None
    card_brand: Optional[str] = None
    card_exp_month: Optional[int] = None
    card_exp_year: Optional[int] = None
    
    # Billing info
    billing_address: Dict[str, Any] = field(default_factory=dict)
    tax_id: Optional[str] = None
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": str(self.id),
            "organization_id": str(self.organization_id),
            "stripe_customer_id": self.stripe_customer_id,
            "email": self.email,
            "name": self.name,
            "payment_method": {
                "type": self.payment_method_type,
                "card_last4": self.card_last4,
                "card_brand": self.card_brand,
            } if self.payment_method_type else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


@dataclass
class BillingSubscription:
    """
    Represents a Stripe subscription for an organization.
    """
    id: UUID
    organization_id: UUID
    stripe_subscription_id: str
    stripe_customer_id: str
    
    # Plan info
    plan: SubscriptionPlan = SubscriptionPlan.FREE
    status: SubscriptionStatus = SubscriptionStatus.ACTIVE
    billing_cycle: str = "monthly"  # monthly, yearly
    
    # Dates
    current_period_start: Optional[datetime] = None
    current_period_end: Optional[datetime] = None
    trial_start: Optional[datetime] = None
    trial_end: Optional[datetime] = None
    canceled_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    
    # Pricing
    unit_amount: int = 0  # in cents
    currency: str = "usd"
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    def is_active(self) -> bool:
        """Check if subscription is active."""
        return self.status in [SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIALING]
    
    def is_trial(self) -> bool:
        """Check if subscription is in trial."""
        return self.status == SubscriptionStatus.TRIALING
    
    def days_until_renewal(self) -> Optional[int]:
        """Days until next billing cycle."""
        if not self.current_period_end:
            return None
        delta = self.current_period_end - datetime.utcnow()
        return max(0, delta.days)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": str(self.id),
            "organization_id": str(self.organization_id),
            "stripe_subscription_id": self.stripe_subscription_id,
            "plan": self.plan.value,
            "plan_name": PLAN_PRICING[self.plan]["name"],
            "status": self.status.value,
            "billing_cycle": self.billing_cycle,
            "current_period_start": self.current_period_start.isoformat() if self.current_period_start else None,
            "current_period_end": self.current_period_end.isoformat() if self.current_period_end else None,
            "trial_end": self.trial_end.isoformat() if self.trial_end else None,
            "is_active": self.is_active(),
            "is_trial": self.is_trial(),
            "days_until_renewal": self.days_until_renewal(),
            "unit_amount": self.unit_amount,
            "currency": self.currency,
        }


@dataclass
class BillingEvent:
    """
    Records billing events for audit and debugging.
    """
    id: UUID
    organization_id: UUID
    event_type: BillingEventType
    stripe_event_id: Optional[str] = None
    
    # Event data
    data: Dict[str, Any] = field(default_factory=dict)
    
    # Related entities
    subscription_id: Optional[str] = None
    invoice_id: Optional[str] = None
    payment_intent_id: Optional[str] = None
    
    # Status
    processed: bool = False
    error_message: Optional[str] = None
    
    # Timestamps
    created_at: Optional[datetime] = None
    processed_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": str(self.id),
            "organization_id": str(self.organization_id),
            "event_type": self.event_type.value,
            "stripe_event_id": self.stripe_event_id,
            "processed": self.processed,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


@dataclass
class Invoice:
    """
    Represents a Stripe invoice.
    """
    id: str  # Stripe invoice ID
    organization_id: UUID
    stripe_customer_id: str
    stripe_subscription_id: Optional[str] = None
    
    # Amounts
    amount_due: int = 0
    amount_paid: int = 0
    amount_remaining: int = 0
    currency: str = "usd"
    
    # Status
    status: str = "draft"  # draft, open, paid, void, uncollectible
    paid: bool = False
    
    # URLs
    hosted_invoice_url: Optional[str] = None
    invoice_pdf: Optional[str] = None
    
    # Dates
    period_start: Optional[datetime] = None
    period_end: Optional[datetime] = None
    due_date: Optional[datetime] = None
    paid_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "organization_id": str(self.organization_id),
            "amount_due": self.amount_due / 100,  # Convert to dollars
            "amount_paid": self.amount_paid / 100,
            "currency": self.currency,
            "status": self.status,
            "paid": self.paid,
            "hosted_invoice_url": self.hosted_invoice_url,
            "invoice_pdf": self.invoice_pdf,
            "due_date": self.due_date.isoformat() if self.due_date else None,
            "paid_at": self.paid_at.isoformat() if self.paid_at else None,
        }
