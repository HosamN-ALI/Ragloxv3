# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Billing Routes
# REST API endpoints for subscription and billing management
# ═══════════════════════════════════════════════════════════════
"""
Billing API endpoints for SaaS subscription management.

Endpoints:
- GET /billing/subscription - Get current subscription
- POST /billing/subscribe - Create subscription
- POST /billing/cancel - Cancel subscription
- GET /billing/invoices - List invoices
- POST /billing/checkout - Create checkout session
- POST /billing/portal - Create billing portal session
- POST /billing/webhook - Stripe webhook handler
"""

import logging
from typing import Optional, Dict, Any, List
from uuid import UUID

from fastapi import APIRouter, HTTPException, Depends, Request, status, Header
from pydantic import BaseModel, Field

from .auth_routes import get_current_user, require_role, require_org_owner
from ..core.billing import (
    BillingService,
    get_billing_service,
    SubscriptionPlan,
    PLAN_PRICING,
)
from ..core.database import OrganizationRepository


logger = logging.getLogger("raglox.api.billing")
router = APIRouter(prefix="/billing", tags=["Billing"])


# ═══════════════════════════════════════════════════════════════
# Request/Response Models
# ═══════════════════════════════════════════════════════════════

class SubscriptionRequest(BaseModel):
    """Request to create a subscription."""
    plan: str = Field(..., description="Plan name: starter, professional, enterprise")
    billing_cycle: str = Field(default="monthly", description="monthly or yearly")
    payment_method_id: Optional[str] = Field(None, description="Stripe payment method ID")


class CheckoutRequest(BaseModel):
    """Request to create a checkout session."""
    plan: str = Field(..., description="Plan name")
    billing_cycle: str = Field(default="monthly", description="monthly or yearly")
    success_url: str = Field(..., description="URL to redirect on success")
    cancel_url: str = Field(..., description="URL to redirect on cancel")


class SubscriptionResponse(BaseModel):
    """Subscription details response."""
    plan: str
    plan_name: str
    status: str
    billing_cycle: str
    current_period_start: Optional[str]
    current_period_end: Optional[str]
    trial_end: Optional[str]
    is_active: bool
    is_trial: bool
    cancel_at_period_end: bool = False
    days_until_renewal: Optional[int]


class InvoiceResponse(BaseModel):
    """Invoice details response."""
    id: str
    amount_due: float
    amount_paid: float
    currency: str
    status: str
    paid: bool
    hosted_invoice_url: Optional[str]
    invoice_pdf: Optional[str]
    due_date: Optional[str]
    paid_at: Optional[str]


class PlanResponse(BaseModel):
    """Plan details response."""
    id: str
    name: str
    price_monthly: int
    price_yearly: int
    features: Dict[str, Any]


# ═══════════════════════════════════════════════════════════════
# Helper Functions
# ═══════════════════════════════════════════════════════════════

def get_billing_service_dep(request: Request) -> BillingService:
    """Get BillingService from app state or global."""
    service = getattr(request.app.state, 'billing_service', None)
    if not service:
        service = get_billing_service()
    
    if not service:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Billing service not configured"
        )
    
    return service


def get_org_repo(request: Request) -> OrganizationRepository:
    """Get OrganizationRepository from app state."""
    repo = getattr(request.app.state, 'org_repo', None)
    if not repo:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database service unavailable"
        )
    return repo


# ═══════════════════════════════════════════════════════════════
# Plan Endpoints
# ═══════════════════════════════════════════════════════════════

@router.get("/plans", response_model=List[PlanResponse])
async def list_plans():
    """
    List all available subscription plans.
    
    Public endpoint - no authentication required.
    """
    plans = []
    for plan_id, config in PLAN_PRICING.items():
        plans.append(PlanResponse(
            id=plan_id.value,
            name=config["name"],
            price_monthly=config["price_monthly"],
            price_yearly=config["price_yearly"],
            features=config["features"],
        ))
    
    return plans


@router.get("/plans/{plan_id}", response_model=PlanResponse)
async def get_plan(plan_id: str):
    """
    Get details of a specific plan.
    """
    try:
        plan = SubscriptionPlan(plan_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Plan '{plan_id}' not found"
        )
    
    config = PLAN_PRICING[plan]
    
    return PlanResponse(
        id=plan.value,
        name=config["name"],
        price_monthly=config["price_monthly"],
        price_yearly=config["price_yearly"],
        features=config["features"],
    )


# ═══════════════════════════════════════════════════════════════
# Subscription Endpoints
# ═══════════════════════════════════════════════════════════════

@router.get("/subscription", response_model=SubscriptionResponse)
async def get_subscription(
    request: Request,
    user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Get current organization's subscription.
    """
    org_repo = get_org_repo(request)
    billing_service = get_billing_service_dep(request)
    
    org_id = UUID(user["organization_id"])
    org = await org_repo.get_by_id(org_id)
    
    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found"
        )
    
    # Get subscription from Stripe if exists
    subscription_data = None
    if org.stripe_subscription_id:
        subscription_data = await billing_service.get_subscription(org.stripe_subscription_id)
    
    # Build response
    if subscription_data:
        return SubscriptionResponse(
            plan=subscription_data["plan"],
            plan_name=PLAN_PRICING.get(
                SubscriptionPlan(subscription_data["plan"]),
                PLAN_PRICING[SubscriptionPlan.FREE]
            )["name"],
            status=subscription_data["status"],
            billing_cycle="yearly" if "yearly" in str(subscription_data.get("price", "")) else "monthly",
            current_period_start=subscription_data["current_period_start"].isoformat() if subscription_data.get("current_period_start") else None,
            current_period_end=subscription_data["current_period_end"].isoformat() if subscription_data.get("current_period_end") else None,
            trial_end=subscription_data["trial_end"].isoformat() if subscription_data.get("trial_end") else None,
            is_active=subscription_data["status"] in ["active", "trialing"],
            is_trial=subscription_data["status"] == "trialing",
            cancel_at_period_end=subscription_data.get("cancel_at_period_end", False),
            days_until_renewal=(subscription_data["current_period_end"] - subscription_data["current_period_start"]).days if subscription_data.get("current_period_end") else None,
        )
    else:
        # Free plan
        return SubscriptionResponse(
            plan="free",
            plan_name="Free",
            status="active",
            billing_cycle="monthly",
            current_period_start=None,
            current_period_end=None,
            trial_end=org.trial_ends_at.isoformat() if org.trial_ends_at else None,
            is_active=True,
            is_trial=org.is_trial,
            cancel_at_period_end=False,
            days_until_renewal=None,
        )


@router.post("/subscribe", response_model=Dict[str, str])
async def create_subscription(
    request: Request,
    data: SubscriptionRequest,
    user: Dict[str, Any] = Depends(require_org_owner()),
):
    """
    Create a new subscription for the organization.
    
    Requires organization owner privileges.
    """
    billing_service = get_billing_service_dep(request)
    org_repo = get_org_repo(request)
    
    org_id = UUID(user["organization_id"])
    org = await org_repo.get_by_id(org_id)
    
    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found"
        )
    
    # Validate plan
    try:
        plan = SubscriptionPlan(data.plan)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid plan: {data.plan}"
        )
    
    if plan == SubscriptionPlan.FREE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot subscribe to free plan"
        )
    
    # Ensure customer exists
    if not org.stripe_customer_id:
        customer = await billing_service.create_customer(
            organization_id=org_id,
            email=org.billing_email or user["email"],
            name=org.name,
        )
        stripe_customer_id = customer.stripe_customer_id
    else:
        stripe_customer_id = org.stripe_customer_id
    
    # Create subscription
    try:
        subscription = await billing_service.create_subscription(
            organization_id=org_id,
            stripe_customer_id=stripe_customer_id,
            plan=plan,
            billing_cycle=data.billing_cycle,
            payment_method_id=data.payment_method_id,
        )
        
        return {
            "message": "Subscription created successfully",
            "subscription_id": subscription.stripe_subscription_id,
            "status": subscription.status.value,
        }
        
    except Exception as e:
        logger.error(f"Failed to create subscription: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post("/cancel")
async def cancel_subscription(
    request: Request,
    immediately: bool = False,
    user: Dict[str, Any] = Depends(require_org_owner()),
):
    """
    Cancel the current subscription.
    
    By default, cancels at the end of the current billing period.
    Set immediately=True to cancel immediately.
    """
    billing_service = get_billing_service_dep(request)
    org_repo = get_org_repo(request)
    
    org_id = UUID(user["organization_id"])
    org = await org_repo.get_by_id(org_id)
    
    if not org or not org.stripe_subscription_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active subscription to cancel"
        )
    
    success = await billing_service.cancel_subscription(
        stripe_subscription_id=org.stripe_subscription_id,
        cancel_immediately=immediately,
    )
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to cancel subscription"
        )
    
    if immediately:
        return {"message": "Subscription canceled immediately"}
    else:
        return {"message": "Subscription will be canceled at the end of the billing period"}


@router.post("/reactivate")
async def reactivate_subscription(
    request: Request,
    user: Dict[str, Any] = Depends(require_org_owner()),
):
    """
    Reactivate a subscription that was scheduled for cancellation.
    """
    billing_service = get_billing_service_dep(request)
    org_repo = get_org_repo(request)
    
    org_id = UUID(user["organization_id"])
    org = await org_repo.get_by_id(org_id)
    
    if not org or not org.stripe_subscription_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No subscription to reactivate"
        )
    
    success = await billing_service.reactivate_subscription(org.stripe_subscription_id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to reactivate subscription"
        )
    
    return {"message": "Subscription reactivated"}


# ═══════════════════════════════════════════════════════════════
# Invoice Endpoints
# ═══════════════════════════════════════════════════════════════

@router.get("/invoices", response_model=List[InvoiceResponse])
async def list_invoices(
    request: Request,
    limit: int = 10,
    user: Dict[str, Any] = Depends(get_current_user),
):
    """
    List invoices for the organization.
    """
    billing_service = get_billing_service_dep(request)
    org_repo = get_org_repo(request)
    
    org_id = UUID(user["organization_id"])
    org = await org_repo.get_by_id(org_id)
    
    if not org or not org.stripe_customer_id:
        return []
    
    invoices = await billing_service.get_invoices(
        stripe_customer_id=org.stripe_customer_id,
        limit=limit,
    )
    
    return [
        InvoiceResponse(
            id=inv.id,
            amount_due=inv.amount_due / 100,
            amount_paid=inv.amount_paid / 100,
            currency=inv.currency,
            status=inv.status,
            paid=inv.paid,
            hosted_invoice_url=inv.hosted_invoice_url,
            invoice_pdf=inv.invoice_pdf,
            due_date=inv.due_date.isoformat() if inv.due_date else None,
            paid_at=inv.paid_at.isoformat() if inv.paid_at else None,
        )
        for inv in invoices
    ]


@router.get("/invoices/upcoming")
async def get_upcoming_invoice(
    request: Request,
    user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Get upcoming invoice preview.
    """
    billing_service = get_billing_service_dep(request)
    org_repo = get_org_repo(request)
    
    org_id = UUID(user["organization_id"])
    org = await org_repo.get_by_id(org_id)
    
    if not org or not org.stripe_customer_id:
        return {"message": "No upcoming invoice"}
    
    invoice = await billing_service.get_upcoming_invoice(org.stripe_customer_id)
    
    if not invoice:
        return {"message": "No upcoming invoice"}
    
    return invoice


# ═══════════════════════════════════════════════════════════════
# Checkout & Portal
# ═══════════════════════════════════════════════════════════════

@router.post("/checkout")
async def create_checkout_session(
    request: Request,
    data: CheckoutRequest,
    user: Dict[str, Any] = Depends(require_org_owner()),
):
    """
    Create a Stripe Checkout session for subscription.
    
    Returns a URL to redirect the user to Stripe's hosted checkout page.
    """
    billing_service = get_billing_service_dep(request)
    org_repo = get_org_repo(request)
    
    org_id = UUID(user["organization_id"])
    org = await org_repo.get_by_id(org_id)
    
    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found"
        )
    
    # Validate plan
    try:
        plan = SubscriptionPlan(data.plan)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid plan: {data.plan}"
        )
    
    # Ensure customer exists
    if not org.stripe_customer_id:
        customer = await billing_service.create_customer(
            organization_id=org_id,
            email=org.billing_email or user["email"],
            name=org.name,
        )
        stripe_customer_id = customer.stripe_customer_id
    else:
        stripe_customer_id = org.stripe_customer_id
    
    try:
        checkout_url = await billing_service.create_checkout_session(
            organization_id=org_id,
            stripe_customer_id=stripe_customer_id,
            plan=plan,
            billing_cycle=data.billing_cycle,
            success_url=data.success_url,
            cancel_url=data.cancel_url,
        )
        
        return {"checkout_url": checkout_url}
        
    except Exception as e:
        logger.error(f"Failed to create checkout session: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post("/portal")
async def create_billing_portal_session(
    request: Request,
    return_url: str,
    user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Create a Stripe Billing Portal session.
    
    Returns a URL to redirect the user to manage their subscription.
    """
    billing_service = get_billing_service_dep(request)
    org_repo = get_org_repo(request)
    
    org_id = UUID(user["organization_id"])
    org = await org_repo.get_by_id(org_id)
    
    if not org or not org.stripe_customer_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No billing account found"
        )
    
    try:
        portal_url = await billing_service.create_billing_portal_session(
            stripe_customer_id=org.stripe_customer_id,
            return_url=return_url,
        )
        
        return {"portal_url": portal_url}
        
    except Exception as e:
        logger.error(f"Failed to create billing portal session: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create billing portal"
        )


# ═══════════════════════════════════════════════════════════════
# Webhook Handler
# ═══════════════════════════════════════════════════════════════

@router.post("/webhook")
async def stripe_webhook(
    request: Request,
    stripe_signature: str = Header(None, alias="Stripe-Signature"),
):
    """
    Handle Stripe webhook events.
    
    This endpoint receives events from Stripe for subscription updates,
    payment status, etc.
    """
    billing_service = get_billing_service_dep(request)
    
    if not stripe_signature:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing Stripe-Signature header"
        )
    
    try:
        # Get raw body
        payload = await request.body()
        
        # Process webhook
        billing_event = await billing_service.process_webhook(
            payload=payload,
            signature=stripe_signature,
        )
        
        logger.info(f"Processed webhook: {billing_event.event_type.value}")
        
        return {"received": True}
        
    except ValueError as e:
        logger.error(f"Webhook error: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Webhook processing failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Webhook processing failed"
        )


# ═══════════════════════════════════════════════════════════════
# Usage & Limits
# ═══════════════════════════════════════════════════════════════

@router.get("/usage")
async def get_usage(
    request: Request,
    user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Get current usage and limits for the organization.
    """
    org_repo = get_org_repo(request)
    
    org_id = UUID(user["organization_id"])
    org = await org_repo.get_by_id(org_id)
    
    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found"
        )
    
    # Get current counts
    user_count = await org_repo.get_current_user_count(org_id)
    mission_count = await org_repo.get_current_mission_count(org_id)
    
    return {
        "plan": org.plan,
        "usage": {
            "users": {
                "current": user_count,
                "limit": org.max_users,
                "percentage": round(user_count / org.max_users * 100, 1) if org.max_users > 0 else 0,
            },
            "missions_this_month": {
                "current": org.missions_this_month,
                "limit": org.max_missions_per_month,
                "percentage": round(org.missions_this_month / org.max_missions_per_month * 100, 1) if org.max_missions_per_month > 0 else 0,
                "resets_at": org.missions_reset_at.isoformat() if org.missions_reset_at else None,
            },
            "concurrent_missions": {
                "current": mission_count,
                "limit": org.max_concurrent_missions,
                "percentage": round(mission_count / org.max_concurrent_missions * 100, 1) if org.max_concurrent_missions > 0 else 0,
            },
            "targets_per_mission": {
                "limit": org.max_targets_per_mission,
            },
        },
    }
