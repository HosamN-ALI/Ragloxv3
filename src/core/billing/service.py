# ===================================================================
# RAGLOX v3.0 - Billing Service
# Stripe integration for SaaS billing
# ===================================================================
"""
Billing service for managing Stripe subscriptions.

This service handles:
- Customer creation and management
- Subscription lifecycle (create, update, cancel)
- Webhook processing
- Usage tracking and billing
- Invoice management
"""

import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from uuid import UUID, uuid4

try:
    import stripe
    STRIPE_AVAILABLE = True
except ImportError:
    STRIPE_AVAILABLE = False
    stripe = None

from .models import (
    SubscriptionPlan,
    SubscriptionStatus,
    BillingCustomer,
    BillingSubscription,
    BillingEvent,
    BillingEventType,
    PLAN_PRICING,
    Invoice,
)

logger = logging.getLogger("raglox.billing")


# ===================================================================
# Global Service Instance
# ===================================================================

_billing_service: Optional["BillingService"] = None


def get_billing_service() -> Optional["BillingService"]:
    """Get the global billing service instance."""
    return _billing_service


def init_billing_service(
    stripe_secret_key: str,
    stripe_webhook_secret: str,
    organization_repo=None,
) -> "BillingService":
    """
    Initialize the global billing service.
    
    Args:
        stripe_secret_key: Stripe API secret key
        stripe_webhook_secret: Stripe webhook signing secret
        organization_repo: OrganizationRepository instance
        
    Returns:
        Initialized BillingService
    """
    global _billing_service
    
    _billing_service = BillingService(
        stripe_secret_key=stripe_secret_key,
        stripe_webhook_secret=stripe_webhook_secret,
        organization_repo=organization_repo,
    )
    
    logger.info("Billing service initialized")
    return _billing_service


# ===================================================================
# Billing Service
# ===================================================================

class BillingService:
    """
    Service for managing Stripe billing operations.
    
    Example:
        service = BillingService(
            stripe_secret_key="sk_test_...",
            stripe_webhook_secret="whsec_..."
        )
        
        # Create customer
        customer = await service.create_customer(
            organization_id=org_id,
            email="billing@company.com",
            name="ACME Corp"
        )
        
        # Create subscription
        subscription = await service.create_subscription(
            organization_id=org_id,
            plan=SubscriptionPlan.PROFESSIONAL,
            payment_method_id="pm_..."
        )
    """
    
    def __init__(
        self,
        stripe_secret_key: str,
        stripe_webhook_secret: str,
        organization_repo=None,
    ):
        """
        Initialize billing service.
        
        Args:
            stripe_secret_key: Stripe API secret key
            stripe_webhook_secret: Stripe webhook signing secret
            organization_repo: OrganizationRepository for updating org data
        """
        if not STRIPE_AVAILABLE:
            raise ImportError("stripe package is not installed. Run: pip install stripe")
        
        self.stripe_secret_key = stripe_secret_key
        self.stripe_webhook_secret = stripe_webhook_secret
        self.organization_repo = organization_repo
        
        # Configure Stripe
        stripe.api_key = stripe_secret_key
        
        logger.info("Billing service configured")
    
    # ===================================================================
    # Customer Management
    # ===================================================================
    
    async def create_customer(
        self,
        organization_id: UUID,
        email: str,
        name: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> BillingCustomer:
        """
        Create a Stripe customer for an organization.
        
        Args:
            organization_id: Organization UUID
            email: Billing email address
            name: Customer name (usually organization name)
            metadata: Additional metadata
            
        Returns:
            BillingCustomer instance
        """
        try:
            # Create Stripe customer
            customer_metadata = {
                "organization_id": str(organization_id),
                **(metadata or {}),
            }
            
            stripe_customer = stripe.Customer.create(
                email=email,
                name=name,
                metadata=customer_metadata,
            )
            
            # Create local customer record
            customer = BillingCustomer(
                id=uuid4(),
                organization_id=organization_id,
                stripe_customer_id=stripe_customer.id,
                email=email,
                name=name,
                metadata=customer_metadata,
                created_at=datetime.utcnow(),
            )
            
            # Update organization with Stripe customer ID
            if self.organization_repo:
                await self.organization_repo.set_stripe_customer(
                    organization_id=organization_id,
                    stripe_customer_id=stripe_customer.id,
                    billing_email=email,
                )
            
            logger.info(f"Created Stripe customer {stripe_customer.id} for org {organization_id}")
            return customer
            
        except stripe.StripeError as e:
            logger.error(f"Failed to create Stripe customer: {e}")
            raise
    
    async def get_customer(
        self,
        stripe_customer_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get Stripe customer details.
        
        Args:
            stripe_customer_id: Stripe customer ID
            
        Returns:
            Customer data dict or None
        """
        try:
            customer = stripe.Customer.retrieve(stripe_customer_id)
            return {
                "id": customer.id,
                "email": customer.email,
                "name": customer.name,
                "default_payment_method": customer.invoice_settings.default_payment_method,
                "created": datetime.fromtimestamp(customer.created),
            }
        except stripe.StripeError as e:
            logger.error(f"Failed to get customer {stripe_customer_id}: {e}")
            return None
    
    async def update_customer(
        self,
        stripe_customer_id: str,
        email: Optional[str] = None,
        name: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Update Stripe customer.
        
        Args:
            stripe_customer_id: Stripe customer ID
            email: New email (optional)
            name: New name (optional)
            metadata: New metadata (optional)
            
        Returns:
            True if updated successfully
        """
        try:
            update_data = {}
            if email:
                update_data["email"] = email
            if name:
                update_data["name"] = name
            if metadata:
                update_data["metadata"] = metadata
            
            if update_data:
                stripe.Customer.modify(stripe_customer_id, **update_data)
                logger.info(f"Updated customer {stripe_customer_id}")
            
            return True
            
        except stripe.StripeError as e:
            logger.error(f"Failed to update customer {stripe_customer_id}: {e}")
            return False
    
    # ===================================================================
    # Payment Methods
    # ===================================================================
    
    async def attach_payment_method(
        self,
        stripe_customer_id: str,
        payment_method_id: str,
        set_as_default: bool = True,
    ) -> bool:
        """
        Attach a payment method to a customer.
        
        Args:
            stripe_customer_id: Stripe customer ID
            payment_method_id: Payment method ID (from Stripe.js)
            set_as_default: Set as default payment method
            
        Returns:
            True if attached successfully
        """
        try:
            # Attach payment method to customer
            stripe.PaymentMethod.attach(
                payment_method_id,
                customer=stripe_customer_id,
            )
            
            # Set as default if requested
            if set_as_default:
                stripe.Customer.modify(
                    stripe_customer_id,
                    invoice_settings={"default_payment_method": payment_method_id},
                )
            
            logger.info(f"Attached payment method {payment_method_id} to {stripe_customer_id}")
            return True
            
        except stripe.StripeError as e:
            logger.error(f"Failed to attach payment method: {e}")
            return False
    
    async def get_payment_methods(
        self,
        stripe_customer_id: str
    ) -> List[Dict[str, Any]]:
        """
        Get all payment methods for a customer.
        
        Args:
            stripe_customer_id: Stripe customer ID
            
        Returns:
            List of payment method dicts
        """
        try:
            payment_methods = stripe.PaymentMethod.list(
                customer=stripe_customer_id,
                type="card",
            )
            
            return [
                {
                    "id": pm.id,
                    "type": pm.type,
                    "card": {
                        "brand": pm.card.brand,
                        "last4": pm.card.last4,
                        "exp_month": pm.card.exp_month,
                        "exp_year": pm.card.exp_year,
                    } if pm.card else None,
                }
                for pm in payment_methods.data
            ]
            
        except stripe.StripeError as e:
            logger.error(f"Failed to get payment methods: {e}")
            return []
    
    # ===================================================================
    # Subscription Management
    # ===================================================================
    
    async def create_subscription(
        self,
        organization_id: UUID,
        stripe_customer_id: str,
        plan: SubscriptionPlan,
        billing_cycle: str = "monthly",
        trial_days: int = 14,
        payment_method_id: Optional[str] = None,
    ) -> BillingSubscription:
        """
        Create a subscription for an organization.
        
        Args:
            organization_id: Organization UUID
            stripe_customer_id: Stripe customer ID
            plan: Subscription plan
            billing_cycle: "monthly" or "yearly"
            trial_days: Number of trial days (0 for no trial)
            payment_method_id: Payment method ID (optional for trial)
            
        Returns:
            BillingSubscription instance
        """
        try:
            plan_config = PLAN_PRICING[plan]
            
            # Get price ID based on billing cycle
            if billing_cycle == "yearly":
                price_id = plan_config["stripe_price_id_yearly"]
            else:
                price_id = plan_config["stripe_price_id_monthly"]
            
            if not price_id:
                raise ValueError(f"No Stripe price configured for plan {plan.value}")
            
            # Build subscription params
            sub_params = {
                "customer": stripe_customer_id,
                "items": [{"price": price_id}],
                "metadata": {
                    "organization_id": str(organization_id),
                    "plan": plan.value,
                },
            }
            
            # Add trial if specified
            if trial_days > 0:
                sub_params["trial_period_days"] = trial_days
            
            # Set default payment method if provided
            if payment_method_id:
                sub_params["default_payment_method"] = payment_method_id
            
            # Create Stripe subscription
            stripe_sub = stripe.Subscription.create(**sub_params)
            
            # Create local subscription record
            subscription = BillingSubscription(
                id=uuid4(),
                organization_id=organization_id,
                stripe_subscription_id=stripe_sub.id,
                stripe_customer_id=stripe_customer_id,
                plan=plan,
                status=SubscriptionStatus(stripe_sub.status),
                billing_cycle=billing_cycle,
                current_period_start=datetime.fromtimestamp(stripe_sub.current_period_start),
                current_period_end=datetime.fromtimestamp(stripe_sub.current_period_end),
                trial_start=datetime.fromtimestamp(stripe_sub.trial_start) if stripe_sub.trial_start else None,
                trial_end=datetime.fromtimestamp(stripe_sub.trial_end) if stripe_sub.trial_end else None,
                created_at=datetime.utcnow(),
            )
            
            # Update organization with subscription info
            if self.organization_repo:
                await self.organization_repo.update_subscription(
                    organization_id=organization_id,
                    plan=plan.value,
                    stripe_subscription_id=stripe_sub.id,
                )
            
            logger.info(f"Created subscription {stripe_sub.id} for org {organization_id}")
            return subscription
            
        except stripe.StripeError as e:
            logger.error(f"Failed to create subscription: {e}")
            raise
    
    async def get_subscription(
        self,
        stripe_subscription_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get subscription details from Stripe.
        
        Args:
            stripe_subscription_id: Stripe subscription ID
            
        Returns:
            Subscription data dict or None
        """
        try:
            sub = stripe.Subscription.retrieve(stripe_subscription_id)
            
            return {
                "id": sub.id,
                "status": sub.status,
                "plan": sub.metadata.get("plan", "unknown"),
                "current_period_start": datetime.fromtimestamp(sub.current_period_start),
                "current_period_end": datetime.fromtimestamp(sub.current_period_end),
                "trial_end": datetime.fromtimestamp(sub.trial_end) if sub.trial_end else None,
                "cancel_at_period_end": sub.cancel_at_period_end,
                "canceled_at": datetime.fromtimestamp(sub.canceled_at) if sub.canceled_at else None,
            }
            
        except stripe.StripeError as e:
            logger.error(f"Failed to get subscription {stripe_subscription_id}: {e}")
            return None
    
    async def update_subscription(
        self,
        stripe_subscription_id: str,
        plan: Optional[SubscriptionPlan] = None,
        billing_cycle: Optional[str] = None,
    ) -> bool:
        """
        Update subscription plan.
        
        Args:
            stripe_subscription_id: Stripe subscription ID
            plan: New plan (optional)
            billing_cycle: New billing cycle (optional)
            
        Returns:
            True if updated successfully
        """
        try:
            update_items = []
            
            if plan:
                plan_config = PLAN_PRICING[plan]
                
                if billing_cycle == "yearly":
                    price_id = plan_config["stripe_price_id_yearly"]
                else:
                    price_id = plan_config["stripe_price_id_monthly"]
                
                # Get current subscription to find item ID
                sub = stripe.Subscription.retrieve(stripe_subscription_id)
                
                update_items = [{
                    "id": sub["items"]["data"][0].id,
                    "price": price_id,
                }]
            
            if update_items:
                stripe.Subscription.modify(
                    stripe_subscription_id,
                    items=update_items,
                    proration_behavior="create_prorations",
                )
                logger.info(f"Updated subscription {stripe_subscription_id}")
            
            return True
            
        except stripe.StripeError as e:
            logger.error(f"Failed to update subscription: {e}")
            return False
    
    async def cancel_subscription(
        self,
        stripe_subscription_id: str,
        cancel_immediately: bool = False,
    ) -> bool:
        """
        Cancel a subscription.
        
        Args:
            stripe_subscription_id: Stripe subscription ID
            cancel_immediately: If True, cancel now; if False, cancel at period end
            
        Returns:
            True if canceled successfully
        """
        try:
            if cancel_immediately:
                stripe.Subscription.cancel(stripe_subscription_id)
                logger.info(f"Canceled subscription {stripe_subscription_id} immediately")
            else:
                stripe.Subscription.modify(
                    stripe_subscription_id,
                    cancel_at_period_end=True,
                )
                logger.info(f"Scheduled subscription {stripe_subscription_id} for cancellation")
            
            return True
            
        except stripe.StripeError as e:
            logger.error(f"Failed to cancel subscription: {e}")
            return False
    
    async def reactivate_subscription(
        self,
        stripe_subscription_id: str
    ) -> bool:
        """
        Reactivate a subscription that was scheduled for cancellation.
        
        Args:
            stripe_subscription_id: Stripe subscription ID
            
        Returns:
            True if reactivated successfully
        """
        try:
            stripe.Subscription.modify(
                stripe_subscription_id,
                cancel_at_period_end=False,
            )
            logger.info(f"Reactivated subscription {stripe_subscription_id}")
            return True
            
        except stripe.StripeError as e:
            logger.error(f"Failed to reactivate subscription: {e}")
            return False
    
    # ===================================================================
    # Invoice Management
    # ===================================================================
    
    async def get_invoices(
        self,
        stripe_customer_id: str,
        limit: int = 10,
    ) -> List[Invoice]:
        """
        Get invoices for a customer.
        
        Args:
            stripe_customer_id: Stripe customer ID
            limit: Maximum number of invoices to return
            
        Returns:
            List of Invoice objects
        """
        try:
            invoices = stripe.Invoice.list(
                customer=stripe_customer_id,
                limit=limit,
            )
            
            result = []
            for inv in invoices.data:
                result.append(Invoice(
                    id=inv.id,
                    organization_id=UUID(inv.metadata.get("organization_id", "00000000-0000-0000-0000-000000000000")),
                    stripe_customer_id=inv.customer,
                    stripe_subscription_id=inv.subscription,
                    amount_due=inv.amount_due,
                    amount_paid=inv.amount_paid,
                    amount_remaining=inv.amount_remaining,
                    currency=inv.currency,
                    status=inv.status,
                    paid=inv.paid,
                    hosted_invoice_url=inv.hosted_invoice_url,
                    invoice_pdf=inv.invoice_pdf,
                    due_date=datetime.fromtimestamp(inv.due_date) if inv.due_date else None,
                    paid_at=datetime.fromtimestamp(inv.status_transitions.paid_at) if inv.status_transitions and inv.status_transitions.paid_at else None,
                    created_at=datetime.fromtimestamp(inv.created),
                ))
            
            return result
            
        except stripe.StripeError as e:
            logger.error(f"Failed to get invoices: {e}")
            return []
    
    async def get_upcoming_invoice(
        self,
        stripe_customer_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get upcoming invoice for a customer.
        
        Args:
            stripe_customer_id: Stripe customer ID
            
        Returns:
            Upcoming invoice data or None
        """
        try:
            invoice = stripe.Invoice.upcoming(customer=stripe_customer_id)
            
            return {
                "amount_due": invoice.amount_due / 100,
                "currency": invoice.currency,
                "period_start": datetime.fromtimestamp(invoice.period_start),
                "period_end": datetime.fromtimestamp(invoice.period_end),
                "lines": [
                    {
                        "description": line.description,
                        "amount": line.amount / 100,
                    }
                    for line in invoice.lines.data
                ],
            }
            
        except stripe.InvalidRequestError:
            # No upcoming invoice (e.g., free plan)
            return None
        except stripe.StripeError as e:
            logger.error(f"Failed to get upcoming invoice: {e}")
            return None
    
    # ===================================================================
    # Webhook Processing
    # ===================================================================
    
    async def process_webhook(
        self,
        payload: bytes,
        signature: str,
    ) -> BillingEvent:
        """
        Process a Stripe webhook event.
        
        Args:
            payload: Raw webhook payload
            signature: Stripe signature header
            
        Returns:
            BillingEvent record
        """
        try:
            # Verify webhook signature
            event = stripe.Webhook.construct_event(
                payload,
                signature,
                self.stripe_webhook_secret,
            )
            
            # Extract organization ID from metadata
            org_id_str = None
            if event.data.object.metadata:
                org_id_str = event.data.object.metadata.get("organization_id")
            
            organization_id = UUID(org_id_str) if org_id_str else uuid4()
            
            # Map Stripe event type to our enum
            event_type_map = {
                "customer.subscription.created": BillingEventType.SUBSCRIPTION_CREATED,
                "customer.subscription.updated": BillingEventType.SUBSCRIPTION_UPDATED,
                "customer.subscription.deleted": BillingEventType.SUBSCRIPTION_CANCELED,
                "invoice.paid": BillingEventType.INVOICE_PAID,
                "invoice.payment_failed": BillingEventType.INVOICE_PAYMENT_FAILED,
                "payment_intent.succeeded": BillingEventType.PAYMENT_SUCCEEDED,
                "payment_intent.payment_failed": BillingEventType.PAYMENT_FAILED,
            }
            
            billing_event_type = event_type_map.get(
                event.type,
                BillingEventType.SUBSCRIPTION_UPDATED  # Default
            )
            
            # Create billing event record
            billing_event = BillingEvent(
                id=uuid4(),
                organization_id=organization_id,
                event_type=billing_event_type,
                stripe_event_id=event.id,
                data=dict(event.data.object),
                processed=False,
                created_at=datetime.utcnow(),
            )
            
            # Process specific event types
            await self._handle_webhook_event(event, billing_event)
            
            billing_event.processed = True
            billing_event.processed_at = datetime.utcnow()
            
            logger.info(f"Processed webhook event {event.id}: {event.type}")
            return billing_event
            
        except stripe.SignatureVerificationError as e:
            logger.error(f"Webhook signature verification failed: {e}")
            raise ValueError("Invalid webhook signature")
        except Exception as e:
            logger.error(f"Failed to process webhook: {e}")
            raise
    
    async def _handle_webhook_event(
        self,
        event: Any,
        billing_event: BillingEvent,
    ) -> None:
        """
        Handle specific webhook event types.
        
        Args:
            event: Stripe event object
            billing_event: Our billing event record
        """
        event_type = event.type
        data = event.data.object
        
        if event_type == "customer.subscription.created":
            # New subscription created
            logger.info(f"Subscription created: {data.id}")
            
        elif event_type == "customer.subscription.updated":
            # Subscription updated (plan change, status change, etc.)
            if self.organization_repo:
                org_id = billing_event.organization_id
                new_status = data.status
                
                if new_status == "canceled":
                    await self.organization_repo.suspend_organization(
                        org_id,
                        reason="Subscription canceled"
                    )
                elif new_status == "active":
                    await self.organization_repo.reactivate_organization(org_id)
            
        elif event_type == "customer.subscription.deleted":
            # Subscription canceled
            if self.organization_repo:
                await self.organization_repo.update_subscription(
                    billing_event.organization_id,
                    plan="free",
                    stripe_subscription_id=None,
                )
            
        elif event_type == "invoice.paid":
            # Invoice paid successfully
            logger.info(f"Invoice paid: {data.id}")
            
        elif event_type == "invoice.payment_failed":
            # Payment failed
            logger.warning(f"Payment failed for invoice: {data.id}")
            
            if self.organization_repo:
                # Could send notification or take action
                pass
    
    # ===================================================================
    # Checkout Session
    # ===================================================================
    
    async def create_checkout_session(
        self,
        organization_id: UUID,
        stripe_customer_id: str,
        plan: SubscriptionPlan,
        billing_cycle: str = "monthly",
        success_url: str = "",
        cancel_url: str = "",
    ) -> str:
        """
        Create a Stripe Checkout session for subscription.
        
        Args:
            organization_id: Organization UUID
            stripe_customer_id: Stripe customer ID
            plan: Subscription plan
            billing_cycle: "monthly" or "yearly"
            success_url: URL to redirect on success
            cancel_url: URL to redirect on cancel
            
        Returns:
            Checkout session URL
        """
        try:
            plan_config = PLAN_PRICING[plan]
            
            if billing_cycle == "yearly":
                price_id = plan_config["stripe_price_id_yearly"]
            else:
                price_id = plan_config["stripe_price_id_monthly"]
            
            if not price_id:
                raise ValueError(f"No price configured for {plan.value}")
            
            session = stripe.checkout.Session.create(
                customer=stripe_customer_id,
                mode="subscription",
                line_items=[{
                    "price": price_id,
                    "quantity": 1,
                }],
                success_url=success_url,
                cancel_url=cancel_url,
                metadata={
                    "organization_id": str(organization_id),
                    "plan": plan.value,
                },
            )
            
            return session.url
            
        except stripe.StripeError as e:
            logger.error(f"Failed to create checkout session: {e}")
            raise
    
    async def create_billing_portal_session(
        self,
        stripe_customer_id: str,
        return_url: str,
    ) -> str:
        """
        Create a Stripe Billing Portal session.
        
        Allows customers to manage their subscription, payment methods, and invoices.
        
        Args:
            stripe_customer_id: Stripe customer ID
            return_url: URL to redirect after portal session
            
        Returns:
            Billing portal URL
        """
        try:
            session = stripe.billing_portal.Session.create(
                customer=stripe_customer_id,
                return_url=return_url,
            )
            
            return session.url
            
        except stripe.StripeError as e:
            logger.error(f"Failed to create billing portal session: {e}")
            raise
