#!/usr/bin/env python3
"""
RAGLOX v3.0 - Stripe Products & Prices Setup Script

This script creates all necessary products and prices in Stripe for RAGLOX SaaS.

Usage:
    python setup_stripe_products.py

Environment:
    STRIPE_SECRET_KEY: Your Stripe secret key (sk_test_... or sk_live_...)
"""

import stripe
import json
from datetime import datetime, timezone

# ===================================================================
# Configuration
# ===================================================================
import os

# Stripe API Key (from environment variable)
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")

if not STRIPE_SECRET_KEY:
    print("❌ Error: STRIPE_SECRET_KEY environment variable not set")
    print("   Set it with: export STRIPE_SECRET_KEY=sk_test_...")
    exit(1)

# Configure Stripe
stripe.api_key = STRIPE_SECRET_KEY

# Product definitions
PRODUCTS = {
    "starter": {
        "name": "RAGLOX Starter",
        "description": "Perfect for small teams getting started with automated penetration testing",
        "features": [
            "Up to 10 users",
            "25 missions per month",
            "3 concurrent missions",
            "50 targets per mission",
            "API access",
            "Advanced reports",
        ],
        "prices": {
            "monthly": 4900,  # $49.00 in cents
            "yearly": 49000,  # $490.00 in cents
        },
    },
    "professional": {
        "name": "RAGLOX Professional",
        "description": "For growing security teams with advanced needs",
        "features": [
            "Up to 50 users",
            "100 missions per month",
            "10 concurrent missions",
            "200 targets per mission",
            "Priority support",
            "API access",
            "Advanced reports",
        ],
        "prices": {
            "monthly": 19900,  # $199.00 in cents
            "yearly": 199000,  # $1990.00 in cents
        },
    },
    "enterprise": {
        "name": "RAGLOX Enterprise",
        "description": "Full-featured solution for large enterprises",
        "features": [
            "Up to 1000 users",
            "Unlimited missions",
            "100 concurrent missions",
            "1000 targets per mission",
            "Priority support",
            "SSO integration",
            "Custom integrations",
            "Dedicated account manager",
        ],
        "prices": {
            "monthly": 49900,  # $499.00 in cents
            "yearly": 499000,  # $4990.00 in cents
        },
    },
}


def create_product(key: str, config: dict) -> str:
    """Create a product in Stripe."""
    print(f"\n📦 Creating product: {config['name']}")
    
    # Check if product already exists
    try:
        existing = stripe.Product.search(query=f"name:'{config['name']}'")
        if existing.data:
            product = existing.data[0]
            print(f"   ℹ️  Product already exists: {product.id}")
            return product.id
    except Exception as e:
        print(f"   ⚠️  Search failed, creating new: {e}")
    
    # Create new product (features are set in marketing_features or via dashboard)
    product = stripe.Product.create(
        name=config["name"],
        description=config["description"],
        metadata={
            "plan_key": key,
            "created_by": "raglox_setup_script",
            "features": ", ".join(config["features"]),
        },
    )
    
    print(f"   ✅ Created product: {product.id}")
    return product.id


def create_price(product_id: str, plan_key: str, interval: str, amount: int) -> str:
    """Create a price for a product in Stripe."""
    interval_name = "month" if interval == "monthly" else "year"
    print(f"   💵 Creating {interval} price: ${amount/100:.2f}")
    
    # Check if price exists with this product and interval
    existing = stripe.Price.list(
        product=product_id,
        active=True,
        limit=100,
    )
    
    for price in existing.data:
        if price.recurring and price.recurring.interval == interval_name:
            print(f"      ℹ️  Price already exists: {price.id}")
            return price.id
    
    # Create new price
    price = stripe.Price.create(
        product=product_id,
        currency="usd",
        unit_amount=amount,
        recurring={
            "interval": interval_name,
        },
        metadata={
            "plan_key": plan_key,
            "billing_cycle": interval,
            "created_by": "raglox_setup_script",
        },
    )
    
    print(f"      ✅ Created price: {price.id}")
    return price.id


def create_customer_portal_config():
    """Create a customer portal configuration."""
    print("\n🚪 Setting up Customer Portal...")
    
    try:
        # List existing configurations
        configs = stripe.billing_portal.Configuration.list(limit=1)
        
        if configs.data:
            config = configs.data[0]
            print(f"   ℹ️  Portal configuration exists: {config.id}")
            return config.id
        
        # Create new configuration
        config = stripe.billing_portal.Configuration.create(
            business_profile={
                "headline": "Manage your RAGLOX subscription",
            },
            features={
                "subscription_cancel": {
                    "enabled": True,
                    "mode": "at_period_end",
                },
                "subscription_update": {
                    "enabled": True,
                    "default_allowed_updates": ["price", "promotion_code"],
                    "proration_behavior": "create_prorations",
                },
                "payment_method_update": {
                    "enabled": True,
                },
                "invoice_history": {
                    "enabled": True,
                },
            },
            default_return_url="https://app.raglox.io/billing",
        )
        
        print(f"   ✅ Created portal configuration: {config.id}")
        return config.id
        
    except Exception as e:
        print(f"   ⚠️  Portal setup skipped: {e}")
        return None


def main():
    """Main setup function."""
    print("=" * 60)
    print("RAGLOX v3.0 - Stripe Products Setup")
    print("=" * 60)
    
    # Verify API key
    try:
        account = stripe.Account.retrieve()
        print(f"\n✅ Connected to Stripe account: {account.get('email', account.id)}")
        print(f"   Mode: {'LIVE' if 'live' in STRIPE_SECRET_KEY else 'TEST'}")
    except stripe.error.AuthenticationError:
        print("\n❌ Invalid Stripe API key!")
        return
    
    # Store created IDs
    created_ids = {
        "products": {},
        "prices": {},
    }
    
    # Create products and prices
    for plan_key, config in PRODUCTS.items():
        product_id = create_product(plan_key, config)
        created_ids["products"][plan_key] = product_id
        
        # Create monthly and yearly prices
        for interval, amount in config["prices"].items():
            price_id = create_price(product_id, plan_key, interval, amount)
            price_key = f"{plan_key}_{interval}"
            created_ids["prices"][price_key] = price_id
    
    # Create customer portal
    portal_config_id = create_customer_portal_config()
    
    # Print summary
    print("\n" + "=" * 60)
    print("📋 SETUP COMPLETE - Copy these IDs to your configuration")
    print("=" * 60)
    
    print("\n# PLAN_PRICING Update (src/core/billing/models.py):")
    print("-" * 60)
    
    config_output = f'''
PLAN_PRICING = {{
    SubscriptionPlan.FREE: {{
        "name": "Free",
        "price_monthly": 0,
        "price_yearly": 0,
        "stripe_price_id_monthly": None,
        "stripe_price_id_yearly": None,
        "features": {{ ... }},
    }},
    SubscriptionPlan.STARTER: {{
        "name": "Starter",
        "price_monthly": 49,
        "price_yearly": 490,
        "stripe_price_id_monthly": "{created_ids['prices'].get('starter_monthly', 'MISSING')}",
        "stripe_price_id_yearly": "{created_ids['prices'].get('starter_yearly', 'MISSING')}",
        "features": {{ ... }},
    }},
    SubscriptionPlan.PROFESSIONAL: {{
        "name": "Professional",
        "price_monthly": 199,
        "price_yearly": 1990,
        "stripe_price_id_monthly": "{created_ids['prices'].get('professional_monthly', 'MISSING')}",
        "stripe_price_id_yearly": "{created_ids['prices'].get('professional_yearly', 'MISSING')}",
        "features": {{ ... }},
    }},
    SubscriptionPlan.ENTERPRISE: {{
        "name": "Enterprise",
        "price_monthly": 499,
        "price_yearly": 4990,
        "stripe_price_id_monthly": "{created_ids['prices'].get('enterprise_monthly', 'MISSING')}",
        "stripe_price_id_yearly": "{created_ids['prices'].get('enterprise_yearly', 'MISSING')}",
        "features": {{ ... }},
    }},
}}
'''
    print(config_output)
    
    # Save to JSON file for reference
    output_file = "stripe_setup_output.json"
    with open(output_file, "w") as f:
        json.dump({
            "created_at": datetime.utcnow().isoformat(),
            "mode": "test" if "test" in STRIPE_SECRET_KEY else "live",
            "products": created_ids["products"],
            "prices": created_ids["prices"],
            "portal_config_id": portal_config_id,
        }, f, indent=2)
    
    print(f"\n💾 Full output saved to: {output_file}")
    print("\n✅ Stripe setup complete!")


if __name__ == "__main__":
    main()
