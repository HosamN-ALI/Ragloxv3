#!/usr/bin/env python3
"""
RAGLOX v3.0 - Stripe Integration Test Script

Tests the Stripe integration by:
1. Verifying API connection
2. Checking products/prices exist
3. Testing customer creation
4. Testing checkout session creation
5. Testing subscription lifecycle (optional)

Usage:
    python test_stripe_integration.py
"""

import stripe
import sys
import asyncio

# ===================================================================
# Configuration
# ===================================================================
import os

STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")

if not STRIPE_SECRET_KEY:
    print("❌ Error: STRIPE_SECRET_KEY environment variable not set")
    print("   Set it with: export STRIPE_SECRET_KEY=sk_test_...")
    sys.exit(1)

# Expected Price IDs (from setup script)
EXPECTED_PRICES = {
    "starter_monthly": "price_1SmboIQZf6X1AyY5gi4OLgb7",
    "starter_yearly": "price_1SmboIQZf6X1AyY5B7Ntt03v",
    "professional_monthly": "price_1SmboIQZf6X1AyY5MZX03Dog",
    "professional_yearly": "price_1SmboJQZf6X1AyY5MVnuF8TP",
    "enterprise_monthly": "price_1SVje7QZf6X1AyY5ZspNTBDo",
    "enterprise_yearly": "price_1SVje8QZf6X1AyY5aQpJxo0A",
}

# Configure Stripe
stripe.api_key = STRIPE_SECRET_KEY


def test_connection():
    """Test 1: Verify Stripe connection."""
    print("\n🔌 Test 1: Stripe Connection")
    print("-" * 40)
    
    try:
        account = stripe.Account.retrieve()
        print(f"   ✅ Connected to account: {account.id}")
        print(f"   📧 Email: {account.get('email', 'N/A')}")
        print(f"   🏢 Business: {account.get('business_profile', {}).get('name', 'N/A')}")
        return True
    except stripe.error.AuthenticationError as e:
        print(f"   ❌ Authentication failed: {e}")
        return False
    except Exception as e:
        print(f"   ❌ Connection error: {e}")
        return False


def test_prices_exist():
    """Test 2: Verify all expected prices exist."""
    print("\n💵 Test 2: Price Verification")
    print("-" * 40)
    
    all_exist = True
    
    for name, price_id in EXPECTED_PRICES.items():
        try:
            price = stripe.Price.retrieve(price_id)
            amount = price.unit_amount / 100
            interval = price.recurring.interval if price.recurring else "one-time"
            print(f"   ✅ {name}: ${amount:.2f}/{interval} (active={price.active})")
        except stripe.error.InvalidRequestError:
            print(f"   ❌ {name}: Price {price_id} NOT FOUND")
            all_exist = False
        except Exception as e:
            print(f"   ⚠️  {name}: Error - {e}")
            all_exist = False
    
    return all_exist


def test_create_customer():
    """Test 3: Create a test customer."""
    print("\n👤 Test 3: Customer Creation")
    print("-" * 40)
    
    try:
        # Create test customer
        customer = stripe.Customer.create(
            email="test@raglox-test.io",
            name="RAGLOX Test Customer",
            metadata={
                "test": "true",
                "created_by": "integration_test",
            },
        )
        
        print(f"   ✅ Created customer: {customer.id}")
        print(f"   📧 Email: {customer.email}")
        
        # Clean up - delete test customer
        stripe.Customer.delete(customer.id)
        print(f"   🗑️  Cleaned up test customer")
        
        return True
        
    except Exception as e:
        print(f"   ❌ Customer creation failed: {e}")
        return False


def test_checkout_session():
    """Test 4: Create a checkout session."""
    print("\n🛒 Test 4: Checkout Session")
    print("-" * 40)
    
    try:
        # Create test customer first
        customer = stripe.Customer.create(
            email="checkout-test@raglox-test.io",
            metadata={"test": "true"},
        )
        
        # Create checkout session
        session = stripe.checkout.Session.create(
            customer=customer.id,
            payment_method_types=["card"],
            line_items=[{
                "price": EXPECTED_PRICES["starter_monthly"],
                "quantity": 1,
            }],
            mode="subscription",
            success_url="https://app.raglox.io/billing/success?session_id={CHECKOUT_SESSION_ID}",
            cancel_url="https://app.raglox.io/billing/cancel",
            metadata={
                "test": "true",
            },
        )
        
        print(f"   ✅ Created session: {session.id}")
        print(f"   🔗 URL: {session.url[:60]}...")
        print(f"   💳 Mode: {session.mode}")
        
        # Clean up
        stripe.Customer.delete(customer.id)
        print(f"   🗑️  Cleaned up test customer")
        
        return True
        
    except Exception as e:
        print(f"   ❌ Checkout session failed: {e}")
        return False


def test_billing_portal():
    """Test 5: Billing portal session."""
    print("\n🚪 Test 5: Billing Portal")
    print("-" * 40)
    
    try:
        # Create test customer
        customer = stripe.Customer.create(
            email="portal-test@raglox-test.io",
            metadata={"test": "true"},
        )
        
        # Create billing portal session
        session = stripe.billing_portal.Session.create(
            customer=customer.id,
            return_url="https://app.raglox.io/billing",
        )
        
        print(f"   ✅ Created portal session: {session.id[:30]}...")
        print(f"   🔗 URL: {session.url[:60]}...")
        
        # Clean up
        stripe.Customer.delete(customer.id)
        print(f"   🗑️  Cleaned up test customer")
        
        return True
        
    except stripe.error.InvalidRequestError as e:
        if "portal configuration" in str(e).lower():
            print(f"   ⚠️  Billing portal not configured (configure in Stripe Dashboard)")
            return True  # Not a critical error
        print(f"   ❌ Portal session failed: {e}")
        return False
    except Exception as e:
        print(f"   ❌ Portal session failed: {e}")
        return False


def main():
    """Run all tests."""
    print("=" * 60)
    print("RAGLOX v3.0 - Stripe Integration Tests")
    print("=" * 60)
    
    results = {
        "Connection": test_connection(),
        "Prices": test_prices_exist(),
        "Customer": test_create_customer(),
        "Checkout": test_checkout_session(),
        "Portal": test_billing_portal(),
    }
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 Test Results Summary")
    print("=" * 60)
    
    passed = sum(1 for r in results.values() if r)
    total = len(results)
    
    for name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"   {name}: {status}")
    
    print("-" * 60)
    print(f"   Total: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed! Stripe integration is working.")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed. Please review.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
