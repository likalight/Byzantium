# Billing Setup

Byzantium uses Stripe metered billing. Each trust check counts as 1 unit.

## Setup

1. Create a metered price in Stripe Dashboard → Products → Add Product → Recurring → Usage-based
2. Copy the Price ID (starts with `price_`)
3. Set env vars:
   STRIPE_SECRET_KEY=sk_live_...
   STRIPE_PRICE_ID=price_...
4. For each operator API key, call UsageMeter::register_key(api_key, stripe_subscription_item_id)

## How it works

- Every trust check increments an in-memory counter per API key
- Every hour a background job flushes counts to Stripe usage records
- Stripe bills the operator at month end based on total units

## Without Stripe

If STRIPE_SECRET_KEY is not set, usage is still counted and logged but never billed.
The /v1/usage endpoint always shows current unbilled count.
