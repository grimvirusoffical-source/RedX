# RedX Hosted plans (Stripe Billing)

redxd can sell the RedX Hosted tiers to signed-in Red-XAI Accounts. Package `billing` does the work;
`host/billing_api.go` wires it in. It is off until the Stripe keys are set, and redxd starts either way.

## Plans

Monthly prices on the Red-XAI LLC Stripe account, found by lookup key (metadata `app=redx`, `plan=<tier>`):

| Tier | Lookup key | Price |
|---|---|---|
| Basic | `redx_hosted_basic_monthly` | $20 / month |
| Bronze | `redx_hosted_bronze_monthly` | $45 / month |
| Silver | `redx_hosted_silver_monthly` | $60 / month |
| Gold | `redx_hosted_gold_monthly` | $80 / month |
| Platinum | `redx_hosted_platinum_monthly` | $90 / month |
| Emerald | `redx_hosted_emerald_monthly` | $100 / month |

The console always shows Stripe's amounts. To change a price, make a new Price in Stripe and move the lookup key.
Customer portal configuration: `bpc_1USGbDCtNDGcw0e6IpAR07TM` (switch between the six tiers, cancel at period end).
Per-tier limits (storage, requests) are not defined yet; `Host.BillingPlan(sub)` returns the paid tier for when they are.

## Configuration

Environment only (never the config file, never logged):

| Variable | |
|---|---|
| `STRIPE_SECRET_KEY` | `sk_live_…` / `sk_test_…` |
| `STRIPE_PUBLISHABLE_KEY` | `pk_…`, same mode as the secret key |
| `STRIPE_WEBHOOK_SECRET` | `whsec_…` from the webhook endpoint below |
| `STRIPE_PORTAL_CONFIG` | `bpc_1USGbDCtNDGcw0e6IpAR07TM` |
| `REDX_STRIPE_LIVE=1` | required for a live key; without it a live key is refused |
| `REDX_BILLING_PUBLIC_URL` / `billing_public_url` | the https URL of this console (default `advertise`) |

## Routes

- `GET /v1/billing/plans`: public; tiers with Stripe prices, `enabled`, the publishable key.
- `POST /v1/billing/checkout {plan, idempotencyKey}`: signed-in Red-XAI Account only (API keys get 403
  `account_required`). Creates a subscription Checkout Session with `ui_mode=elements`, metadata
  `app/plan/account` on the session and the subscription; returns `clientSecret`. One subscription per
  account: a second one answers `409 manage_in_portal`.
- `GET /v1/billing/checkout/{cs_…}`: return-page status; only the account that started it can read it.
- `GET /v1/billing/me`, `POST /v1/billing/portal`: current plan; Stripe customer portal link.
- `POST /v1/billing/webhook`: Stripe events, `Stripe-Signature` checked (5 minute tolerance), event ids
  de-duplicated, live/test mode must match the key.

The page is `/ui/billing.html` (Settings → RedX Hosted plan → Choose a plan): Stripe's Payment Element with
the Appearance API in the console's crimson theme. Only that page's CSP allows `https://js.stripe.com` and
Stripe's frames; the rest of the console keeps the strict policy. `?preview=1` renders it without Stripe.

## Webhook endpoint

Register `https://<your console host>/v1/billing/webhook` in Stripe with API version `2026-09-30.endive` and
these events: `checkout.session.completed`, `customer.subscription.created`, `customer.subscription.updated`,
`customer.subscription.deleted`, `customer.subscription.paused`, `customer.subscription.resumed`,
`invoice.paid`, `invoice.payment_failed`. Put its signing secret in `STRIPE_WEBHOOK_SECRET`.

Every event makes redxd re-read the subscription from Stripe (the event body is not trusted). The tier
comes from the price's lookup key; access runs to the paid period end plus 3 days while Stripe retries a
failed renewal (`past_due`); canceled / unpaid / incomplete subscriptions grant nothing. Subscriptions
whose `metadata.app` is not `redx` (Rotten Apple shares the Stripe account) are ignored.

Plans are kept in `<data_dir>/billing/plans.json` (0600) on the node that receives the webhook; in a
cluster point Stripe at the leader.
