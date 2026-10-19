# RedX Hosted plans (Stripe Billing)

redxd can sell the RedX Hosted tiers to signed-in Red-XAI Accounts. Package `billing` does the work;
`host/billing_api.go` wires it in. It is off until the Stripe keys are set, and redxd starts either way.

## Plans

Prices on the Red-XAI LLC Stripe account, found by lookup key (metadata `app=redx`, `plan=<tier>`).
**Annual = 10× monthly (2 months free).** Monthly and annual share the same quotas.

| Tier | Monthly lookup | Monthly | Annual lookup | Annual |
|---|---|---|---|---|
| Basic | `redx_hosted_basic_monthly` | $20 / month | `redx_hosted_basic_annual` | $200 / year |
| Bronze | `redx_hosted_bronze_monthly` | $45 / month | `redx_hosted_bronze_annual` | $450 / year |
| Silver | `redx_hosted_silver_monthly` | $60 / month | `redx_hosted_silver_annual` | $600 / year |
| Gold | `redx_hosted_gold_monthly` | $80 / month | `redx_hosted_gold_annual` | $800 / year |
| Platinum | `redx_hosted_platinum_monthly` | $90 / month | `redx_hosted_platinum_annual` | $900 / year |
| Emerald | `redx_hosted_emerald_monthly` | $100 / month | `redx_hosted_emerald_annual` | $1000 / year |

The console always shows Stripe's amounts. To change a price, make a new Price in Stripe and move the lookup key.
Customer portal configuration: `bpc_1USGbDCtNDGcw0e6IpAR07TM` (switch between the six tiers and monthly↔annual, cancel at period end).

### Quotas (same for monthly and annual)

Bytes are GiB/TiB (1024-based). Traffic and host switches reset each month on the billing cycle
(day-of-month from the subscription period end). Storage is a continuous cap.

| Tier | Traffic / month | Storage | Host on↔off switches / month |
|---|---|---|---|
| Basic | 10 GB | 1 GB | 2 |
| Bronze | 50 GB | 5 GB | 5 |
| Silver | 150 GB | 20 GB | 10 |
| Gold | 500 GB | 50 GB | 20 |
| Platinum | 1 TB | 100 GB | 40 |
| Emerald | 5 TB | 500 GB | unlimited |

Enforcement (signed-in Red-XAI Account with an active Hosted plan only; API keys and owner sessions are not capped):

- **Storage**: a write that would push stored bytes past the cap is refused with **402** `storage_quota` and an upgrade hint.
- **Traffic**: HTTP traffic (request body + a small response floor) is metered; when the monthly cap is already reached, further requests get **429** `traffic_quota`.
- **Host switches**: creating or dropping a database, or `POST /v1/billing/hosting` with `action=on|off`, counts toward the budget; when exhausted, **402** `host_switch_quota`. Emerald is unlimited.

`Host.BillingPlan(sub)` returns the paid tier; `Host.BillingUsage(sub)` returns quota + counters for the billing/my-plan page and owners (`GET /v1/owner/accounts/{id}` includes `hosted` when the account is on a plan). Counters live in `<data_dir>/billing/usage.json` (0600).

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

- `GET /v1/billing/plans`: public; each tier as monthly and annual rows (with `quota`), `enabled`, the publishable key.
- `POST /v1/billing/checkout {plan, interval, idempotencyKey}`: signed-in Red-XAI Account only (API keys get 403
  `account_required`). `interval` is `month` (default) or `year`. Creates a subscription Checkout Session with
  `ui_mode=elements`, metadata `app/plan/interval/account` on the session and the subscription; returns
  `clientSecret`. One subscription per account: a second one answers `409 manage_in_portal`.
- `GET /v1/billing/checkout/{cs_…}`: return-page status; only the account that started it can read it.
- `GET /v1/billing/me`, `POST /v1/billing/portal`: current plan (includes `interval`, `quota`, `usage`); Stripe customer portal link.
- `POST /v1/billing/hosting {action: "on"|"off"}`: flip Hosted on/off (counts toward the switch budget).
- `POST /v1/billing/webhook`: Stripe events, `Stripe-Signature` checked (5 minute tolerance), event ids
  de-duplicated, live/test mode must match the key.

The page is `/ui/billing.html` (Settings → RedX Hosted plan → Choose a plan): Stripe's Payment Element with
the Appearance API in the console's crimson theme. Only that page's CSP allows `https://js.stripe.com` and
Stripe's frames; the rest of the console keeps the strict policy. `?preview=1` renders it without Stripe.
Pick monthly or annual on the plan grid.

## Creating Stripe prices

Use `scripts/stripe-create-annual-prices.sh` (test mode only). It creates the six annual prices with lookup
keys `redx_hosted_<tier>_annual` on the same Products as the monthly prices. **Live prices need Josh** —
the script refuses `sk_live_` keys. See that script's header for Stripe CLI / API steps.

## Webhook endpoint

Register `https://<your console host>/v1/billing/webhook` in Stripe with API version `2026-09-30.endive` and
these events: `checkout.session.completed`, `customer.subscription.created`, `customer.subscription.updated`,
`customer.subscription.deleted`, `customer.subscription.paused`, `customer.subscription.resumed`,
`invoice.paid`, `invoice.payment_failed`. Put its signing secret in `STRIPE_WEBHOOK_SECRET`.

Every event makes redxd re-read the subscription from Stripe (the event body is not trusted). The tier and
billing interval come from the price's lookup key; access runs to the paid period end plus 3 days while
Stripe retries a failed renewal (`past_due`); canceled / unpaid / incomplete subscriptions grant nothing.
Subscriptions whose `metadata.app` is not `redx` (Rotten Apple shares the Stripe account) are ignored.

Plans are kept in `<data_dir>/billing/plans.json` (0600) on the node that receives the webhook; in a
cluster point Stripe at the leader.
