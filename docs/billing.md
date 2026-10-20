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

Enforcement applies to a signed-in non-owner and to API keys that account created (the key stores the account id). A lapsed or suspended plan is still that account: reads and writes are refused with the plan-state codes below, and quota checks keep using the stored tier instead of treating the key as self-hosted. Owner sessions, host-admin keys and self-hosted keys (no account on the key) are not capped. Storage is the bytes on disk for that account's databases plus its hosted apps, not a counter that only goes up.

- **Storage**: a write that would pass the cap is refused with **402**, `code: "quota_exceeded"`, `limit: "storage_quota"`.
- **Traffic**: request body + response bytes are metered. When the monthly total is already spent, further requests get **429**, `code: "quota_exceeded"`, `limit: "traffic_quota"`.
- **Host switches**: creating or dropping a database, `POST /v1/billing/hosting` with `action=on|off`, and starting or stopping a hosted app (only when the running state changes) count toward the budget. When it is exhausted, **402**, `code: "quota_exceeded"`, `limit: "host_switch_quota"`. The hosting route's `error` field stays `host_switch_quota`. Emerald is unlimited (`hostSwitches: -1`).
- **Hosted apps**: each tier also caps how many apps an account may run, and the CPU, memory, disk and log retention of each one. Those numbers live in [Hosting apps and sites](hosting-apps.md) and can be overridden with `apps_limits` / `REDX_APPS_LIMITS`. A second app past the cap is **402**, `limit: "app_quota"`. A deploy past the per-app disk cap is **402**, `limit: "app_disk_quota"`.

### When a plan is not active

`GET /v1/billing/me` includes `access`:

| `access` | When | What the account can do |
|---|---|---|
| `full` | status `active` or `trialing`, and now is before period end + 3 days | create, read, write, drop, keys — quotas apply |
| `readonly` | any other status while now is still before period end + 3 days (`past_due`, `canceled`, `unpaid`, `paused`, `incomplete`) | reads work; create, write, drop and key changes return **402** `plan_readonly` |
| `suspended` | a plan row exists and the 3-day window has ended | data-plane calls return **402** `plan_required`; `GET /v1/dbs` is 200 with `suspended: true` |
| `none` | no plan row | create returns **402** `plan_required`; `GET /v1/dbs` stays **403** |

`active` on `/v1/billing/me` is unchanged: it follows `Plan.Active`, which still treats `past_due` as entitled until the grace ends so the billing page can show the tier. Writes use `access`, not `active`.

Nothing is deleted when a plan lapses. The files stay under `<data>/dbs/`. A later `active` or `trialing` subscription (webhook `customer.subscription.updated`, or the checkout return sync) opens them again. `customer.subscription.deleted` and `invoice.payment_failed` update the row the same way; they do not drop databases. The webhook checks `Stripe-Signature` (5 minute tolerance) with `STRIPE_WEBHOOK_SECRET`. The tier is the price lookup key `redx_hosted_<tier>_<monthly|annual>`, or `metadata.plan` on the price or the subscription when the lookup key is empty. `metadata.app` must be `redx`.

`Host.BillingPlan(sub)` returns the paid tier; `Host.BillingUsage(sub)` returns quota + counters for the billing/my-plan page and owners (`GET /v1/owner/accounts/{id}` includes `hosted` when the account is on a plan). Counters live in `<data_dir>/billing/usage.json` (0600). Who owns which database lives in `<data_dir>/tenants.json` (0600).

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
- `GET /v1/billing/me`, `POST /v1/billing/portal`: current plan (includes `interval`, `quota`, `usage`, and `access`: `full` | `readonly` | `suspended` | `none`); Stripe customer portal link.
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
