# Red-XAI Accounts in RedX

RedX can let people sign in to the web console with their **Red-XAI Account**, the one account shared by every
Red-XAI app. It follows the Red-XAI Accounts **contract v1.1** (OIDC provider + sign-up API). API keys keep working
exactly as before for SDKs, the CLI and machines; account sign-in is only for people using the console.

## Register the confidential client

RedX is a **confidential** first-party client of Red-XAI Accounts (`client_id` = `redx` by default). PKCE S256 is
still required on every authorize request. The client secret is never committed:

1. On the Accounts host, after it has been started with `--redx-advertise <your RedX public base URL>` (so the
   redirect URI is seeded), print the secret once:

   ```bash
   redxai-accounts app-secret redx
   ```

2. Put that value in the RedX host environment (or a file the process can read), never in the repository:

   ```bash
   export REDX_ACCOUNTS_CLIENT_SECRET='…'          # preferred
   # or
   export REDX_ACCOUNTS_CLIENT_SECRET_FILE=/run/secrets/redx-accounts-client
   ```

3. Register (or confirm) the redirect URI as exactly:

   ```
   <advertise>/v1/auth/callback
   ```

   where `<advertise>` is this host's public base URL (`advertise` / `REDX_ADVERTISE`). Accounts also accepts a
   loopback URI without a port matching any port (RFC 8252 §7.3) for local development.

RedX refuses to start with an issuer configured and no client secret.

## Configuration

| Setting | Env | Meaning |
|---|---|---|
| `accounts_issuer` | `REDX_ACCOUNTS_ISSUER` | Issuer URL (empty = off) |
| `accounts_client_id` | `REDX_ACCOUNTS_CLIENT_ID` | Default `redx` |
| `accounts_redirect_url` | `REDX_ACCOUNTS_REDIRECT_URL` | Default `<advertise>/v1/auth/callback` |
| `accounts_master_db` | `REDX_ACCOUNTS_MASTER_DB` | Default `redxai_accounts` |
| *(secret, never in TOML)* | `REDX_ACCOUNTS_CLIENT_SECRET` | Confidential client secret |
| `accounts_client_secret_file` | `REDX_ACCOUNTS_CLIENT_SECRET_FILE` | File holding the secret |
| `owner_emails` | `REDXAI_OWNER_EMAILS` | Owner logins (deploy only; never commit real addresses) |
| `accounts_sms_resend_path` | `REDX_ACCOUNTS_SMS_RESEND_PATH` | Default `/v1/signup/resend-sms`; set to `off` to hide the button |
| `accounts_events_poll_seconds` | `REDX_ACCOUNTS_EVENTS_POLL_SECONDS` | Default 15 |

On every sign-up and sign-in call RedX forwards to Accounts it sends the end-user IP as
`X-RedXAI-Client-IP` (honoured only for confidential clients).

## Owner role

Owner privileges need **all** of:

1. The email is in `owner_emails` / `REDXAI_OWNER_EMAILS` (folded).
2. `email_verified` is true.
3. The sign-in's `amr` contains `otp` or `sms` (password alone is not enough).
4. The token response's `scope` list includes `owner`. RedX requests `openid profile email owner` at sign-in;
   Accounts **silently drops** `owner` when the account is ineligible, so RedX checks the granted `scope`
   before elevating the session. Missing scope → `owner_scope_missing`.

Owners keep their Red-XAI access (and refresh) token in memory only, and use it for moderation:

- `POST /v1/owner/accounts/{id}/kick` `{reason}`
- `POST /v1/owner/accounts/{id}/ban` `{reason, untilMs}` (`0` = forever)
- `POST /v1/owner/accounts/{id}/terminate` `{reason, confirm: "TERMINATE"}` (confirm is enforced by RedX; Accounts itself only needs `{reason}`)

The Owner page wires the same actions. Every call is audit-logged; on success RedX also ends that account's
console sessions on this host.

## Cross-app events

redxd polls `GET /v1/apps/events?since=<cursor>&limit=…` with HTTP Basic client authentication, persists the
cursor under `<data_dir>/accounts/events.json` (mode 0600), and ends console sessions (and WebSocket
subscriptions) for `account.kicked`, `account.banned`, `account.terminated` and `account.deleted`. Delivery is
at-least-once; events are deduped by `seq`. The wire-shape adapter lives in `host/accounts_events_adapter.go`
so a docs bump can change that file alone. Unknown event types are ignored. `update.available`,
`update.analysed`, `rollout.state`, `rollout.health` and `rollback.done` on this same feed are forwarded to
`GET /v1/updates/events` and do not end sessions.

## Sign-up

The console sign-up UI mirrors the Accounts rules (ToS gate, live hints, confirm boxes, DOB, 2FA). Age uses
`minAge` from `/v1/rules?app=` (never below the central 13). Phone 2FA shows a **Resend text message** button
when `sms_resend` is on in `/v1/auth/config` (forwards to `POST /v1/signup/resend-sms`).

## Hosted tenants

A signed-in account that is not an owner can create databases and API keys only while its RedX Hosted plan is `active` or `trialing` (see [billing](billing.md) for the 3-day read-only grace and for what happens after it). The account sees and manages only its own databases. Names are stored namespaced, so two accounts may both choose `game`. Owners keep full visibility, and every owner request is an audit line. Owner emails are never written into the repository; set them with `REDXAI_OWNER_EMAILS` on the server.

## Same account as the website

Sign-in and the quick sign-up on the console (`Sign in with Red-XAI Account`, `Create a Red-XAI Account`) talk to the Red-XAI Accounts issuer in `accounts_issuer`. That is the same account database the Red-XAI website uses. RedX does not create a user table, does not copy passwords into its own store, and does not keep a second login list. A console session (`rxs_…`) is only a session on this host. API keys remain the way programs and the CLI call the API.

The sign-up form posts to Accounts (`POST /v1/signup` on the issuer). Age, terms, and two-factor rules are Accounts rules. RedX checks the fields and forwards them.

## What stays local

- Console session tokens (`rxs_…`) are hashed (SHA-256) in memory; Red-XAI tokens are kept only for owner
  sessions and never written to disk or logs.
- The master accounts database is hidden from non-owners (404 "database not found"); creating it is reserved
  for owners. Online backups and cluster join tokens are owner-only while Accounts is on. So is applying a
  preset that would set a join link or change `role` or `advertise`: that write is what the next start
  redeems, and the audit line records the join leader URL, never the join secret.
