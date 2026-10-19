# Red-XAI Accounts in RedX

RedX can let people sign in to the web console with their **Red-XAI Account**, the one account shared by every
Red-XAI app. It follows the Red-XAI Accounts v1 contract (OIDC provider + sign-up API). API keys keep working
exactly as before for SDKs, the CLI and machines; account sign-in is only for people using the console.

## Turn it on

```toml
# redx.toml (deploy config)
accounts_issuer = "https://accounts.red-xai.example"   # the Red-XAI Accounts issuer
accounts_client_id = "redx"                             # the OAuth client registered for this host
advertise = "https://redx.example.com"                  # the redirect is <advertise>/v1/auth/callback
owner_emails = ["owner@example.com"]                    # or env REDXAI_OWNER_EMAILS (comma separated)
```

* Register `<advertise>/v1/auth/callback` (or `accounts_redirect_url`) as the exact redirect URI of the client.
* A confidential client's secret comes from the environment only: `REDX_ACCOUNTS_CLIENT_SECRET`.
* The issuer must be `https` (plain `http` is accepted only for `localhost`, for development).
* Never put real owner addresses in a repository; keep them in the deploy config or the environment.

## Sign-in

The console shows **Sign in with Red-XAI Account** under the API key form. redxd runs the authorization code flow
with PKCE (S256), a `state` bound to the browser by an HttpOnly cookie, and a `nonce`. It verifies the ES256 ID
token against the issuer's JWKS (issuer, audience, expiry, nonce) and then gives the console its own session
(an `rxs_…` bearer token, kept in this browser's session storage). redxd keeps no Red-XAI access or refresh
tokens. Console sessions live in memory on the node: 12 hours at most, 2 hours idle, and a restart signs everyone
out. **Sign out** ends the session.

A signed-in account that is not an owner has no database rights on this host yet (hosted plans will add them).

## Sign-up

**Create a Red-XAI Account** runs the sign-up in the console. Every rule is checked live in the browser, again by
redxd, and again by Red-XAI Accounts:

1. Terms of Service from Red-XAI Accounts: scroll to the bottom to enable **Read ToS**, then **Agree to ToS**. The
   accepted version and time are recorded by Red-XAI Accounts.
2. Username: 8–32 characters, only letters, numbers, `_ . -`, at least 3 letters, not taken.
3. Email: a real address, entered twice; the domain must accept mail, throw-away domains are refused, not used.
4. Password: 12–665 characters with an upper-case letter, a lower-case letter, a number and one of
   `! # $ % & ( ) * + , - . / : ; = ? @ [ ] ^ _ { | } ~`; no spaces, quotes, backslashes, backticks or `< >`. Entered twice.
5. The ⇅ button next to a confirm box copies the first box into it.
6. Date of birth: `MM/DD/YYYY`, typed or picked from the calendar. Age is worked out when needed and never stored
   by RedX. Under 13 is refused; there are no under-13 Red-XAI Accounts.
7. A warning that false information means the account cannot be recovered, which must be acknowledged.
8. Two-factor authentication: Phone, App, Red-XAI Auth (coming soon, cannot be chosen) or None (needs the risk
   to be accepted). App shows a QR code and key; the first code finishes the setup.

Hints are red until a rule is met, then green. Live checks of passwords and dates of birth never leave redxd.

## Owners

An account is an **owner** of this host only while all of these hold:

* its email is listed in `owner_emails` / `REDXAI_OWNER_EMAILS`,
* the email is verified, and
* this sign-in was finished with two-factor authentication (`amr` contains `otp` or `sms`).

An owner email without 2FA (or without a verified email) gets no owner rights and the console says why.

Owners act as host admins and can see:

* every hosted database,
* the **master Red-XAI accounts database** (`accounts_master_db`, default `redxai_accounts`), and
* every Red-XAI Account, on the **Owner** page (`GET /v1/owner/accounts`). Password hashes, 2FA secrets, phone
  numbers and dates of birth are never shown; age and age band are derived.

Every request made with an owner session is written to the audit log **before** anything is returned, as
`owner.read` / `owner.write` with the acting owner (`actor`), what was touched (`target`) and the time. The Owner
page shows this trail (`GET /v1/owner/audit`).

### The master accounts database

While accounts are on, the master database is invisible to everyone except owners and keys scoped to exactly that
database (the Red-XAI Accounts service's own key, which an owner creates):

* it answers like a database that does not exist (`404 database not found`), even to host-wide admin keys,
* it is left out of `/v1/dbs`, `/v1/stats` and the status page,
* non-owners cannot create it, mint keys for it, or see keys bound to it,
* online backups and cluster join tokens (both contain every database) are owner-only.

Anyone with access to the server's files can still read the data directory; protect the machine itself.

## API

| Route | Who | What |
|---|---|---|
| `GET /v1/auth/config` | anyone | `{enabled, issuer, client_id, hosted_signup, …}` |
| `GET /v1/auth/login` | browser | starts the sign-in (redirect) |
| `GET /v1/auth/callback` | browser | finishes it, redirects to `/#/signin?handoff=…` |
| `POST /v1/auth/handoff {code}` | console | single-use code → `{token, account}` |
| `POST /v1/auth/logout` | session | ends the console session |
| `GET /v1/auth/rules`, `GET /v1/auth/tos` | anyone | sign-up rules and the current ToS |
| `POST /v1/auth/tos/read {version}`, `POST /v1/auth/tos/agree {grant}` | anyone | the ToS gate |
| `POST /v1/auth/validate/{username,email,password,dob}` | anyone | live checks (rate-limited) |
| `POST /v1/auth/signup`, `POST /v1/auth/signup/2fa {handle, code}` | anyone | create the account, finish 2FA |
| `GET /v1/owner/overview`, `/dbs`, `/accounts?q=&limit=&offset=`, `/accounts/{id}`, `/audit` | owners | everything, audit-logged |

`GET /v1/ui/whoami` adds `owner` and, for account sessions, `account {username, email, owner, owner_blocked}`.
