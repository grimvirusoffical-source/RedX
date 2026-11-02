# Same-site website account access for the native RedX console

This opt-in HTTP integration lets the native console use the existing
`red-xai.com` account session. It does not replace the custom RedX engine,
BoxQL, native files, API-key ACLs, or hosted tenant and billing rules.

This document describes a deployment candidate. It is not evidence that the
candidate has been staged, approved for public routing, or validated in production.

## Authentication and ownership

Set `REDX_WEBSITE_SESSION=true` only for the first-party deployment on the
website's origin, `https://red-xai.com`. The browser uses its existing
`redx_session` cookie. Before each protected cookie-authenticated request, the
server validates exactly one bounded cookie with the fixed loopback authority:

```
http://127.0.0.1:4200/api/accounts/me
```

The authority URL is not chosen by a request or an environment override. Other
cookies, caller Authorization and identity headers are not forwarded. Redirects,
oversized or malformed profiles, expired sessions, explicit inactive or rejected
account states, and authority errors fail closed. No API key is minted or placed
in the browser for this login path.

The authoritative canonical account ID becomes the existing native account
principal. RedX's tenant ownership map, reserved names, plan, storage and traffic
gates still authorize database operations. A successful login does not purchase
a plan or grant access to another account's database. Existing native API keys
remain available through the explicit advanced developer flow and retain their
normal scope, database and prefix checks.

Website-mode owner access requires all three of these signals:

1. The immutable canonical account ID is in the private deployment setting
   `REDX_WEBSITE_OWNER_ACCOUNT_IDS`.
2. The fixed authority reports the `owner` role.
3. The sign-in has recognized MFA evidence, including phone-call MFA.

Email equality alone does not grant this role. Missing email-verification
metadata remains unknown/false; the adapter does not invent a verified-email
claim. This explicitly configured canonical-ID owner policy is separate from
the existing OIDC owner's verified-email policy, which remains unchanged.
Privileged requests use the existing native audit path, including the canonical
account key ID. This mode does not add primary-account moderation or manual
email-verification operations to the legacy authority.

Unsafe cookie-authenticated requests and WebSocket handshakes require the exact
website Origin. Protected responses are not cached. Live cookie-authenticated
streams revalidate at 15-second intervals and close when the session, subject or
owner status changes. Ordinary HTTP authorization is checked per request.

## Native console behavior

`GET /v1/auth/config` reports `enabled:true, mode:"website"`. The native console
uses same-origin cookies, ignores saved keys for its normal account flow, and
does not put a credential in the WebSocket URL. Sign-in and account management
link to `/signin` and `/settings` on the existing website.

Account changes clear the previous account's views and isolate selected
databases, Studio drafts/history and transient page state by canonical subject.
Old in-flight responses cannot populate a new account's state. Focus and
visibility revalidation conceal existing workspace data while identity is checked.

The console keeps the existing Data Explorer, files, BoxQL Studio, raw editor,
keys, connected apps/devices, watch, policies, backups and other native tools.
Server permissions continue to determine which operations each account may use.
Standalone and OIDC modes remain available. Website mode does not register the
standalone root service worker, which would otherwise interfere with the existing
website's worker and cache namespace. It never unregisters the website's worker.

## Isolated deployment plan

The proposed first-party deployment uses a **new** RedX instance bound only to
`127.0.0.1:17790`, with a separate protected fresh data directory. The original
native account/DB service on `127.0.0.1:7790`, its legacy account records and all
old data stay in place. The user authorized a fresh database workspace while
preserving account information; that does not authorize deleting old native data.

Prepare a private environment file owned by the service user, mode `0600`:

```dotenv
REDX_WEBSITE_SESSION=true
# Supply verified immutable owner IDs privately; never commit actual values.
REDX_WEBSITE_OWNER_ACCOUNT_IDS=
REDX_NO_BOOTSTRAP=1
```

Use a dedicated data directory, a loopback listener, `tls="off"` only behind the
existing HTTPS ingress, and `bootstrap="off"`. The integration also suppresses
browser admin bootstrap in website mode. Do not expose a first-run key screen.
Keep config, account IDs, secrets, logs and data out of build artifacts.

Review these proposed ingress changes before public exposure:

| Main-site path | Proposed destination |
| --- | --- |
| `/db` | New instance's fixed redirect to `/v1/console/` |
| `/v1/console/*`, other native `/v1/*` API paths | New instance on `127.0.0.1:17790` |
| `/ui/*` native assets | New instance on `127.0.0.1:17790` |

The native console uses absolute `/v1` and `/ui` paths. They must reach the same
new instance on the website origin; placing only the HTML behind a prefix does
not provide working cookie authentication. Do not move this mode to
`api.red-xai.com` without a separate reviewed session integration.

Preserve existing `api.red-xai.com` routes to the old native service, the original
website/account service on `4200`, Hub on `4210`, Host on `14202`, and unrelated
ingress rules. Point the Host DB entry at the reviewed same-site native console
only after private checks pass. Current account records must not be copied or
rewritten using an assumed modern schema.

## Backups, validation and rollback

Before a public switch, record the exact source SHA and binary hash, retain the
current ingress and service definitions in a private rollback directory, and
verify their contents/hashes. Back up the new instance with the native supported
backup mechanism and verify restoration in a separate private directory. A source
archive or a Host SQLite backup is not a native account-data backup. The known
legacy native backup failure remains a blocker for maintenance or replacement of
the old account store; staging a fresh isolated instance does not fix that failure.

Run the dedicated workflow's native HTTP/engine-adapter/console race tests,
browser-module tests and binary builds. The existing full CI remains required
for broader compatibility. These fixture tests are not production validation.

Before declaring DB access complete, verify real browser flows with two normal
accounts and a separately authenticated owner:

- An existing website sign-in opens its native workspace without entering a key;
  normal users see only their own databases and cannot read/write another user's
  records, keys or host administration. Owner access is explicitly configured
  and audit logged.
- Account switching removes old views, drafts and responses. Logout/revocation
  stops protected HTTP operations and closes established watches within the
  documented revalidation interval. Missing or untrusted Origin writes fail.
- Existing developer-key flows, native files, Data Explorer, BoxQL and other
  retained tools work with the correct backend permissions.
- Plans and quota behavior match the configured billing authority. Fresh staging
  has no inherited paid entitlements; do not insert test plans into production or
  use an admin key to bypass billing. Live payment-provider setup remains separate.

If a public check fails, restore the saved ingress and any changed service/Host
entry configuration, restart only the affected routing/service components, and
verify the original website, login and API paths. Stop the new service if needed;
retain its data and evidence for diagnosis. Do not delete, reset or migrate the
old native databases, account records or keys as a UI rollback.
