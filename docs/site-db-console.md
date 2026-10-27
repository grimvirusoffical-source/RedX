# Red-XAI Hub: native database workspace and site-account sign-in

## Product behavior

The RedX engine embeds a complete, native Red-XAI Hub console at
`/v1/console/`. It is **not** a static proxy, a CSS overlay injected into an
unrelated site, or an owner-only master console. The existing `/ui/` and
CLI/SDK APIs remain supported.

The native Hub exposes the original database functions—database list, create
and delete, file browser, Data Explorer, record create/edit, raw editor,
BoxQL Studio, backups, connected apps/devices, key generation/rotation/revoke,
security, policies, live watch and settings—alongside first-party links to
Red-XAI Apps and Host. Owner-only administration stays restricted to a
separately verified owner principal.

The dashboard uses one native CSS design system (`host/ui/css/app.css`) and
one embedded module-based UI (`host/ui/js/*`). There is no `forge.css`
static overlay and no separate static-console proxy service.

### Customer sign-in: **no API key or special pairing number**

RedX already implements the correct server-side OIDC Authorization Code +
PKCE S256 relying party. With a valid first-party Red-XAI provider configured,
the native Hub attempts one account redirect automatically. Users already
signed into `red-xai.com` in that browser return directly to their own
database workspace, without entering a database API key or copying codes.
Other users sign into the **same** website account, then return automatically
through the one-time, server-validated handoff.

The API-key/pairing screen is a collapsed **developer (advanced)** option
for SDKs, CLI or third-party integrations. Customer browser CRUD, files and
database listing use a normal, account-scoped console session (opaque
`rxs_` session); the API never sends a host-owner key to a browser.

If OIDC is **not** configured yet, the Hub explicitly shows that the shared
account integration is unavailable; it does not fake a successful login.
Never bypass the login just because `/api/accounts/me` returns a profile,
and never treat the presence of an email string as ownership proof.

## Production setup (requires authorized website/account operator)

1. Register the RedX console as a **confidential OIDC relying party** with
   the existing Red-XAI Accounts issuer. Register the fixed redirect URI
   `https://api.red-xai.com/v1/auth/callback` (or the verified branded
   endpoint actually used in your Cloudflare setup). Ensure the provider's
   `/.well-known/openid-configuration`, JWKS, auth and token endpoints
   are HTTPS, valid and match the configured issuer. Do not guess the issuer.
2. Configure the RedX server (e.g. via protected env or secret file):
   - `REDX_ACCOUNTS_ISSUER`: exact provider issuer URL
   - `REDX_ACCOUNTS_CLIENT_ID`: registered RedX console client ID
   - `REDX_ACCOUNTS_CLIENT_SECRET_FILE`: server-only file, mode 0600
   - `REDX_ACCOUNTS_REDIRECT_URL`: registered absolute callback URL
   The provider secret must not enter the repository, environment of a
   browser, frontend JavaScript, or audit log.
3. Build and test the new **Go redxd binary** and native embedded UI.
   With the old host and any owner data preserved, stage a backup of the
   current Cloudflare ingress and `redxd` service unit.
4. Change the existing `api.red-xai.com` Cloudflare ingress so
   `/v1/console/*` routes directly to the authenticated **redxd API
   service**, together with the existing `/v1/*` API endpoints.
   Do not keep routing `/v1/console/*` to the former read-only
   `redx-console-ui.service` proxy. Only after the native route is
   verified, disable the old static proxy, retaining its rollback backup.
5. Verify `GET https://api.red-xai.com/v1/auth/config` reports
   `{"enabled":true,...}`. Verify a real customer who is already logged into
   `red-xai.com` can visit `/v1/console/`, finish the OIDC redirect and
   list/edit **only their own databases** without entering an API key.
   Verify a second customer's data is inaccessible, and the owner/master
   endpoints remain forbidden to both.
6. Verify a revoked session cannot read or write, owner elevation requires
   the owner's independent verified-email + 2FA + owner scope checks, and
   a lapsed plan retains data while enforcing the server's billing policy.
   Test API key creation separately for external developers.

### Expected permission boundaries

- A Red-XAI account login is sufficient **authentication** to open its
  customer workspace. It is **not** a master-database credential and never
  grants host-admin/owner privileges on its own.
- Database listing and record/file operations use `Principal.Account.Sub`
  and the existing tenant ownership map in `tenant.go`; account A never
  sees account B's database names.
- Existing plan/access conditions still apply to **mutations** and any
  restricted read operations. Do not use a hidden admin API key to avoid a
  hosting subscription.
- Existing API key scopes remain for external apps, automation and SDKs;
  changing the Hub UI does not loosen them.
- Never assert the production site is using OIDC until the provider and
  RedX host have been configured, deployed, and real-account tested.

## Tests and rollback

Run `go test ./host ./...` and `node --test host/uitest/*.test.mjs`.
The Go tests verify native embedded HTML, JS, CSS, safe route handling,
CSP, denial of non-GET static requests and protected API behavior.
The browser tests check customer CRUD navigation, developer-only key
options, one-shot SSO, responsive shell and absence of static overlays.

On errors, restore the previous Go service binary and Cloudflare ingress,
and re-enable the old static console route if needed. **Never** delete,
reset or recreate tenant databases or master account records as a UI
rollback. The old provider/owner deployment keys must remain unchanged.
