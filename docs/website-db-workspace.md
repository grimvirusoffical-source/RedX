# Website database workspace

This extends the existing website-session integration. It does not change the
native RedX engine, BoxQL, files, account authentication or database permissions.

## In-site embedding

The configured website service can serve the native console inside its own
same-origin shell:

```html
<iframe src="/v1/console/?embed=site" title="Red-XAI database workspace"></iframe>
```

For the existing database-key page, use `/v1/console/?embed=site#/keys`.
The parent must allow `frame-src 'self'`. Only an explicit `embed=site` request
for the website console's index gets `frame-ancestors 'self'` and
`X-Frame-Options: SAMEORIGIN`. Standalone installations, ordinary console pages,
billing and other assets retain their existing framing restrictions. No external
ancestor, inline script, untrusted parent identity or extra credential is allowed.

Embedded presentation hides the repeated brand/profile/theme controls. Database
selection, native data tools, editor modes and explicit access scope remain.
A confirmed website sign-out navigates the same-origin outer shell to the
existing `/signin?next=%2Fdb` flow. Authority failures remain recoverable errors;
they do not become a second DB login or grant identity. The parent should unmount
the frame on account changes or logout, rather than retaining an old account's
rendered workspace. The child retains its existing focus/visibility/periodic
canonical-account revalidation and stale-request invalidation.

## Database and Host separation

Website navigation contains DB tools only. Local replica installation, daemon
configuration and presets remain fully available in the standalone RedX console,
Red-XAI DB Local and native CLI. Direct website links to those local-service
screens show an explanation instead of loading their controls. A deliberate
developer-key selection does not turn website presentation into a Host panel.

Normal accounts see private account scope. Verified owners see an explicit
`Owner · all databases` label, audited tenant/system database administration and
the native owner access audit. Explicit developer keys are labeled separately;
they are never presented as an owner's authenticated website identity. The
website owner page does not present the separate native master DB's account
moderation as management of the primary website accounts.

DB subscription links use `/products/subscriptions` in the outer website.
Existing paid-plan, quota, scope, path, IP, CSRF and owner/MFA checks are preserved.
An ordinary account can authenticate without MFA; database creation and API-key
management still require its configured native DB entitlement. This change does
not invent a free tier, prices, project-wide keys or a new billing policy.

## Validation boundaries

Synthetic native fixtures cover password-only A/B tenant accounts sharing an
email but having distinct canonical IDs. They check own DB writes, foreign
record/file/stats/BoxQL/WebSocket denial, isolated listings, owner denial,
audited owner overview and revocation. Existing hosted tests retain developer-key
ownership and lapsed-plan checks. UI tests cover mode separation, account cache
reset and same-origin outer-login recovery. These tests do not establish the
state of any production user, invoice, deployment or existing database.
