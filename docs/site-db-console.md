# Red-XAI DB customer console restoration

The native RedX console still provides database creation, API-key rotation, BoxQL Studio, the data explorer, record editor, setup wizard, file views, and host-owner tools. This release restores customer navigation and hosted tenant UI without giving customers host-administration privileges.

## Shared sign-in vs database permissions

The website at red-xai.com has its own existing Red-XAI session. The database engine is the separately authenticated `redxd` service. The database engine's `/v1/auth/config` on the current Kamatera server reports `enabled:false`; therefore the old database console **requires a RedX API key** until the website identity and its app-scoped OIDC integration are configured and tested.

Never forward a host admin bearer token or a master-database key to an end user's browser. The API already implements signed-in account tenant database mapping and billing plan gates; all UI forms use the same endpoints. The master account database and global owner API remain private.

## Serving the old full console

The authenticated database API already lives at `https://api.red-xai.com/v1/`. The static console can be served on **that same hostname** at `https://api.red-xai.com/v1/console/` by the read-only `host/ui-console-proxy.cjs` service on 127.0.0.1:17782.

The proxy only accepts GET/HEAD for allowlisted UI assets under `/v1/console/` and retrieves them from the existing redxd `/ui/` files. It rewrites UI asset references from `/ui/` to `/v1/console/` without intercepting `/v1/dbs`, `/v1/keys`, `/v1/db/<tenant>/...` or owner endpoints. It does not access or forward credentials. All protected API requests continue to route to the current redxd service and enforce their original permissions.

Example cloudflared ingress order for `api.red-xai.com`:

```yaml
- hostname: api.red-xai.com
  path: ^/v1/console(/.*)?$
  service: http://127.0.0.1:17782
- hostname: api.red-xai.com
  path: ^/(v1/.*|healthz)$
  service: http://127.0.0.1:7790
```

Keep the console UI service after RedX starts. Before deployment run `node --test host/uitest/*.test.mjs` and validate the existing Cloudflare ingress. After deployment verify `/v1/console/` returns HTML and JS, and unauthenticated `/v1/dbs` and `/v1/owner/accounts` still return HTTP 401. The website Hub should include a visible customer link to the full DB console, while host control remains independently authorized.

## Rollback

Restore the saved Cloudflare ingress config, restart the tunnel, and restore the prior Hub index.html. Leave database data and existing keys unchanged. Stop/disable the console static proxy. Changing a stylesheet or navigation must never change authorization or expose the master database.
