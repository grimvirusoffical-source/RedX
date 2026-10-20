# Hosting apps and sites

Paying subscribers on a RedX host can run their own sites and apps next to their databases. The Kamatera
VPS at `host.rottenapplestore.org` is the first machine that does this. Databases stay as they are.
BoxQL is still the only user-facing query language; apps are not queried with it.

The console pages are **Apps**, **Deploy**, **Domains**. The CLI is `redx app`. The HTTP API is `/v1/hosted`
([API](api.md#hosted-apps-v1hosted)).

## What a tenant can deploy

| Kind | Source | What runs |
|---|---|---|
| `static` | uploaded zip, tar or tar.gz, or a public GitHub `owner/repo` at a tag, branch or commit | files from the archive. A single top-level directory is lifted. If `public/index.html` exists, that directory is the site |
| `container` | an image reference, or a GitHub repo with a Dockerfile | rootless podman. The container listens on port **8080**. redxd publishes it on `127.0.0.1` only |
| `process` | same as container, with an optional command | same sandbox |

Deploys are kept. `strategy` is `direct` (becomes current), `canary` (a percent of requests, default 10) or
`blue_green` (standby until promote). Each deploy writes a signed `redx.update-manifest/v1` using the
host's update signing key, and a `redx.update-snapshot/v1` of the previous release before the switch.
Rollback restores any previous deploy. These records are **not** registered as update-system apps, so a
tenant app id cannot collide with a database name in the updater.

Creating an app does not consume a host switch. Start and stop do, and only when the running state
actually changes. A stopped app answers `503` on its hostname. Delete (`redx app delete`,
`DELETE /v1/hosted/apps/{id}`) is dangerous and needs `X-RedX-Confirm: deleteHostedApp`. It revokes the
app's database key and removes the files. It does not consume a switch.

## Isolation

The generated runtime spec (returned on the app as `runtime`, and executed only when the runtime is
podman and `REDX_APPS_APPLY` is not `0`) is rootless podman, one unprivileged uid per tenant:

* `sudo -n -u rxapp-<tenant> -- podman`, so pasta and the container run as that uid
* `--userns=keep-id:uid=<uid>,gid=<uid>` and `--user <uid>:<uid>`
* `--cgroup-parent redx-tenant-<tenant>.slice` with `--cpus`, `--memory` and `--pids-limit` from the tier
* `--storage-opt size=<disk>m` for the per-app byte cap (cgroup v2 has no capacity controller; the account storage quota is the other cap)
* `--cap-drop=ALL`
* `--security-opt=no-new-privileges`
* `--security-opt=seccomp=<apps_seccomp>` (default `/usr/share/containers/seccomp.json`)
* `--read-only`
* `--network=pasta:--no-map-gw` (or `slirp4netns:allow_host_loopback=false`). Egress to the internet is allowed. There is no host gateway, so the guest cannot open `127.0.0.1` on the VPS
* publish `127.0.0.1:<port>:8080` only. That is host-to-app, for Caddy and redxd. It is not a path the guest can use to reach redxd
* `--tmpfs /tmp:rw,noexec,nosuid,size=64m`
* one volume: that deploy's release directory, mounted read-only at `/srv` (`:ro,Z`)
* env via `--env-file`, never `--env KEY=value`. The host process environment (Stripe keys, the keystore passphrase, other tenants) is not passed through

nftables on the host drops packets from the tenant uid range to `127.0.0.0/8`, `::1`, `169.254.0.0/16`, and TCP 7777 and 7780 (redxd and the accounts listener). The guest is not given `REDX_URL` or `REDX_KEY`. A database name on the app is only `REDX_DB`, the logical name. `allowTenant`, `refuseHiddenDB` and `refuseMasterMutation` still apply when a tenant binds an app to a database: another tenant's database, the master accounts database, and the host default database are refused.

The uid is `apps_uid_base + SHA256("redx-app-uid/v1\0" + account) mod apps_uid_span` (defaults 200000 and 20000). The login is `rxapp-` plus the same 10 hex characters used in the hostname. Setup is `deploy/kamatera-apps.md`.

The container runtime integration test is skipped unless `REDX_APPS_PODMAN_TEST=1` and `podman` is on
`PATH`. CI does not set that variable, so CI checks the spec and the API without starting a container.

## Limits

These are the built-in caps. Override a tier with `apps_limits` (TOML) or `REDX_APPS_LIMITS` (JSON).
A zero field keeps the built-in value. Account-wide storage and traffic quotas still apply on top.
Emerald is not unlimited apps: this is one VPS.

| Tier | Apps | CPU | Memory | Disk / app | Log retention | PIDs | Custom domains |
|---|---|---|---|---|---|---|---|
| Basic | 1 | 0.25 | 256 MB | 512 MB | 1 day | 64 | 1 |
| Bronze | 2 | 0.5 | 512 MB | 2 GB | 3 days | 128 | 2 |
| Silver | 4 | 1 | 1 GB | 8 GB | 7 days | 256 | 4 |
| Gold | 8 | 2 | 2 GB | 20 GB | 14 days | 512 | 8 |
| Platinum | 16 | 4 | 4 GB | 40 GB | 30 days | 1024 | 16 |
| Emerald | 32 | 8 | 8 GB | 100 GB | 90 days | 2048 | 32 |

Host on/off switches stay the billing quotas (Basic 2, Bronze 5, Silver 10, Gold 20, Platinum 40, Emerald unlimited).

An owner or a host-admin key is not plan-capped and uses the Emerald app limits. Their apps are stored
under the account name `operator`.

## Domains and TLS

Every app gets `<name>-<tenant>.<apps_host>`. `<tenant>` is 10 hex characters of
`SHA256("redx-tenant/v1\0" + account)`, the same prefix as a tenant database name. The default name is
verified immediately. It lives under the wildcard for `apps_host` (default `host.rottenapplestore.org`).

A custom domain cannot be inside that zone, an IP, a wildcard, `localhost`, `.local` or `.internal`.
The tenant adds it and receives:

* `CNAME` to the app's default hostname (and an `A` record when `apps_public_ip` is set). `method=cname` verifies that CNAME
* `TXT` `_redx-challenge.<domain>` = the token when `method=txt`, or `GET http://<domain>/.well-known/redx-challenge/<token>` when `method=http`

The default hostname does not count toward the custom-domain cap. A further name returns `domain_quota`.

Routing and certificates wait until `POST .../domains/<domain>/verify` succeeds. One tenant cannot take
another's verified domain, or an unverified claim younger than 7 days.

Caddy uses on-demand TLS. The ask URL is `http://127.0.0.1:7777/v1/hosted/tls/ask`. redxd returns 200
only for a verified name. Unverified names, unknown names, and asks that are not from loopback are
refused, which stops a client from burning certificates on names this host does not serve. Set
`REDX_APPS_TLS_ASK_SECRET` when Caddy is not on the same host; Caddy must then send
`X-RedX-Caddy-Ask: <secret>`.

`redx app caddy` (owner or host-admin) prints a Caddyfile fragment. Point the site `https://` at redxd's
listen address with `tls { on_demand }` and the ask URL above. Also proxy
`/.well-known/redx-challenge/*` so HTTP-01 can reach redxd before the certificate exists.

## Env, secrets and logs

Non-secret variables are `PUT /v1/hosted/apps/{id}/env` with `{"vars":{...}}`. Names match
`[A-Z_][A-Z0-9_]*`. `REDX_KEY` and `REDX_URL` cannot be set, and a value that is a loopback, private, `.internal`, `.local`, or port 7777/7780 URL is refused. Changing env or secrets after a deploy sets `needsRedeploy`. The console asks for a restart, which counts as one host switch and injects the new file.

Secrets are `PUT /v1/hosted/apps/{id}/secrets/{name}` with `{"value":"..."}`. They are AES-256-GCM with
the key from `REDX_APPS_SECRET_KEY` or `<data>/hosted/secret.key` (mode 0600, created once). The API,
the console and the audit log show a mask, never the value. Changes are audit-logged as
`app.secret.set` / `app.secret.delete` with the name only. The runtime env file
`<data>/hosted/apps/<id>/env` (mode 0600) holds the plaintext for podman and is not served by the API.

Logs are stdout/stderr (`runtime`) and request lines (`access`), one line `time \t kind \t message`.
Retention is the tier's `log_days`. `GET .../logs?kind=runtime&q=text` searches retained lines.
`?stream=1` is a live tail for at most 15 seconds (the console opens it only from the Tail button).
`GET .../logs/download` returns `text/plain`. Response bytes and log bytes count toward `traffic_quota`.

## Config and environment

| TOML | Environment | Flag | Default |
|---|---|---|---|
| `apps_host` | `REDX_APPS_HOST` | `--apps-host` | `host.rottenapplestore.org` |
| `apps_runtime` | `REDX_APPS_RUNTIME` | `--apps-runtime` | `podman` (`none` skips exec) |
| `apps_network` | `REDX_APPS_NETWORK` | `--apps-network` | `pasta` (`slirp4netns` also allowed) |
| `apps_public_ip` | `REDX_APPS_PUBLIC_IP` | `--apps-public-ip` | empty |
| `apps_base_port` | `REDX_APPS_BASE_PORT` | `--apps-base-port` | `20000` |
| `apps_seccomp` | `REDX_APPS_SECCOMP` | `--apps-seccomp` | `/usr/share/containers/seccomp.json` |
| `apps_podman_bin` | `REDX_APPS_PODMAN_BIN` | `--apps-podman-bin` | `podman` |
| `apps_secret_key_file` | `REDX_APPS_SECRET_KEY_FILE` | `--apps-secret-key-file` | `<data>/hosted/secret.key` |
| `apps_redx_url` | `REDX_APPS_REDX_URL` | `--apps-redx-url` | `http://host.containers.internal:7777` (not injected; that URL is on the deny list) |
| `apps_uid_base` | `REDX_APPS_UID_BASE` | `--apps-uid-base` | `200000` |
| `apps_uid_span` | `REDX_APPS_UID_SPAN` | `--apps-uid-span` | `20000` |
| `apps_limits` | `REDX_APPS_LIMITS` | — | the table above |
| — | `REDX_APPS_SECRET_KEY` | — | env only, 32 bytes, base64 or hex |
| — | `REDX_APPS_TLS_ASK_SECRET` | — | env only; empty means loopback asks only |
| — | `REDX_APPS_APPLY` | — | `0` forces spec-only even when runtime is podman |
| — | `REDX_GITHUB_TOKEN` | — | sent when fetching `codeload.github.com` |

Port **8080** inside the container is fixed. It is not a config key.

Files: `<data>/hosted/apps.json` (0600), `<data>/hosted/secret.key` (0600),
`<data>/hosted/apps/<id>/{releases,snapshots,logs,env}`.

## Kamatera (host.rottenapplestore.org)

The steps that create tenant users, subuid ranges, the nftables deny list, and the Caddy site live in
[deploy/kamatera-apps.md](../deploy/kamatera-apps.md). Run that before the first real deploy. The notes
below are the short form.

The host already runs redxd and Caddy. Apps need a rootless container runtime and a DNS wildcard.
Do this as the `redx` service user, not as root inside the containers.

### Runtime

```sh
sudo apt-get update
sudo apt-get install -y podman containers-common uidmap slirp4netns
# pasta ships with passt; slirp4netns is the fallback if you set apps_network = "slirp4netns"
sudo apt-get install -y passt || true
sudo loginctl enable-linger redx
```

`/usr/share/containers/seccomp.json` comes from `containers-common`. Confirm it is there before
redxd starts applying specs. `/etc/subuid` and `/etc/subgid` must list `redx` (the podman package
adds this when the user exists).

```sh
grep '^redx:' /etc/subuid /etc/subgid
sudo -u redx XDG_RUNTIME_DIR=/run/user/$(id -u redx) podman info
```

redxd's systemd unit should keep `User=redx` and pick up the runtime directory. A drop-in:

```ini
# /etc/systemd/system/redxd.service.d/apps.conf
[Service]
Environment=XDG_RUNTIME_DIR=/run/user/UID
Environment=REDX_APPS_APPLY=1
# Environment=REDX_APPS_SECRET_KEY=...
# Environment=REDX_APPS_TLS_ASK_SECRET=...
# Environment=REDX_GITHUB_TOKEN=...
```

Replace `UID` with `id -u redx`. Do not put secret values in the unit file in git. Prefer
`EnvironmentFile=-/etc/redx/apps.env` with mode 0600. Then `systemctl daemon-reload && systemctl restart redxd`.

Leave `apps_runtime = "podman"`. Set `REDX_APPS_APPLY=0` only while you want the spec written and not run.

### DNS

At the DNS host for `rottenapplestore.org`:

```text
*.host.rottenapplestore.org.   A   <Kamatera public IPv4>
host.rottenapplestore.org.     A   <same>
```

`apps_public_ip` should be that same address so custom-domain instructions can include an `A` record.
Tenants who use a CNAME to their default hostname do not need the A record.

### Caddy

Caddy already terminates TLS for the host. Add on-demand TLS that asks redxd. Ask from loopback so
no shared secret is required; keep `trusted_proxies` including `127.0.0.1` so client IPs stay accurate.

```caddy
{
	on_demand_tls {
		ask http://127.0.0.1:7777/v1/hosted/tls/ask
	}
}

http:// {
	handle /.well-known/redx-challenge/* {
		reverse_proxy 127.0.0.1:7777
	}
	redir https://{host}{uri}
}

https:// {
	tls {
		on_demand
	}
	reverse_proxy 127.0.0.1:7777
}
```

`redx app caddy` prints this shape, plus a comment for every verified name. Reload Caddy after editing
its unit (`systemctl reload caddy`). Caddy will not obtain a certificate for a name redxd has not verified.

redxd itself can keep listening on `127.0.0.1:7777`. Public HTTP and HTTPS enter through Caddy.
App containers publish only on `127.0.0.1:<apps_base_port+n>` and are reached through redxd, not from
the public internet directly.
