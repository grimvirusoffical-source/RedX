# Configuration reference

File `redx.toml` (all optional; see `deploy/redx.example.toml`), env `REDX_*`, flags.

**Precedence, highest first: command-line flags > `REDX_*` environment variables > `redx.toml` > the preset > built-in defaults.**
Which file is read: `--config`, else `REDX_CONFIG`, else `<data dir>/redx.toml`, where the data dir is the one the host will use
(`--data-dir`, else `REDX_DATA_DIR`, else the default below). A missing default file is fine; a missing `--config` file is an
error. The console's *Presets → Apply* and `redx preset apply` write `<data dir>/redx.toml`, so a restart with the same
`--data-dir` picks the preset up. Values are checked before anything is written and again at start-up: `listen` must be
`host:port` (port 0-65535), `advertise` must be an `http(s)://` URL.

**Presets.** `redxd run --preset NAME` (or `preset = "NAME"`, `REDX_PRESET`, the console's *Presets* page, `redx preset apply NAME`).
Ten profiles: `server`, `vps`, `website`, `app`, `game`, `edge`, `dev`, `cluster`, `backup`, `all`; `redx preset show NAME` prints every
value with its reason. See [the console guide](console.md#4-presets).

**Certificate health.** With `tls = "files"` (and `auto`) the host checks the certificate it serves. If it has expired, is not
valid yet, or expires within 14 days, startup logs a `WARNING:` line, `GET /v1/admin/status` carries `tls_warning` and
`tls_cert`, the console shows a banner, and `redx doctor` reports `warn` or `FAIL`. The host still starts.

**Secrets in help output.** `-h` never prints a secret taken from the environment or `redx.toml`: `--key` reads "(currently set from
$REDX_KEY)" and `--join` "(currently set from $REDX_JOIN or redx.toml)".

| Key | Env | Default |
|---|---|---|
| `data_dir` | `REDX_DATA_DIR` | `/var/lib/redx` (root) · `~/.redx/data` (Linux user) · `%LOCALAPPDATA%\RedX\data` (Windows user; an existing `C:\ProgramData\RedX\data` is kept) · `~/Library/Application Support/RedX/data` (macOS user; an existing `/usr/local/var/redx` is kept, root uses it) |
| `listen` | `REDX_LISTEN` | `127.0.0.1:7777` |
| `tls` (`off`/`auto`/`files`), `tls_cert`, `tls_key`, `tls_hosts` | `REDX_TLS…` | `off` |
| `node_id` | `REDX_NODE_ID` | generated once → `<data>/node.id` |
| `role` (`leader`/`follower`), `peers`, `advertise`, `cluster_secret` | `REDX_ROLE/PEERS/ADVERTISE/CLUSTER_SECRET` | `leader` |
| `default_db` | `REDX_DEFAULT_DB` | `default` |
| `rate_limit_rps`, `rate_limit_burst` | `REDX_RATE_LIMIT_RPS` | 100 / 200 |
| `keystore_encrypt` | `REDX_KEYSTORE_ENCRYPT` + `REDX_KEYSTORE_PASSPHRASE` | off |
| `audit_log`, `audit_success` | `REDX_AUDIT_LOG` | `<data>/audit.log` (50 MB rotate to `.1`), successes off |
| `engine_durability` (`sync`/`group`/`async`), `engine_default_ttl` | `REDX_ENGINE_DURABILITY` | `group`, 0 |
| `repl_log_max`, `heartbeat_seconds`, `max_body_mb` | | 1,000,000 · 3 · 16 |
| `max_upload_mb` (largest single pack upload) | | 1024 |
| `master_key_file` | `REDX_MASTER_KEY_FILE` (a path) | `<data>/master.key` if present; must be mode 0600 (POSIX) |
| `code_allowed_boxes` (list of `file:Box` globs) | `REDX_CODE_ALLOWED_BOXES` | empty = scripts touch no record |
| `grpc_listen` | `REDX_GRPC_LISTEN` | reserved, ignored |
| `preset` | `REDX_PRESET` | none (flag `--preset NAME`) |
| `bootstrap` (`auto`/`web`/`console`/`off`) | flag `--bootstrap` | `auto` |
| `join` | `REDX_JOIN`, flag `--join LINK` | none (makes the node a follower) |
| `accounts_issuer` | `REDX_ACCOUNTS_ISSUER` | empty = Red-XAI Accounts sign-in off ([accounts.md](accounts.md)) |
| `accounts_client_id`, `accounts_redirect_url` | `REDX_ACCOUNTS_CLIENT_ID`, `REDX_ACCOUNTS_REDIRECT_URL` | `redx`, `<advertise>/v1/auth/callback` |
| — | `REDX_ACCOUNTS_CLIENT_SECRET` (env only) | none (public client with PKCE) |
| `accounts_master_db` | `REDX_ACCOUNTS_MASTER_DB` | `redxai_accounts` (owners only while accounts are on) |
| `owner_emails` (deploy config only) | `REDXAI_OWNER_EMAILS` (comma separated) | none |
| `trusted_proxies` (IPs or CIDRs) | `REDX_TRUSTED_PROXIES`, flag `--trusted-proxies` | empty = ignore `X-Forwarded-For` and `X-Real-IP` ([security](security.md)) |
| — | `REDX_NO_BOOTSTRAP=1` | disable first-run admin key (web and terminal) |
| — | `REDX_NO_OPEN=1` | never open a browser automatically |
| `apps_host` | `REDX_APPS_HOST`, flag `--apps-host` | `host.rottenapplestore.org` |
| `apps_runtime` (`podman`/`none`) | `REDX_APPS_RUNTIME`, flag `--apps-runtime` | `podman` (tests and hosts without podman use `none`) |
| `apps_network` (`pasta`/`slirp4netns`) | `REDX_APPS_NETWORK`, flag `--apps-network` | `pasta` |
| `apps_public_ip` | `REDX_APPS_PUBLIC_IP`, flag `--apps-public-ip` | empty (custom domains then get a CNAME only) |
| `apps_base_port` | `REDX_APPS_BASE_PORT`, flag `--apps-base-port` | `20000` (1024..60000) |
| `apps_seccomp` | `REDX_APPS_SECCOMP`, flag `--apps-seccomp` | `/usr/share/containers/seccomp.json` |
| `apps_podman_bin` | `REDX_APPS_PODMAN_BIN`, flag `--apps-podman-bin` | `podman` |
| `apps_secret_key_file` | `REDX_APPS_SECRET_KEY_FILE`, flag `--apps-secret-key-file` | `<data>/hosted/secret.key` (mode 0600) |
| `apps_redx_url` | `REDX_APPS_REDX_URL`, flag `--apps-redx-url` | `http://host.containers.internal:7777` (not injected into guests; loopback and ports 7777/7780 are denied) |
| `apps_uid_base` | `REDX_APPS_UID_BASE`, flag `--apps-uid-base` | `200000` |
| `apps_uid_span` | `REDX_APPS_UID_SPAN`, flag `--apps-uid-span` | `20000` |
| `apps_limits` | `REDX_APPS_LIMITS` (JSON object) | built-in per-tier caps ([hosting apps](hosting-apps.md)) |
| — | `REDX_APPS_SECRET_KEY` (env only, base64 or hex, 32 bytes) | unset = the key file above |
| — | `REDX_APPS_TLS_ASK_SECRET` (env only) | unset = the TLS ask endpoint accepts loopback only |
| — | `REDX_APPS_APPLY=0` | write the podman spec but do not run podman |
| — | `REDX_GITHUB_TOKEN` (env only) | unset = public GitHub archives only |

Data layout: `<data>/dbs/<name>/*.red-xai*` (engine files; also hand-placed `.red-xai-sec`, `.red-xai-code`, `.red-xai-db-link`), `master.key` (optional), `keys.red-xai-keys` (+`.lock`), `audit.log`, `node.id`, `tls/`, `cluster/{cluster.json,repl.json,oplog.jsonl,members.json,ttl.json}`, `connect/{connect.json,id.key}` (app connect requests and connections, 0600), `redxd.lock` (single-instance lock).
