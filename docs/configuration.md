# Configuration reference

File `redx.toml` (all optional; see `deploy/redx.example.toml`), env `REDX_*`, flags. Precedence: defaults < file < env < flags.

| Key | Env | Default |
|---|---|---|
| `data_dir` | `REDX_DATA_DIR` | `/var/lib/redx` (root) · `~/.redx/data` · `C:\ProgramData\RedX\data` · `/usr/local/var/redx` (macOS) |
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
| — | `REDX_NO_BOOTSTRAP=1` | disable first-run admin key |

Data layout: `<data>/dbs/<name>/*.red-xai*` (engine files; also hand-placed `.red-xai-sec`, `.red-xai-code`, `.red-xai-db-link`), `master.key` (optional), `keys.red-xai-keys` (+`.lock`), `audit.log`, `node.id`, `tls/`, `cluster/{cluster.json,repl.json,oplog.jsonl,members.json,ttl.json}`, `redxd.lock` (single-instance lock).
