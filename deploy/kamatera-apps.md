# Kamatera: hosted apps on host.rottenapplestore.org

redxd on this VPS is unprivileged. Tenant apps are too. Each tenant gets one login in the uid pool
`apps_uid_base` .. `apps_uid_base+apps_uid_span-1` (default `200000` .. `219999`). Podman runs as that
login, inside a systemd cgroup v2 slice, with pasta egress and no route back to this host.

Do these steps once, as root, before the first app deploy. Paths assume redxd's user is `redx` and
its data directory is `/var/lib/redx`.

## 1. Packages

```sh
apt-get update
apt-get install -y podman containers-common uidmap slirp4netns passt sudo nftables
loginctl enable-linger redx
```

`pasta` (from `passt`) is the default network. `slirp4netns` is only used when
`apps_network = "slirp4netns"`.

Confirm cgroup v2 is mounted (Ubuntu on Kamatera already does this):

```sh
mount | grep 'cgroup2 on /sys/fs/cgroup'
```

## 2. Tenant user helper

Copy `deploy/kamatera-app-user.sh` to `/usr/local/sbin/redx-app-user` and install the sudoers drop-in.
redxd calls `sudo -n /usr/local/sbin/redx-app-user <user> <uid>` before `podman run`, then
`sudo -n -u <user> -- podman ...`.

```sh
install -m 0755 deploy/kamatera-app-user.sh /usr/local/sbin/redx-app-user
cat >/etc/sudoers.d/redx-apps <<'EOF'
redx ALL=(root) NOPASSWD: /usr/local/sbin/redx-app-user
redx ALL=(rxapp-*) NOPASSWD: /usr/bin/podman
EOF
chmod 0440 /etc/sudoers.d/redx-apps
visudo -cf /etc/sudoers.d/redx-apps
```

The helper creates `rxapp-<10 hex>` with the uid redxd computed, a 65536-wide subuid/subgid range
starting at 1_000_000, a home under `/var/lib/redx/hosted/uids/`, and lingering so rootless podman
has a runtime dir. It refuses uids outside 200000–219999.

## 3. Firewall

Tenant uids may open the public internet. They may not open this host's loopback, link-local, or the
ports redxd (`7777`) and the accounts listener (`7780`) use. Publish `127.0.0.1:<port>:8080` is
host-to-app: Caddy and redxd connect to the app. The app does not connect to them.

```sh
nft add table inet redx_apps
nft add chain inet redx_apps output '{ type filter hook output priority 0; policy accept; }'
nft add rule inet redx_apps output meta skuid 200000-219999 ip daddr 127.0.0.0/8 drop
nft add rule inet redx_apps output meta skuid 200000-219999 ip daddr 169.254.0.0/16 drop
nft add rule inet redx_apps output meta skuid 200000-219999 ip6 daddr ::1 drop
nft add rule inet redx_apps output meta skuid 200000-219999 tcp dport { 7777, 7780 } drop
nft list table inet redx_apps >/etc/nftables.d/redx-apps.nft
```

Load that file from `/etc/nftables.conf` so it survives reboot. If `apps_uid_base` or `apps_uid_span`
change, edit the `skuid` range to match.

## 4. cgroup slices

systemd creates `redx-tenant-<label>.slice` when podman is started with
`--cgroup-parent redx-tenant-<label>.slice`. CPU, memory and pids come from the tier on the `podman run`
line (`--cpus`, `--memory`, `--pids-limit`). cgroup v2 has no byte disk cap. The byte cap is
`--storage-opt size=<diskMB>m` (needs a graph driver that honors it, such as overlay over xfs/btrfs)
plus redxd's storage quota, which refuses the deploy before extract when the account is over its plan.

## 5. redxd config

In `/etc/redx/redx.toml` (see `deploy/redx.example.toml`):

```toml
apps_host = "host.rottenapplestore.org"
apps_runtime = "podman"
apps_network = "pasta"
apps_base_port = 20000
apps_uid_base = 200000
apps_uid_span = 20000
apps_seccomp = "/usr/share/containers/seccomp.json"
```

Do not point guests at redxd. `apps_redx_url` defaults to `http://host.containers.internal:7777` and
redxd refuses to inject that, any loopback or private URL, and ports 7777 and 7780. Leave
`REDX_APPS_APPLY` unset so a real deploy runs podman. Set `REDX_APPS_SECRET_KEY` (32 bytes, base64 or
hex) in the service environment, not in the repo and not in the toml file. If it is unset, redxd
creates `<data>/hosted/secret.key` mode 0600.

`REDX_APPS_TLS_ASK_SECRET` stays unset when Caddy is on this host. The ask endpoint then accepts
loopback only.

Keep Stripe keys, `REDX_KEYSTORE_PASSPHRASE`, and the master key in the redxd service environment.
`podman` is started with `PATH`, `HOME`, `USER`, `XDG_RUNTIME_DIR` and `DBUS_SESSION_BUS_ADDRESS`
only.

## 6. DNS and Caddy

Add a wildcard:

```text
*.host.rottenapplestore.org.  A  <this VPS>
```

Every app is `<name>-<tenant>.host.rottenapplestore.org`. `<tenant>` is 10 hex characters.

As an owner, `redx app caddy` prints the on-demand TLS site. Put it in the Caddyfile. The ask URL is
`http://127.0.0.1:7777/v1/hosted/tls/ask`. redxd returns 200 only for a verified name. Unverified
custom domains and unknown names are refused, so Caddy will not mint a certificate for them.

Also proxy `/.well-known/redx-challenge/*` to `127.0.0.1:7777` on port 80 so HTTP-01 can complete
before a certificate exists.

Reload Caddy after the site is installed.

## 7. Check

```sh
sudo -n -u redx true
sudo -n /usr/local/sbin/redx-app-user rxapp-test000000 200000
sudo -n -u rxapp-test000000 -- podman info >/dev/null
```

A deploy from the console Deploy page with `REDX_APPS_APPLY` unset should report `runtimeStatus`
`applied` and `health` `healthy`. If the user helper is missing, the deploy error names `sudo` or
`tenant user` instead of starting the container as `redx`.
