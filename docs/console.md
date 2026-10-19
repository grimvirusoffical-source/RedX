# The RedX web console

`redxd` serves its own management console. Start the daemon, open the address it prints
(by default <http://127.0.0.1:7777>) and do everything from the browser: create a database,
browse and edit records, run BoxQL, manage keys, add devices, back up. **You never have to type a
terminal command.** Every page also shows a collapsible *Terminal equivalent* panel with the exact
`redx` / `curl` commands for what you just did, so the CLI stays available (and unchanged) for scripts.

The console is part of the `redxd` binary (`go:embed`). It is plain ES modules and CSS: no Node, no
build step, no CDN and no network access at runtime. It works offline, from a USB stick, on a Pi.

* Open it: `redxd open` (opens the browser on this machine), or `redxd run --open`, or just type the address.
* Disable the automatic first-run browser launch: `REDX_NO_OPEN=1` (it is also skipped on headless machines: no
  display, `CI`, SSH sessions, and for services).
* Where is it? `/` and `/ui/` on the same port as the API.

## 1. First run

| Situation | What you see |
|---|---|
| Empty keystore, request from **this machine** (loopback), bootstrap mode allows it | **Welcome**: *Create admin key*. The key is shown **once** with Copy and Download buttons. Then the Simple-mode setup wizard. |
| Keystore already has keys | **Sign in**: paste an API key. |
| Request from any other machine | Sign in only. A non-loopback request is **never** offered key creation, whatever the mode. |

`bootstrap` setting (`redx.toml`, `--bootstrap`, preset key):

| Value | Behaviour |
|---|---|
| `auto` (default when loaded from config) | web bootstrap if the listener is loopback-only, otherwise the key is printed to the terminal |
| `web` | the console offers the key (loopback visitors only); nothing is printed |
| `console` | the old behaviour: the one-time key is printed on stdout at first start, no web offer |
| `off` | no first key at all (create it with `redx key create --offline`) |

`REDX_NO_BOOTSTRAP=1` disables **both** the stdout key and the web offer (the installers set this because they
create the first key themselves). The web offer works once: after a key exists, the endpoint refuses.

### Where the key lives in the browser

The console signs in with an API key sent as `Authorization: Bearer ...` to the normal `/v1` API
(WebSocket: `access_token` query parameter, because browsers cannot set headers on WebSockets). By default
the key is kept in **sessionStorage** (gone when the tab closes). Tick *Remember this device* to use
**localStorage** instead. *Settings → Sign out* removes it. Keys are never logged by the console or the daemon.

### Security headers

Every console response carries `Content-Security-Policy` (`script-src 'self'`, no inline script, no inline
style, `connect-src 'self'`, `frame-ancestors 'none'`, `object-src 'none'`), `X-Frame-Options: DENY`,
`Referrer-Policy: no-referrer` and `X-Content-Type-Options: nosniff`. The UI builds DOM nodes only; it never
uses `innerHTML`, `eval` or inline handlers (a Go test scans the shipped files for these).

### Appearance: Dark, System, Light

The console is **dark by default**. The switcher in the top bar (also in *Settings*) offers **Dark**, **System** (follows the
device's light/dark setting live, via `prefers-color-scheme`) and **Light**. The choice is stored in the browser's
`localStorage` (`redx.theme`) and survives reloads and restarts. A tiny classic script, `js/theme-init.js`, runs in `<head>`
before the stylesheet, so there is no flash of the wrong theme (it is an external file because the CSP forbids inline script).
The browser's `theme-color` follows the shown theme; the PWA manifest uses the dark colour (a manifest cannot change with
the theme). All colours are CSS variables at the top of `css/app.css`: red accent `#f2495a` (dark) / `#c81e35` (light), primary
buttons `#c91c34` / `#c8102e` with white text. Every text colour meets WCAG AA (4.5:1) on the surfaces it is drawn on, in both
themes; `host/theme_test.go` checks this (including the syntax colours) so a bad edit fails the build. Everything is offline:
system fonts, inline SVG icons, no CDN. The logo is two crossed red scythes forming an X (`assets/icons/`, regenerate all sizes
with `python3 assets/icons/make.py`; it needs Node, playwright-core, Chrome and Pillow, and is not part of the build).

## 2. Pages

*Simple mode* (default) shows the everyday pages; *Advanced* (toggle in the sidebar and Settings) adds the
rest. The sidebar lists only the pages `GET /v1/ui/whoami` marks with `pages.<id>: true`. Opening any other address shows **Page not found**. The server still answers 403 on the API. Keyboard: `Tab`/`Shift+Tab` everywhere, `Ctrl+Enter` runs a BoxQL query, `Ctrl+S` saves a record or file,
`Esc` closes dialogs. The theme switcher (moon / monitor / sun) is in the top bar; layout is responsive down to phone width.
See *Appearance* below.

The header centre is a **Database / Host** switch. **Database** is the default and lists the database pages below, including Help. **Host** lists only the pages that work: Plans & billing, Usage & quotas, Updates, and Logs (this account's database activity). The owner audit log stays on the Owner page. The last choice is remembered for the signed-in user. `?mode=host` or `?mode=database` selects that mode (hash routes stay, for example `/?mode=host#/hosting`). Opening a host page selects Host. Owner and other role-gated pages stay hidden unless this session is allowed to open them.

| Page | What you can do | Terminal equivalent shown |
|---|---|---|
| **Dashboard** | live requests/s and latency sparklines, databases, keys, uptime, cluster role, recent audit events, *Get started* checklist | `redx stats`, `redx doctor`, `curl .../v1/admin/status` |
| **Databases** | create (name validated), list files per database, delete with typed-name confirmation (`DELETE /v1/db/{name}?confirm=name`) | `redx db create`, `redx db list` (dropping is `curl -X DELETE ...?confirm=NAME`) |
| **Plans & billing** *(Host)* | plans and prices from the host, monthly or annual, current plan and access (`full`, `readonly`, `suspended`, `none`), create a hosted database (logical name and physical name) | `GET /v1/billing/plans`, `GET /v1/billing/me` |
| **Usage & quotas** *(Host)* | storage, monthly traffic, and host on/off switches against this plan's quotas | `GET /v1/billing/me` |
| **Logs** *(Host)* | this account's own database activity: request counts, errors, recent denied requests | `GET /v1/hosting/activity` |
| **Updates** *(Host, host admin and owner)* | installed version and sequence, manifest signature, update source (Host, GitHub, or Both), plan then apply, canary and blue-green health, snapshots and restore, public signing keys, live status | `redx update` |
| **Data Explorer** | file/box tree with counts, paginated table, filter builder that **writes the BoxQL for you**, record editor (Box text or JSON), TTL and sliding TTL, new record (next free ID), delete, *Open in Studio* | `redx get/set/del`, `redx bx` |
| **BoxQL Studio** | own editor with syntax highlighting, context-aware autocomplete (verbs, files, boxes, fields, options), `$param` inputs, `Ctrl+Enter`, **Explain**, Table / JSON / Box-text results, history, saved queries, cheat-sheet, snippets, errors with `line:col` squiggles | `redx bx '...' --param/--sparam` |
| **Live Watch** *(Advanced)* | WebSocket to `bx/watch` or a topic, pause, clear, download, 500-event cap, auto-reconnect | `redx bx '{Watch[]} = ...'` / `websocat` |
| **API Keys** | list, create (label, database, scope, expiry, advanced prefix/roles/rate), **rotate** with a grace period, revoke with confirmation. A new key is shown once with Copy, Download, a ready-made `curl` example and a sign-in QR | `redx key create/list/rotate/revoke` |
| **Add a device** | pairing code + QR for a new **node**, scoped keys for a **phone or browser**, one-line install commands per OS, config bundle download, iPhone/iPad install steps | `redx node token`, `redxd join` |
| **Backups** | download an online snapshot (`.tgz`) of everything, what it contains, restore guidance, disk usage of the data folder | `redx backup --out FILE`, `redx restore FILE` |
| **Settings** | theme, simple/advanced, sign out, reset the checklist, clear saved queries, service-worker status, the effective configuration (redacted, grouped, with env-var overrides marked), TLS fingerprint | `redx doctor` |
| **Connected apps** | apps that got a workspace through *Connect* (Rotten Apple, Gendragoon, ...): workspace, access, status, **Revoke**; open requests with *Deny* | `curl .../v1/connect/apps` |
| **Connect an app** (opened by an app's link, `#/connect?...`) | consent page: the app's name from RedX's own list, the access in plain words, the workspace name, **Approve** / **Deny**. See [Connecting apps](connect.md) | |
| **Help** | the console, BoxQL, Box grammar, hosting, clustering and connect guides rendered in the console (embedded copies, table of contents) | |
| **Raw editor** *(Advanced)* | open a file of a database as text, validate it with the server's parser, save | `redx` / `curl` per file type |
| **Security · Rules · Code** *(Advanced)* | readable summaries of the access policy (`sec`), pulse rules, scripts (`code`) and search indexes (`idx`); links into the raw editor | `redx pulse/idx ...` |
| **Cluster & nodes** *(Advanced)* | role, members, lag, heartbeat; **promote** with typed confirmation and warnings (lost writes, divergence); join help | `redx node status/promote` |
| **Presets** *(Advanced)* | ten settings profiles, comparison table, editable values, *what changed* diff, apply | `redx preset ls/show/apply` |

### What is real and what is limited (per page)

All pages talk to the real `/v1` API of the running host; nothing in the console is mocked. Honest limits:

* **Raw editor**: writable for `sec`, `pulse`, `code` and `idx` files (the API has write endpoints for them).
  Data files (`.red-xai.db`, `-qs`, `-qs-ls`, `-link`) and media/pack files are **read-only** here: change records
  through the Data Explorer or BoxQL. Read-only files say so in a banner.
* **Security · Rules · Code**: *summaries*, not designers. Editing happens in the Raw editor.
* **Backups**: download only. Restoring is an offline operation (`redx restore ...`), described on the page.
  There is no free-disk-space readout, only the size of the data folder.
* **Cluster**: shows and promotes; it cannot start another machine for you. Failover is manual: there is no
  automatic election (see [Clustering](clustering.md)).
* **Watch**: events stream while the tab is open; nothing is stored.
* **Presets**: write the configuration file; **a restart of `redxd` is required** for them to take effect.
  Settings that come from environment variables win over the file and are flagged. A preset cannot set the
  keystore passphrase (that is a secret in the environment).
* **Windows, macOS, iOS, Docker, a real phone browser**: not run by the author (see section 10).

## 3. The setup wizard (Simple mode)

First sign-in opens a four-step wizard: **name** your first database → pick a **template** → pick a **profile**
(a preset, or skip) → **review**. Templates:

| Template | Creates | Notes |
|---|---|---|
| Game saves | `saves.red-xai.db`, box `Save`, a few example records | durable file |
| Sessions / cache | `sessions.red-xai-db-qs`, box `Session`, TTL 3600 s | memory file, every record expires |
| Notes | `notes.red-xai.db`, box `Note`, example records | |
| Empty | just the database | |

It finishes with next steps (open the Explorer, run a query, make a key, add a device). *Advanced* skips it.
The wizard uses exactly the API calls the other pages use; you can redo or ignore it at any time.

## 4. Presets

Ten embedded profiles live in `host/presets/*.toml`. Each setting has a plain-English *why*. The only performance
numbers quoted come from [Benchmarks](benchmarks.md) (one virtualised test machine; yours will differ).

| Preset | For | Key choices |
|---|---|---|
| `server` | always-on box on a trusted LAN | listens on all interfaces, TLS auto, `group` durability, 200 rps/key |
| `vps` | rented machine with a public IP | TLS auto, **encrypted keystore** (needs `REDX_KEYSTORE_PASSPHRASE`), audit successes, 20 rps/key, no web bootstrap |
| `website` | web/API back end next to its web server | loopback, TLS off, default TTL 1 h, 500 rps/key |
| `app` | mobile/desktop app back end with per-user keys | TLS auto, 50 rps/key |
| `game` | game back end: hot counters, many small writes | TLS auto, default TTL 24 h, 1000 rps/key |
| `edge` | Raspberry Pi / IoT / small low-power device | **follower**, `async` durability (up to 10 ms of acknowledged writes can be lost on a power cut), small memory and upload limits |
| `dev` | laptop development | loopback, TLS off, `sync` durability, audit successes |
| `cluster` | follower node of an existing host | follower role; needs a join link or peers |
| `backup` | archive / long-term safekeeping | loopback, `sync` durability, audit successes, large uploads; optional encrypted packs need a master key |
| `all` | "any and all": balanced all-rounder | loopback, nothing exposed to the network, every feature available |

Use `redx preset show NAME` (or the console's Presets page) to see every value with its reason: the table above is a summary.

Apply a preset any of four ways; precedence is **defaults < preset < config file < environment < flags**:

1. Console: *Presets* → card → edit values if you like → review the *what changed* diff → Apply (writes `redx.toml`, keeps the old file as a backup, asks for a restart). The wizard does the same for its profile step.
2. `redxd run --preset NAME` (or `REDX_PRESET=NAME`).
3. `redx preset ls | show NAME [--diff] | apply NAME [--dry-run] [--set key=value] [--join LINK]`.
4. `preset = "NAME"` in `redx.toml`.

Only the keys a preset lists are changed; everything stays editable. While Red-XAI Accounts is on, an apply that sets a join link or changes `role` or `advertise` needs an owner login; a host-admin key is refused. The audit line records the join leader's URL and never the join secret.

## 5. Adding a device (nodes, phones, browsers)

*Add a device* has four tabs:

1. **Add a node** (another computer running `redxd`): shows a **pairing code** (`RX-XXXXX-XXXXX`, no look-alike
   characters) with a countdown, a QR code of the join link and the command to run on the new machine:
   `redxd join "<join link>"` or `redxd join https://this-host:7777 RX-XXXXX-XXXXX` (the page fills in the real address).
   The code is **single use**, valid **10 minutes** by default (1 hour at most), and grants **join only**: it cannot
   read data or manage keys. Guessing is rate-limited. The join link carries the TLS fingerprint so the joining node
   pins the certificate. The new node becomes a follower; promoting it is manual.
   You can also download a **config bundle** (`redx.toml` + a README) instead.
   Watch the address field: a `127.0.0.1` address is useless to another device, and the page warns you.
2. **Phone or browser**: signs another browser in with a **one-time pairing code**, shown as text (`RP-XXXXX-XXXXX`) and as
   a QR code of `https://this-host/#/login?code=...`. **The QR contains no key.** The code works once, expires after
   5 minutes, and lives only in the memory of the leader (a restart or a leader change voids unused codes). The new key is
   created only when the code is redeemed, with the database, access and expiry you chose, so an unused code leaves nothing to
   revoke. On the phone, scan the QR or type the code on the sign-in page (it accepts `rx_...` keys and `RP-...` codes).
   Wrong codes are rate-limited (8 a minute per client, 40 overall). Only an admin key can make codes (`POST /v1/keys/pairing`);
   redeeming needs no key (`POST /v1/pair/exchange`); both are for the leader (a follower answers 409). The *Your new key*
   dialog on the API Keys page has *Pair another device*, which makes a **new** key with the same access (an existing key can
   never be shown again).
3. **Install commands**: one-liners for Linux, macOS, Windows and Docker. They assume you copied the release archive to the
   machine: nothing is downloaded for you.
4. **iPhone & iPad**: how to *Add to Home Screen*, and why a self-signed certificate limits that (section 6).

mDNS/Bonjour auto-discovery was considered and **not implemented**: the codes and QR are simpler and safer
(no broadcast of a database on the network).

## 6. Install it as an app (PWA)

The console has a web-app manifest, icons (any + maskable), `apple-touch-icon` and a service worker, so browsers
offer *Install*. The service worker caches only the console shell (static files, **never** `/v1`), is network-first,
and the console still opens offline (data pages then show their error states).

**A PWA needs HTTPS or loopback.** Browsers only register the service worker (and so only offer *Install*) in a secure context:
`https://` with a certificate the device trusts, or `http://127.0.0.1` / `http://localhost` on the same machine. A page opened
at `http://192.168.x.y:7777` from a phone still works as a normal web page and the console is fully usable, but it cannot be
installed as an app and does not work offline. A self-signed `https` certificate works only if the device trusts it. On iPhone/iPad, Safari's
*Share → Add to Home Screen* works for a trusted HTTPS address; with an untrusted self-signed certificate it will add a
shortcut but the service worker will not register. A reverse proxy with a real certificate (or a VPN name with one)
is the practical fix. This was not tested on real iOS hardware. There is no iOS build of `redxd`, so an iPhone or iPad cannot be a node.

## 7. The BoxQL Studio editor

The editor is custom (a textarea over a highlighted layer; no external library). Tokenizers for BoxQL and raw Box
text live in `host/ui/js/tokenizers.js` and are unit-tested (`node --test host/uitest`, run by `go test ./host`).
It handles bracket matching, auto-closing, `Tab` indent, undo/redo, a find bar, light and dark token colours and
inline error squiggles. Syntax is checked live by the **server's own parser** via `/v1/ui/validate`.
Results can be viewed as a table, as JSON or as Box text. The only query language is BoxQL.

## 8. Terminal ↔ console map

| Terminal | Console |
|---|---|
| `redxd run` (prints first key) | open the console, *Create admin key* |
| `redx key create/list/rotate/revoke` | API Keys |
| `redx set/get/del`, `curl .../path/...` | Data Explorer |
| `redx bx '{Get[]} = ...'` | BoxQL Studio |
| `redx node token`, `redx node join`, `redxd join` | Add a device |
| `redx node status/promote` | Cluster & nodes |
| `redx backup` | Backups |
| `redx preset ...`, `redxd run --preset` | Presets / wizard |
| `redx doctor` | Settings, Dashboard |
| an app's Connect button | Connect an app, Connected apps |

## 9. Endpoints the console added

Existing routes are reused as they are. The console needed a few more; all are covered by Go tests.

| Route | Auth | Purpose |
|---|---|---|
| `GET /v1/ui/bootstrap-status` | none | `{"needsSetup":bool}`; true only for loopback requests while setup is pending |
| `POST /v1/ui/bootstrap` | none, loopback, once | creates the first admin key (refused after the first key, from non-loopback hosts, and with `REDX_NO_BOOTSTRAP`) |
| `GET /v1/ui/whoami` | key | the caller's scope, database, version |
| `POST /v1/ui/validate` | key | parse Box text, BoxQL, or a policy document and return `line:col` errors |
| `GET /v1/admin/status` `audit` `config` | host admin | dashboard data, audit tail, redacted effective config |
| `GET /v1/admin/presets[/NAME]`, `POST .../apply` | host admin; owner while Accounts is on if the apply sets `join` or changes `role` or `advertise` | preset list, diff, write config file |
| `GET /v1/db/{db}/files[/name]` | read | file list / file text for the raw editor |
| `DELETE /v1/db/{db}?confirm=name` | host admin | drop a database |
| `POST /v1/cluster/join` (code form) | join code | the join-code flow used by `redxd join` |
| `/v1/connect/*` | see [Connecting apps](connect.md) | app connect handshake, Connected apps, revoke |

## 10. Not done / not tested

* Windows, macOS, iOS/iPadOS Safari and Docker were **not** run. The binaries cross-compile; the console was driven
  end to end only in headless Chrome on Linux (screenshots of every page, mobile width too).
* No automatic failover (a promoted node fences the old leader, see [Clustering](clustering.md)), no mDNS, no native iOS app.
* The scythe icon is embedded in the Windows executables (`.syso` resources) and used by the installer shortcuts; the
  `.exe` files and installers are unsigned, so Windows SmartScreen and macOS Gatekeeper warn on first run.
* The console cannot restart the daemon: preset changes need a restart (service manager or `Ctrl+C` and run again).
* Self-signed certificates: browsers warn once; PWA install and some phone features need a trusted certificate.
