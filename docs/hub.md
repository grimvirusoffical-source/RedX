# red-xai-hub and the RedX host

red-xai-hub runs RedX by starting the `redxd` binary and opening its console. The console is already inside that binary. The hub does not ship a second copy of the UI, does not keep its own user database, and does not rewrite databases, packs, or sealed records.

## Spawn `redxd`

Put `redxd` next to the hub (the archives from `scripts/build.sh` contain it). Start it as a child process and wait until it answers:

```sh
redxd run --data-dir /var/lib/redx --listen 127.0.0.1:7777 --no-open
# then, until HTTP 200:
#   GET http://127.0.0.1:7777/healthz
```

`--no-open` skips the browser. When `/healthz` is 200, open `http://127.0.0.1:7777/` in the user's browser. `redxd open` does that open step on its own if the host is already running.

`redx-launcher`, shipped beside `redxd` in the same archive, is the one-click form of this: if `http://127.0.0.1:7777/healthz` is down it starts `redxd`, waits up to 30 seconds, then opens `/`. `REDX_LISTEN` changes the address. `REDX_LAUNCHER_NO_OPEN=1` prints the URL instead of opening a browser.

Give the process its own data directory. Do not point two hosts at the same directory.

## The console is embedded, not iframed

`redxd` serves the console from the same port (`/` and `/ui/`). The pages are compiled into the binary. A hub that can run `redxd` already has the console.

Do not put the console in an iframe. Responses send `Content-Security-Policy: frame-ancestors 'none'` and `X-Frame-Options: DENY`. Open a browser window or tab instead.

## Sign-in

People sign in with an API key, or with a Red-XAI Account when `accounts_issuer` is set. That issuer is the same account database the Red-XAI website uses. The hub must not add a user table in RedX. See [Accounts](accounts.md).

## Editing data

The Data Explorer is the website editing page: browse record files, create a record, edit Box text or JSON, Save. A read or write key can list record files (`GET /v1/db/{db}/files?kind=records`). Seal and Open use a Red-SecretsXAI password and do not write until the user presses Save. They do not convert red-X PNGs and they do not rewrite packs or existing sealed payloads. Delivery of sealed text as a red-X PNG is the [Red-SecretsXAI wiki](https://github.com/grimvirusoffical-source/Red-SecretsXAI/wiki), not a step the hub runs against stored files.

## Packaging

`scripts/build.sh` builds `redxd`, `redx`, and `redx-launcher` for linux (amd64, arm64, armv7), darwin (amd64, arm64), and windows (amd64, arm64). The binaries and archives are unsigned.
