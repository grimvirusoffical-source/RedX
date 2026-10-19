# Getting started

This guide takes you from a downloaded archive to a first query. Terminal commands are shown throughout; the same operations are available over the HTTP API and the SDKs ([API reference](api.md), [SDKs](sdks.md)).

## 1. Install and start the host

Follow the section for your platform in [Hosting](hosting.md#installation). The shortest path, with no installation, is a foreground run:

```sh
tar xzf redx-<ver>-<os>-<arch>.tar.gz && cd redx-<ver>-<os>-<arch>
./redxd run --data-dir ./data
```

On first start, open `http://127.0.0.1:7777` in a browser on the same machine: the console offers *Create admin key* and shows the key once (see [the console guide](console.md)). If the host listens on a non-loopback address, or you start it with `--bootstrap console`, it prints the one-time admin key in the terminal instead. Copy it; it is stored only as a hash and is not shown again. The host listens on `http://127.0.0.1:7777` by default. Stop it with Ctrl+C.

## 2. Check the installation

In a second terminal, from the same folder:

```sh
export REDX_KEY=rx_live_...        # the first admin key
./redx doctor
curl -s http://127.0.0.1:7777/healthz
```

`redx doctor` checks the configuration, data directory, key store, TLS certificate, and whether the daemon answers.

## 3. Keys

* **Installers** create the first admin key *offline* and print it once. It is stored only as a salted argon2id hash.
* **Foreground first run** (`redxd run`, empty data dir) prints a one-time admin key on the console. It is **not** written to any log file.
  Under a service manager the console output is not visible, so the installers create the key up front and set `REDX_NO_BOOTSTRAP=1`.
* Lost the admin key? Create a new one directly on the data dir (it needs filesystem access, so only the machine's owner can do it):
  `redx key create --offline --data-dir <dir> --scope admin --db '*' --label recovery`

### Create an application key

This requires an admin key in `REDX_KEY`:
```sh
redx key create --db default --scope write --ttl 30d --label my-game-server   # shown ONCE: rx_live_<43 chars>
redx key create --db game --scope read --prefix 'public.red-xai.db:Box[ID=1]' # path-prefix ACL
redx key list
redx key rotate <id> --grace 10m       # new key now, old one dies in 10 minutes
redx key revoke <id>                   # effective immediately on this node
```
Scopes: `read` < `write` < `admin`. A key is bound to one database (or `*`). `admin` on `*` is the *host admin*
(create databases/keys, backups, cluster). `admin` on one db manages keys of that db only. Prefix-restricted keys cannot use `/v1/query`.
Each key may carry its own `--rate-rps/--rate-burst` (default 100 rps, burst 200; `-1` = unlimited).
Key format: `rx_live_` + 43 base62 characters (32 random bytes). The first 8 characters are a non-secret lookup id; the rest is only ever compared via argon2id + constant-time compare.

## 4. Store and read data

Paths address a file, a box and a record: `file.red-xai.db:Box[ID=1].Key`. See the [Box grammar](box-grammar.md#4-paths-query-language-used-by-getsetdeletequery).

```sh
./redx set  'players.red-xai.db:Player[ID=1].Name' '"Ann"'
./redx get  'players.red-xai.db:Player[ID=1].Name'
```

Query with BoxQL, the RedX query language ([reference](boxql.md)):

```sh
./redx bx '{Get[]} = players:Player[ID=*] -> Name'
```

## 5. Next steps

* [Hosting](hosting.md): install as a service, Docker, troubleshooting.
* [Configuration](configuration.md): `redx.toml`, environment variables, defaults.
* [Security](security.md): keys, TLS, policy, encryption.
* [Clustering and replication](clustering.md): add nodes on other devices.
* [Backup and restore](backup.md).
