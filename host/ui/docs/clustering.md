# Clustering and replication

A RedX cluster is one leader and any number of followers, using asynchronous replication. Any device that can run the static binary can be a node: PC, Mac, Linux machine, Raspberry Pi. Android is possible through Termux with the linux/arm64 or armv7 build; this has been cross-compiled but not run on a device.

## Adding nodes

**Easiest: a pairing code from the console.** On the leader open *Add a device → Add a node*. It shows a code like
`RX-ABCDE-FGHJK`, a QR code and a ready-made command. On the new machine, after installing the binaries:
```sh
redxd join "https://<leader-ip>:7777/#/join?c=RX-ABCDE-FGHJK&pin=<fingerprint>"      # the link from the page
redxd join https://<leader-ip>:7777 RX-ABCDE-FGHJK                                    # or URL + code (a self-signed https leader also needs its pin: prefer the link)
```
The code is single use, valid 10 minutes (at most 1 hour) and can only join: it cannot read data or manage keys.
`redxd join` redeems it, writes `cluster/cluster.json` and starts the node as a follower (`--no-run` to only join; `--advertise URL`
tells the leader how to reach this node). The token procedure below does the same thing step by step.

1. **Leader must be reachable and use TLS** if the nodes talk over anything but a trusted LAN:
   in `redx.toml`: `listen = "0.0.0.0:7777"`, `tls = "auto"`, `advertise = "https://<leader-ip>:7777"`. On start it prints the certificate fingerprint
   (`redx doctor` / the log show it; also `openssl x509 -in <data>/tls/cert.pem -noout -fingerprint -sha256`). Open the firewall for that port only on your private network.
2. **On the leader** create a short-lived, single-use join token (admin key required, default 15 min):
   ```sh
   export REDX_ADDR=https://<leader-ip>:7777 REDX_PIN=<leader cert sha256 hex>
   redx node token            # prints rxj_...
   ```
3. **On the new device** install with the follower role (`sudo ./install.sh --from . --role follower` / `.\install.ps1 -From . -Role follower`;
   this installs the service but does not start it and creates no admin key), then:
   ```sh
   redx node join https://<leader-ip>:7777 --token rxj_... --pin <fingerprint> \
        --advertise https://<this-device-ip>:7777 --node-id pi-garage --data-dir /var/lib/redx
   sudo chown -R redx:redx /var/lib/redx && sudo systemctl start redxd   # Windows: redxd.exe start; macOS: sudo launchctl load -w /Library/LaunchDaemons/com.redx.redxd.plist
   ```
   `join` redeems the token, stores a per-node secret in `<data>/cluster/cluster.json` (0600) and the node starts replicating. State in `cluster.json`
   wins over `role/peers` in the config file.
   Already-running node? `redx node join <leader> --token T --local http://127.0.0.1:7777 --key <local admin key>` repoints it live.
4. Check: `redx node status` (on the leader: members, ack offsets, lag, health).
5. Static clusters (docker-compose): set the same `cluster_secret` / `REDX_CLUSTER_SECRET` on every node and `role=follower`, `peers=[leader url]`; no token needed.

Clients may talk to **any** node: reads are served locally (eventually consistent), writes/key changes/db creation are transparently forwarded to the leader.
For read-your-writes send the `X-Redx-Seq` you got from the write as `X-Redx-Wait-Seq` on the read (waits up to 3 s for that offset).
For a stronger write ack send `X-Redx-Wait-Replicas: N` on the write: the leader waits up to 2 s for N followers to confirm and returns `X-Redx-Replicas-Acked`
(it does **not** fail the write if fewer ack — it is a measurement, not a quorum).

## Consistency model
* **Asynchronous** replication of an ordered log (one offset space per leader "replication id"). The leader acknowledges a write after applying it locally, **before** followers have it.
* A follower **resumes by (replication id, offset)** after a restart or disconnect. If the leader no longer has that offset (log truncated — default retains 1,000,000 entries,
  `repl_log_max`) or the replication id is unknown/diverged, the follower is told to do a **full snapshot resync** (leader pauses writes while it copies; follower swaps in the files and continues from the snapshot offset).
* **Followers never expire keys.** The leader's engine decides expiry and replicates an explicit `expire` delete; followers apply it as a plain delete. (Absolute deadlines, not relative TTLs, are shipped.)
  Consequence: a follower can serve a key for a short moment after its TTL passed, until the leader's delete arrives. Sliding-TTL extensions caused by reads on the leader are leader-local.
* **Failover is manual and can lose acknowledged writes** (see [Failover](#failover-promote-fencing-and-repoint)). `redx node promote` (on a follower, admin key) bumps the replication id (the old id + offset are remembered), re-arms expiry and makes it a leader.
  Any write the old leader acknowledged but had not yet replicated is **lost**. The other followers are re-attached with `redx node repoint <new-leader> --token <token from new leader>`;
  a follower whose history is a prefix of the new leader's resumes by offset (partial resync), otherwise it takes a snapshot and its extra writes are discarded.
* **Split brain is limited by fencing**: a promoted node tells the old leader to stop taking writes as soon as it can reach it (see below). While the old leader is unreachable (a real partition) it can still accept writes; those are discarded when it is repointed.
* **Key revocation is eventually consistent across nodes** (keys replicate through the same log). Revoking on the leader is instant there; followers apply it within the replication lag. Revoke on all nodes if urgency matters.
* **Volatile data** (`.red-xai-db-qs`) is RAM-only by definition: a restart loses it; a follower that needs a full snapshot does not receive volatile contents, only later changes.
* The snapshot is write-paused file copy after an engine checkpoint; engine-initiated expiry commits during the copy may be replayed on the follower (idempotent).
* Not implemented: automatic election, quorum acks, multi-leader, partial/sharded replication, bounded-staleness reads.

## Failover: promote, fencing and repoint

1. **Promote** a follower (admin key on that node): `redx node promote`. It starts a new replication history and becomes the leader.
   The node status no longer shows the follower-era "last error".
2. **Fencing.** The promoted node remembers the old leader (its URL, its certificate pin and the node secret it was given) and tells it,
   every heartbeat until it answers, that it has been superseded (`POST /v1/cluster/superseded`, authenticated with that node secret; the old
   leader accepts it only from a node promoted out of its own replication history). From then on the old leader is **fenced**: it still
   serves reads but refuses every write with `503` and a message telling you to repoint it. `redx node status` shows `FENCED`. The fence is
   stored in `cluster.json` and survives restarts. If you really want the old node to lead again, `redx node promote` on it clears the fence.
3. **Repoint** the old leader and the other followers at the new leader:
   ```sh
   redx node token                                              # on the new leader
   redx node repoint https://<new-leader>:7777 --token rxj_...  # against the node to repoint (--addr/--key/--pin for that node)
   ```
   With self-signed TLS the node must trust the new leader's certificate. A fenced old leader already learned the new leader's
   fingerprint through the fence, so no flag is needed. Otherwise pass it: `--leader-pin <sha256 hex>` (alias `--fingerprint`), or give
   the new leader's join link (`https://host:7777/#/join?c=CODE&pin=FP`) instead of the URL and token. Without trust, repoint stops with a
   clear error and leaves the node unchanged. `--pin` is the pin of the node you talk to (`--addr`), `--leader-pin` the pin of the new leader.
   `redx node join --local` takes `--leader-pin` the same way.
4. After repoint, exactly one node is a writable leader; the old leader resyncs (by offset, or by snapshot if it diverged, which discards
   its un-replicated writes) and forwards writes to the new leader.

Remaining window: while the old leader cannot be reached, or in the first heartbeat after it comes back, it can still acknowledge writes.
Those writes are lost when it is repointed. Stop the old leader before promoting when you can.

## Behavior of indexes, packs and rules in a cluster

| What | Replicated to followers? |
|---|---|
| Index and pulse **definitions** (small text files) | **Yes**, as log entries (and inside snapshots) |
| Index **contents** | No. Rebuilt from replicated data on a node when it is first queried as leader (so a promoted node answers correctly, after a rebuild pause) |
| **Pack contents** | **No.** They exist only on the node that received the upload (and in a full snapshot taken at that moment). After a failover the new leader lacks packs uploaded after its last snapshot. Back packs up (`redx backup`) if you cannot lose them |
| Pulse timers | No (in memory on the leader) |
| Link resolution | Works on any node (reads replicated data) |

A follower **forwards** index/pack/pulse requests (reads too, and WebSocket subscriptions) to the leader, because that is where this state lives; resolution is answered locally.
