# Clustering and replication

A RedX cluster is one leader and any number of followers, using asynchronous replication. Any device that can run the static binary can be a node: PC, Mac, Linux machine, Raspberry Pi. Android is possible through Termux with the linux/arm64 or armv7 build; this has been cross-compiled but not run on a device.

## Adding nodes

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
* **Failover is manual and can lose acknowledged writes.** `redx node promote` (on a follower, admin key) bumps the replication id (the old id + offset are remembered), re-arms expiry and makes it a leader.
  Any write the old leader acknowledged but had not yet replicated is **lost**. The other followers are re-attached with `redx node repoint <new-leader> --token <token from new leader>`;
  a follower whose history is a prefix of the new leader's resumes by offset (partial resync), otherwise it takes a snapshot and its extra writes are discarded.
* **Split brain is possible**: nothing stops the old leader from continuing to accept writes if it is merely partitioned. Make sure it is stopped (or demote it with `redx node repoint`, which discards its un-replicated writes via snapshot) before promoting.
* **Key revocation is eventually consistent across nodes** (keys replicate through the same log). Revoking on the leader is instant there; followers apply it within the replication lag. Revoke on all nodes if urgency matters.
* **Volatile data** (`.red-xai-db-qs`) is RAM-only by definition: a restart loses it; a follower that needs a full snapshot does not receive volatile contents, only later changes.
* The snapshot is write-paused file copy after an engine checkpoint; engine-initiated expiry commits during the copy may be replayed on the follower (idempotent).
* Not implemented: automatic election, quorum acks, multi-leader, partial/sharded replication, bounded-staleness reads.

## Behavior of indexes, packs and rules in a cluster

| What | Replicated to followers? |
|---|---|
| Index and pulse **definitions** (small text files) | **Yes**, as log entries (and inside snapshots) |
| Index **contents** | No. Rebuilt from replicated data on a node when it is first queried as leader (so a promoted node answers correctly, after a rebuild pause) |
| **Pack contents** | **No.** They exist only on the node that received the upload (and in a full snapshot taken at that moment). After a failover the new leader lacks packs uploaded after its last snapshot. Back packs up (`redx backup`) if you cannot lose them |
| Pulse timers | No (in memory on the leader) |
| Link resolution | Works on any node (reads replicated data) |

A follower **forwards** index/pack/pulse requests (reads too, and WebSocket subscriptions) to the leader, because that is where this state lives; resolution is answered locally.
