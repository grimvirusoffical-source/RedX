"""Persistence and crash recovery: real redxd processes killed with SIGKILL and restarted
on the same data directory. Every write the host acknowledged must be there afterwards.
"""
import concurrent.futures as cf
import os
import signal
import threading
import time

import pytest
from conftest import Host, P


def load_key(h):
    k, _ = h.make_key("admin", db="*", label="load", rate_rps=-1, rate_burst=-1)
    return k


@pytest.mark.parametrize("mode", ["sync", "group"])
def test_acked_writes_survive_sigkill_mid_load(mode):
    h = Host(env={"REDX_ENGINE_DURABILITY": mode}).start()
    k = load_key(h)
    acked, stop = [], threading.Event()
    lock = threading.Lock()

    def writer(t):
        i = 0
        while not stop.is_set():
            i += 1
            path = "crash.red-xai.db:C[ID=%d].V" % (t * 1000000 + i)
            try:
                r = h.req("PUT", "/v1/path/" + P(path), str(i), key=k, timeout=5)
            except OSError:
                return
            if r.status == 200:
                with lock:
                    acked.append((path, str(i)))

    ths = [threading.Thread(target=writer, args=(t,)) for t in range(8)]
    for t in ths:
        t.start()
    time.sleep(2.0)
    h.kill(signal.SIGKILL)
    stop.set()
    for t in ths:
        t.join()
    assert len(acked) > 100, len(acked)
    h.start()
    missing = [p for p, v in acked if h.req("GET", "/v1/path/" + P(p), key=k).status != 200]
    h.kill()
    assert not missing, "%d of %d acknowledged writes lost after SIGKILL (%s)" % (len(missing), len(acked), mode)


def test_revoked_key_stays_revoked_after_sigkill():
    h = Host().start()
    k, kid = h.make_key("write")
    assert h.req("DELETE", "/v1/keys/" + kid, key=h.admin_key, headers={"X-RedX-Confirm": "revokeKey"}).status == 200
    h.kill(signal.SIGKILL)
    h.start()
    assert h.req("GET", "/v1/stats", key=k).status == 401
    h.kill()


def test_committed_tx_is_all_or_nothing_across_crash():
    h = Host().start()
    k = load_key(h)
    for i in (1, 2):
        assert h.req("PUT", "/v1/path/" + P("t.red-xai.db:A[ID=%d].Gold" % i), "1000", key=k).status == 200
    xfer = ('{Tx[]} = [ {Require[]} = t:A[ID=1, Gold >= 1], {Set[]} = t:A[ID=1].Gold = Gold - 1, '
            '{Set[]} = t:A[ID=2].Gold = Gold + 1 ]')
    stop = threading.Event()

    def loop():
        while not stop.is_set():
            try:
                h.req("POST", "/v1/bx", {"q": xfer}, key=k, timeout=5)
            except OSError:
                return
    ths = [threading.Thread(target=loop) for _ in range(6)]
    [t.start() for t in ths]
    time.sleep(1.5)
    h.kill(signal.SIGKILL)
    stop.set()
    [t.join() for t in ths]
    h.start()
    g = lambda i: int(h.req("GET", "/v1/path/" + P("t.red-xai.db:A[ID=%d].Gold" % i), key=k).json()["value"])
    a, b = g(1), g(2)
    h.kill()
    assert a + b == 2000, "torn transaction after crash: %d + %d" % (a, b)
    assert a < 1000


def test_torn_wal_tail_recovers_and_keeps_serving():
    """Test harness (needs filesystem access): append junk to the WAL tail, as a crash mid-write would."""
    h = Host(env={"REDX_ENGINE_DURABILITY": "sync"}).start()
    k = h.admin_key
    for i in range(50):
        assert h.req("PUT", "/v1/path/" + P("w.red-xai.db:W[ID=%d].V" % i), str(i), key=k).status == 200
    h.kill(signal.SIGKILL)
    d = os.path.join(h.data_dir, "dbs", "default")
    wals = sorted(f for f in os.listdir(d) if f.startswith("w.red-xai.db.wal"))
    assert wals
    with open(os.path.join(d, wals[-1]), "ab") as f:
        f.write(os.urandom(37))
    h.start()
    for i in range(50):
        r = h.req("GET", "/v1/path/" + P("w.red-xai.db:W[ID=%d].V" % i), key=k)
        assert r.status == 200 and r.json()["value"] == str(i)
    assert h.req("PUT", "/v1/path/" + P("w.red-xai.db:W[ID=99].V"), "99", key=k).status == 200
    h.restart(signal.SIGKILL)
    assert h.req("GET", "/v1/path/" + P("w.red-xai.db:W[ID=99].V"), key=k).status == 200
    h.kill()


def test_second_daemon_on_same_data_dir_is_refused():
    h = Host().start()
    import subprocess
    import conftest
    p = subprocess.run([conftest.REDXD, "run", "--data-dir", h.data_dir, "--listen",
                        "127.0.0.1:%d" % conftest.free_port()], capture_output=True, timeout=20)
    h.kill()
    assert p.returncode != 0
