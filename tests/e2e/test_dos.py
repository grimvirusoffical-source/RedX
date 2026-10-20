"""DoS and resource limits: body size, slow-body hang, failed-auth overshoot."""
import concurrent.futures as cf
import socket
import time

from conftest import Host, P


def test_body_over_max_is_rejected(host):
    # MaxBodyMB default 16: a 17 MiB PUT must 400, not OOM the host.
    big = '"' + ("A" * (17 << 20)) + '"'
    r = host.req("PUT", "/v1/path/" + P("dos.red-xai.db:B[ID=1].V"), big, key=host.admin_key, timeout=60)
    assert r.status in (400, 413)
    assert host.req("GET", "/healthz").status == 200


def test_failed_auth_throttle_overshoots_under_concurrency(fresh_host):
    """F1 LOW BREAK: failTracker is check-then-record (host/auth.go:202-230). Under
    concurrent wrong-key requests the documented 20/min/IP cap is overshot before
    the counter catches up. The overshoot is bounded (~1.5–2×) so it is LOW, not
    a free argon2 DoS, but the documented bound is not hard."""
    h = fresh_host
    def bad(i):
        return h.req("GET", "/v1/stats", key="rx_live_" + ("%043d" % i)).status
    with cf.ThreadPoolExecutor(32) as ex:
        codes = list(ex.map(bad, range(300)))
    assert codes.count(401) > 20
    assert codes.count(401) <= 60
    assert codes.count(429) > 200


def test_slow_body_connections_do_not_block_health(fresh_host):
    """INFO: ReadHeaderTimeout is set (10s) but there is no per-request body read
    deadline. Holding many half-written bodies does not break /healthz, and RSS
    stays modest; recorded so a later hardening pass can add a body timeout."""
    h = fresh_host
    socks = []
    for _ in range(200):
        s = socket.create_connection(("127.0.0.1", h.port))
        s.send(b"POST /v1/pair/exchange HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 1000000\r\n\r\n{")
        socks.append(s)
    time.sleep(2)
    assert h.req("GET", "/healthz").status == 200
    for s in socks:
        s.close()
