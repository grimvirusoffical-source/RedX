"""DoS and resource limits: body size, F1 failed-auth throttle, reserve leak probe."""
import concurrent.futures as cf
import socket
import time

from conftest import Host, P


def test_body_over_max_is_rejected(host):
    big = '"' + ("A" * (17 << 20)) + '"'
    r = host.req("PUT", "/v1/path/" + P("dos.red-xai.db:B[ID=1].V"), big, key=host.admin_key, timeout=60)
    assert r.status in (400, 413)
    assert host.req("GET", "/healthz").status == 200


def test_f1_exactly_twenty_401_then_429(fresh_host):
    """F1 regression: reserve-before-verify → exactly 20 failures/min/IP, then 429."""
    h = fresh_host

    def bad(i):
        return h.req("GET", "/v1/stats", key="rx_live_" + ("%043d" % i)).status

    # Serial first: hard bound
    serial = [bad(i) for i in range(40)]
    assert serial.count(401) == 20, serial.count(401)
    assert serial.count(429) == 20
    # Concurrent must not overshoot either
    h2 = Host().start()
    try:
        with cf.ThreadPoolExecutor(32) as ex:
            codes = list(ex.map(lambda i: h2.req("GET", "/v1/stats",
                                                 key="rx_live_" + ("%043d" % i)).status, range(300)))
        assert codes.count(401) == 20, codes.count(401)
        assert codes.count(429) == 280
    finally:
        h2.kill()


def test_bypass_reserve_does_not_leak_on_verification_errors(fresh_host):
    """Probe: failed verifies keep the reserved slot (no release), so 20 bad
    attempts still throttle. Mixed with occasional successes that release must
    not leave the window permanently full of ghosts beyond the failure count."""
    h = fresh_host
    # 10 failures
    for i in range(10):
        assert h.req("GET", "/v1/stats", key="rx_live_" + ("%043d" % i)).status == 401
    # Success releases its reserved slot
    assert h.req("GET", "/v1/stats", key=h.admin_key).status == 200
    # 10 more failures → still room for exactly 10 more 401s (slot was released)
    more = [h.req("GET", "/v1/stats", key="rx_live_b" + ("%042d" % i)).status for i in range(15)]
    assert more.count(401) == 10, more
    assert more.count(429) == 5
    # Empty / malformed bearer also consume slots (already reserved before check)
    # Window is full → further missing bearer is 429
    assert h.req("GET", "/v1/stats").status == 429


def test_slow_body_connections_do_not_block_health(fresh_host):
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
