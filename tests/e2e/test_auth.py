"""API authentication against a running host."""
import concurrent.futures as cf
import time

from conftest import Host, P

REC = P("players.red-xai.db:Player[ID=1].Name")


def test_missing_bad_revoked_expired_keys_look_identical(host):
    k, kid = host.make_key("read")
    assert host.req("GET", "/v1/path/" + REC, key=k).status in (200, 404)
    r = host.req("DELETE", "/v1/keys/" + kid, key=host.admin_key, headers={"X-RedX-Confirm": "revokeKey"})
    assert r.status == 200, r.text
    ek, _ = host.make_key("read", ttl="1s")
    time.sleep(2.2)
    bodies = set()
    for key in (None, "rx_live_" + "A" * 43, k[:-1] + ("B" if k[-1] != "B" else "C"), k, ek, "garbage", "rxs_notasession"):
        r = host.req("GET", "/v1/path/" + REC, key=key)
        assert r.status == 401, (key, r.status, r.text)
        bodies.add(r.body)
    assert len(bodies) == 1, bodies


def test_query_string_token_ignored_without_websocket_upgrade(host):
    r = host.req("GET", "/v1/path/" + REC + "?access_token=" + host.admin_key)
    assert r.status == 401


def test_non_bearer_schemes_rejected(host):
    for hv in ("Basic " + host.admin_key, host.admin_key, "Bearer", "Bearer  "):
        r = host.req("GET", "/v1/stats", headers={"Authorization": hv})
        assert r.status == 401, hv


def test_failed_auth_throttle_cannot_be_reset_by_forwarding_headers(fresh_host):
    h = fresh_host
    seen429 = False
    for i in range(30):
        r = h.req("GET", "/v1/stats", key="rx_live_" + ("%043d" % i),
                  headers={"X-Forwarded-For": "10.0.0.%d" % i, "X-Real-IP": "10.1.0.%d" % i})
        if r.status == 429:
            seen429 = True
            assert "Retry-After" in r.headers
            break
        assert r.status == 401
    assert seen429, "no throttle after 30 failed attempts with rotating forwarding headers"
    # throttle applies to the source address even for a valid key
    assert h.req("GET", "/v1/stats", key=h.admin_key).status == 429


def test_parallel_wrong_keys_do_not_starve_valid_clients(fresh_host):
    """CPU guard: hammering with wrong keys must not make a valid request slow (argon2 work is bounded)."""
    h = fresh_host
    def bad(i):
        return h.req("GET", "/v1/stats", key="rx_live_" + ("%043d" % i)).status
    with cf.ThreadPoolExecutor(32) as ex:
        codes = list(ex.map(bad, range(400)))
    assert set(codes) <= {401, 429}
    # F1 fixed: reserve-before-verify makes the 20/min/IP cap hard under concurrency.
    assert codes.count(401) == 20, "expected exactly 20 failures before 429, got %d" % codes.count(401)


def test_bootstrap_endpoints_closed_after_first_key(host):
    assert host.req("GET", "/v1/ui/bootstrap-status").json() == {"needsSetup": False}
    r = host.req("POST", "/v1/ui/bootstrap", {"label": "x"})
    assert r.status == 404


def test_web_bootstrap_refuses_rebound_host_and_cross_site():
    h = Host(extra_args=[]).start()
    # start with --bootstrap console already created a key; use a host started with web bootstrap instead
    h.kill()
    w = Host()
    w.extra_args = []
    import subprocess, os
    w.port = __import__("conftest").free_port()
    w.logpath = w.data_dir + ".log"
    w.proc = subprocess.Popen([__import__("conftest").REDXD, "run", "--data-dir", w.data_dir, "--listen",
                               "127.0.0.1:%d" % w.port, "--bootstrap", "web"],
                              stdout=open(w.logpath, "wb"), stderr=subprocess.STDOUT, env=w.env)
    try:
        for _ in range(200):
            try:
                if w.req("GET", "/healthz").status == 200:
                    break
            except OSError:
                time.sleep(0.05)
        assert w.req("GET", "/v1/ui/bootstrap-status").json() == {"needsSetup": True}
        attacks = [
            {"Host": "evil.example:%d" % w.port},                      # DNS rebinding
            {"Origin": "http://evil.example"},                          # cross-site form/fetch
            {"Sec-Fetch-Site": "cross-site"},
            {"X-Forwarded-For": "127.0.0.1"},
        ]
        for hd in attacks:
            r = w.req("POST", "/v1/ui/bootstrap", {"label": "x"}, headers=hd)
            assert r.status == 404, (hd, r.status, r.text)
        r = w.req("POST", "/v1/ui/bootstrap", "label=x", headers={"Content-Type": "text/plain"})
        assert r.status == 415
        r = w.req("POST", "/v1/ui/bootstrap", {"label": "ok"})
        assert r.status == 201 and r.json()["key"].startswith("rx_live_")
        assert w.req("POST", "/v1/ui/bootstrap", {"label": "again"}).status == 404
    finally:
        w.kill()


def test_web_bootstrap_race_issues_exactly_one_key():
    import subprocess
    import conftest
    w = Host()
    w.port = conftest.free_port()
    w.logpath = w.data_dir + ".log"
    w.proc = subprocess.Popen([conftest.REDXD, "run", "--data-dir", w.data_dir, "--listen",
                               "127.0.0.1:%d" % w.port, "--bootstrap", "web"],
                              stdout=open(w.logpath, "wb"), stderr=subprocess.STDOUT, env=w.env)
    try:
        for _ in range(200):
            try:
                if w.req("GET", "/healthz").status == 200:
                    break
            except OSError:
                time.sleep(0.05)
        with cf.ThreadPoolExecutor(24) as ex:
            rs = list(ex.map(lambda i: w.req("POST", "/v1/ui/bootstrap", {"label": "r%d" % i}), range(24)))
        assert sorted(r.status for r in rs).count(201) == 1
        k = [r for r in rs if r.status == 201][0].json()["key"]
        keys = w.req("GET", "/v1/keys", key=k).json()["keys"]
        assert len(keys) == 1
    finally:
        w.kill()
