"""API-key lifecycle: TTL extension via rotate, concurrent rotate fan-out.

These are BREAKs an outsider with any one live key (or an admin who rotates under
race) can exercise through the documented API alone.
"""
import concurrent.futures as cf
import time

from conftest import Host


def test_rotate_extends_ttl_by_resetting_created(fresh_host):
    """F2 HIGH BREAK: Rotate copies the original TTL measured from Created, then
    stamps a new Created=now. A short-lived key can be extended indefinitely by
    rotating before it expires. Documented TTL is relative to Create, not to
    absolute expiry, so this is a lifetime extension."""
    h = fresh_host
    k, kid = h.make_key("admin", db="default", ttl="4s")
    cur, cid = k, kid
    for i in range(4):
        time.sleep(3)
        r = h.req("POST", "/v1/keys/%s/rotate" % cid, {"grace": "0s"}, key=cur,
                  headers={"X-RedX-Confirm": "rotateKey"})
        assert r.status == 201, r.text
        j = r.json()
        cur, cid = j["key"], j["id"]
    assert h.req("GET", "/v1/stats", key=cur).status == 200
    # 4 * 3s = 12s on a key whose TTL was 4s: lifetime was extended.


def test_concurrent_rotate_fans_out_many_live_successors(fresh_host):
    """F3 HIGH BREAK: Rotate of the same key id under parallel load issues many
    live successors (CreateSpec with Replaces=old, then a separate Expires update
    of the old record). With a long grace every successor stays live; with grace=0
    a subset still races past Revoke. An attacker who holds one key and can fire
    N parallel rotates (or who races an admin's rotate) gets N live copies."""
    h = fresh_host
    L, _ = h.make_key("admin", db="*", rate_rps=-1, rate_burst=-1)
    k, kid = h.make_key("read")
    rs = list(cf.ThreadPoolExecutor(8).map(
        lambda _: h.req("POST", "/v1/keys/%s/rotate" % kid, {"grace": "1h"}, key=L,
                        headers={"X-RedX-Confirm": "rotateKey"}), range(8)))
    new = [r.json()["key"] for r in rs if r.status == 201]
    live = sum(1 for nk in new if h.req("GET", "/v1/stats", key=nk).status == 200)
    assert len(new) == 8 and live == 8, (len(new), live)
    # With grace=0 the TOCTOU still lets several succeed.
    k2, k2id = h.make_key("read")
    rs = list(cf.ThreadPoolExecutor(8).map(
        lambda _: h.req("POST", "/v1/keys/%s/rotate" % k2id, {"grace": "0s"}, key=L,
                        headers={"X-RedX-Confirm": "rotateKey"}), range(8)))
    live0 = sum(1 for r in rs if r.status == 201 and h.req("GET", "/v1/stats", key=r.json()["key"]).status == 200)
    assert live0 >= 2, live0


def test_global_pair_fail_budget_lets_one_ip_lock_out_everyone(fresh_host):
    """F4 MEDIUM BREAK: pairStore.redeem has a global fail budget (pairFailTotal=40
    in host/pairing.go). One or a few source IPs spending that budget make every
    subsequent redeem, including a legitimate one with a valid unused code, return
    429 for a minute. No authentication is required to burn the budget."""
    import http.client, json
    h = fresh_host
    # Issue a real code first (confirm header).
    r = h.req("POST", "/v1/keys/pairing", {"db": "default", "scope": "read"}, key=h.admin_key,
              headers={"X-RedX-Confirm": "createPairingCode"})
    assert r.status == 201, r.text
    code = r.json()["code"]

    def burn(src, n):
        for j in range(n):
            c = http.client.HTTPConnection("127.0.0.1", h.port, source_address=(src, 0), timeout=5)
            c.request("POST", "/v1/pair/exchange", json.dumps({"code": "RP-AAAAA-%04d" % j}),
                      {"Content-Type": "application/json"})
            c.getresponse().read()
            c.close()

    # 5 loopback-family source addresses × 8 fails = 40, exactly the global budget.
    for i in range(2, 7):
        burn("127.0.0.%d" % i, 8)
    c = http.client.HTTPConnection("127.0.0.1", h.port, source_address=("127.0.0.1", 0), timeout=5)
    c.request("POST", "/v1/pair/exchange", json.dumps({"code": code}), {"Content-Type": "application/json"})
    st = c.getresponse().status
    assert st == 429, st
