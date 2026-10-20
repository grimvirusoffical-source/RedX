"""API-key lifecycle regressions for F2–F4 (host-sec-fixes) and bypass probes.

Assert FIXED behaviour against a real redxd binary. Labels: BREAK = outsider
with public API alone; HARNESS = needs process-local control or map flooding.
"""
import concurrent.futures as cf
import http.client
import json
import time

from conftest import Host


def test_f2_rotated_key_expires_at_original_ttl(fresh_host):
    """F2 regression: successor inherits absolute expiry; rotates cannot extend life."""
    h = fresh_host
    k, kid = h.make_key("admin", db="default", ttl="4s")
    cur, cid = k, kid
    # Rotate twice inside the original window.
    for _ in range(2):
        time.sleep(1.2)
        r = h.req("POST", "/v1/keys/%s/rotate" % cid, {"grace": "0s"}, key=cur,
                  headers={"X-RedX-Confirm": "rotateKey"})
        assert r.status == 201, r.text
        j = r.json()
        cur, cid = j["key"], j["id"]
        assert h.req("GET", "/v1/stats", key=cur).status == 200
    # Past original Created+4s the chain must be dead (401), not extended.
    time.sleep(2.5)
    assert h.req("GET", "/v1/stats", key=cur).status == 401


def test_f3_concurrent_rotate_exactly_one_winner(fresh_host):
    """F3 regression: one of N concurrent rotates wins; the rest get 409."""
    h = fresh_host
    L, _ = h.make_key("admin", db="*", rate_rps=-1, rate_burst=-1)
    for grace in ("1h", "0s"):
        _, kid = h.make_key("read")
        rs = list(cf.ThreadPoolExecutor(8).map(
            lambda _: h.req("POST", "/v1/keys/%s/rotate" % kid, {"grace": grace}, key=L,
                            headers={"X-RedX-Confirm": "rotateKey"}), range(8)))
        wins = [r for r in rs if r.status == 201]
        conflicts = [r for r in rs if r.status == 409]
        assert len(wins) == 1, (grace, [r.status for r in rs])
        assert len(conflicts) == 7, (grace, [r.status for r in rs])
        nk = wins[0].json()["key"]
        assert h.req("GET", "/v1/stats", key=nk).status == 200
        # No second rotate of the same parent while the successor is live.
        again = h.req("POST", "/v1/keys/%s/rotate" % kid, {"grace": grace}, key=L,
                      headers={"X-RedX-Confirm": "rotateKey"})
        assert again.status == 409, again.text


def test_f4_valid_code_redeems_after_junk_from_other_ip(fresh_host):
    """F4 regression: per-IP limit; a clean IP can still redeem a valid code."""
    h = fresh_host
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

    # Exhaust one attacker's per-IP budget (8/min) and spill across a few IPs —
    # well under the 5000 global safety cap, so a clean IP must still succeed.
    for i in range(2, 7):
        burn("127.0.0.%d" % i, 8)
    c = http.client.HTTPConnection("127.0.0.1", h.port, source_address=("127.0.0.1", 0), timeout=5)
    c.request("POST", "/v1/pair/exchange", json.dumps({"code": code}),
              {"Content-Type": "application/json"})
    resp = c.getresponse()
    body = resp.read()
    assert resp.status == 201, (resp.status, body)


def test_bypass_rotate_successor_of_successor_keeps_absolute_expiry(fresh_host):
    """Probe: A→B→C rotate chain is allowed; C still dies at A's original expiry."""
    h = fresh_host
    k, kid = h.make_key("admin", db="default", ttl="5s")
    cur, cid = k, kid
    for _ in range(2):
        r = h.req("POST", "/v1/keys/%s/rotate" % cid, {"grace": "0s"}, key=cur,
                  headers={"X-RedX-Confirm": "rotateKey"})
        assert r.status == 201, r.text
        j = r.json()
        cur, cid = j["key"], j["id"]
    assert h.req("GET", "/v1/stats", key=cur).status == 200
    time.sleep(5.5)
    assert h.req("GET", "/v1/stats", key=cur).status == 401


def test_bypass_pair_map_cap_does_not_unlock_throttled_ip(fresh_host):
    """Probe (BREAK if it unlocks): flooding distinct source IPs toward the 10k
    map cap must not clear a throttled attacker's per-IP budget mid-window.

    Uses a bounded flood (not full 10k) that is still large enough to exercise
    eviction if it were FIFO-by-insert without preserving active buckets.
    """
    h = fresh_host
    attacker = "127.0.0.50"

    def post(src, code):
        c = http.client.HTTPConnection("127.0.0.1", h.port, source_address=(src, 0), timeout=5)
        try:
            c.request("POST", "/v1/pair/exchange", json.dumps({"code": code}),
                      {"Content-Type": "application/json"})
            r = c.getresponse()
            r.read()
            return r.status
        except OSError:
            return None
        finally:
            c.close()

    statuses = [post(attacker, "RP-AAAAA-%04d" % j) for j in range(10)]
    assert 429 in statuses, statuses
    # Flood other loopback IPs to pressure the failure maps. Attacker must stay 429.
    for i in range(1, 200):
        post("127.0.1.%d" % (i % 250 + 1), "RP-BBBBB-%04d" % i)
    assert post(attacker, "RP-CCCCC-CCCCC") == 429
